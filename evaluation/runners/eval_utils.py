"""
Shared utilities for DarkHotel evaluation scripts.
Provides pipeline-aware console output and JSON detail extraction.
"""


def format_slither_status(slither):
    """Parse slither_analysis into human-readable status + real warning count.

    Returns: (status_str, real_warning_count, unique_hints)

    Handles 3 cases from SlitherSmartWrapper:
      1. "No vulnerabilities detected by Slither" -> OK
      2. "[Low] reentrancy-events ..." -> real findings
      3. "SLITHER UNAVAILABLE ..." -> unavailable
    """
    warnings = slither.get('warnings', [])
    hints = slither.get('hints_used', [])
    if not warnings:
        return 'No data', 0, []
    first = str(warnings[0]) if warnings else ''
    if 'UNAVAILABLE' in first:
        return 'UNAVAILABLE', 0, []
    if 'No vulnerabilities detected' in first:
        return 'OK (no findings)', 0, []
    # Real warnings: count those starting with [ (e.g. "[Low] reentrancy-...")
    real_count = sum(1 for w in warnings if str(w).startswith('['))
    unique_hints = sorted(set(hints))
    return f'{real_count} findings', real_count, unique_hints


def print_pipeline_result(idx, total, contract_info, result, elapsed, verdict, status, detected_types):
    """Print compact pipeline output per contract to console.

    Args:
        idx: current contract index (1-based)
        total: total contracts
        contract_info: dict with filename, lines, chain, pragma
        result: raw API response dict (or {"error": ...})
        elapsed: analysis time in seconds
        verdict: "SAFE" | "VULNERABLE" | "ERROR" | "UNKNOWN"
        status: display status string ("CORRECT", "FP!", "MISSED", etc.)
        detected_types: list of {"type": ..., "swc_id": ...}
    """
    fname = contract_info.get('filename', '?')
    lines = contract_info.get('lines', '?')
    chain = contract_info.get('chain', '?')
    pragma = contract_info.get('pragma', '?')

    # Header
    print(f"\n{'='*70}")
    print(f"[{idx}/{total}] {fname} ({lines} lines, {chain}, pragma {pragma})")
    print(f"{'-'*70}")

    # Error case
    if 'error' in result:
        print(f"  ERROR: {str(result['error'])[:150]}")
        print(f"  Time: {elapsed:.1f}s")
        return

    # STEP 1: AST
    summary = result.get('summary', {})
    func_analysis = result.get('function_analysis', {})
    risky_names = [f['name'] for f in func_analysis.get('functions_analyzed', [])]
    risky_preview = ', '.join(risky_names[:4])
    if len(risky_names) > 4:
        risky_preview += f' +{len(risky_names)-4} more'
    print(f"  AST       | {summary.get('total_functions', 0)} functions, "
          f"{func_analysis.get('risky_functions', 0)} risky"
          f"{' [' + risky_preview + ']' if risky_names else ''}")

    # STEP 2: Slither
    slither = result.get('slither_analysis', {})
    sl_status, _, sl_unique_hints = format_slither_status(slither)
    hint_str = ', '.join(sl_unique_hints) if sl_unique_hints else ''
    print(f"  Slither   | {sl_status}"
          f"{' -> hints: ' + hint_str if hint_str else ''}")

    # STEP 3+4: RAG + CRAG
    rag = result.get('rag_findings', {})
    cases = rag.get('similar_cases', [])
    score_dist = rag.get('score_distribution', {})
    max_rel = score_dist.get('max_relevance', 0)
    crag = rag.get('crag_action', 'N/A')
    print(f"  RAG+CRAG  | {rag.get('total_candidates', 0)} candidates -> "
          f"{rag.get('top_k_ranked', 0)} reranked, "
          f"CRAG={crag} (max_score={max_rel})")
    for c in cases[:2]:
        ctype = str(c.get('type', '?'))[:40]
        print(f"              -> {ctype} ({c.get('swc_id', '?')}) "
              f"rerank={c.get('relevance_score', 0):.3f}")

    # STEP 5: LLM
    llm = result.get('llm_analysis', {})
    tokens = llm.get('tokens', {})
    print(f"  LLM       | {llm.get('model', 'N/A')}, "
          f"{tokens.get('prompt', 0)}+{tokens.get('completion', 0)} tokens")

    # STEP 6: Verdict
    st = result.get('ai_analysis_structured', {})
    confidence = st.get('confidence', 'N/A') if st else 'N/A'
    print(f"{'-'*70}")
    print(f"  RESULT    | {verdict} (confidence={confidence}) -- {elapsed:.1f}s [{status}]")

    if detected_types:
        for dt in detected_types:
            print(f"              -> {dt.get('type', '?')} ({dt.get('swc_id', '?')})")


def extract_pipeline_details(result):
    """Extract full pipeline details from API response for JSON output.

    Returns a dict with all pipeline step data, or minimal dict on error.
    This goes into each entry in the results JSON so reviewers can inspect
    any contract's full pipeline trace.
    """
    if 'error' in result:
        return {"error": result['error']}

    # AST
    summary = result.get('summary', {})
    func_analysis = result.get('function_analysis', {})

    # Slither
    slither = result.get('slither_analysis', {})
    sl_status, sl_real_count, sl_unique_hints = format_slither_status(slither)

    # RAG + CRAG
    rag = result.get('rag_findings', {})
    score_dist = rag.get('score_distribution', {})
    similar_cases = rag.get('similar_cases', [])

    # LLM
    llm = result.get('llm_analysis', {})

    # Structured verdict
    st = result.get('ai_analysis_structured', {}) or {}

    return {
        "ast": {
            "solidity_version": summary.get("solidity_version", "N/A"),
            "total_functions": summary.get("total_functions", 0),
            "risky_functions": func_analysis.get("risky_functions", 0),
            "risky_names": [f["name"] for f in func_analysis.get("functions_analyzed", [])],
        },
        "slither": {
            "status": sl_status,
            "real_warnings": sl_real_count,
            "unique_hints": sl_unique_hints,
            "raw_warnings": slither.get("warnings", []),
        },
        "rag": {
            "total_candidates": rag.get("total_candidates", 0),
            "top_k_ranked": rag.get("top_k_ranked", 0),
            "crag_action": rag.get("crag_action", "N/A"),
            "max_relevance": score_dist.get("max_relevance", 0),
            "crag_thresholds": score_dist.get("crag_thresholds", {}),
            "similar_cases": [
                {
                    "type": c.get("type", "?"),
                    "swc_id": c.get("swc_id", "?"),
                    "bi_encoder_score": c.get("bi_encoder_score", 0),
                    "relevance_score": c.get("relevance_score", 0),
                    "audit_company": c.get("audit_company", "N/A"),
                }
                for c in similar_cases
            ],
        },
        "llm": {
            "model": llm.get("model", "N/A"),
            "prompt_tokens": llm.get("tokens", {}).get("prompt", 0),
            "completion_tokens": llm.get("tokens", {}).get("completion", 0),
        },
        "verdict": {
            "verdict": st.get("verdict", "N/A"),
            "confidence": st.get("confidence", "N/A"),
            "vulnerabilities": st.get("vulnerabilities", []),
            "primary_vulnerability": st.get("primary_vulnerability"),
            "reasoning": st.get("reasoning", ""),
        },
    }
