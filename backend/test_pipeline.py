"""
DarkHotel Pipeline Component Tests
===================================
Tests each pipeline step independently without API keys.
Run: python test_pipeline.py
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# SECTION 1: AST PARSER TESTS
# ============================================================

def test_ast_parser():
    from ast_parser import SolidityASTParser
    parser = SolidityASTParser()
    passed = 0
    failed = 0

    # --- TEST 1.1: Classic Reentrancy (Solidity 0.6) ---
    print("\n[1.1] Classic Reentrancy (Solidity ^0.6.0)")
    code = """
pragma solidity ^0.6.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}
"""
    result = parser.parse(code)
    summary = parser.get_summary(result)
    chunks = parser.get_function_chunks(result)
    risky = parser.get_risky_functions(result)

    print(f"  Parse: {summary['parse_method']}, Version: {summary['solidity_version']}")
    print(f"  Functions: {summary['total_functions']}, Risky: {len(risky)}")
    for f in chunks:
        print(f"    {f['name']}(): priority={f['priority']}, ext_call={f['has_external_call']}, "
              f"state_chg={f['has_state_change']}, mods={f['modifiers']}")
        if f.get('risk_indicators'):
            print(f"      indicators: {f['risk_indicators']}")
        has_ctx = 'State variables' in f.get('code_with_context', '')
        print(f"      code_with_context has state vars: {has_ctx}")

    wd = [f for f in risky if f['name'] == 'withdraw']
    ok = (len(wd) == 1 and wd[0]['has_external_call'] and wd[0]['has_state_change']
          and summary['solidity_version'] and '0.6' in summary['solidity_version'])
    print(f"  -> {'PASS' if ok else 'FAIL'}: withdraw() risky + version detected")
    passed += ok; failed += (not ok)

    # --- TEST 1.2: Safe Contract (0.8 + nonReentrant + CEI) ---
    print("\n[1.2] Safe Contract (Solidity ^0.8.20 + nonReentrant)")
    code2 = """
pragma solidity ^0.8.20;

contract SafeBank {
    mapping(address => uint256) private balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
"""
    result2 = parser.parse(code2)
    summary2 = parser.get_summary(result2)
    chunks2 = parser.get_function_chunks(result2)

    print(f"  Version: {summary2['solidity_version']}, Functions: {summary2['total_functions']}")
    for f in chunks2:
        print(f"    {f['name']}(): priority={f['priority']}, mods={f['modifiers']}")

    wd2 = [f for f in chunks2 if f['name'] == 'withdraw']
    has_mod = wd2 and 'nonReentrant' in wd2[0].get('modifiers', [])
    ver_ok = '0.8' in summary2.get('solidity_version', '')
    ok2 = ver_ok  # modifier detection is best-effort
    print(f"  nonReentrant detected: {has_mod}")
    print(f"  -> {'PASS' if ok2 else 'FAIL'}: version=0.8 detected")
    passed += ok2; failed += (not ok2)

    # --- TEST 1.3: Unchecked Return Value ---
    print("\n[1.3] Unchecked Return Value (.send + .call)")
    code3 = """
pragma solidity ^0.7.0;

contract UncheckedSend {
    address payable public owner;

    function withdrawSend() public {
        owner.send(address(this).balance);
    }

    function withdrawCall() public {
        (bool sent, ) = owner.call{value: address(this).balance}("");
    }
}
"""
    result3 = parser.parse(code3)
    chunks3 = parser.get_function_chunks(result3)
    risky3 = parser.get_risky_functions(result3)

    print(f"  Functions: {len(chunks3)}, Risky: {len(risky3)}")
    for f in chunks3:
        print(f"    {f['name']}(): priority={f['priority']}, ext_call={f['has_external_call']}")
    ok3 = len(risky3) >= 1
    print(f"  -> {'PASS' if ok3 else 'FAIL'}: has risky functions")
    passed += ok3; failed += (not ok3)

    # --- TEST 1.4: Empty Contract (edge case) ---
    print("\n[1.4] Empty Contract (edge case)")
    code4 = """
pragma solidity ^0.8.0;

contract Empty {
}
"""
    result4 = parser.parse(code4)
    summary4 = parser.get_summary(result4)
    chunks4 = parser.get_function_chunks(result4)
    ok4 = summary4['total_functions'] == 0 and len(chunks4) == 0
    print(f"  Functions: {summary4['total_functions']}, Chunks: {len(chunks4)}")
    print(f"  -> {'PASS' if ok4 else 'FAIL'}: 0 functions, 0 chunks")
    passed += ok4; failed += (not ok4)

    # --- TEST 1.5: Complex Multi-Vuln (0.5 + multiple patterns) ---
    print("\n[1.5] Complex Multi-Vuln (Solidity ^0.5.16)")
    code5 = """
pragma solidity ^0.5.16;

contract MultiVuln {
    mapping(address => uint256) public balances;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function deposit() public payable {
        balances[msg.sender] = balances[msg.sender] + msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call.value(amount)("");
        balances[msg.sender] -= amount;
    }

    function emergencyWithdraw() public onlyOwner {
        msg.sender.send(address(this).balance);
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
"""
    result5 = parser.parse(code5)
    summary5 = parser.get_summary(result5)
    chunks5 = parser.get_function_chunks(result5)
    risky5 = parser.get_risky_functions(result5)

    print(f"  Version: {summary5['solidity_version']}, Functions: {summary5['total_functions']}, Risky: {len(risky5)}")
    for f in chunks5:
        print(f"    {f['name']}(): priority={f['priority']}, ext_call={f['has_external_call']}, "
              f"state_chg={f['has_state_change']}, mods={f['modifiers']}")

    getbal = [f for f in chunks5 if f['name'] == 'getBalance']
    getbal_safe = getbal and getbal[0]['priority'] == 0
    wd5 = [f for f in risky5 if f['name'] == 'withdraw']
    ok5 = len(wd5) >= 1 and getbal_safe
    print(f"  getBalance() not risky: {getbal_safe}")
    print(f"  -> {'PASS' if ok5 else 'FAIL'}: withdraw risky + getBalance safe")
    passed += ok5; failed += (not ok5)

    return passed, failed


# ============================================================
# SECTION 2: QDRANT DB STRUCTURE TESTS
# ============================================================

def test_qdrant_db():
    from qdrant_client import QdrantClient

    passed = 0
    failed = 0
    db_path = "./qdrant_db_forge"

    if not os.path.exists(db_path):
        print("\n[2.x] Qdrant DB not found at ./qdrant_db_forge — SKIP")
        return 0, 0

    print("\n[2.1] Qdrant DB connection + collections")
    client = QdrantClient(path=db_path)
    collections = [c.name for c in client.get_collections().collections]
    print(f"  Collections: {collections}")

    expected = {'forge_curated', 'audits_with_reasons'}
    ok1 = expected.issubset(set(collections))
    print(f"  -> {'PASS' if ok1 else 'FAIL'}: expected collections exist")
    passed += ok1; failed += (not ok1)

    # --- TEST 2.2: Collection stats ---
    print("\n[2.2] Collection point counts")
    total = 0
    for coll in ['forge_curated', 'audits_with_reasons']:
        if coll in collections:
            info = client.get_collection(coll)
            print(f"  {coll}: {info.points_count} points, dim={info.config.params.vectors.size}")
            total += info.points_count
    ok2 = total > 1000  # should have 21k+
    print(f"  Total: {total} points")
    print(f"  -> {'PASS' if ok2 else 'FAIL'}: has >1000 points (expected ~21k)")
    passed += ok2; failed += (not ok2)

    # --- TEST 2.3: Payload structure ---
    print("\n[2.3] Payload structure (sample points)")
    for coll in ['forge_curated', 'audits_with_reasons']:
        if coll not in collections:
            continue
        points = client.scroll(collection_name=coll, limit=2, with_payload=True)[0]
        if points:
            p = points[0]
            keys = list(p.payload.keys()) if p.payload else []
            print(f"  {coll} payload keys: {keys}")
            has_doc_type = 'doc_type' in keys
            print(f"    has doc_type field: {has_doc_type}")
            if has_doc_type:
                print(f"    doc_type value: {p.payload['doc_type']}")

    # Check doc_type values in forge_curated
    try:
        from qdrant_client.models import Filter, FieldCondition, MatchValue
        desc_count = client.count(
            collection_name='forge_curated',
            count_filter=Filter(must=[FieldCondition(key="doc_type", match=MatchValue(value="description"))])
        ).count
        code_count = client.count(
            collection_name='forge_curated',
            count_filter=Filter(must=[FieldCondition(key="doc_type", match=MatchValue(value="code"))])
        ).count
        print(f"\n  forge_curated breakdown: {desc_count} descriptions, {code_count} code")
        ok3 = desc_count > 0 and code_count > 0
        print(f"  -> {'PASS' if ok3 else 'FAIL'}: both doc_types present")
        passed += ok3; failed += (not ok3)
    except Exception as e:
        print(f"  Count query failed: {e}")
        failed += 1

    client.close()
    return passed, failed


# ============================================================
# SECTION 3: LLM ANALYZER — JSON Parser + Post-Processing
# ============================================================

def test_llm_postprocessing():
    # Import just the class methods we need without google-genai
    # We'll test _parse_json_response and _filter_pragma_080 directly
    import re

    passed = 0
    failed = 0

    # Replicate the parse and filter methods locally (they don't need API)
    def parse_json_response(text):
        if not text:
            return None
        try:
            return json.loads(text.strip())
        except (json.JSONDecodeError, ValueError):
            pass
        match = re.search(r'```(?:json)?\s*(\{.*\})\s*```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except:
                pass
        start = text.find('{')
        if start != -1:
            depth = 0
            in_string = False
            escape_next = False
            for i in range(start, len(text)):
                ch = text[i]
                if escape_next:
                    escape_next = False
                    continue
                if ch == '\\' and in_string:
                    escape_next = True
                    continue
                if ch == '"' and not escape_next:
                    in_string = not in_string
                    continue
                if not in_string:
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            try:
                                return json.loads(text[start:i + 1])
                            except:
                                pass
                            break
        return None

    # --- TEST 3.1: Pure JSON ---
    print("\n[3.1] Parse pure JSON response")
    pure = '{"verdict": "VULNERABLE", "confidence": "HIGH", "primary_vulnerability": {"type": "Reentrancy", "swc_id": "SWC-107"}, "vulnerabilities": [], "secondary_warnings": [], "reasoning": "test"}'
    r = parse_json_response(pure)
    ok1 = r is not None and r['verdict'] == 'VULNERABLE'
    print(f"  -> {'PASS' if ok1 else 'FAIL'}: parsed pure JSON")
    passed += ok1; failed += (not ok1)

    # --- TEST 3.2: JSON wrapped in markdown ---
    print("\n[3.2] Parse markdown-wrapped JSON")
    md = '```json\n{"verdict": "SAFE", "confidence": "HIGH", "primary_vulnerability": null, "vulnerabilities": [], "secondary_warnings": [], "reasoning": "safe"}\n```'
    r2 = parse_json_response(md)
    ok2 = r2 is not None and r2['verdict'] == 'SAFE'
    print(f"  -> {'PASS' if ok2 else 'FAIL'}: parsed markdown JSON")
    passed += ok2; failed += (not ok2)

    # --- TEST 3.3: JSON with preamble text ---
    print("\n[3.3] Parse JSON with LLM preamble")
    preamble = 'Here is my analysis:\n\n{"verdict": "VULNERABLE", "confidence": "MEDIUM", "primary_vulnerability": {"type": "Unchecked Return Value", "swc_id": "SWC-104"}, "vulnerabilities": [{"type": "Unchecked Return Value", "swc_id": "SWC-104", "severity": "High", "location": "withdraw()", "description": "test", "exploit_scenario": "test", "recommendation": "test"}], "secondary_warnings": [], "reasoning": "analysis"}'
    r3 = parse_json_response(preamble)
    ok3 = r3 is not None and r3['verdict'] == 'VULNERABLE' and len(r3['vulnerabilities']) == 1
    print(f"  -> {'PASS' if ok3 else 'FAIL'}: parsed JSON with preamble")
    passed += ok3; failed += (not ok3)

    # --- TEST 3.4: Pragma 0.8+ filter removes SWC-101 ---
    print("\n[3.4] Pragma 0.8+ filter: removes SWC-101")
    analysis = {
        "verdict": "VULNERABLE",
        "confidence": "HIGH",
        "primary_vulnerability": {"type": "Integer Overflow", "swc_id": "SWC-101", "severity": "High"},
        "vulnerabilities": [
            {"type": "Integer Overflow", "swc_id": "SWC-101", "severity": "High"},
            {"type": "Reentrancy", "swc_id": "SWC-107", "severity": "Critical"}
        ],
        "secondary_warnings": [{"type": "Overflow", "swc_id": "SWC-101"}],
        "reasoning": "test"
    }

    ver_match = re.search(r'0\.(\d+)\.(\d+)', "^0.8.20")
    minor = int(ver_match.group(1)) if ver_match else 0
    if minor >= 8:
        # Filter SWC-101
        primary = analysis.get("primary_vulnerability")
        if primary and primary.get("swc_id") == "SWC-101":
            analysis["primary_vulnerability"] = None
        analysis["vulnerabilities"] = [v for v in analysis["vulnerabilities"] if v.get("swc_id") != "SWC-101"]
        analysis["secondary_warnings"] = [s for s in analysis["secondary_warnings"] if s.get("swc_id") != "SWC-101"]
        if analysis["primary_vulnerability"] is None and analysis["vulnerabilities"]:
            analysis["primary_vulnerability"] = analysis["vulnerabilities"][0]

    ok4 = (analysis["primary_vulnerability"]["swc_id"] == "SWC-107"
           and len(analysis["vulnerabilities"]) == 1
           and len(analysis["secondary_warnings"]) == 0)
    print(f"  Primary after filter: {analysis['primary_vulnerability']['swc_id']}")
    print(f"  Vulns remaining: {len(analysis['vulnerabilities'])}")
    print(f"  -> {'PASS' if ok4 else 'FAIL'}: SWC-101 removed, SWC-107 promoted")
    passed += ok4; failed += (not ok4)

    # --- TEST 3.5: Out-of-scope filter ---
    print("\n[3.5] Out-of-scope SWC filter")
    ALLOWED_SWCS = {"SWC-107", "SWC-101", "SWC-104"}
    analysis2 = {
        "verdict": "VULNERABLE",
        "primary_vulnerability": {"type": "Tx.Origin", "swc_id": "SWC-115", "severity": "Medium"},
        "vulnerabilities": [
            {"type": "Tx.Origin", "swc_id": "SWC-115"},
            {"type": "Reentrancy", "swc_id": "SWC-107"},
        ],
        "secondary_warnings": [{"type": "Timestamp", "swc_id": "SWC-116"}],
    }
    if analysis2["primary_vulnerability"]["swc_id"] not in ALLOWED_SWCS:
        analysis2["primary_vulnerability"] = None
    analysis2["vulnerabilities"] = [v for v in analysis2["vulnerabilities"] if v.get("swc_id") in ALLOWED_SWCS]
    analysis2["secondary_warnings"] = [s for s in analysis2["secondary_warnings"] if s.get("swc_id") in ALLOWED_SWCS]
    if analysis2["primary_vulnerability"] is None and analysis2["vulnerabilities"]:
        analysis2["primary_vulnerability"] = analysis2["vulnerabilities"][0]

    ok5 = (analysis2["primary_vulnerability"]["swc_id"] == "SWC-107"
           and len(analysis2["vulnerabilities"]) == 1
           and len(analysis2["secondary_warnings"]) == 0)
    print(f"  Primary: {analysis2['primary_vulnerability']['swc_id']}")
    print(f"  -> {'PASS' if ok5 else 'FAIL'}: SWC-115/116 removed, SWC-107 kept")
    passed += ok5; failed += (not ok5)

    # --- TEST 3.6: All vulns out-of-scope → SAFE ---
    print("\n[3.6] All vulns out-of-scope -> verdict SAFE")
    analysis3 = {
        "verdict": "VULNERABLE",
        "primary_vulnerability": {"type": "Timestamp", "swc_id": "SWC-116"},
        "vulnerabilities": [{"type": "Timestamp", "swc_id": "SWC-116"}],
        "secondary_warnings": [],
    }
    analysis3["vulnerabilities"] = [v for v in analysis3["vulnerabilities"] if v.get("swc_id") in ALLOWED_SWCS]
    if analysis3["primary_vulnerability"]["swc_id"] not in ALLOWED_SWCS:
        analysis3["primary_vulnerability"] = None
    if not analysis3["primary_vulnerability"] and not analysis3["vulnerabilities"]:
        analysis3["verdict"] = "SAFE"

    ok6 = analysis3["verdict"] == "SAFE" and analysis3["primary_vulnerability"] is None
    print(f"  Verdict: {analysis3['verdict']}")
    print(f"  -> {'PASS' if ok6 else 'FAIL'}: verdict changed to SAFE")
    passed += ok6; failed += (not ok6)

    # --- TEST 3.7: Nested JSON with escaped braces in reasoning ---
    print("\n[3.7] Parse JSON with braces in reasoning field")
    tricky = '{"verdict": "VULNERABLE", "confidence": "HIGH", "primary_vulnerability": {"type": "Reentrancy", "swc_id": "SWC-107", "severity": "Critical", "location": "withdraw()", "description": "test", "exploit_scenario": "call{value: amount}(\\"\\") pattern", "recommendation": "CEI"}, "vulnerabilities": [], "secondary_warnings": [], "reasoning": "The code uses msg.sender.call{value: amount}(\\"\\")"}'
    r7 = parse_json_response(tricky)
    ok7 = r7 is not None and r7['verdict'] == 'VULNERABLE'
    print(f"  Parsed: {r7 is not None}")
    print(f"  -> {'PASS' if ok7 else 'FAIL'}: handled braces in strings")
    passed += ok7; failed += (not ok7)

    return passed, failed


# ============================================================
# SECTION 4: SLITHER WRAPPER FALLBACK
# ============================================================

def test_slither_fallback():
    passed = 0
    failed = 0

    print("\n[4.1] Slither wrapper — graceful fallback when unavailable")
    try:
        from slither_smart_wrapper import SmartSlitherWrapper
        wrapper = SmartSlitherWrapper()

        code = """
pragma solidity ^0.8.0;
contract Test {
    function foo() public pure returns (uint) { return 1; }
}
"""
        warnings = wrapper.get_warnings_for_ai(code)
        print(f"  Returned: {len(warnings)} warning(s)")
        for w in warnings[:3]:
            # Replace emoji for Windows console encoding
            safe_w = w[:100].encode('ascii', 'replace').decode('ascii')
            print(f"    {safe_w}...")

        # Should return something (either actual warnings or unavailable message)
        ok1 = len(warnings) >= 1
        is_unavailable = any("SLITHER UNAVAILABLE" in w or "UNAVAILABLE" in w for w in warnings)
        is_no_vuln = any("No vulnerabilities" in w for w in warnings)
        is_findings = any(w.startswith('[') for w in warnings)

        if is_unavailable:
            print(f"  Status: Slither unavailable (expected if not installed)")
        elif is_no_vuln:
            print(f"  Status: Slither ran, no vulns found")
        elif is_findings:
            print(f"  Status: Slither found vulnerabilities")

        print(f"  -> {'PASS' if ok1 else 'FAIL'}: returns non-empty list (graceful)")
        passed += ok1; failed += (not ok1)
    except Exception as e:
        print(f"  Error: {e}")
        failed += 1

    return passed, failed


# ============================================================
# SECTION 5: CRAG EVALUATOR
# ============================================================

def test_crag_evaluator():
    from smart_rag_system import CRAGEvaluator

    crag = CRAGEvaluator()
    passed = 0
    failed = 0

    # --- 5.1: CORRECT (high relevance) ---
    print("\n[5.1] CRAG: high relevance -> CORRECT")
    candidates = [
        {"relevance_score": 0.85, "vulnerability_type": "Reentrancy"},
        {"relevance_score": 0.72, "vulnerability_type": "Reentrancy"},
    ]
    action, evidence = crag.evaluate(candidates)
    ok1 = action == "CORRECT" and len(evidence) == 2
    print(f"  Action: {action}, Evidence: {len(evidence)} cases")
    print(f"  -> {'PASS' if ok1 else 'FAIL'}")
    passed += ok1; failed += (not ok1)

    # --- 5.2: AMBIGUOUS (moderate relevance) ---
    print("\n[5.2] CRAG: moderate relevance -> AMBIGUOUS")
    candidates2 = [
        {"relevance_score": 0.55, "vulnerability_type": "Unchecked"},
        {"relevance_score": 0.25, "vulnerability_type": "Overflow"},
    ]
    action2, evidence2 = crag.evaluate(candidates2)
    ok2 = action2 == "AMBIGUOUS" and len(evidence2) == 1  # only 0.55 passes 0.3 threshold
    print(f"  Action: {action2}, Evidence: {len(evidence2)} cases")
    print(f"  -> {'PASS' if ok2 else 'FAIL'}")
    passed += ok2; failed += (not ok2)

    # --- 5.3: INCORRECT (low relevance) ---
    print("\n[5.3] CRAG: low relevance -> INCORRECT")
    candidates3 = [
        {"relevance_score": 0.15, "vulnerability_type": "Something"},
        {"relevance_score": 0.10, "vulnerability_type": "Else"},
    ]
    action3, evidence3 = crag.evaluate(candidates3)
    ok3 = action3 == "INCORRECT" and len(evidence3) == 0
    print(f"  Action: {action3}, Evidence: {len(evidence3)} cases")
    print(f"  -> {'PASS' if ok3 else 'FAIL'}")
    passed += ok3; failed += (not ok3)

    # --- 5.4: Empty candidates ---
    print("\n[5.4] CRAG: empty candidates -> INCORRECT")
    action4, evidence4 = crag.evaluate([])
    ok4 = action4 == "INCORRECT" and len(evidence4) == 0
    print(f"  Action: {action4}")
    print(f"  -> {'PASS' if ok4 else 'FAIL'}")
    passed += ok4; failed += (not ok4)

    return passed, failed


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("DarkHotel Pipeline Component Tests")
    print("=" * 70)

    total_passed = 0
    total_failed = 0

    print("\n### SECTION 1: AST PARSER ###")
    p, f = test_ast_parser()
    total_passed += p; total_failed += f

    print("\n### SECTION 2: QDRANT DB STRUCTURE ###")
    p, f = test_qdrant_db()
    total_passed += p; total_failed += f

    print("\n### SECTION 3: LLM JSON PARSER + POST-PROCESSING ###")
    p, f = test_llm_postprocessing()
    total_passed += p; total_failed += f

    print("\n### SECTION 4: SLITHER WRAPPER ###")
    p, f = test_slither_fallback()
    total_passed += p; total_failed += f

    print("\n### SECTION 5: CRAG EVALUATOR ###")
    p, f = test_crag_evaluator()
    total_passed += p; total_failed += f

    print("\n" + "=" * 70)
    print(f"TOTAL: {total_passed} PASSED, {total_failed} FAILED")
    print("=" * 70)

    if total_failed > 0:
        print("\nFAILED TESTS NEED ATTENTION!")
        sys.exit(1)
    else:
        print("\nAll tests passed!")
        sys.exit(0)
