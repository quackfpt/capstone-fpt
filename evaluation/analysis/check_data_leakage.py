"""
DarkHotel - Data Leakage Check
================================
Checks if SmartBugs evaluation contracts overlap with the Qdrant knowledge base.

If an evaluation contract appears in the KB (as an audit finding), the RAG system
could be "cheating" by retrieving the exact same code → inflated recall.

Method:
  1. Read each SmartBugs .sol contract
  2. Embed using voyage-code-3 (same model as pipeline)
  3. Search Qdrant for nearest neighbors
  4. Flag any result with similarity > LEAK_THRESHOLD as potential leakage

Usage:
    cd evaluation && python check_data_leakage.py

Output:
    - List of potential overlaps with similarity scores
    - Summary statistics
    - Saved to data_leakage_report.json
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Add backend to path
EVAL_DIR = Path(__file__).parent.parent  # evaluation/
BACKEND_DIR = EVAL_DIR.parent / "backend"
if not BACKEND_DIR.exists():
    BACKEND_DIR = EVAL_DIR.parent.parent / "DarkHotel-Capstone" / "backend"
sys.path.insert(0, str(BACKEND_DIR))

load_dotenv(BACKEND_DIR / ".env")

MAPPING_FILE = EVAL_DIR / "ground_truth" / "smartbugs_ground_truth.json"
DATASET_DIR = EVAL_DIR / "external_datasets" / "SmartBugs-Curated" / "dataset"
OUTPUT_FILE = EVAL_DIR / "report_result" / "data_leakage_report.json"

# Similarity threshold above which we flag potential leakage
# 0.95+ = near-exact match (likely same code in KB)
# 0.90-0.95 = very similar (may be variant of same vuln)
# 0.85-0.90 = similar pattern (expected for same vuln type)
LEAK_THRESHOLD = 0.90
WARN_THRESHOLD = 0.85


def main():
    print("=" * 60)
    print("DARKHOTEL - DATA LEAKAGE CHECK")
    print("=" * 60)

    # Load ground truth
    if not MAPPING_FILE.exists():
        print(f"ERROR: Ground truth not found: {MAPPING_FILE}")
        sys.exit(1)

    with open(MAPPING_FILE, "r") as f:
        ground_truth = json.load(f)["contracts"]

    print(f"Contracts to check: {len(ground_truth)}")

    # Initialize RAG system (uses same embedding + Qdrant as pipeline)
    try:
        from smart_rag_system import SmartRAGSystem
        qdrant_path = os.getenv("QDRANT_DB_PATH", str(BACKEND_DIR / "qdrant_db_forge"))
        rag = SmartRAGSystem(persist_directory=qdrant_path)
        print(f"RAG system ready ({rag.total_entries} points in KB)")
    except Exception as e:
        print(f"ERROR initializing RAG system: {e}")
        print("Make sure VOYAGE_API_KEY is set in backend/.env")
        sys.exit(1)

    # Check each contract
    results = []
    leaks_found = 0
    warnings_found = 0

    for i, (rel_path, truth) in enumerate(ground_truth.items(), 1):
        filepath = DATASET_DIR / rel_path
        if not filepath.exists():
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
        except Exception:
            continue

        if not code.strip():
            continue

        # Truncate for embedding (same as pipeline)
        query_code = code[:3000]

        print(f"[{i}/{len(ground_truth)}] {filepath.name} ({truth['type']})...", end=" ", flush=True)

        try:
            # Search KB for similar code
            matches = rag.search_similar(query_code, top_k=3, filter_type=None)

            if matches:
                top_score = matches[0].get("similarity", 0)
                top_type = matches[0].get("vulnerability_type", "?")
                top_source = matches[0].get("audit_company", "?")
                top_code = matches[0].get("code_snippet_vulnerable", "")[:200]

                entry = {
                    "file": rel_path,
                    "filename": filepath.name,
                    "expected_type": truth["type"],
                    "expected_swc": truth["swc_id"],
                    "top_similarity": round(top_score, 4),
                    "top_match_type": top_type,
                    "top_match_source": top_source,
                    "top_match_code_preview": top_code,
                    "all_scores": [round(m.get("similarity", 0), 4) for m in matches],
                }

                if top_score >= LEAK_THRESHOLD:
                    entry["status"] = "LEAK"
                    leaks_found += 1
                    print(f"LEAK! score={top_score:.4f} ({top_type} from {top_source})")
                elif top_score >= WARN_THRESHOLD:
                    entry["status"] = "WARN"
                    warnings_found += 1
                    print(f"WARN  score={top_score:.4f}")
                else:
                    entry["status"] = "OK"
                    print(f"OK    score={top_score:.4f}")

                results.append(entry)
            else:
                print("OK (no matches)")
                results.append({
                    "file": rel_path,
                    "filename": filepath.name,
                    "expected_type": truth["type"],
                    "top_similarity": 0,
                    "status": "OK",
                })

        except Exception as e:
            print(f"ERROR: {e}")
            continue

        # Rate limit Voyage API
        time.sleep(0.5)

    # Summary
    total = len(results)
    ok_count = sum(1 for r in results if r["status"] == "OK")

    print(f"\n{'=' * 60}")
    print(f"DATA LEAKAGE REPORT")
    print(f"{'=' * 60}")
    print(f"  Total checked:      {total}")
    print(f"  Clean (OK):         {ok_count} ({ok_count/max(total,1)*100:.1f}%)")
    print(f"  Warnings (>={WARN_THRESHOLD}):  {warnings_found}")
    print(f"  Leaks (>={LEAK_THRESHOLD}):     {leaks_found}")

    if leaks_found > 0:
        print(f"\n  POTENTIAL LEAKS (similarity >= {LEAK_THRESHOLD}):")
        for r in results:
            if r["status"] == "LEAK":
                print(f"    {r['filename']:40s} score={r['top_similarity']:.4f} "
                      f"({r.get('top_match_type', '?')} from {r.get('top_match_source', '?')})")

        print(f"\n  RECOMMENDATION:")
        print(f"  - {leaks_found} contracts may overlap with the knowledge base")
        print(f"  - Consider excluding these from evaluation OR")
        print(f"  - Document as limitation: 'KB may contain similar code patterns'")
        print(f"  - Ablation study (LLM-only vs Full) still shows relative improvement")
    else:
        print(f"\n  No significant data leakage detected.")
        print(f"  The knowledge base does not contain near-exact copies of eval contracts.")

    if warnings_found > 0:
        print(f"\n  WARNINGS (similarity {WARN_THRESHOLD}-{LEAK_THRESHOLD}):")
        for r in results:
            if r["status"] == "WARN":
                print(f"    {r['filename']:40s} score={r['top_similarity']:.4f}")
        print(f"\n  These are similar patterns but not exact matches.")
        print(f"  This is EXPECTED for contracts with the same vulnerability type.")

    # Save report
    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "leak_threshold": LEAK_THRESHOLD,
            "warn_threshold": WARN_THRESHOLD,
            "kb_size": rag.total_entries,
            "contracts_checked": total,
        },
        "summary": {
            "clean": ok_count,
            "warnings": warnings_found,
            "leaks": leaks_found,
            "leak_rate": round(leaks_found / max(total, 1), 4),
        },
        "results": sorted(results, key=lambda x: -x.get("top_similarity", 0)),
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\nReport saved to: {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()
