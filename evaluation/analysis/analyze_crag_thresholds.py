"""
DarkHotel - CRAG Threshold Analysis
====================================
Analyzes score distributions from evaluation results to empirically
validate or tune the CRAG thresholds (currently 0.7 / 0.3).

Reads evaluation result files and extracts relevance_score distributions,
then shows where the current thresholds fall relative to actual data.

Usage:
    python analyze_crag_thresholds.py
    python analyze_crag_thresholds.py --results path/to/results.json
    python analyze_crag_thresholds.py --results smartbugs_evaluation_results.json top200_evaluation_results.json
"""

import json
import argparse
import sys
from pathlib import Path
from collections import Counter

EVAL_DIR = Path(__file__).parent.parent  # evaluation/
SCRIPT_DIR = EVAL_DIR  # backward compat for CLI args


def extract_scores_from_results(filepath: Path) -> list:
    """Extract top relevance scores from evaluation results."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    scores = []

    for r in results:
        rag = r.get("rag_findings", {})
        score_dist = rag.get("score_distribution", {})
        rel_scores = score_dist.get("relevance_scores", [])
        max_rel = score_dist.get("max_relevance", 0)

        # If new format with score_distribution
        if rel_scores:
            scores.append({
                "file": r.get("filename", r.get("file", "?")),
                "verdict": r.get("predicted_verdict", "?"),
                "expected": r.get("expected_type", r.get("expected", "?")),
                "crag_action": rag.get("crag_action", "?"),
                "max_relevance": max_rel,
                "all_scores": rel_scores,
                "top5_mean": sum(rel_scores[:5]) / max(len(rel_scores[:5]), 1),
            })
        else:
            # Old format: extract from similar_cases
            cases = rag.get("similar_cases", [])
            if cases:
                rel = [c.get("relevance_score", 0) for c in cases]
                scores.append({
                    "file": r.get("filename", r.get("file", "?")),
                    "verdict": r.get("predicted_verdict", "?"),
                    "expected": r.get("expected_type", r.get("expected", "?")),
                    "crag_action": rag.get("crag_action", "?"),
                    "max_relevance": max(rel) if rel else 0,
                    "all_scores": rel,
                    "top5_mean": sum(rel[:5]) / max(len(rel[:5]), 1),
                })

    return scores


def analyze_distribution(scores: list, label: str):
    """Analyze and print score distribution with threshold analysis."""
    if not scores:
        print(f"\n  No scores found for {label}")
        return

    max_scores = [s["max_relevance"] for s in scores]
    max_scores_sorted = sorted(max_scores)

    n = len(max_scores)
    mean_val = sum(max_scores) / n
    median_val = max_scores_sorted[n // 2]
    p25 = max_scores_sorted[int(n * 0.25)]
    p75 = max_scores_sorted[int(n * 0.75)]
    min_val = min(max_scores)
    max_val = max(max_scores)

    print(f"\n{'=' * 60}")
    print(f"  SCORE DISTRIBUTION: {label} ({n} contracts)")
    print(f"{'=' * 60}")
    print(f"  Min:    {min_val:.4f}")
    print(f"  P25:    {p25:.4f}")
    print(f"  Median: {median_val:.4f}")
    print(f"  Mean:   {mean_val:.4f}")
    print(f"  P75:    {p75:.4f}")
    print(f"  Max:    {max_val:.4f}")

    # CRAG action distribution
    crag_actions = Counter(s["crag_action"] for s in scores)
    print(f"\n  CRAG Gate Distribution:")
    for action in ["CORRECT", "AMBIGUOUS", "INCORRECT", "?"]:
        count = crag_actions.get(action, 0)
        if count > 0:
            pct = count / n * 100
            print(f"    {action:12s}: {count:4d} ({pct:.1f}%)")

    # Threshold analysis
    CORRECT_T = 0.7
    INCORRECT_T = 0.3

    above_correct = sum(1 for s in max_scores if s >= CORRECT_T)
    ambiguous = sum(1 for s in max_scores if INCORRECT_T <= s < CORRECT_T)
    below_incorrect = sum(1 for s in max_scores if s < INCORRECT_T)

    print(f"\n  Current Thresholds (CORRECT={CORRECT_T}, INCORRECT={INCORRECT_T}):")
    print(f"    >= {CORRECT_T} (CORRECT):     {above_correct:4d} ({above_correct/n*100:.1f}%)")
    print(f"    [{INCORRECT_T}, {CORRECT_T}) (AMBIGUOUS): {ambiguous:4d} ({ambiguous/n*100:.1f}%)")
    print(f"    < {INCORRECT_T} (INCORRECT):   {below_incorrect:4d} ({below_incorrect/n*100:.1f}%)")

    # Histogram (text-based)
    print(f"\n  Score Histogram (max_relevance per contract):")
    bins = [(i/10, (i+1)/10) for i in range(10)]
    for low, high in bins:
        count = sum(1 for s in max_scores if low <= s < high)
        bar = "#" * (count * 40 // max(n, 1))
        marker = ""
        if low <= INCORRECT_T < high:
            marker = " <-- INCORRECT threshold"
        if low <= CORRECT_T < high:
            marker = " <-- CORRECT threshold"
        print(f"    [{low:.1f}-{high:.1f}): {count:4d} |{bar}{marker}")

    # Optimal threshold suggestion
    # Find threshold that maximizes separation between correct/incorrect verdicts
    print(f"\n  Threshold Sensitivity:")
    for t in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        above = sum(1 for s in max_scores if s >= t)
        print(f"    CORRECT threshold = {t}: {above}/{n} ({above/n*100:.1f}%) contracts get full evidence")


def main():
    parser = argparse.ArgumentParser(description="Analyze CRAG score distributions")
    parser.add_argument("--results", nargs="+", type=Path,
                        help="Evaluation result JSON files to analyze")
    args = parser.parse_args()

    print("=" * 60)
    print("DARKHOTEL - CRAG THRESHOLD ANALYSIS")
    print("=" * 60)

    if args.results:
        files = args.results
    else:
        # Auto-discover result files
        files = []
        candidates = [
            SCRIPT_DIR / "report_result" / "smartbugs_evaluation_results.json",
            SCRIPT_DIR / "report_result" / "top200_evaluation_results.json",
        ]
        # Also check ablation results
        ablation_dir = SCRIPT_DIR / "report_result" / "ablation_results"
        if ablation_dir.exists():
            candidates.extend(sorted(ablation_dir.glob("ablation_*_results.json")))

        for f in candidates:
            if f.exists():
                files.append(f)

    if not files:
        print("\nNo evaluation result files found.")
        print("Run evaluations first, then re-run this script.")
        print("Or specify files: python analyze_crag_thresholds.py --results path/to/results.json")
        sys.exit(1)

    print(f"\nFiles to analyze: {len(files)}")
    for f in files:
        print(f"  - {f.name}")

    all_scores = []
    for filepath in files:
        try:
            scores = extract_scores_from_results(filepath)
            if scores:
                analyze_distribution(scores, filepath.stem)
                all_scores.extend(scores)
            else:
                print(f"\n  {filepath.name}: no score data found (re-run eval with updated pipeline)")
        except Exception as e:
            print(f"\n  ERROR reading {filepath.name}: {e}")

    # Combined analysis
    if len(files) > 1 and all_scores:
        analyze_distribution(all_scores, "ALL COMBINED")

    print(f"\n{'=' * 60}")
    print("RECOMMENDATION")
    print(f"{'=' * 60}")
    print("If most contracts fall in AMBIGUOUS (0.3-0.7), consider:")
    print("  1. Lowering CORRECT threshold (e.g., 0.5 or 0.6)")
    print("  2. Raising INCORRECT threshold (e.g., 0.4)")
    print("  3. Keeping current if distribution is well-separated")
    print("")
    print("NOTE: Re-run evaluations with the updated pipeline to get")
    print("score_distribution data in the results JSON.")
    print("=" * 60)


if __name__ == "__main__":
    main()
