"""
DarkHotel - Combined Cross-Dataset Metrics Calculator
======================================================
Combines results from SmartBugs-Curated (vulnerable) and GPTScan Top200 (safe)
to compute cross-dataset Precision, Recall, F1, Specificity, and FPR.

Why cross-dataset?
  SmartBugs contains ONLY vulnerable contracts → gives TP and FN (Recall)
  Top200 contains ONLY safe contracts → gives TN and FP (Specificity)
  Neither dataset alone can compute F1 (needs both TP+FP for Precision).
  This script combines them to estimate full confusion matrix metrics.

  CAVEAT: The two datasets have different characteristics:
    - SmartBugs: older contracts (0.4.x-0.6.x), small, textbook vulnerabilities
    - Top200: newer contracts (0.8.x), large, production DeFi
  The combined F1 is an ESTIMATE, not a true single-dataset F1.
  This is the same methodology used by GPTScan (ISSTA 2024).

Usage:
    python calculate_combined_metrics.py
    python calculate_combined_metrics.py --smartbugs path/to/results.json --top200 path/to/results.json
    python calculate_combined_metrics.py --manual-tp 97 --manual-fn 0 --manual-fp 15 --manual-tn 210
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime

# Default paths (relative to this script)
EVAL_DIR = Path(__file__).parent.parent  # evaluation/
DEFAULT_SMARTBUGS = EVAL_DIR / "report_result" / "smartbugs_evaluation_results.json"
DEFAULT_TOP200 = EVAL_DIR / "report_result" / "top200_evaluation_results.json"
OUTPUT_FILE = EVAL_DIR / "report_result" / "combined_metrics_report.json"


def load_smartbugs_metrics(filepath: Path) -> dict:
    """Extract TP and FN from SmartBugs evaluation results."""
    with open(filepath, "r") as f:
        data = json.load(f)

    metrics = data.get("metrics", {})
    tp = metrics.get("tp", 0)
    fn = metrics.get("fn", 0)
    total = metrics.get("total", tp + fn)

    per_type = data.get("per_type_recall", {})

    return {
        "tp": tp,
        "fn": fn,
        "total": total,
        "recall": tp / total if total > 0 else 0,
        "per_type_recall": per_type,
        "source_file": str(filepath),
    }


def load_top200_metrics(filepath: Path) -> dict:
    """Extract TN and FP from Top200 evaluation results."""
    with open(filepath, "r") as f:
        data = json.load(f)

    metrics = data.get("metrics", {})
    tn = metrics.get("correct_safe", 0)
    fp = metrics.get("false_positives", 0)
    total = metrics.get("total", tn + fp)

    fp_types = data.get("false_positive_types", {})

    return {
        "tn": tn,
        "fp": fp,
        "total": total,
        "specificity": tn / total if total > 0 else 0,
        "fpr": fp / total if total > 0 else 0,
        "false_positive_types": fp_types,
        "source_file": str(filepath),
    }


def calculate_combined(tp: int, fn: int, fp: int, tn: int) -> dict:
    """Calculate all confusion matrix metrics from combined TP/FN/FP/TN."""
    total = tp + fn + fp + tn

    # Core metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    accuracy = (tp + tn) / total if total > 0 else 0

    # F1 score
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # F2 score (weights recall higher — common in security where missing vulns is worse)
    beta = 2
    f2 = ((1 + beta**2) * precision * recall / (beta**2 * precision + recall)
          if (beta**2 * precision + recall) > 0 else 0)

    # Matthews Correlation Coefficient (robust to class imbalance)
    mcc_denom = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = (tp * tn - fp * fn) / mcc_denom if mcc_denom > 0 else 0

    return {
        "confusion_matrix": {
            "tp": tp, "fp": fp,
            "fn": fn, "tn": tn,
            "total": total,
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "f2_score": round(f2, 4),
            "specificity": round(specificity, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "accuracy": round(accuracy, 4),
            "mcc": round(mcc, 4),
        },
    }


def print_report(smartbugs: dict, top200: dict, combined: dict):
    """Print formatted combined metrics report."""
    cm = combined["confusion_matrix"]
    m = combined["metrics"]

    print("=" * 70)
    print("DARKHOTEL - COMBINED CROSS-DATASET METRICS REPORT")
    print("=" * 70)

    # Source data
    print(f"\nData Sources:")
    print(f"  SmartBugs-Curated: {smartbugs['tp']} TP + {smartbugs['fn']} FN = {smartbugs['total']} vulnerable contracts")
    print(f"  GPTScan Top200:    {top200['tn']} TN + {top200['fp']} FP = {top200['total']} safe contracts")
    print(f"  Combined:          {cm['total']} total contracts")

    # Confusion matrix
    print(f"\n{'-' * 50}")
    print(f"  CONFUSION MATRIX")
    print(f"{'-' * 50}")
    print(f"                        Actual VULNERABLE  Actual SAFE")
    print(f"  Predicted VULNERABLE      TP = {cm['tp']:>4d}        FP = {cm['fp']:>4d}")
    print(f"  Predicted SAFE            FN = {cm['fn']:>4d}        TN = {cm['tn']:>4d}")

    # Metrics
    print(f"\n{'-' * 50}")
    print(f"  METRICS")
    print(f"{'-' * 50}")
    print(f"  Precision:             {m['precision']:.2%}  (of predicted VULNERABLE, how many are truly vulnerable)")
    print(f"  Recall (Sensitivity):  {m['recall']:.2%}  (of truly vulnerable, how many did we catch)")
    print(f"  F1 Score:              {m['f1_score']:.2%}  (harmonic mean of Precision & Recall)")
    print(f"  F2 Score:              {m['f2_score']:.2%}  (recall-weighted, penalizes missed vulns more)")
    print(f"  Specificity:           {m['specificity']:.2%}  (of truly safe, how many correctly identified)")
    print(f"  False Positive Rate:   {m['false_positive_rate']:.2%}  (safe contracts wrongly flagged)")
    print(f"  False Negative Rate:   {m['false_negative_rate']:.2%}  (vulnerable contracts missed)")
    print(f"  Accuracy:              {m['accuracy']:.2%}  (overall correct predictions)")
    print(f"  MCC:                   {m['mcc']:.4f}  (Matthews Correlation Coefficient, [-1, 1])")

    # Per-type recall
    per_type = smartbugs.get("per_type_recall", {})
    if per_type:
        print(f"\n{'-' * 50}")
        print(f"  PER-TYPE RECALL (from SmartBugs)")
        print(f"{'-' * 50}")
        for swc, info in per_type.items():
            r = info.get("recall", info.get("detected", 0) / info.get("total", 1))
            print(f"  {info.get('label', swc):35s} ({swc}): "
                  f"{info.get('detected', '?')}/{info.get('total', '?')} = {r:.0%}")

    # FP type breakdown
    fp_types = top200.get("false_positive_types", {})
    if fp_types:
        print(f"\n{'-' * 50}")
        print(f"  FALSE POSITIVE BREAKDOWN (from Top200)")
        print(f"{'-' * 50}")
        for fp_type, count in sorted(fp_types.items(), key=lambda x: -x[1]):
            print(f"  {fp_type:35s}: {count} false positives")

    # Caveat
    print(f"\n{'-' * 50}")
    print(f"  IMPORTANT CAVEAT")
    print(f"{'-' * 50}")
    print(f"  This F1 is a CROSS-DATASET ESTIMATE:")
    print(f"  - TP/FN from SmartBugs (old contracts, textbook vulns)")
    print(f"  - FP/TN from Top200 (production DeFi, modern Solidity)")
    print(f"  - Same methodology as GPTScan (ISSTA 2024)")
    print(f"  - For a true F1, a single mixed dataset is needed")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Calculate combined cross-dataset metrics for DarkHotel"
    )
    parser.add_argument("--smartbugs", type=Path, default=DEFAULT_SMARTBUGS,
                        help="Path to SmartBugs evaluation results JSON")
    parser.add_argument("--top200", type=Path, default=DEFAULT_TOP200,
                        help="Path to Top200 evaluation results JSON")
    # Manual override (for when result files don't exist yet)
    parser.add_argument("--manual-tp", type=int, default=None, help="Manual TP count")
    parser.add_argument("--manual-fn", type=int, default=None, help="Manual FN count")
    parser.add_argument("--manual-fp", type=int, default=None, help="Manual FP count")
    parser.add_argument("--manual-tn", type=int, default=None, help="Manual TN count")
    args = parser.parse_args()

    # Check if using manual mode
    manual_values = [args.manual_tp, args.manual_fn, args.manual_fp, args.manual_tn]
    if any(v is not None for v in manual_values):
        if not all(v is not None for v in manual_values):
            print("ERROR: Must provide ALL of --manual-tp, --manual-fn, --manual-fp, --manual-tn")
            sys.exit(1)

        tp, fn, fp, tn = args.manual_tp, args.manual_fn, args.manual_fp, args.manual_tn
        smartbugs_info = {
            "tp": tp, "fn": fn, "total": tp + fn,
            "recall": tp / (tp + fn) if (tp + fn) > 0 else 0,
            "per_type_recall": {}, "source_file": "manual input",
        }
        top200_info = {
            "tn": tn, "fp": fp, "total": tn + fp,
            "specificity": tn / (tn + fp) if (tn + fp) > 0 else 0,
            "fpr": fp / (fp + tn) if (fp + tn) > 0 else 0,
            "false_positive_types": {}, "source_file": "manual input",
        }
    else:
        # Load from files
        if not args.smartbugs.exists():
            print(f"ERROR: SmartBugs results not found: {args.smartbugs}")
            print("Run evaluation first, or use --manual-tp/fn/fp/tn flags")
            sys.exit(1)

        smartbugs_info = load_smartbugs_metrics(args.smartbugs)

        if not args.top200.exists():
            print(f"WARNING: Top200 results not found: {args.top200}")
            print("Using placeholder FP=0, TN=0 (run Top200 eval for real metrics)")
            top200_info = {
                "tn": 0, "fp": 0, "total": 0,
                "specificity": 0, "fpr": 0,
                "false_positive_types": {},
                "source_file": "NOT AVAILABLE",
            }
        else:
            top200_info = load_top200_metrics(args.top200)

    tp = smartbugs_info["tp"]
    fn = smartbugs_info["fn"]
    fp = top200_info["fp"]
    tn = top200_info["tn"]

    # Calculate combined metrics
    combined = calculate_combined(tp, fn, fp, tn)

    # Print report
    print_report(smartbugs_info, top200_info, combined)

    # Save to JSON
    output = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "description": "Cross-dataset combined metrics (SmartBugs + Top200)",
            "caveat": "F1 is cross-dataset estimate: TP/FN from SmartBugs, FP/TN from Top200",
            "methodology": "Same approach as GPTScan (ISSTA 2024)",
        },
        "sources": {
            "smartbugs": {
                "file": smartbugs_info.get("source_file", ""),
                "tp": tp, "fn": fn,
                "total_vulnerable": tp + fn,
                "recall": round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0,
            },
            "top200": {
                "file": top200_info.get("source_file", ""),
                "fp": fp, "tn": tn,
                "total_safe": fp + tn,
                "specificity": round(tn / (tn + fp), 4) if (tn + fp) > 0 else 0,
            },
        },
        "combined": combined,
        "per_type_recall": smartbugs_info.get("per_type_recall", {}),
        "false_positive_types": top200_info.get("false_positive_types", {}),
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
