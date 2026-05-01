"""
DarkHotel Ablation Study - SmartBugs-Curated Dataset (4 Conditions)
Runs all 4 ablation conditions via the /analyze endpoint on 98 vulnerable contracts.

Conditions:
  A. LLM-only:     disable_rag=true  & disable_slither=true
  B. LLM+RAG:      disable_slither=true
  C. LLM+Slither:  disable_rag=true
  D. Full pipeline: (default)

Usage:
    1. Start backend: cd backend && uvicorn main:app --port 8000
    2. Run all 4:     cd evaluation && python run_ablation_smartbugs.py
    3. Run one:       python run_ablation_smartbugs.py --condition A
    4. Resume:        python run_ablation_smartbugs.py --condition A --resume

Options:
    --condition   A, B, C, D, or ALL (default: ALL)
    --resume      Resume from checkpoint
    --category    reentrancy, arithmetic, unchecked (optional filter)
    --delay       Delay between API calls in seconds (default: 3)
"""

import os
import sys
import json
import re
import time
import argparse
import requests
from datetime import datetime
from pathlib import Path
from eval_utils import print_pipeline_result, extract_pipeline_details

# --- CONFIG ---
API_URL = os.getenv("API_URL", "http://localhost:8000/analyze")
EVAL_DIR = Path(__file__).parent.parent  # evaluation/
DATASET_DIR = EVAL_DIR / "external_datasets" / "SmartBugs-Curated" / "dataset"
MAPPING_FILE = EVAL_DIR / "ground_truth" / "smartbugs_ground_truth.json"
OUTPUT_DIR = EVAL_DIR / "report_result" / "ablation_results"

DELAY_BETWEEN_CALLS = 3

# Ablation conditions
CONDITIONS = {
    "A": {
        "name": "LLM-only",
        "description": "LLM only (no RAG, no Slither)",
        "params": {"disable_rag": "true", "disable_slither": "true"},
    },
    "B": {
        "name": "LLM+RAG",
        "description": "LLM + RAG (no Slither)",
        "params": {"disable_slither": "true"},
    },
    "C": {
        "name": "LLM+Slither",
        "description": "LLM + Slither (no RAG)",
        "params": {"disable_rag": "true"},
    },
    "D": {
        "name": "Full",
        "description": "Full pipeline (LLM + RAG + Slither)",
        "params": {},
    },
}

ALLOWED_SWCS = {"SWC-107", "SWC-101", "SWC-104"}


# ============================================================
# GROUND TRUTH & CHECKPOINT
# ============================================================

def load_ground_truth(category_filter=None):
    with open(MAPPING_FILE, "r") as f:
        data = json.load(f)

    contracts = data["contracts"]

    if category_filter:
        filter_map = {
            "reentrancy": "SWC-107",
            "arithmetic": "SWC-101",
            "unchecked": "SWC-104"
        }
        swc_filter = filter_map.get(category_filter)
        if swc_filter:
            contracts = {k: v for k, v in contracts.items() if v["swc_id"] == swc_filter}

    return contracts


def load_checkpoint(condition_id):
    cp_file = OUTPUT_DIR / f"checkpoint_{condition_id}.json"
    if cp_file.exists():
        with open(cp_file, "r") as f:
            return json.load(f)
    return {"results": [], "evaluated_files": []}


def save_checkpoint(condition_id, results, evaluated_files):
    cp_file = OUTPUT_DIR / f"checkpoint_{condition_id}.json"
    with open(cp_file, "w") as f:
        json.dump({
            "results": results,
            "evaluated_files": evaluated_files,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)


# ============================================================
# API CALL
# ============================================================

def analyze_contract(filepath: Path, params: dict) -> dict:
    """Send contract to API with ablation params"""
    with open(filepath, "rb") as f:
        files = {"file": (filepath.name, f, "text/plain")}
        response = requests.post(API_URL, files=files, params=params, timeout=300)

    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}: {response.text[:200]}"}

    return response.json()


# ============================================================
# RESULT EXTRACTION
# ============================================================

def normalize_swc(swc_id: str) -> str:
    if not swc_id:
        return ""
    match = re.search(r'SWC-(\d+)', swc_id)
    if match:
        return f"SWC-{match.group(1)}"
    return swc_id


def extract_verdict(api_response: dict) -> str:
    structured = api_response.get("ai_analysis_structured")
    if structured and isinstance(structured, dict):
        verdict = structured.get("verdict", "").upper()
        if verdict in ["VULNERABLE", "SAFE"]:
            return verdict

    llm = api_response.get("llm_analysis", {})
    verdict = llm.get("verdict", "").upper()
    if verdict in ["VULNERABLE", "SAFE"]:
        return verdict

    raw = api_response.get("ai_analysis", "")
    if "VULNERABLE" in raw.upper():
        return "VULNERABLE"
    if "SAFE" in raw.upper():
        return "SAFE"

    return "UNKNOWN"


def extract_detected_types(api_response: dict) -> list:
    types = []
    structured = api_response.get("ai_analysis_structured")
    if structured and isinstance(structured, dict):
        for vuln in structured.get("vulnerabilities", []):
            vtype = vuln.get("type", "")
            swc = vuln.get("swc_id", "")
            types.append({"type": vtype, "swc_id": swc})
    return types


# ============================================================
# SECONDARY FINDINGS VERIFICATION
# ============================================================

def read_contract(filepath: Path) -> str:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def get_solidity_version(code: str) -> float:
    match = re.search(r'pragma\s+solidity\s+[\^~>=]*(\d+\.\d+)', code)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return 0.0
    return 0.0


def has_safemath(code: str) -> bool:
    return bool(re.search(r'(SafeMath|using\s+SafeMath)', code))


def has_call_value(code: str) -> bool:
    return bool(re.search(r'\.(call\s*\{|call\.value\s*\()', code))


def has_unchecked_send_or_call(code: str) -> bool:
    lines = code.split('\n')
    for i, line in enumerate(lines):
        stripped = line.strip()
        if '.send(' in stripped:
            if not re.search(r'(require|if)\s*\(.*\.send\(', stripped):
                if not re.search(r'(bool\s+\w+|success)\s*=', stripped):
                    return True
        if '.call(' in stripped or '.call{' in stripped or '.call.value(' in stripped:
            if not re.search(r'(require|if)\s*\(.*\.(call|call\.value)', stripped):
                if not re.search(r'(bool\s+\w+|success)\s*[\,\)]\s*=', stripped):
                    found_check = False
                    for j in range(i, min(i + 3, len(lines))):
                        if re.search(r'require\s*\(\s*(success|\w+)\s*\)', lines[j]):
                            found_check = True
                            break
                    if not found_check:
                        return True
    return False


def verify_secondary(swc_id: str, code: str) -> bool:
    if swc_id == "SWC-107":
        return has_call_value(code)
    elif swc_id == "SWC-101":
        version = get_solidity_version(code)
        if version >= 0.8:
            return False
        if has_safemath(code):
            return False
        return bool(re.search(r'[\+\-\*]', code))
    elif swc_id == "SWC-104":
        return has_unchecked_send_or_call(code)
    return False


def get_false_alarm_reason(swc_id: str, code: str) -> str:
    if swc_id == "SWC-107":
        if not has_call_value(code):
            return "No .call{value:}() — only .send()/.transfer() (2300 gas)"
        return "Unknown"
    elif swc_id == "SWC-101":
        if get_solidity_version(code) >= 0.8:
            return f"Solidity {get_solidity_version(code)} has built-in overflow protection"
        if has_safemath(code):
            return "SafeMath is used"
        return "No exploitable arithmetic"
    elif swc_id == "SWC-104":
        return "Return values are checked"
    return "Outside target SWC types"


def analyze_secondary(results: list):
    type_recall = {
        "SWC-107": {"label": "Reentrancy", "total": 0, "detected": 0},
        "SWC-101": {"label": "Integer Overflow/Underflow", "total": 0, "detected": 0},
        "SWC-104": {"label": "Unchecked Return Value", "total": 0, "detected": 0}
    }

    secondary_stats = {
        "total": 0, "verified_true": 0, "false_alarm": 0, "details": []
    }
    primary_miss = []

    for r in results:
        expected_swc = normalize_swc(r["expected_swc"])
        predicted_types = r.get("predicted_types", [])
        predicted_swcs = [normalize_swc(t.get("swc_id", "")) for t in predicted_types]

        if expected_swc in type_recall:
            type_recall[expected_swc]["total"] += 1
            if expected_swc in predicted_swcs:
                type_recall[expected_swc]["detected"] += 1
            else:
                primary_miss.append(r)

        secondary_swcs = list(set(s for s in predicted_swcs if s and s != expected_swc))
        if secondary_swcs:
            sol_file = DATASET_DIR / r["file"]
            code = read_contract(sol_file)

            for sec_swc in secondary_swcs:
                secondary_stats["total"] += 1
                is_valid = verify_secondary(sec_swc, code) if code else False

                if is_valid:
                    secondary_stats["verified_true"] += 1
                else:
                    secondary_stats["false_alarm"] += 1
                    secondary_stats["details"].append({
                        "file": r["filename"],
                        "expected": expected_swc,
                        "false_alarm_swc": sec_swc,
                        "reason": get_false_alarm_reason(sec_swc, code)
                    })

    return type_recall, secondary_stats, primary_miss


# ============================================================
# RUN ONE CONDITION
# ============================================================

def run_condition(condition_id: str, resume=False, category_filter=None, delay=DELAY_BETWEEN_CALLS):
    cond = CONDITIONS[condition_id]
    params = cond["params"]

    print("=" * 70)
    print(f"ABLATION CONDITION {condition_id}: {cond['description']}")
    print(f"  API params: {params if params else '(none — full pipeline)'}")
    print("=" * 70)

    # Check API
    try:
        health = requests.get("http://localhost:8000/", timeout=5)
        info = health.json()
        print(f"API Status: {info.get('status')}")
        print(f"Model: {info.get('model')}")
    except requests.ConnectionError:
        print("ERROR: Backend not running! Start it first:")
        print("  cd backend && uvicorn main:app --port 8000")
        sys.exit(1)

    ground_truth = load_ground_truth(category_filter)
    total = len(ground_truth)
    print(f"\nContracts to evaluate: {total}")
    if category_filter:
        print(f"  Category filter: {category_filter}")

    type_counts = {}
    for v in ground_truth.values():
        t = v["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    for t, c in sorted(type_counts.items()):
        print(f"  {t}: {c}")
    print("-" * 70)

    # Resume
    results = []
    evaluated_files = []
    if resume:
        checkpoint = load_checkpoint(condition_id)
        results = checkpoint.get("results", [])
        evaluated_files = checkpoint.get("evaluated_files", [])
        if evaluated_files:
            print(f"\nResuming from checkpoint: {len(evaluated_files)} already evaluated")

    errors = []
    start_time = time.time()

    for i, (rel_path, truth) in enumerate(ground_truth.items(), 1):
        if rel_path in evaluated_files:
            continue

        filepath = DATASET_DIR / rel_path

        if not filepath.exists():
            print(f"[{i}/{total}] SKIP (not found): {rel_path}")
            errors.append({"file": rel_path, "error": "File not found"})
            continue

        # Read file info for pipeline display
        try:
            code = read_contract(filepath)
            file_lines = len(code.strip().splitlines()) if code else 0
        except Exception:
            file_lines = 0
            code = ""
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', code) if code else None
        pragma = pragma_match.group(1).strip() if pragma_match else "unknown"
        contract_info = {
            "filename": filepath.name,
            "lines": file_lines,
            "chain": "smartbugs",
            "pragma": pragma,
        }

        try:
            t0 = time.time()
            response = analyze_contract(filepath, params)
            elapsed = time.time() - t0

            if "error" in response:
                print_pipeline_result(i, total, contract_info, response, elapsed,
                                      "ERROR", "ERROR", [])
                errors.append({"file": rel_path, "error": response["error"]})
                continue

            verdict = extract_verdict(response)
            detected_types = extract_detected_types(response)

            correct = (verdict == "VULNERABLE")
            status = "TP" if correct else "FN"

            # Console: compact pipeline output
            print_pipeline_result(i, total, contract_info, response, elapsed,
                                  verdict, f"{status} (expected: {truth['type']})", detected_types)

            # JSON: full pipeline details
            pipeline = extract_pipeline_details(response)

            type_match = any(
                normalize_swc(dt.get("swc_id", "")) == truth["swc_id"]
                for dt in detected_types
            )

            result = {
                "file": rel_path,
                "filename": filepath.name,
                "expected_type": truth["type"],
                "expected_swc": truth["swc_id"],
                "predicted_verdict": verdict,
                "predicted_types": detected_types,
                "type_match": type_match,
                "correct": correct,
                "time_seconds": round(elapsed, 1),
                "ablation": response.get("ablation", ""),
                "pipeline": pipeline,
            }
            results.append(result)
            evaluated_files.append(rel_path)
            save_checkpoint(condition_id, results, evaluated_files)

        except Exception as e:
            print(f"  EXCEPTION: {e}")
            errors.append({"file": rel_path, "error": str(e)})

        if i < total:
            time.sleep(delay)

    total_time = time.time() - start_time

    # ============================================================
    # METRICS
    # ============================================================
    print("\n" + "=" * 70)
    print(f"RESULTS — CONDITION {condition_id}: {cond['description']}")
    print("=" * 70)

    tp = sum(1 for r in results if r["correct"])
    fn = sum(1 for r in results if not r["correct"])
    type_matches = sum(1 for r in results if r.get("type_match"))
    n_total = len(results)

    recall = tp / n_total if n_total > 0 else 0
    type_accuracy = type_matches / n_total if n_total > 0 else 0

    print(f"\nDetection (all contracts are vulnerable):")
    print(f"  Detected (TP):  {tp}/{n_total}")
    print(f"  Missed (FN):    {fn}/{n_total}")
    print(f"\n  Recall (Detection Rate): {recall:.2%}")
    print(f"  Type Accuracy:           {type_accuracy:.2%}")

    # Per-category
    print(f"\nPer-Category Breakdown:")
    categories = {}
    for r in results:
        cat = r["expected_type"]
        if cat not in categories:
            categories[cat] = {"total": 0, "detected": 0, "type_match": 0}
        categories[cat]["total"] += 1
        if r["correct"]:
            categories[cat]["detected"] += 1
        if r.get("type_match"):
            categories[cat]["type_match"] += 1

    for cat, stats in sorted(categories.items()):
        det_rate = stats["detected"] / stats["total"] if stats["total"] > 0 else 0
        type_rate = stats["type_match"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {cat:30s}: {stats['detected']}/{stats['total']} detected ({det_rate:.0%}), "
              f"type match: {stats['type_match']}/{stats['total']} ({type_rate:.0%})")

    times = [r["time_seconds"] for r in results]
    if times:
        print(f"\nAvg Analysis Time: {sum(times)/len(times):.1f}s")
        print(f"Total Time: {total_time/60:.1f} min")

    # Per-type recall
    print("\n" + "-" * 70)
    print("PER-TYPE RECALL:")
    type_recall, secondary_stats, primary_miss = analyze_secondary(results)

    for swc, stats in type_recall.items():
        rate = stats["detected"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {stats['label']:35s} ({swc}): {stats['detected']}/{stats['total']} = {rate:.0%}")

    total_detected = sum(s["detected"] for s in type_recall.values())
    total_all = sum(s["total"] for s in type_recall.values())
    if total_all > 0:
        print(f"  {'Overall':35s}       : {total_detected}/{total_all} = {total_detected/total_all:.0%}")

    if primary_miss:
        print(f"\n  MISSED contracts:")
        for m in primary_miss[:10]:
            print(f"    {m['filename']} — expected {m['expected_swc']}, "
                  f"got {[t['swc_id'] for t in m.get('predicted_types', [])]}")

    # Secondary findings
    print(f"\nSECONDARY FINDINGS:")
    print(f"  Total: {secondary_stats['total']}, "
          f"Verified: {secondary_stats['verified_true']}, "
          f"False alarm: {secondary_stats['false_alarm']}")

    if secondary_stats['total'] > 0:
        false_rate = secondary_stats['false_alarm'] / secondary_stats['total']
        print(f"  False alarm rate: {false_rate:.1%}")

    # Save results
    metrics = {
        "tp": tp, "fn": fn, "total": n_total,
        "recall": round(recall, 4),
        "type_accuracy": round(type_accuracy, 4),
    }

    output = {
        "metadata": {
            "evaluation": f"Ablation Study - Condition {condition_id}",
            "condition": condition_id,
            "condition_name": cond["name"],
            "description": cond["description"],
            "api_params": cond["params"],
            "timestamp": datetime.now().isoformat(),
            "dataset": "SmartBugs-Curated",
            "total_contracts": total,
            "evaluated": len(results),
            "errors": len(errors),
            "total_time_minutes": round(total_time / 60, 1),
            "category_filter": category_filter,
        },
        "metrics": metrics,
        "per_category": categories,
        "per_type_recall": {swc: {
            "label": s["label"], "detected": s["detected"],
            "total": s["total"],
            "recall": round(s["detected"] / s["total"], 4) if s["total"] > 0 else 0
        } for swc, s in type_recall.items()},
        "secondary_analysis": {
            "total": secondary_stats["total"],
            "verified_true": secondary_stats["verified_true"],
            "false_alarm": secondary_stats["false_alarm"],
            "false_alarm_details": secondary_stats["details"]
        },
        "results": results,
        "errors": errors
    }

    output_file = OUTPUT_DIR / f"ablation_{condition_id}_{cond['name'].lower().replace('+', '_')}_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to: {output_file}")

    # Cleanup checkpoint
    cp_file = OUTPUT_DIR / f"checkpoint_{condition_id}.json"
    if len(evaluated_files) >= total and cp_file.exists():
        cp_file.unlink()
        print("Checkpoint cleaned up (evaluation complete)")

    print("=" * 70)
    return condition_id, metrics, type_recall, secondary_stats


# ============================================================
# COMPARISON TABLE
# ============================================================

def print_comparison_table(all_results):
    """Print comparison table across all conditions"""
    print("\n" + "=" * 70)
    print("ABLATION STUDY COMPARISON TABLE")
    print("=" * 70)

    # Header
    print(f"\n{'Condition':<25s} | {'TP':>4s} | {'FN':>4s} | {'Recall':>8s} | {'Type Acc':>8s} | {'SWC-107':>8s} | {'SWC-101':>8s} | {'SWC-104':>8s}")
    print("-" * 100)

    for cond_id, metrics, type_recall, secondary_stats in all_results:
        cond = CONDITIONS[cond_id]
        r107 = type_recall["SWC-107"]
        r101 = type_recall["SWC-101"]
        r104 = type_recall["SWC-104"]

        r107_rate = f"{r107['detected']}/{r107['total']}" if r107['total'] > 0 else "N/A"
        r101_rate = f"{r101['detected']}/{r101['total']}" if r101['total'] > 0 else "N/A"
        r104_rate = f"{r104['detected']}/{r104['total']}" if r104['total'] > 0 else "N/A"

        print(f"{cond_id}. {cond['name']:<21s} | {metrics['tp']:>4d} | {metrics['fn']:>4d} | "
              f"{metrics['recall']:>7.2%} | {metrics['type_accuracy']:>7.2%} | "
              f"{r107_rate:>8s} | {r101_rate:>8s} | {r104_rate:>8s}")

    print("-" * 100)

    # Delta analysis (D vs A)
    if len(all_results) >= 2:
        print("\nDelta Analysis (improvement over LLM-only):")
        baseline = None
        for cond_id, metrics, _, _ in all_results:
            if cond_id == "A":
                baseline = metrics
                break

        if baseline:
            for cond_id, metrics, _, _ in all_results:
                if cond_id == "A":
                    continue
                delta_recall = metrics["recall"] - baseline["recall"]
                delta_type = metrics["type_accuracy"] - baseline["type_accuracy"]
                sign_r = "+" if delta_recall >= 0 else ""
                sign_t = "+" if delta_type >= 0 else ""
                print(f"  {cond_id}. {CONDITIONS[cond_id]['name']:<20s}: "
                      f"Recall {sign_r}{delta_recall:.2%}, "
                      f"Type Accuracy {sign_t}{delta_type:.2%}")

    # Save comparison
    comparison_file = OUTPUT_DIR / "ablation_comparison.json"
    comparison = {
        "timestamp": datetime.now().isoformat(),
        "conditions": {}
    }
    for cond_id, metrics, type_recall, secondary_stats in all_results:
        comparison["conditions"][cond_id] = {
            "name": CONDITIONS[cond_id]["name"],
            "description": CONDITIONS[cond_id]["description"],
            "metrics": metrics,
            "per_type_recall": {swc: {
                "label": s["label"], "detected": s["detected"], "total": s["total"],
                "recall": round(s["detected"] / s["total"], 4) if s["total"] > 0 else 0
            } for swc, s in type_recall.items()},
            "secondary_false_alarm_rate": round(
                secondary_stats["false_alarm"] / secondary_stats["total"], 4
            ) if secondary_stats["total"] > 0 else 0
        }

    with open(comparison_file, "w") as f:
        json.dump(comparison, f, indent=2)
    print(f"\nComparison saved to: {comparison_file}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DarkHotel Ablation Study on SmartBugs")
    parser.add_argument("--condition", choices=["A", "B", "C", "D", "ALL"],
                        default="ALL", help="Which condition to run (default: ALL)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--category", choices=["reentrancy", "arithmetic", "unchecked"],
                        help="Only evaluate one category")
    parser.add_argument("--delay", type=int, default=DELAY_BETWEEN_CALLS,
                        help=f"Delay between API calls in seconds (default: {DELAY_BETWEEN_CALLS})")
    args = parser.parse_args()

    # Create output directory
    OUTPUT_DIR.mkdir(exist_ok=True)

    if args.condition == "ALL":
        conditions_to_run = ["A", "B", "C", "D"]
    else:
        conditions_to_run = [args.condition]

    print("=" * 70)
    print("DarkHotel ABLATION STUDY — SmartBugs-Curated Dataset")
    print(f"Conditions to run: {', '.join(conditions_to_run)}")
    print(f"Contracts: 98 (31 SWC-107, 15 SWC-101, 52 SWC-104)")
    print("=" * 70)

    all_results = []
    for cond_id in conditions_to_run:
        print(f"\n{'#' * 70}")
        print(f"# STARTING CONDITION {cond_id}: {CONDITIONS[cond_id]['description']}")
        print(f"{'#' * 70}\n")

        result = run_condition(
            cond_id,
            resume=args.resume,
            category_filter=args.category,
            delay=args.delay
        )
        all_results.append(result)

        # Brief pause between conditions
        if cond_id != conditions_to_run[-1]:
            print(f"\nPausing 5s before next condition...")
            time.sleep(5)

    # Print comparison if multiple conditions
    if len(all_results) > 1:
        print_comparison_table(all_results)

    print("\nAblation study complete!")
