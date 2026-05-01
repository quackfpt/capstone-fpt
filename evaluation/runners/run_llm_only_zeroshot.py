"""
DarkHotel Evaluation — TRUE Zero-Shot LLM-Only Baseline
========================================================

Đánh giá sức mạnh "tay không" của LLM (Gemini 2.5 Pro) khi:
  - KHÔNG có RAG (không có ví dụ lỗi tương tự từ knowledge base)
  - KHÔNG có Slither (không có cảnh báo từ static analysis)
  - KHÔNG có checklist khoanh vùng (không gợi ý "hãy tìm Reentrancy, SWC-107...")
  - KHÔNG có expert rules (không có safe pattern recognition)
  - KHÔNG có AST context (không biết hàm nào risky)

Prompt chỉ chứa:
  1. Role: "Bạn là chuyên gia bảo mật smart contract"
  2. Code Solidity thô (nguyên văn từ file .sol)
  3. Yêu cầu: "Phân tích và cho biết VULNERABLE hay SAFE"
  4. Output format JSON tối giản

Script gọi TRỰC TIẾP Gemini API — KHÔNG đi qua backend để tránh mọi context leak.

Hỗ trợ 2 dataset:
  --dataset smartbugs   98 vulnerable contracts (recall test)
  --dataset top200      225 safe production contracts (FPR test)
  --dataset both        Chạy cả 2 rồi tính combined metrics

Usage:
    python run_llm_only_zeroshot.py --dataset smartbugs
    python run_llm_only_zeroshot.py --dataset top200
    python run_llm_only_zeroshot.py --dataset both
    python run_llm_only_zeroshot.py --dataset smartbugs --resume
    python run_llm_only_zeroshot.py --dataset smartbugs --category reentrancy
"""

import os
import sys
import json
import re
import time
import argparse
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load .env from backend
EVAL_DIR = Path(__file__).parent.parent  # evaluation/
BACKEND_DIR = EVAL_DIR.parent / "backend" if (EVAL_DIR.parent / "backend").exists() \
    else EVAL_DIR / ".." / "backend"
load_dotenv(BACKEND_DIR / ".env")

# Google GenAI SDK
from google import genai
from google.genai.types import HttpOptions, GenerateContentConfig

# --- CONFIG ---
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "")
LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.5-pro")

SMARTBUGS_DIR = EVAL_DIR / "external_datasets" / "SmartBugs-Curated" / "dataset"
SMARTBUGS_MAPPING = EVAL_DIR / "ground_truth" / "smartbugs_ground_truth.json"
TOP200_DIR = EVAL_DIR / "external_datasets" / "GPTScan-Top200"

OUTPUT_DIR = EVAL_DIR / "report_result" / "llm_zeroshot_results"
DELAY_BETWEEN_CALLS = 3
REQUEST_TIMEOUT = 120
MIN_FILE_LINES = 10

# Allowed SWC types for type-match evaluation
ALLOWED_SWCS = {"SWC-107", "SWC-101", "SWC-104"}


# ============================================================
# ZERO-SHOT PROMPT — Trần trụi, không gợi ý
# ============================================================

ZERO_SHOT_PROMPT = """You are a smart contract security auditor.

Read the following Solidity source code and check for these 3 vulnerability types:
- Reentrancy (SWC-107)
- Integer Overflow/Underflow (SWC-101)
- Unchecked Return Value (SWC-104)

```solidity
{code}
```

Respond with ONLY a JSON object:

{{
  "verdict": "VULNERABLE" or "SAFE",
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "vulnerabilities": [
    {{
      "type": "Vulnerability name",
      "swc_id": "SWC-107 or SWC-101 or SWC-104",
      "severity": "Critical" or "High" or "Medium" or "Low",
      "location": "function or line where the issue exists",
      "description": "Brief explanation"
    }}
  ],
  "reasoning": "Your analysis"
}}

If no vulnerabilities found, return empty vulnerabilities array with verdict SAFE.
Output ONLY valid JSON — no markdown, no commentary, no code blocks.
"""


# ============================================================
# GEMINI CLIENT
# ============================================================

class GeminiZeroShot:
    """Direct Gemini API caller — no pipeline, no context, pure zero-shot."""

    def __init__(self):
        if not PROJECT_ID:
            print("ERROR: GOOGLE_CLOUD_PROJECT not set in .env")
            sys.exit(1)

        self.client = genai.Client(
            http_options=HttpOptions(api_version="v1beta1"),
            vertexai=True,
            project=PROJECT_ID,
            location=LOCATION,
        )
        self.model = MODEL_NAME
        self.max_retries = 5

    def analyze(self, code: str) -> dict:
        """Send raw code with zero-shot prompt. No hints, no context."""
        prompt = ZERO_SHOT_PROMPT.format(code=code)

        for attempt in range(self.max_retries):
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=GenerateContentConfig(temperature=0),
                )

                text = response.text
                analysis_json = self._parse_json(text)

                prompt_tokens = 0
                completion_tokens = 0
                if hasattr(response, 'usage_metadata') and response.usage_metadata:
                    usage = response.usage_metadata
                    prompt_tokens = getattr(usage, 'prompt_token_count', 0) or 0
                    completion_tokens = getattr(usage, 'candidates_token_count', 0) or 0

                return {
                    "success": True,
                    "analysis_json": analysis_json,
                    "raw": text,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                }

            except Exception as e:
                error_msg = str(e)
                print(f"    Error attempt {attempt + 1}: {error_msg[:120]}")

                if attempt >= self.max_retries - 1:
                    return {"success": False, "error": error_msg}

                if "429" in error_msg or "quota" in error_msg.lower() or "rate" in error_msg.lower():
                    retry_match = re.search(r'retry in (\d+\.?\d*)s', error_msg)
                    wait = float(retry_match.group(1)) + 5 if retry_match else 60 * (2 ** attempt)
                else:
                    wait = min(10 * (2 ** attempt), 120)

                print(f"    Waiting {wait:.0f}s...")
                time.sleep(wait)

        return {"success": False, "error": "Max retries exceeded"}

    def _parse_json(self, text: str) -> dict:
        if not text:
            return None

        # Strategy 1: Direct parse
        try:
            return json.loads(text.strip())
        except (json.JSONDecodeError, ValueError):
            pass

        # Strategy 2: Markdown code block
        match = re.search(r'```(?:json)?\s*(\{.*\})\s*```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        # Strategy 3: Brace matching
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
                            except (json.JSONDecodeError, ValueError):
                                pass
                            break

        return None


# ============================================================
# SMARTBUGS DATASET
# ============================================================

def load_smartbugs_ground_truth(category_filter=None):
    with open(SMARTBUGS_MAPPING, "r") as f:
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


# ============================================================
# TOP200 DATASET
# ============================================================

def discover_top200_contracts():
    contracts = []
    skipped = 0

    for project_dir in sorted(TOP200_DIR.iterdir()):
        if not project_dir.is_dir() or not project_dir.name.startswith("0x"):
            continue

        sol_files = list(project_dir.rglob("*.sol"))
        if len(sol_files) != 1:
            skipped += 1
            continue

        sol_file = sol_files[0]
        try:
            if sol_file.stat().st_size < 10:
                skipped += 1
                continue

            with open(sol_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = len(content.strip().splitlines())
            if lines < MIN_FILE_LINES:
                skipped += 1
                continue

            pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', content)
            pragma = pragma_match.group(1).strip() if pragma_match else "unknown"
            chain = project_dir.name.split("_")[-1] if "_" in project_dir.name else "unknown"

            contracts.append({
                "project": project_dir.name,
                "filepath": str(sol_file),
                "filename": sol_file.name,
                "lines": lines,
                "pragma": pragma,
                "chain": chain,
            })
        except Exception:
            skipped += 1

    print(f"Top200: {len(contracts)} valid contracts, {skipped} skipped")
    return contracts


# ============================================================
# RESULT EXTRACTION
# ============================================================

def normalize_swc(swc_id: str) -> str:
    if not swc_id:
        return ""
    match = re.search(r'SWC-(\d+)', swc_id)
    return f"SWC-{match.group(1)}" if match else ""


def infer_swc_from_type(vuln_type: str) -> str:
    """Infer SWC ID from vulnerability type name (since zero-shot LLM may not output SWC IDs)."""
    if not vuln_type:
        return ""
    t = vuln_type.lower()
    if any(k in t for k in ["reentrancy", "re-entrancy", "reentrant"]):
        return "SWC-107"
    if any(k in t for k in ["overflow", "underflow", "integer", "arithmetic"]):
        return "SWC-101"
    if any(k in t for k in ["unchecked", "return value", "low-level call", "send", "call return"]):
        return "SWC-104"
    return ""


def extract_verdict(analysis_json: dict) -> str:
    if not analysis_json:
        return "UNKNOWN"
    verdict = analysis_json.get("verdict", "").upper()
    if verdict in ["VULNERABLE", "SAFE"]:
        return verdict
    return "UNKNOWN"


def extract_detected_types(analysis_json: dict) -> list:
    if not analysis_json:
        return []
    types = []
    for vuln in analysis_json.get("vulnerabilities", []):
        vtype = vuln.get("type", "")
        swc = vuln.get("swc_id", "") or infer_swc_from_type(vtype)
        types.append({"type": vtype, "swc_id": swc})
    return types


# ============================================================
# CHECKPOINT
# ============================================================

def load_checkpoint(name: str) -> dict:
    cp_file = OUTPUT_DIR / f"checkpoint_{name}.json"
    if cp_file.exists():
        with open(cp_file, "r") as f:
            return json.load(f)
    return {"results": [], "evaluated_files": []}


def save_checkpoint(name: str, results: list, evaluated_files: list):
    cp_file = OUTPUT_DIR / f"checkpoint_{name}.json"
    with open(cp_file, "w") as f:
        json.dump({
            "results": results,
            "evaluated_files": evaluated_files,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)


# ============================================================
# SECONDARY FINDINGS VERIFICATION (SmartBugs only)
# ============================================================

def read_contract(filepath) -> str:
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


def has_call_value(code: str) -> bool:
    return bool(re.search(r'\.(call\s*\{|call\.value\s*\()', code))


def has_safemath(code: str) -> bool:
    return bool(re.search(r'(SafeMath|using\s+SafeMath)', code))


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
        if get_solidity_version(code) >= 0.8:
            return False
        if has_safemath(code):
            return False
        return bool(re.search(r'[\+\-\*]', code))
    elif swc_id == "SWC-104":
        return has_unchecked_send_or_call(code)
    return False


# ============================================================
# RUN SMARTBUGS EVALUATION
# ============================================================

def run_smartbugs(llm: GeminiZeroShot, resume=False, category_filter=None, delay=DELAY_BETWEEN_CALLS):
    print("\n" + "=" * 70)
    print("ZERO-SHOT LLM-ONLY — SmartBugs-Curated (Vulnerable Contracts)")
    print("Prompt: Raw code only. No SWC hints, no checklist, no expert rules.")
    print("=" * 70)

    ground_truth = load_smartbugs_ground_truth(category_filter)
    total = len(ground_truth)
    print(f"\nContracts: {total}")

    type_counts = {}
    for v in ground_truth.values():
        t = v["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    for t, c in sorted(type_counts.items()):
        print(f"  {t}: {c}")
    print("-" * 70)

    cp_name = f"smartbugs_zeroshot{'_' + category_filter if category_filter else ''}"
    results = []
    evaluated_files = []
    if resume:
        checkpoint = load_checkpoint(cp_name)
        results = checkpoint.get("results", [])
        evaluated_files = checkpoint.get("evaluated_files", [])
        if evaluated_files:
            print(f"Resuming: {len(evaluated_files)} already done")

    errors = []
    start_time = time.time()

    for i, (rel_path, truth) in enumerate(ground_truth.items(), 1):
        if rel_path in evaluated_files:
            continue

        filepath = SMARTBUGS_DIR / rel_path
        if not filepath.exists():
            print(f"[{i}/{total}] SKIP (not found): {rel_path}")
            errors.append({"file": rel_path, "error": "File not found"})
            continue

        code = read_contract(filepath)
        if not code.strip():
            print(f"[{i}/{total}] SKIP (empty): {rel_path}")
            errors.append({"file": rel_path, "error": "Empty file"})
            continue

        print(f"\n[{i}/{total}] {filepath.name}")
        print(f"  Expected: VULNERABLE ({truth['type']} — {truth['swc_id']})")

        try:
            t0 = time.time()
            response = llm.analyze(code)
            elapsed = time.time() - t0

            if not response["success"]:
                print(f"  ERROR: {response['error'][:100]}")
                errors.append({"file": rel_path, "error": response["error"]})
                continue

            analysis_json = response["analysis_json"]
            verdict = extract_verdict(analysis_json)
            detected_types = extract_detected_types(analysis_json)

            correct = (verdict == "VULNERABLE")
            status = "TP" if correct else "FN"
            print(f"  Predicted: {verdict} | {status} | {elapsed:.1f}s")

            if detected_types:
                for dt in detected_types[:3]:
                    print(f"    - {dt['type']} ({dt['swc_id']})")

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
                "prompt_tokens": response.get("prompt_tokens", 0),
                "completion_tokens": response.get("completion_tokens", 0),
            }
            results.append(result)
            evaluated_files.append(rel_path)
            save_checkpoint(cp_name, results, evaluated_files)

        except Exception as e:
            print(f"  EXCEPTION: {e}")
            errors.append({"file": rel_path, "error": str(e)})

        if i < total:
            time.sleep(delay)

    total_time = time.time() - start_time

    # === METRICS ===
    print("\n" + "=" * 70)
    print("RESULTS — ZERO-SHOT LLM-ONLY on SmartBugs-Curated")
    print("=" * 70)

    tp = sum(1 for r in results if r["correct"])
    fn = sum(1 for r in results if not r["correct"])
    n = len(results)
    recall = tp / n if n > 0 else 0
    type_matches = sum(1 for r in results if r.get("type_match"))
    type_accuracy = type_matches / n if n > 0 else 0

    print(f"\n  TP: {tp}/{n}  |  FN: {fn}/{n}")
    print(f"  Recall: {recall:.2%}")
    print(f"  Type Accuracy: {type_accuracy:.2%}")

    # Per-type
    print(f"\nPer-Type Recall:")
    type_recall = {}
    for r in results:
        swc = r["expected_swc"]
        if swc not in type_recall:
            type_recall[swc] = {"total": 0, "detected": 0, "type_match": 0, "label": r["expected_type"]}
        type_recall[swc]["total"] += 1
        if r["correct"]:
            type_recall[swc]["detected"] += 1
        if r.get("type_match"):
            type_recall[swc]["type_match"] += 1

    for swc, s in sorted(type_recall.items()):
        rate = s["detected"] / s["total"] if s["total"] > 0 else 0
        type_rate = s["type_match"] / s["total"] if s["total"] > 0 else 0
        print(f"  {s['label']:35s} ({swc}): {s['detected']}/{s['total']} = {rate:.0%}, type match: {type_rate:.0%}")

    # Secondary findings
    secondary_stats = {"total": 0, "verified_true": 0, "false_alarm": 0, "details": []}
    for r in results:
        expected_swc = r["expected_swc"]
        for dt in r.get("predicted_types", []):
            dt_swc = normalize_swc(dt.get("swc_id", ""))
            if dt_swc and dt_swc != expected_swc and dt_swc in ALLOWED_SWCS:
                secondary_stats["total"] += 1
                sol_file = SMARTBUGS_DIR / r["file"]
                code = read_contract(sol_file)
                if verify_secondary(dt_swc, code):
                    secondary_stats["verified_true"] += 1
                else:
                    secondary_stats["false_alarm"] += 1
                    secondary_stats["details"].append({
                        "file": r["filename"],
                        "expected": expected_swc,
                        "false_alarm_swc": dt_swc,
                    })

    print(f"\nSecondary Findings: {secondary_stats['total']} total, "
          f"{secondary_stats['verified_true']} verified, "
          f"{secondary_stats['false_alarm']} false alarm")

    # FN details
    fn_list = [r for r in results if not r["correct"]]
    if fn_list:
        print(f"\nMissed contracts (FN):")
        for r in fn_list:
            print(f"  {r['filename']} — expected {r['expected_swc']}, got {r['predicted_verdict']}")

    # Timing
    times = [r["time_seconds"] for r in results]
    if times:
        print(f"\nAvg time: {sum(times)/len(times):.1f}s | Total: {total_time/60:.1f} min")

    # Save
    output = {
        "metadata": {
            "evaluation": "Zero-Shot LLM-Only Baseline",
            "model": MODEL_NAME,
            "prompt_type": "zero-shot (raw code only, no SWC hints, no checklist)",
            "dataset": "SmartBugs-Curated",
            "timestamp": datetime.now().isoformat(),
            "total_contracts": total,
            "evaluated": n,
            "errors": len(errors),
            "total_time_minutes": round(total_time / 60, 1),
            "category_filter": category_filter,
        },
        "metrics": {
            "tp": tp, "fn": fn, "total": n,
            "recall": round(recall, 4),
            "type_accuracy": round(type_accuracy, 4),
        },
        "per_type_recall": {swc: {
            "label": s["label"], "detected": s["detected"], "total": s["total"],
            "recall": round(s["detected"] / s["total"], 4) if s["total"] > 0 else 0
        } for swc, s in type_recall.items()},
        "secondary_analysis": secondary_stats,
        "results": results,
        "errors": errors,
    }

    output_file = OUTPUT_DIR / "zeroshot_smartbugs_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {output_file}")

    # Cleanup checkpoint
    cp_file = OUTPUT_DIR / f"checkpoint_{cp_name}.json"
    if len(evaluated_files) >= total and cp_file.exists():
        cp_file.unlink()

    return {
        "dataset": "smartbugs",
        "tp": tp, "fn": fn, "fp": 0, "tn": 0,
        "recall": recall, "type_accuracy": type_accuracy,
        "secondary_false_alarm": secondary_stats["false_alarm"],
    }


# ============================================================
# RUN TOP200 EVALUATION
# ============================================================

def run_top200(llm: GeminiZeroShot, resume=False, delay=DELAY_BETWEEN_CALLS):
    print("\n" + "=" * 70)
    print("ZERO-SHOT LLM-ONLY — GPTScan Top200 (Safe Production Contracts)")
    print("Prompt: Raw code only. Any detection = False Positive.")
    print("=" * 70)

    contracts = discover_top200_contracts()
    total = len(contracts)

    # Chain distribution
    chain_counts = {}
    for c in contracts:
        chain_counts[c["chain"]] = chain_counts.get(c["chain"], 0) + 1
    for chain, count in sorted(chain_counts.items()):
        print(f"  {chain}: {count}")
    print("-" * 70)

    cp_name = "top200_zeroshot"
    results = []
    evaluated_files = []
    if resume:
        checkpoint = load_checkpoint(cp_name)
        results = checkpoint.get("results", [])
        evaluated_files = checkpoint.get("evaluated_files", [])
        if evaluated_files:
            print(f"Resuming: {len(evaluated_files)} already done")

    errors = []
    start_time = time.time()

    for i, contract in enumerate(contracts, 1):
        if contract["project"] in evaluated_files:
            continue

        filepath = Path(contract["filepath"])
        code = read_contract(filepath)
        if not code.strip():
            errors.append({"file": contract["project"], "error": "Empty file"})
            continue

        # Truncate very large files to avoid token limit
        if len(code) > 100000:
            code = code[:100000] + "\n// ... (truncated)"

        print(f"\n[{i}/{total}] {contract['filename']} ({contract['chain']}, {contract['lines']} lines)")
        print(f"  Expected: SAFE")

        try:
            t0 = time.time()
            response = llm.analyze(code)
            elapsed = time.time() - t0

            if not response["success"]:
                print(f"  ERROR: {response['error'][:100]}")
                errors.append({"file": contract["project"], "error": response["error"]})
                continue

            analysis_json = response["analysis_json"]
            verdict = extract_verdict(analysis_json)
            detected_types = extract_detected_types(analysis_json)

            is_fp = (verdict == "VULNERABLE")
            status = "FP" if is_fp else "TN"
            print(f"  Predicted: {verdict} | {status} | {elapsed:.1f}s")

            if detected_types and is_fp:
                for dt in detected_types[:3]:
                    print(f"    - {dt['type']} ({dt['swc_id']})")

            result = {
                "project": contract["project"],
                "filename": contract["filename"],
                "chain": contract["chain"],
                "lines": contract["lines"],
                "pragma": contract["pragma"],
                "predicted_verdict": verdict,
                "predicted_types": detected_types,
                "is_false_positive": is_fp,
                "time_seconds": round(elapsed, 1),
                "prompt_tokens": response.get("prompt_tokens", 0),
                "completion_tokens": response.get("completion_tokens", 0),
            }
            results.append(result)
            evaluated_files.append(contract["project"])
            save_checkpoint(cp_name, results, evaluated_files)

        except Exception as e:
            print(f"  EXCEPTION: {e}")
            errors.append({"file": contract["project"], "error": str(e)})

        if i < total:
            time.sleep(delay)

    total_time = time.time() - start_time

    # === METRICS ===
    print("\n" + "=" * 70)
    print("RESULTS — ZERO-SHOT LLM-ONLY on Top200")
    print("=" * 70)

    n = len(results)
    fp = sum(1 for r in results if r["is_false_positive"])
    tn = n - fp
    fpr = fp / n if n > 0 else 0
    specificity = tn / n if n > 0 else 0

    print(f"\n  TN: {tn}/{n}  |  FP: {fp}/{n}")
    print(f"  False Positive Rate: {fpr:.2%}")
    print(f"  Specificity: {specificity:.2%}")

    # Per-chain FPR
    print(f"\nPer-Chain FPR:")
    chain_stats = {}
    for r in results:
        chain = r["chain"]
        if chain not in chain_stats:
            chain_stats[chain] = {"total": 0, "fp": 0}
        chain_stats[chain]["total"] += 1
        if r["is_false_positive"]:
            chain_stats[chain]["fp"] += 1

    for chain, s in sorted(chain_stats.items()):
        rate = s["fp"] / s["total"] if s["total"] > 0 else 0
        print(f"  {chain:12s}: {s['fp']}/{s['total']} FP ({rate:.0%})")

    # FP type distribution
    fp_types = {}
    for r in results:
        if r["is_false_positive"]:
            for dt in r.get("predicted_types", []):
                t = dt.get("type", "Unknown")
                fp_types[t] = fp_types.get(t, 0) + 1

    if fp_types:
        print(f"\nFalse Positive Type Distribution:")
        for t, c in sorted(fp_types.items(), key=lambda x: -x[1]):
            print(f"  {t}: {c}")

    # Timing
    times = [r["time_seconds"] for r in results]
    if times:
        print(f"\nAvg time: {sum(times)/len(times):.1f}s | Total: {total_time/60:.1f} min")

    # Save
    output = {
        "metadata": {
            "evaluation": "Zero-Shot LLM-Only Baseline",
            "model": MODEL_NAME,
            "prompt_type": "zero-shot (raw code only, no SWC hints, no checklist)",
            "dataset": "GPTScan-Top200",
            "timestamp": datetime.now().isoformat(),
            "total_contracts": total,
            "evaluated": n,
            "errors": len(errors),
            "total_time_minutes": round(total_time / 60, 1),
        },
        "metrics": {
            "fp": fp, "tn": tn, "total": n,
            "false_positive_rate": round(fpr, 4),
            "specificity": round(specificity, 4),
        },
        "per_chain": {chain: {
            "fp": s["fp"], "total": s["total"],
            "fpr": round(s["fp"] / s["total"], 4) if s["total"] > 0 else 0
        } for chain, s in chain_stats.items()},
        "fp_type_distribution": fp_types,
        "results": results,
        "errors": errors,
    }

    output_file = OUTPUT_DIR / "zeroshot_top200_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {output_file}")

    # Cleanup checkpoint
    cp_file = OUTPUT_DIR / f"checkpoint_{cp_name}.json"
    if len(evaluated_files) >= total and cp_file.exists():
        cp_file.unlink()

    return {
        "dataset": "top200",
        "tp": 0, "fn": 0, "fp": fp, "tn": tn,
        "fpr": fpr, "specificity": specificity,
    }


# ============================================================
# COMBINED METRICS
# ============================================================

def print_combined(smartbugs_result, top200_result):
    print("\n" + "=" * 70)
    print("COMBINED METRICS — Zero-Shot LLM-Only Baseline")
    print("=" * 70)

    tp = smartbugs_result["tp"]
    fn = smartbugs_result["fn"]
    fp = top200_result["fp"]
    tn = top200_result["tn"]

    total = tp + fn + fp + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    f2 = 5 * precision * recall / (4 * precision + recall) if (4 * precision + recall) > 0 else 0
    accuracy = (tp + tn) / total if total > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    # MCC
    denom = ((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)) ** 0.5
    mcc = (tp*tn - fp*fn) / denom if denom > 0 else 0

    print(f"\n  TP: {tp}  |  FN: {fn}  |  FP: {fp}  |  TN: {tn}")
    print(f"\n  Precision:   {precision:.2%}")
    print(f"  Recall:      {recall:.2%}")
    print(f"  F1 Score:    {f1:.2%}")
    print(f"  F2 Score:    {f2:.2%}")
    print(f"  Accuracy:    {accuracy:.2%}")
    print(f"  Specificity: {specificity:.2%}")
    print(f"  FPR:         {fpr:.2%}")
    print(f"  MCC:         {mcc:.4f}")

    combined = {
        "metadata": {
            "evaluation": "Zero-Shot LLM-Only Combined",
            "model": MODEL_NAME,
            "timestamp": datetime.now().isoformat(),
        },
        "confusion_matrix": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "f2": round(f2, 4),
            "accuracy": round(accuracy, 4),
            "specificity": round(specificity, 4),
            "fpr": round(fpr, 4),
            "mcc": round(mcc, 4),
        }
    }

    output_file = OUTPUT_DIR / "zeroshot_combined_metrics.json"
    with open(output_file, "w") as f:
        json.dump(combined, f, indent=2)
    print(f"\nSaved: {output_file}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Shot LLM-Only Evaluation (no hints, no context)")
    parser.add_argument("--dataset", choices=["smartbugs", "top200", "both"],
                        default="smartbugs", help="Which dataset to evaluate")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--category", choices=["reentrancy", "arithmetic", "unchecked"],
                        help="SmartBugs only: filter by category")
    parser.add_argument("--delay", type=int, default=DELAY_BETWEEN_CALLS,
                        help=f"Delay between calls (default: {DELAY_BETWEEN_CALLS}s)")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)

    print("=" * 70)
    print("DarkHotel — TRUE ZERO-SHOT LLM-ONLY BASELINE")
    print(f"Model: {MODEL_NAME}")
    print(f"Prompt: Raw Solidity code only. NO SWC hints, NO checklist,")
    print(f"        NO expert rules, NO Slither, NO RAG.")
    print("=" * 70)

    llm = GeminiZeroShot()

    smartbugs_result = None
    top200_result = None

    if args.dataset in ("smartbugs", "both"):
        smartbugs_result = run_smartbugs(llm, resume=args.resume,
                                         category_filter=args.category, delay=args.delay)

    if args.dataset in ("top200", "both"):
        top200_result = run_top200(llm, resume=args.resume, delay=args.delay)

    if smartbugs_result and top200_result:
        print_combined(smartbugs_result, top200_result)

    print("\nDone!")
