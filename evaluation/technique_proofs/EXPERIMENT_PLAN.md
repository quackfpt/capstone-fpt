# Experiment Plan v7: Technique Validation for DarkHotel v7.0

> **Pre-registered**: All hypotheses and falsification criteria written BEFORE running experiments.
> **Date**: 2026-04-16
> **Rule**: Commit `hypotheses.md` BEFORE running ANY experiment. Note commit hash.
> **Version**: v7.2 — adds jina embedding model, empirical threshold validation (Step 3.5),
> INCORRECT threshold sweep (Step 4B), hypotheses H3.5/H3.6.
> v7.2 fixes: GPTScan citation (ICSE 2024), MCID self-justification, H3.4 falsification,
> Exp 2 Holm correction, data leakage acknowledgment, SWC-101 CI caveat, LLM determinism spec.
> **Hard rule**: After committing `hypotheses.md`, NO amendments. New issues → `methodology_qa.md`.

---

## Overview

Three experiments to validate core technical choices in DarkHotel's pipeline:

| Exp | Technique | Question |
|-----|-----------|----------|
| 1 | AST Function-Level Chunking | Is AST chunking better than industry-standard alternatives for vulnerability detection? |
| 2 | voyage-code-3 Embedding | Does voyage-code-3 outperform general-purpose and open-source embeddings for Solidity vulnerability retrieval? |
| 3 | CRAG Gate Thresholds | Are 0.65/0.30 optimal thresholds, and does CRAG improve end-to-end performance? |

### Mapping to advisor's 3 requirements

| Requirement | Answered by | Defense output |
|-------------|-------------|----------------|
| 1. Chunking — why AST? | Exp 1A/1B/1C (4 methods) | Table: 4 methods × F1 |
| 2. Embedding — why voyage-code-3? | Exp 2 (4 models) | Table: 4 models × discrimination gap |
| 3a. CRAG 0.65 — why? | Exp 3 Step 2-3 (analytical) + Step 3.5 (empirical 3×100) | Table: 3 thresholds × actual F1/FPR |
| 3b. CRAG 0.30 — why? | Exp 3 Step 4B (sweep 6 INCORRECT thresholds) | Table: 6 thresholds × OOD detection / FP rate |

---

## Day 0 (MANDATORY): Pre-register Hypotheses

**This step MUST be completed and git-committed before ANY experiment runs.**

Create `hypotheses.md` containing all hypotheses with:
- Prediction + numeric threshold
- Falsification condition (what result would reject the hypothesis)

Then: `git commit -m "Pre-register experimental hypotheses"` and record the commit hash.

This is the only defense against cherry-pick accusations. Skipping this step invalidates ~80% of the scientific value of all experiments below.

**Day 0 pre-commit checklist** (complete BEFORE `git commit`):
1. All 13 hypotheses written with prediction + threshold + falsification
2. Power analysis: run `statsmodels.stats.contingency_tables` McNemar power calc for primary tests (A vs C, B vs C). If underpowered for 5pp at α=0.025 → pre-register "inconclusive" as valid outcome
3. LLM determinism locked: `temperature=0, top_p=1, top_k=1` documented. MoE residual variance acknowledged
4. Data leakage check: verify voyage-code-3 training cutoff date. If verifiable → filter SmartBugs for post-cutoff contracts as supplementary hold-out analysis. If not verifiable → document in Known Limitations only

---

## Task 0.5: Verify Existing Data Validity

**Before using `top200_evaluation_results.json` (224 records out of 225 contracts; 1 API error) in any experiment.**

The existing Top200 data is used as Config C baseline (Exp 3 Step 5) and for threshold sweep (Exp 3 Step 2-3). If the pipeline has changed since that data was generated, comparisons are invalid.

Steps:
1. Check `git log` for when `top200_evaluation_results.json` was created
2. Check if `smart_rag_system.py`, `main.py`, or `llm_analyzer.py` have changed since then
3. **Check Qdrant collection point counts** match what existed when data was generated (if KB changed, scores are definitely stale)
4. Re-run 5 random Top200 contracts with current code (seed=42)
5. Compare `max_relevance` between existing vs current
6. **If Qdrant point count differs OR drift > 0.05 on >= 2/5 cases**: existing data is stale → must re-run full Top200 (~$30, ~6h) before Exp 3
7. **If point count matches AND drift <= 0.05 on >= 4/5 cases**: existing data is valid → proceed

Cost: ~$0.20, ~15 minutes. Saves from building entire Exp 3 on stale data.

---

## Experiment 1: AST Function-Level Chunking

### Research Question

Does AST-based function-level chunking produce higher-quality chunks for vulnerability detection compared to industry-standard text splitting methods?

### Hypotheses (Falsifiable)

**H1.1 — Structural completeness (comparative)**:
AST chunking will achieve >= 30 percentage points higher function-complete rate than RecursiveCharacterTextSplitter.
- **Falsification**: If the gap is < 15pp, AST's structural advantage is marginal and may not justify the added complexity of tree-sitter parsing.
- **Note**: AST chunking returns whole functions by design, so near-100% completeness is expected. H1.1 is primarily a **sanity check** + baseline characterization — the meaningful comparison is the gap vs RecursiveChar, not the absolute number. The real tests are H1.2 and H1.3.

**H1.2 — Retrieval quality**:
AST chunks will produce higher average top-1 cosine similarity when querying the knowledge base, compared to all other methods.
- **Falsification**: If RecursiveCharacterTextSplitter achieves average top-1 similarity within 0.05 of AST, then the structural advantage does not translate to retrieval improvement.

**H1.3 — End-to-end detection (critical test)**:
AST chunking will produce higher Detection F1 than all baselines when plugged into the full pipeline.
- **Falsification**: If any baseline achieves F1 within 2 percentage points of AST, then AST chunking is not a significant contributor. This is the test that actually matters — H1.1 and H1.2 are supporting evidence only.

### Baselines (4 methods)

| Method | Config | Rationale |
|--------|--------|-----------|
| **Fixed-size** | 500 chars, no overlap | Naive baseline (lower bound) |
| **Line-based** | 30 lines, no overlap | Simple structural baseline |
| **RecursiveCharacterTextSplitter** | chunk_size=512, overlap=50, separators=["\n\n", "\n", " "] | Industry standard (LangChain). This is the real competitor. |
| **AST function-level (DarkHotel)** | tree-sitter parse, function-level, state vars context enrichment | Our method |

### Dataset

**Part A — Structural analysis (no API needed):**
- Full SmartBugs: 98 vulnerable contracts
- Random 50 from Top200: safe contracts (seed=42)
- Total: 148 files

**Part B — Retrieval quality (needs VOYAGE_API_KEY):**
- Stratified sample SET-B: 30 files (10 Reentrancy + 7 Overflow + 7 Unchecked + 6 Safe), seed=42
- Each file: chunk with all 4 methods, embed each chunk, query Qdrant, record top-1 similarity

**Part C — End-to-end mini (needs VOYAGE + LLM):**
- Separate stratified sample SET-C: 50 files (16 Reentrancy + 10 Overflow + 14 Unchecked + 10 Safe), seed=43
- SET-C has NO overlap with SET-B (avoids overfitting to chunking choice)
- Each file: run full pipeline with each chunking method swapped in
- Record: verdict, detected types, F1
- **Sample size rationale**: McNemar's test requires ~25 discordant pairs for 80% power
  at medium effect size. With 50 contracts and expected ~40-60% discordance rate between
  methods, we expect 20-30 discordant pairs — borderline adequate. If discordant pairs
  < 20, use exact binomial test as fallback (better power at small N).

> **Limitation note**: If budget requires reusing SET-B for Part C, note in thesis:
> "Same sample used for component and end-to-end evaluation; results should be interpreted
> as upper bound on consistency between metrics."

### DECISION GATE between Part B and Part C

After Part B results:
- **H1.2 PASS** (AST top-1 sim > RecursiveChar + 0.05): Proceed to Part C.
- **H1.2 WEAK** (gap > 0 but < 0.05): Still proceed to Part C — component metric weak but end-to-end may differ.
- **H1.2 FAIL** (AST <= RecursiveChar): **STOP**. Re-evaluate chunking choice before spending $18 on Part C. Document the failure.

### Metrics

| Metric | Part | Description |
|--------|------|-------------|
| % function-complete chunks | A | Chunk contains exactly 1 full function (start to end) |
| % split-across chunks | A | A single function spans 2+ chunks |
| Total chunks produced | A | Fewer = more efficient (less API calls) |
| Has state var context | A | Chunk includes state variable declarations for context |
| Has risk metadata | A | Chunk has risk indicators, priority score |
| Avg top-1 similarity | B | Mean cosine similarity of top-1 KB match per chunk |
| Detection F1 | C | End-to-end F1 on 50-file sample |

### Statistical Tests

- Part A: Descriptive statistics (proportions with 95% Wilson CI)
- Part B: Wilcoxon signed-rank test on top-1 similarity (AST vs each baseline) — robust for
  bounded [0,1] scores that may be skewed. If Shapiro-Wilk normality test passes (p > 0.05),
  also report paired t-test for comparison. Report: p-value, 95% CI, effect size r.
- Part C: McNemar's test on detection outcomes (paired binary: correct/incorrect per contract).
  If discordant pairs < 20, use exact binomial test as fallback (better power at small N).
  Report: p-value, 95% CI, odds ratio.

### Cost Estimate

- Part A: Free (no API calls)
- Part B: ~120 embed calls (30 files x 4 methods) = ~$1-2
- Part C: ~200 LLM calls (50 files x 4 methods) = ~$15-20, ~3-4 hours

---

## Experiment 2: voyage-code-3 Embedding Quality

### Research Question

Does voyage-code-3 produce embeddings that discriminate vulnerability types and support cross-modal (code-to-NL) retrieval better than general-purpose and open-source embedding models?

### Hypotheses (Falsifiable)

**H2.1 — Intra-pattern similarity**:
Code samples with the same vulnerability pattern (e.g., two reentrancy variants) will have cosine similarity >= 0.75.
- **Falsification**: If intra-pattern similarity < 0.60, the model does not reliably group same-pattern code.

**H2.2 — Inter-pattern discrimination**:
The discrimination gap (sim_same_pattern - sim_different_pattern) will be >= 0.25 for voyage-code-3.
- **Falsification**: If gap < 0.15, the model cannot reliably separate vulnerability types in embedding space.

**H2.3 — voyage-code-3 vs all alternatives**:
voyage-code-3 will have a larger discrimination gap than all 3 alternatives (text-embedding-3-large, jina-embeddings-v2-base-code, UniXcoder-base).
- **Falsification**: If any alternative achieves equal or larger gap, then voyage-code-3's cost premium is not justified for this task.

**H2.4 — Cross-modal retrieval**:
Code-to-NL similarity (reentrancy code vs reentrancy NL description) will be >= 0.55 for voyage-code-3.
- **Falsification**: If cross-modal similarity < 0.40, the model does not effectively bridge code and natural language — which undermines our KB design (forge_curated contains NL descriptions).

### Models Compared

4 models covering 2 decision axes: code-specialized vs general-purpose, commercial vs open-source.

| Model | Type | Dimension | Cost | Rationale |
|-------|------|-----------|------|-----------|
| **voyage-code-3** | Code-specialized, commercial (API) | 1024d | ~$0.15 | Our choice |
| **text-embedding-3-large** (OpenAI) | General-purpose, commercial (API) | 3072d | ~$0.15 | Tests "do we need code-specialized?" |
| **jina-embeddings-v2-base-code** (Jina AI) | Code-specialized, open-source (local) | 768d | $0 | Tests "do we need commercial?" (2024 model) |
| **UniXcoder-base** (Microsoft) | Code-specialized, open-source (local) | 768d | $0 | Older open-source baseline (2022 model) |

> **Scope note**: 4 models cover the 2 primary decision axes but are not an exhaustive
> benchmark. Other models (nomic-embed-code, CodeBERT, bge-code) exist. We do not claim
> "best in absolute terms" — only that voyage-code-3 is justified vs these representative alternatives.

### Dataset — Hybrid Design

**Controlled samples (9, hand-written):**
Written to have known ground-truth relationships:

| ID | Group | Description |
|----|-------|-------------|
| A1 | Reentrancy vulnerable | Classic: call{value:} before state update |
| A2 | Reentrancy vulnerable | DAO-style variant (different syntax, same pattern) |
| B1 | Reentrancy safe | ReentrancyGuard + nonReentrant |
| B2 | Reentrancy safe | CEI pattern (state update before call) |
| C1 | Integer overflow | Unchecked addition overflow, pragma 0.6 |
| C2 | Integer overflow | Subtraction underflow pattern, pragma 0.5 |
| C3 | Integer overflow | Multiplication overflow in token calculation, pragma 0.7 |
| D1 | NL description | Reentrancy vulnerability description (English, 50-100 words, technical audit style) |
| D2 | NL description | Integer overflow vulnerability description (English, 50-100 words, technical audit style) |

**Real-world samples (20, from datasets):**
Selected from SmartBugs + Top200 to add diversity:
- 6 reentrancy contracts (SmartBugs SWC-107)
- 4 overflow contracts (SmartBugs SWC-101)
- 4 unchecked return value contracts (SmartBugs SWC-104)
- 6 safe contracts (Top200)

Total: 29 samples (9 controlled + 20 real-world). Provides both internal validity (controlled) and external validity (real-world).

**Intra-pattern pair counts**: Reentrancy has 6 intra-pairs (A1↔A2, B1↔B2, + cross),
Overflow has 3 intra-pairs (C1↔C2, C1↔C3, C2↔C3). Safe patterns use B1↔B2.

### Metrics

| Metric | Formula | What it measures |
|--------|---------|------------------|
| Intra-pattern similarity | mean(sim(Ai, Aj)) for same pattern i,j | Does model group same-vuln code? |
| Inter-pattern similarity | mean(sim(Ai, Cj)) for different patterns | Does model separate different vulns? |
| **Discrimination gap** | intra - inter | Key metric: larger = better separation |
| Cross-modal similarity | mean(sim(code_i, NL_i)) for matched pairs | Code-to-NL retrieval quality |
| Vulnerable-Safe gap | mean(sim(vuln, vuln)) - mean(sim(vuln, safe)) | Can model distinguish vuln from safe? |

### Statistical Tests

- Paired t-test: voyage-code-3 gap vs each alternative (3 tests)
- **Holm-Bonferroni correction** for 3 comparisons (α₁=0.0167, α₂=0.025, α₃=0.05)
- Bootstrap 95% CI on discrimination gap (1000 resamples)
- Report effect size (Cohen's d)

### Cost Estimate

- voyage-code-3: 29 embed calls = ~$0.15
- text-embedding-3-large: 29 embed calls = ~$0.15
- jina-embeddings-v2-base-code: 29 embed calls = $0 (local)
- UniXcoder-base: 29 embed calls = $0 (local)
- Total: < $1, ~2 minutes (includes local model loading)

---

## Experiment 3: CRAG Gate Threshold Validation

### Research Question

1. Are 0.65 (CORRECT) and 0.30 (INCORRECT) optimal thresholds for the CRAG gate?
2. Does the CRAG gate improve end-to-end performance compared to no gating?

### Hypotheses (Falsifiable)

**H3.1 — CORRECT threshold optimality (confirmatory)**:
0.65 will be within the top-3 threshold values (0.50 to 0.85, step 0.05) when ranked by F1 score on combined SmartBugs + Top200 data.
- **Falsification**: If 0.65 ranks outside top-3, a different threshold is objectively better and 0.65 was suboptimal.
- **Honesty note**: τ=0.65 was already selected based on v7.0 evaluation data (224 records). H3.1 is confirmatory re-analysis on extended data (322 records), not a novel pre-registered test. Value lies in: (a) confirmation on larger dataset, (b) Pareto frontier analysis, (c) identifying if threshold needs adjustment.

**H3.2 — CRAG improves FP rate**:
Full pipeline with CRAG (0.65/0.30) will have lower FP rate on Top200 than pipeline without CRAG (always send all evidence).
- **Falsification**: If No-CRAG achieves equal or lower FP rate, the CRAG gate adds complexity without benefit.

**H3.3 — RAG + CRAG improves over LLM-Only**:
Full pipeline (RAG + CRAG) will have higher F1 than LLM-Only baseline.
- **Falsification**: If LLM-Only F1 >= Full pipeline F1, the entire RAG subsystem is unnecessary.

**H3.4 — INCORRECT threshold as safety net**:
>= 70% of OOD (out-of-distribution) inputs will score below 0.65 (not in CORRECT zone). >= 40% will score below 0.30 (INCORRECT zone).
- **Falsification**: If < 50% of OOD inputs score below 0.65 OR < 25% score below 0.30, the CRAG gate cannot reliably distinguish OOD from in-distribution.
- **Inconclusive zone**: 50-70% below 0.65 or 25-40% below 0.30 — partial OOD sensitivity, warrants investigation but not outright failure.

**H3.5 — Analytical-empirical consistency (NEW v7)**:
The top-1 threshold by estimated F1 (analytical, Step 2-3) will be the same as the top-1 by actual F1 (empirical, Step 3.5).
- **Falsification**: If top-1 empirical differs from top-1 analytical, the analytical sweep does not reliably predict the best threshold and cannot substitute empirical validation.
- **Note**: Step 3.5 only runs the top 3 analytical candidates, so "top 3 empirical" = all 3 candidates (trivially satisfied). The meaningful test is top-1 match. With only 3 candidates, random match probability = 1/3 = 33%. Interpret as **supportive evidence**, not confirmatory proof.

**H3.6 — INCORRECT threshold optimality (NEW v7)**:
0.30 will be within the top-3 INCORRECT thresholds when ranked by OOD detection F1 (Step 4B sweep).
- **Falsification**: If 0.30 ranks outside top-3, a different INCORRECT threshold is objectively better.

**Framing for INCORRECT threshold (defense-in-depth)**:
> The INCORRECT threshold is intentionally calibrated as a safety net for out-of-distribution inputs. Its low trigger rate on benchmark datasets (SmartBugs, Top200) is expected and demonstrates correct calibration of upstream retrieval. We validate its activation behavior via OOD injection (Step 4).

### Step 1 — Collect relevance scores for SmartBugs (NEW DATA NEEDED)

Run Step 1-4 only (AST -> RAG search -> Rerank -> CRAG) on 98 SmartBugs contracts.
No LLM call needed — only collecting max_relevance_score per contract.

Output: `smartbugs_relevance_scores.json`
```json
[
  {
    "filename": "xxx.sol",
    "expected_swc": "SWC-107",
    "max_relevance": 0.78,
    "all_relevance_scores": [0.78, 0.65, 0.52, 0.41, 0.30],
    "top_candidate_type": "Reentrancy (SWC-107)"
  }
]
```

Combine with existing Top200 data (224 records with pipeline.rag.max_relevance).

### Step 2-3 — CORRECT + INCORRECT Threshold Sweep (Analytical)

Sweep correct_threshold from 0.50 to 0.85 (step 0.05).

At each threshold T, compute:
- **Vuln_in_CORRECT**: # SmartBugs contracts with max_relevance >= T (want: high)
- **Safe_in_CORRECT**: # Top200 contracts with max_relevance >= T
- **FP_rate_CORRECT**: Among Safe_in_CORRECT, % that were FP in the actual evaluation
- **FP_rate_below**: Among contracts below T, % that were FP
- **Estimated F1**: Using TP from SmartBugs, FP from Top200, at this threshold

Selection criteria for optimal threshold:
- Maximize F1 (or: maximize recall subject to FP_rate_CORRECT <= 25%)
- Report the full Pareto frontier, not just one point
- **Identify top 3 thresholds for empirical validation** (Step 3.5)

### Step 3.5 — Empirical Threshold Validation (NEW v7)

**Purpose**: Defend 0.65 with empirical evidence, not just analytical estimates.

Take the top 3 thresholds from Step 2-3 (expected: {0.60, 0.65, 0.70}).
Run actual full pipeline for each threshold on 100 stratified MIXED contracts.

- 100 contracts (seed=42): **70 vulnerable (SmartBugs) + 30 safe (Top200)**
  - 30 reentrancy (SWC-107) from SmartBugs — measure Recall reentrancy
  - 15 integer overflow (SWC-101) from SmartBugs — measure Recall overflow (all available, no buffer)
  - 25 unchecked return value (SWC-104) from SmartBugs — measure Recall unchecked
  - 30 safe contracts from Top200 — measure FPR
- Mixed dataset enables full F1 calculation (both recall and precision), not just FPR
- **No overlap with Step 5 pilot**: 30 safe contracts selected here MUST NOT overlap with the 50 contracts used in Step 5 pilot (avoid data contamination between experiments). Use seed=42 but filter out Step 5 pilot filenames before selection.
- **Save filename list in `raw/run_config.json`** (critical: SWC-101 uses all available, needs reproducibility)
- 3 thresholds × 100 contracts = 300 LLM calls
- Per (threshold, contract): record verdict, detected_types, crag_action, confidence
- Measure per threshold:
  - Overall F1, FPR, Recall, Precision
  - **Recall per SWC type** (reentrancy / overflow / unchecked) — detect if a threshold is good overall but misses a specific vuln class
- Compare: estimated F1 (Step 2-3) vs actual F1 (Step 3.5)

**Decision rule**:
- If F1 gap between thresholds > 3pp → conclusive, pick best
- If F1 gap < 3pp → optionally extend sample (+50 contracts, +$10) to confirm
- **Per-SWC warning rule**: If winning threshold has any SWC-type Recall < 80% → flag warning in findings, document trade-off (threshold good overall but misses specific vuln class)

### Step 4 — OOD Injection + INCORRECT Threshold Sweep

**Purpose**: Validate 0.30 with empirical evidence.

**Part A: OOD Injection**

Prepare 15-17 OOD (out-of-distribution) inputs across 5 categories.
N >= 15 ensures H3.4 thresholds (70%, 40%) are testable — with n=10, a single
sample = 10% swing, making percentage-based thresholds unreliable.

| # | OOD Type | Count | Fair? | Rationale |
|---|----------|-------|-------|-----------|
| 1-3 | Vyper smart contracts | 3 | Fair | Different language, similar domain |
| 4-6 | Cairo / Move contracts | 3 | Fair | Different platform entirely |
| 7-12 | Complex governance / cross-chain / NFT Solidity (domain far from KB) | 6 | Fairest | "Soft OOD" — production-realistic, most informative |
| 13-15 | Obfuscated / minified Solidity | 3 | Fair | Adversarial robustness |
| 16-17 | Solidity with only events/structs/interfaces, no callable functions | 2 | Fair | Edge case: no attack surface |

Run each through Step 1-4, record max_relevance + CRAG action.

**Part B: INCORRECT Threshold Sweep (NEW v7)**

Combine OOD scores (17) + in-distribution scores (322 from Step 1).
Sweep INCORRECT thresholds: 0.20, 0.25, 0.30, 0.35, 0.40, 0.45.

At each threshold measure:
- **OOD detection rate**: % OOD samples below threshold (higher = better)
- **In-distribution false-flag rate**: % in-dist contracts below threshold (lower = better)
- **F1-like metric**: harmonic mean of OOD_rate and (1 - false_flag_rate)

Draw ROC-like curve: OOD detection rate vs in-distribution false-flag rate.
Identify optimal threshold by F1-like metric.

### Step 5 — Ablation: CRAG vs No-CRAG vs LLM-Only

Four configurations on Top200 (225 safe contracts):

| Config | RAG | CRAG Gate | Evidence to LLM | Tier 2 Rules |
|--------|-----|-----------|-----------------|--------------|
| **A: LLM-Only** | OFF | OFF | None | None |
| **B: RAG, No CRAG** | ON | OFF (always send all) | All 5 candidates always | Always injected |
| **C: RAG + CRAG (0.65/0.30)** | ON | ON | Gated by CRAG action | Gated by CRAG action |
| **D: CRAG gate + always Tier 2** | ON | ON (gate evidence) | Gated by CRAG action | Always injected |

Config D isolates the CRAG evidence-gating effect from the Tier 2 rule-gating effect.
Without Config D, comparing B vs C conflates two changes: (1) filtering evidence and
(2) conditionally injecting Tier 2 rules. Config D keeps Tier 2 always on but still
gates evidence, so B vs D = pure effect of evidence gating, D vs C = pure effect of
Tier 2 gating.

**Existing data:**
- Config A (LLM-Only Top200): Already run. FP rate = 44.4% (100/225)
- Config C (Full pipeline Top200): Already run. FP rate = 25.3% (57/225)
- Config B (No CRAG): **NEEDS NEW RUN**
- Config D (CRAG gate + always Tier 2): **NEEDS NEW RUN** (pilot only, 50 contracts)

Metrics:
- FP count and FP rate on Top200
- Recall on SmartBugs (expect: same ~100% for all configs)
- Combined F1
- Per-vulnerability-type breakdown

### STOPPING RULE for Step 5

Run pilot first (50 contracts stratified from Top200). After pilot:

- **McNemar's p < 0.01 AND |FP_rate(B) - FP_rate(C)| > 5pp**: STOP. Pilot results sufficient — effect is clear and statistically significant. Use pilot results.
- **McNemar's p < 0.01 AND effect < 5pp**: STOP. Document as "statistically significant but below MCID — CRAG provides measurable but practically minor improvement". This is a valid and informative result.
- **McNemar's p < 0.05 but effect small (< 5pp)**: Run full 225 to increase statistical power and confirm whether effect is real.
- **McNemar's p > 0.05**: Run full 225 to distinguish "no effect" from "underpowered test".

**5pp MCID justification**: We adopt 5 percentage points absolute FP difference as the
Minimum Clinically Important Difference. Justification: baseline FP rate is ~25% (57/225).
A 5pp improvement (25% → 20%) = ~11 fewer false alarms on 225 contracts — operationally
meaningful for security audit triage (each false alarm requires manual review effort).
An improvement < 5pp (e.g., 25% → 22%) = ~7 fewer false alarms — insufficient practical
impact to justify CRAG gate complexity. GPTScan (ICSE 2024) demonstrated comparable
absolute FP reductions through static confirmation, supporting this magnitude as meaningful.

Potential savings: $60 if pilot is conclusive.

### Statistical Tests

- McNemar's test with **tiered analysis** (pre-register tier assignment in hypotheses.md):
  - **Primary (2 tests, Holm correction at α=0.025 each)**:
    - A vs C (H3.3: overall RAG+CRAG contribution)
    - B vs C (H3.2: CRAG gate contribution)
  - **Exploratory (3 tests, uncorrected p + effect size, no FWER correction)**:
    - B vs D (decomposition: pure evidence gating effect — Tier 2 constant)
    - D vs C (decomposition: pure Tier 2 gating effect — evidence gating constant)
    - A vs B (decomposition: RAG contribution without CRAG)
  - Rationale: Primary tests have adequate power at n=50. Exploratory tests likely
    underpowered for small effects — report as decomposition analysis, not hypothesis tests.
- Report p-value, odds ratio, 95% CI for each pair

### Cost Estimate

| Step | API calls | Cost | Time |
|------|-----------|------|------|
| Step 1 (SmartBugs scores) | ~98 embed + ~98 rerank | ~$3-5 | ~20 min |
| Step 2-3 (Threshold sweep) | 0 (offline analysis) | Free | Seconds |
| Step 3.5 (Empirical validation) | 300 LLM calls (3×100) | ~$20 | ~3-4 hours |
| Step 4 (OOD injection + sweep) | ~17 embed + ~17 rerank | ~$0.75 | ~5 min |
| Step 5 pilot (50 contracts, Config B+D) | 100 LLM calls (50×2 new configs) | ~$16 | ~3 hours |
| Step 5 full (if needed, Config B+D on 225) | 450 LLM calls (225×2) | ~$60 | ~6-8h parallel |
| **Total (if pilot sufficient)** | | **~$40-42** | **~7 hours** |
| **Total (if full needed)** | | **~$100-102** | **~14 hours** |

---

## Execution Order with Decision Gates

**Time estimates include coding + debugging, not just runtime.**

```
Day 1 (6-8h):
  Task 0:   Write hypotheses.md → git commit → record hash
            (MANDATORY before any experiment, includes careful writing)
  Task 0.5: Verify existing Top200 data validity (~15min, ~$0.20)
            (Run RIGHT AFTER Task 0 — if data stale, re-plan Day 2+)
  Exp 1A:   Code run_chunking_structural.py (implement 4 methods)
  Exp 1A:   Run structural analysis on 148 files

Day 2 (5-7h):
  Exp 2:  Prep 9 controlled samples + select 20 real-world samples
  Exp 2:  Code + run 4 embedding models comparison

Day 3 (8-10h, long day — Step 3.5 LLM calls dominate):
  Exp 3 Step 1:    Code + run SmartBugs score collection      [~$5, ~20min run]
  Exp 3 Step 2-3:  Code + run threshold sweep analytical      [free]
  Exp 3 Step 3.5:  Empirical 3 thresholds × 100 contracts     [~$20, 3-5h wall clock]

Day 4 (5-7h):
  Exp 3 Step 4:    Prep 15-17 OOD + run injection + sweep     [~$0.75, moved from Day 3]
  Exp 1B: Code + run chunking retrieval quality               [~$2]
  ┌─────────────────────────────────────┐
  │ DECISION GATE after Exp 1B:         │
  │  H1.2 PASS  → proceed to Exp 1C    │
  │  H1.2 WEAK  → proceed to Exp 1C    │
  │  H1.2 FAIL  → STOP, re-evaluate    │
  └─────────────────────────────────────┘
  Exp 1C: Code + run end-to-end (50 files)                    [~$18] (conditional)

Day 5 (5-7h):
  Exp 3 Step 5 pilot: Code + run CRAG ablation 50             [~$16]
  (Config B and D can run in parallel if 2 API sessions available)
  ┌──────────────────────────────────────────┐
  │ STOPPING RULE after pilot:               │
  │  p<0.01 AND effect>5pp  → STOP          │
  │  p<0.01 AND effect<5pp  → STOP (doc)    │
  │  p<0.05, effect small   → run full      │
  │  p>0.05                 → run full       │
  └──────────────────────────────────────────┘
  Exp 3 Step 5 full: Run CRAG ablation 225                    [~$60, ~6-8hr parallel] (conditional)
  (If parallel not available: 12-15h sequential → overflow to Day 6, shift compile to Day 7)

Day 6 (3-4h):
  Compile all results
  Write hypothesis verdicts (PASS / FAIL / INCONCLUSIVE)
  Steelman review: check suspicious PASS results
  Write findings report + methodology_qa.md
  **DO NOT amend hypotheses.md. New issues → methodology_qa.md only.**
  Final git commit
```

### Cost Summary

| Scenario | Total Cost | Total Time (incl. coding) |
|----------|-----------|--------------------------|
| Best case (pilot sufficient + H1.2 pass) | ~$62 | ~32 hours over 6 days |
| Worst case (full ablation + all parts) | ~$120 | ~48 hours over 6-7 days |

**Cost breakdown v6 → v7:**
- Embedding +1 model (jina): +$0
- CRAG threshold 0.65 empirical (3×100 contracts): +$20
- CRAG threshold 0.30 sweep (analytical on existing data): +$0
- **Total v7 over v6: +$20, +4-6h**

---

## Contingency Plans (What if hypotheses FAIL?)

### Exp 1 — If AST chunking fails

**H1.1 FAIL (gap < 15pp):**
- AST structural advantage marginal → RecursiveChar may suffice
- But still proceed to H1.2/H1.3: structural completeness ≠ retrieval/detection quality

**H1.2 FAIL (AST <= RecursiveChar in retrieval quality):**
- Investigate: Is the gap due to context enrichment being unhelpful, or chunk boundaries being wrong?
- Try: AST chunking without context enrichment (ablate the state var prepend)
- If still fails: Conclude RecursiveCharacterTextSplitter is a viable alternative. Revise thesis.
- Do NOT proceed to Exp 1C — save $18.

**H1.3 FAIL (AST F1 within 2pp of baseline):**
- Conclude: Chunking method has minimal impact on end-to-end detection. The pipeline is
  robust to chunking choice. This is a valid finding — document it.
- Implication: Other components (reranker, CRAG, LLM prompting) dominate performance.

### Exp 2 — If voyage-code-3 fails

**H2.1 FAIL (intra-pattern < 0.60):**
- Check controlled vs real-world samples separately — if real-world is higher,
  controlled samples may be poorly designed → redesign.
- If both fail: voyage-code-3 does not reliably cluster same-pattern code.

**H2.3 FAIL (any alternative gap >= voyage-code-3 gap):**
- Identify which alternative wins:
  - text-embedding-3-large wins → general-purpose sufficient, recommend switching (cheaper API)
  - jina-embeddings-v2-base-code wins → open-source competitive, recommend switching (free)
  - UniXcoder wins → unexpected (older model), investigate measurement issue
- Actionable: revise embedding choice in thesis.

### Exp 3 — If CRAG fails

**H3.1 FAIL (0.65 not in top-3 by F1):**
- Report the optimal threshold from the sweep. Update the system to use it.
- This is a straightforward configuration improvement, not a design flaw.

**H3.2 FAIL (No-CRAG FP rate <= CRAG FP rate):**
- CRAG gate adds complexity without benefit → recommend removing.
- Check decomposition: B vs D and D vs C to understand which component is the problem.
- If Config D also fails: issue is evidence quality, not gating → investigate reranker.

**H3.3 FAIL (LLM-Only F1 >= Full pipeline F1):**
- Entire RAG subsystem unnecessary. Before accepting:
  - Verify data integrity (re-run 5 contracts manually)
  - Check if LLM-Only achieves high F1 by over-reporting (high recall, low precision)
- If confirmed: Pipeline simplifies to LLM-only. Significant negative finding but publishable.

**H3.5 FAIL (analytical ranking ≠ empirical ranking):**
- Estimated F1 from analytical sweep not reliable → use empirical results as ground truth.
- Document: analytical sweep useful for narrowing candidates but cannot substitute empirical run.
- Pick optimal threshold by empirical F1, not analytical estimate.

**H3.6 FAIL (0.30 not in top-3 INCORRECT thresholds):**
- Report optimal INCORRECT threshold from sweep. Update system config.
- Configuration improvement, not design flaw.

---

## Known Limitations (Acknowledge in thesis)

1. **Exp 1 confound: AST boundary vs context enrichment** — AST chunking includes state
   variable context enrichment that other methods do not have. If AST wins, the advantage
   may be partly due to enrichment rather than boundary detection. A clean isolation would
   require "RecursiveChar + manual state var prepend" variant, which is out of scope.

2. **LLM component not validated** — No experiment compares Gemini 2.5 Pro against
   alternatives (GPT-4o, Claude). The LLM is the most expensive component and likely has
   the largest impact on results. LLM comparison is left as future work.

3. **Slither contribution not isolated** — Existing ablation data (LLM-Only vs Full)
   bundles Slither + RAG + CRAG. A clean Slither-only ablation is not included.

4. **Reranker not compared** — voyage-rerank-2.5 is not compared against alternative
   rerankers (Cohere, local cross-encoder). Its contribution is bundled into the RAG
   pipeline evaluation.

5. **Embedding comparison scope** — 4 models cover the 2 primary decision axes
   (code-specialized vs general, commercial vs open-source) but are not exhaustive.
   Other models (nomic-embed-code, CodeBERT, bge-code) exist. We do not claim "best
   in absolute terms."

6. **Interaction effect untestable** — 4 configs (A/B/C/D) cover 3/4 cells of 2×2 factorial
   (evidence gating × Tier 2 gating). Missing cell E = "evidence always + Tier 2 gated".
   Without E, interaction effect is not testable. If publication is the goal → consider adding E.

7. **Threshold validation sample size (Step 3.5)** — 100 contracts × 3 thresholds is pilot
   validation, not full evaluation. Decision based on F1 differences > 3pp. If differences
   are smaller → optionally extend.

8. **Data leakage / memorization risk** — SmartBugs dataset is public since 2019 and likely
   present in training data of voyage-code-3 (Voyage AI) and Gemini 2.5 Pro. Embedding
   similarity and LLM detection may be inflated by memorization. Results should be
   interpreted as upper-bound estimates; production performance on truly novel contracts
   may be lower. Mitigation: if voyage-code-3 training cutoff date is verifiable, filter
   SmartBugs for post-cutoff contracts as instant hold-out. Otherwise, acknowledge and
   defer hold-out validation to deployment phase.

9. **SWC-101 sample size (Step 3.5)** — Only 15 SmartBugs contracts for integer overflow.
   Wilson 95% CI for recall is ±15-20pp (e.g., 14/15 → [68%, 100%]). Cross-threshold
   comparisons within SWC-101 are non-conclusive. Per-SWC recall reported as point
   estimates only.

---

## Steelman Review (Day 6)

After compiling results, perform adversarial self-review:

**For each hypothesis marked PASS:**
- Pass by extreme margin (>= 99% or score >> threshold): Check for data leak, implementation bug, or test contamination. Re-run with seed=99 to confirm.
- Pass at exact threshold boundary (e.g., cross-modal = 0.55 exactly): Suspicious coincidence. Investigate.
- ALL hypotheses pass: Step back and check for systemic confirmation bias. Are the thresholds too lenient?

**For each hypothesis marked FAIL:**
- Is the failure informative? Does it suggest a specific design change?
- Is the failure due to low power (small N) rather than true negative?

**Pre-written reviewer Q&A** (save to `methodology_qa.md`):

Q1: "Why is Exp 1B only 30 files while Exp 1C is 50?"
→ Exp 1B measures retrieval similarity (continuous metric, Wilcoxon) — n=30 provides 80% power for effect size d=0.5. Exp 1C measures binary detection outcomes (McNemar's) which requires more discordant pairs, hence n=50.

Q2: "Why only 15-17 OOD samples for Step 4?"
→ OOD validation tests trigger behavior across 5 categories (3+ samples per category). N=17 allows H3.4 percentage thresholds (70%, 40%) to be meaningful (1 sample = ~6% swing). A larger-scale OOD evaluation across hundreds of contracts is future work for production deployment.

Q3: "Why not bootstrap instead of paired t-test for Exp 1B?"
→ Voyage embedding scores are bounded [-1, 1] and empirically symmetric. Wilcoxon signed-rank test is used as primary (robust). Paired t-test reported as secondary if normality holds. Bootstrap is used in Exp 2 because heterogeneous metrics (gap, cross-modal) do not guarantee normality.

Q4: "Why 4 configs (A/B/C/D) instead of 3?"
→ Comparing B (no CRAG) vs C (full CRAG) conflates two changes: evidence filtering and Tier 2 rule gating. Config D (CRAG gate evidence + always Tier 2) isolates the evidence gating effect. B vs D = pure evidence gating, D vs C = pure Tier 2 gating. 2 primary + 3 exploratory comparisons, manageable with Holm correction on primaries only.

Q5: "H3.1 tests τ=0.65 which was already chosen based on prior data. Isn't this post-hoc?"
→ Yes — H3.1 is **confirmatory re-analysis**, not a novel pre-registered test. Threshold 0.65 was selected based on v7.0 evaluation (224 Top200 records). Exp 3 Step 2-3 re-verifies on extended data (322 records = 98 SmartBugs + 224 Top200). The value lies in: (a) confirmation on larger and more diverse dataset, (b) Pareto frontier analysis showing the full trade-off landscape, (c) identifying if threshold needs adjustment given new SmartBugs score data. We acknowledge this upfront rather than presenting it as a novel finding.

Q6: "Why add Step 3.5 empirical after Step 2-3 analytical?"
→ Analytical sweep uses existing evaluation labels to estimate F1 at each threshold. Empirical run executes the actual pipeline for the top 3 candidate thresholds to verify. This defends 0.65 with two independent methods. Step 3.5 is cost-controlled (3 thresholds × 100 contracts = $20).

Q7: "Why doesn't 0.30 have empirical validation like 0.65?"
→ 0.30 does not trigger on in-distribution data — there are no positive cases to measure actual F1. Defense is via INCORRECT threshold sweep (Step 4 Part B) on OOD + in-distribution data, measuring the optimal balance between OOD detection and in-distribution false-flagging.

---

## Reproducibility Requirements

Every experiment script MUST:

1. **Set random seeds**: `random.seed(42)`, `numpy.random.seed(42)`
2. **Log raw outputs**: Save to `exp{N}/raw/` directory:
   - LLM full responses (not just verdict)
   - Embedding vectors (numpy arrays)
   - Retrieval results per query (all candidates + scores)
3. **Log config**: Save to `exp{N}/raw/run_config.json`:
   - Git commit hash of codebase at runtime
   - All API model versions used
   - Random seeds
   - Timestamps (start, end)
   - Environment (Python version, package versions)
4. **Save before analyze**: Raw JSON results saved BEFORE any statistical analysis
5. **LLM determinism**: All LLM calls use `temperature=0`, `top_p=1`, `top_k=1`
   (temperature=0 already set in `llm_analyzer.py:537`; add top_p/top_k to config).
   Note: Determinism not guaranteed even at temp=0 due to MoE routing in Gemini 2.5 Pro.
   We accept residual variance and report single-run results. Log full LLM responses
   so results can be verified without re-calling the API.
   All experiment scripts MUST log these settings in `raw/run_config.json`.
6. **Error budget**: LLM call timeout (>300s) or API error → retry once. If retry fails →
   mark contract as "error", exclude from analysis, report exclusion count. Do NOT re-run
   with different parameters or skip silently.
7. **Idempotent**: Re-running with same seeds + same API responses = same results

---

## File Structure

```
evaluation/technique_proofs/
  EXPERIMENT_PLAN.md              <- This file (v7)
  hypotheses.md                   <- Pre-registered hypotheses (committed FIRST)
  methodology_qa.md               <- Pre-written answers to anticipated reviewer questions

  exp1_chunking/
    run_chunking_structural.py    <- Part A: structural analysis
    run_chunking_retrieval.py     <- Part B: retrieval quality
    run_chunking_e2e.py           <- Part C: end-to-end
    chunking_analysis.py          <- Statistical tests + tables
    raw/                          <- Raw outputs + run_config.json
    results/                      <- Aggregated results JSONs

  exp2_embedding/
    README.md                     <- Comparison Set Rationale
    run_embedding_comparison.py
    embedding_analysis.py         <- Heatmap + statistical tests
    samples/                      <- Controlled + real-world samples
    raw/                          <- Embedding vectors + run_config.json
    results/                      <- Aggregated results JSONs

  exp3_crag/
    run_collect_scores.py         <- Step 1: SmartBugs relevance scores
    run_threshold_sweep.py        <- Step 2-3: analytical sweep
    run_threshold_empirical.py    <- Step 3.5: empirical validation (NEW v7)
    run_ood_injection.py          <- Step 4A: OOD injection
    run_incorrect_sweep.py        <- Step 4B: INCORRECT threshold sweep (NEW v7)
    run_ablation_no_crag.py       <- Step 5: No-CRAG + Config D
    crag_analysis.py              <- Statistical tests + visualization
    ood_samples/                  <- OOD test inputs
    raw/                          <- Raw outputs + run_config.json
    results/                      <- Aggregated results JSONs
```
