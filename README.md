# DarkHotel - Smart Contract Vulnerability Analyzer

AI-powered Solidity vulnerability detection using a **6-Step Sequential Pipeline**: AST Chunking (tree-sitter) + Slither + RAG (voyage-code-3 + Qdrant) + Voyage Reranking + CRAG Gate + LLM Chain-of-Thought.

![Version](https://img.shields.io/badge/Version-7.0-blue)
![Backend](https://img.shields.io/badge/Backend-FastAPI-green)
![Frontend](https://img.shields.io/badge/Frontend-Next.js%2016-black)
![AI](https://img.shields.io/badge/AI-Gemini%202.5%20Pro-purple)
![RAG](https://img.shields.io/badge/RAG-FORGE%2021%2C032%20points-orange)

---

## Overview

DarkHotel phan tich smart contract Solidity qua 6 buoc:

```
Upload .sol  -->  [1] AST Chunking  -->  [2+3] Slither + RAG (parallel)
                                                      |
                  [6] Report  <--  [5] LLM CoT  <--  [4] Weighted Ranking + RAG Gate
```

| Step | Component | Technology | Purpose |
|------|-----------|-----------|---------|
| 1 | AST Chunking | tree-sitter + Regex fallback | Tach function, xac dinh risky functions |
| 2 | Slither | Static Analyzer | Phat hien pattern, tao hints cho RAG |
| 3 | RAG Search | Qdrant + voyage-code-3 (1024d) | Tim vuln tuong tu trong 21,032 points (FORGE-Curated + audits-with-reasons) |
| 4 | Voyage Reranking + CRAG Gate | voyage-rerank-2.5 + Rule-based CRAG | Rerank + quality gate (Correct/Ambiguous/Incorrect) |
| 5 | LLM CoT | Gemini 2.5 Pro | Chain-of-Thought reasoning + 14 anti-hallucination rules |
| 6 | Report | JSON structured | Verdict + vulnerabilities + evidence |

### 3 Loai Vulnerability Duoc Kiem Tra

| Type | SWC ID | Severity | Description |
|------|--------|----------|-------------|
| Reentrancy | SWC-107 | Critical/High | External call truoc state update (CEI violation) |
| Integer Overflow/Underflow | SWC-101 | High | Arithmetic overflow/underflow (pre-0.8, khong co SafeMath) |
| Unchecked Return Value | SWC-104 | Medium/High | .send()/.call() khong kiem tra return value |

---

## Quick Start

### Yeu Cau He Thong

- **Python** 3.10+
- **Node.js** 18+
- **Git**
- **Gemini API Key** (lay tai: https://aistudio.google.com/apikey)

### 1. Clone Repository

```bash
git clone https://github.com/quackfpt/capstone-fpt.git
cd capstone-fpt
```

### 2. Setup Backend

```bash
cd backend

# Tao virtual environment
python -m venv venv

# Kich hoat (Windows)
venv\Scripts\activate

# Kich hoat (Linux/Mac)
# source venv/bin/activate

# Cai dat dependencies
pip install -r requirements.txt

# Cai dat Slither
pip install slither-analyzer

# Cai dat solc-select (quan ly Solidity compiler versions)
pip install solc-select
solc-select install 0.8.0 0.4.26 0.5.17 0.6.12 0.7.6
solc-select use 0.8.0
```

### 3. Cau Hinh API Key

```bash
# Tao file .env tu template
cp .env.example .env
```

Mo file `backend/.env` va them API key:

```env
GOOGLE_CLOUD_PROJECT=your_project_id_here
GOOGLE_CLOUD_LOCATION=us-central1
MODEL_NAME=gemini-2.5-pro
VOYAGE_API_KEY=your_voyage_api_key_here
QDRANT_DB_PATH=./qdrant_db_forge
```

> **Luu y:** Can chay `python archive/migrate_to_qdrant_v8.py` lan dau de build Knowledge Base (`qdrant_db_forge/`) voi 21,032 points tu FORGE-Curated + audits-with-reasons.

### 4. Setup Frontend

```bash
cd ../frontend
npm install
```

### 5. Chay Ung Dung

**Terminal 1 - Backend:**
```bash
cd backend
venv\Scripts\activate
uvicorn main:app --reload --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

### 6. Truy Cap

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs

---

## Cach Su Dung

1. Mo http://localhost:3000
2. Keo tha file `.sol` vao khu vuc upload (hoac click de chon file)
3. Nhan **Analyze Contract**
4. Doi 30-45 giay de he thong phan tich qua 6 buoc
5. Xem ket qua:
   - **Verdict Banner**: SAFE (xanh) hoac VULNERABLE (do)
   - **Primary Vulnerability**: Loi chinh voi severity, SWC ID, exploit scenario, recommendation
   - **Secondary Warnings**: Cac loi phu
   - **Slither Analysis**: Ket qua static analysis
   - **RAG Knowledge Base**: Similar cases tu FORGE-Curated + audits-with-reasons
   - **AI Reasoning**: Chain-of-Thought tu LLM

---

## Project Structure

```
DarkHotel-Capstone/
|
+-- backend/
|   +-- main.py                         # FastAPI server (6-step pipeline v7.0)
|   +-- ast_parser.py                   # AST chunking - tree-sitter + regex (Step 1)
|   +-- slither_smart_wrapper.py        # Slither integration + auto solc (Step 2)
|   +-- smart_rag_system.py             # RAG v7 - voyage-code-3 + Qdrant + voyage-rerank-2.5 + CRAG (Step 3-4)
|   +-- llm_analyzer.py                 # Gemini 2.5 Pro + CoT + 14 anti-hallucination rules (Step 5)
|   |
|   +-- qdrant_db_forge/                # Vector DB (21,032 points, voyage-code-3 1024d) [not committed]
|   +-- archive/
|   |   +-- darkhotel_knowledge_base_v7.json  # Knowledge base source (JSON)
|   |   +-- migrate_to_qdrant_v8.py           # Script rebuild Qdrant DB
|   +-- .env.example                    # Environment template
|   +-- requirements.txt                # Python dependencies
|
+-- frontend/
|   +-- app/
|   |   +-- page.tsx                    # Main dashboard (structured results UI)
|   |   +-- layout.tsx                  # Root layout
|   |   +-- globals.css                 # Global styles
|   +-- package.json
|
+-- evaluation/
|   +-- runners/
|   |   +-- run_smartbugs_eval.py       # SmartBugs-Curated evaluation (98 contracts)
|   |   +-- run_ablation_smartbugs.py   # Ablation study (4 conditions: LLM-only / +RAG / +Slither / Full)
|   |   +-- eval_utils.py               # Shared evaluation utilities
|   |
|   +-- external_datasets/
|   |   +-- SmartBugs-Curated/          # 98 vulnerable contracts (SWC-107/101/104)
|   |   +-- safe_contracts/             # Verified safe contracts
|   |   +-- top_10_reentrancy/          # 10 reentrancy test contracts
|   |
|   +-- ground_truth/                   # Ground truth labels + vulnerable/safe contracts
|
+-- README.md                           # This file
```

---

## Evaluation Results (v7.0)

> *Chua co ket qua. Can chay lai evaluation sau khi test.*

---

## Tech Stack

### Backend

| Component | Technology |
|-----------|-----------|
| Web Framework | FastAPI 0.128+ |
| Static Analyzer | Slither |
| Vector Database | Qdrant (local mode) |
| Embeddings | voyage-code-3 (Voyage AI, 1024d) |
| Reranker | voyage-rerank-2.5 (Voyage AI, instruction-following) |
| RAG Quality Gate | CRAG Evaluator (rule-based) |
| LLM | Gemini 2.5 Pro |
| Python | 3.10+ |

### Frontend

| Component | Technology |
|-----------|-----------|
| Framework | Next.js 16 (App Router) |
| Language | TypeScript 5.x |
| Styling | Tailwind CSS 4.x |
| Icons | Lucide React |

---

## API

### Health Check

```bash
curl http://localhost:8000/
```

### Analyze Contract

```bash
curl -X POST http://localhost:8000/analyze -F "file=@contract.sol"
```

Response tra ve JSON voi:
- `ai_analysis_structured`: verdict, primary vulnerability, secondary warnings, reasoning
- `rag_findings`: similar cases, detected vulnerabilities, confidence scores
- `slither_analysis`: static analysis warnings
- `function_analysis`: risky functions tu AST

---

## Troubleshooting

### Backend khong khoi dong

```bash
# Kiem tra Python version
python --version  # Can 3.10+

# Cai lai dependencies
pip install -r requirements.txt
```

### Slither loi version solc

```bash
# He thong tu dong cai solc version tu pragma
# Neu van loi, cai thu cong:
solc-select install 0.8.20
solc-select use 0.8.20
```

### Frontend loi ket noi

```bash
# Kiem tra backend dang chay
curl http://localhost:8000/
```

### Database not found

```bash
cd backend
# Rebuild Qdrant tu knowledge base JSON (voyage-code-3)
python archive/migrate_to_qdrant_v8.py
```

---

## License

MIT License

---

**Version:** 7.0
**Last Updated:** 2026-05-01
**Knowledge Base:** 21,032 points — FORGE-Curated (208 audit reports) + audits-with-reasons (2,472 entries)
**Embedding:** voyage-code-3 (Voyage AI, 1024d)
**Reranker:** voyage-rerank-2.5 (Voyage AI, instruction-following)
**Vector DB:** Qdrant (local mode, `qdrant_db_forge/`)
**Detection:** Reentrancy (SWC-107), Integer Overflow (SWC-101), Unchecked Return Value (SWC-104)

**Made by DarkHotel Team**
