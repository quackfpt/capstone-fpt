"""
Smart RAG System v7 - DarkHotel
================================
Knowledge-level RAG with:
- voyage-code-3 (Voyage AI, 1024d) for code embedding
- Qdrant (local mode) for vector search
- voyage-rerank-2.5 (Voyage AI) for instruction-following reranking
- CRAG (Corrective RAG) evaluator for retrieval quality gating

v7.1 Updates:
- Upgraded knowledge base: FORGE-Curated (208 audit reports) + audits-with-reasons (2472 entries)
- 21,032 total points (up from 407)
- 2 collections: forge_curated (descriptions + code), audits_with_reasons (vuln + safe examples)
- Payload fields mapped to existing format for backward compatibility
"""

import os
import re
import sys
from typing import Dict, List, Optional
import voyageai
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, Filter, FieldCondition, MatchValue
from dotenv import load_dotenv

# Fix Windows encoding
if sys.stdout:
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

load_dotenv()

# --- CONFIG ---
QDRANT_PATH = os.getenv("QDRANT_DB_PATH", "./qdrant_db_forge")
FORGE_COLLECTION = "forge_curated"
AWR_COLLECTION = "audits_with_reasons"


# =============================================================================
# EMBEDDING: voyage-code-3 (Voyage AI)
# =============================================================================

class VoyageCodeEmbeddings:
    """
    voyage-code-3 - Code-specialized embedding model by Voyage AI.
    Trained on code + NL pairs across 300+ programming languages.
    Supports text-to-code, code-to-code, and docstring-to-code retrieval.
    Default 1024d, supports 256/512/1024/2048. Context: 32K tokens.
    """

    def __init__(self, model_name: str = "voyage-code-3", dimension: int = 1024):
        api_key = os.getenv("VOYAGE_API_KEY")
        if not api_key:
            raise ValueError(
                "VOYAGE_API_KEY not found in environment variables! "
                "Get your key at https://dash.voyageai.com/"
            )
        self.client = voyageai.Client(api_key=api_key)
        self.model_name = model_name
        self.dimension = dimension

    def embed_query(self, text: str) -> List[float]:
        """Embed a search query (input_type='query' per Voyage API)"""
        result = self.client.embed(
            texts=[text[:16000]],
            model=self.model_name,
            input_type="query",
            output_dimension=self.dimension,
        )
        return result.embeddings[0]

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple documents (input_type='document').
        Auto-batches to stay within Voyage API limit (max 128 texts per request).
        """
        MAX_BATCH = 128
        truncated = [t[:16000] for t in texts]

        if len(truncated) <= MAX_BATCH:
            result = self.client.embed(
                texts=truncated,
                model=self.model_name,
                input_type="document",
                output_dimension=self.dimension,
            )
            return result.embeddings

        # Batch large requests
        all_embeddings = []
        for i in range(0, len(truncated), MAX_BATCH):
            batch = truncated[i:i + MAX_BATCH]
            result = self.client.embed(
                texts=batch,
                model=self.model_name,
                input_type="document",
                output_dimension=self.dimension,
            )
            all_embeddings.extend(result.embeddings)
        return all_embeddings


# =============================================================================
# RERANKER: voyage-rerank-2.5 (Voyage AI)
# =============================================================================

class VoyageReranker:
    """
    voyage-rerank-2.5 - Instruction-following reranker by Voyage AI.
    Returns relevance_score [0, 1] directly (no normalization needed).
    Supports 32K context per document, up to 1000 documents per request.
    Code-aware: understands Solidity/code semantics (unlike ms-marco NL-only).
    Supports instruction-following via query prefix.
    """

    def __init__(self, model_name: str = "rerank-2.5"):
        api_key = os.getenv("VOYAGE_API_KEY")
        if not api_key:
            raise ValueError(
                "VOYAGE_API_KEY not found in environment variables! "
                "Get your key at https://dash.voyageai.com/"
            )
        self.client = voyageai.Client(api_key=api_key)
        self.model_name = model_name

    RERANK_BATCH_LIMIT = 500  # Voyage rerank-2.5: max 1000 items & 600K tokens

    def rerank(self, query: str, candidates: List[Dict], top_k: int = 5) -> List[Dict]:
        """
        Rerank candidates using voyage-rerank-2.5.

        Returns top_k candidates with relevance_score [0, 1] from Voyage API.
        No normalization needed — scores are pre-calibrated:
        - 0.8-1.0: Highly relevant
        - 0.5-0.8: Moderately relevant
        - 0.0-0.5: Less relevant
        """
        if not candidates:
            return []

        # Truncate to Voyage batch limit — keep top candidates by bi-encoder score
        if len(candidates) > self.RERANK_BATCH_LIMIT:
            candidates = sorted(candidates, key=lambda x: x.get("similarity", 0), reverse=True)[:self.RERANK_BATCH_LIMIT]
            print(f"[VoyageReranker] Truncated candidates to {self.RERANK_BATCH_LIMIT} (Voyage batch limit)")

        # Build document texts for reranking
        documents = [self._build_doc_text(c) for c in candidates]

        # Prepend instruction for instruction-following reranker
        instructed_query = (
            "Find Solidity smart contract vulnerability patterns matching this code. "
            "Focus on reentrancy, integer overflow, and unchecked return values.\n\n"
            + query[:8000]
        )

        # Call Voyage rerank API
        reranking = self.client.rerank(
            query=instructed_query,
            documents=documents,
            model=self.model_name,
            top_k=top_k,
        )

        # Map results back to candidates with scores
        for result in reranking.results:
            idx = result.index
            candidates[idx]["relevance_score"] = result.relevance_score
            candidates[idx]["bi_encoder_score"] = candidates[idx].get("similarity", 0)

        # Sort by relevance_score and return top_k
        scored = [c for c in candidates if "relevance_score" in c]
        scored.sort(key=lambda x: x["relevance_score"], reverse=True)
        return scored[:top_k]

    def _build_doc_text(self, candidate: Dict) -> str:
        """Build text representation of a candidate for reranker."""
        parts = []
        vtype = candidate.get("vulnerability_type", "")
        swc = candidate.get("swc_id", "")
        if vtype:
            parts.append(f"Solidity vulnerability: {vtype} ({swc})")
        severity = candidate.get("severity", "")
        if severity:
            parts.append(f"Severity: {severity}")
        func = candidate.get("function", "")
        if func:
            parts.append(f"in function {func}")
        root = candidate.get("root_cause", "")
        if root:
            parts.append(f"Root cause: {root}")
        trigger = candidate.get("trigger_condition", "")
        if trigger:
            parts.append(f"Trigger: {trigger}")
        fix = candidate.get("fix_solution", "")
        if fix:
            parts.append(f"Fix: {fix}")
        code = candidate.get("code_snippet_vulnerable", "")
        if code:
            parts.append(f"Code: {code[:500]}")
        return ". ".join(parts) if parts else str(candidate)


# =============================================================================
# CRAG EVALUATOR (Corrective Retrieval Augmented Generation)
# =============================================================================

class CRAGEvaluator:
    """
    Corrective RAG evaluator based on Yan et al. (arXiv:2401.15884).

    Adapted for voyage-rerank-2.5 scores (pre-calibrated [0, 1]):
    - CORRECT (score >= 0.65): Highly relevant, pass all evidence to LLM
    - AMBIGUOUS (0.3 <= score < 0.65): Partially relevant, pass filtered evidence
    - INCORRECT (score < 0.3): Irrelevant, discard and let LLM judge alone

    voyage-rerank-2.5 understands code natively, so the bi-encoder floor
    workaround (needed when ms-marco NL-only reranker disagreed with
    CodeRankEmbed on code similarity) is no longer necessary.
    """

    CORRECT_THRESHOLD = 0.65
    INCORRECT_THRESHOLD = 0.3

    def evaluate(self, candidates: List[Dict]) -> tuple:
        """
        Evaluate retrieval quality and determine action.

        Uses MAX relevance_score across all candidates (not just [0]).

        Decision logic:
        1. Max relevance_score >= 0.65 → CORRECT (high confidence)
        2. Max relevance_score >= 0.3 → AMBIGUOUS (partial relevance)
        3. Otherwise → INCORRECT (discard, LLM judges alone)

        Args:
            candidates: Reranked candidates (must have 'relevance_score'
                        field from VoyageReranker)

        Returns:
            (action, filtered_candidates):
                action: "CORRECT" | "AMBIGUOUS" | "INCORRECT"
                filtered_candidates: evidence to pass to LLM (may be empty)
        """
        if not candidates:
            return "INCORRECT", []

        max_relevance = max(c.get("relevance_score", 0) for c in candidates)

        if max_relevance >= self.CORRECT_THRESHOLD:
            return "CORRECT", candidates

        elif max_relevance >= self.INCORRECT_THRESHOLD:
            filtered = [
                c for c in candidates
                if c.get("relevance_score", 0) >= self.INCORRECT_THRESHOLD
            ]
            return "AMBIGUOUS", filtered

        else:
            return "INCORRECT", []


# =============================================================================
# SMART RAG SYSTEM v7.1
# =============================================================================

class SmartRAGSystem:
    """
    Smart RAG System v7.1 - Knowledge-level RAG for Smart Contract Vulnerability Detection

    Components:
    - voyage-code-3 (1024d) for code-specialized embedding
    - Qdrant (local mode) for vector similarity search with metadata filtering
    - voyage-rerank-2.5 for instruction-following reranking
    - CRAG evaluator for retrieval quality gating

    v7.1 Updates:
    - Knowledge base: FORGE-Curated + audits-with-reasons (21,032 points)
    - 2 collections: forge_curated (expert audit findings + code), audits_with_reasons (labeled examples)
    - Safe (negative) examples included to reduce false positives
    - CWE mapping for broader vulnerability coverage
    """

    def __init__(self, persist_directory: str = QDRANT_PATH):
        print(f"[SmartRAG v7.1] Initializing...")

        self.persist_directory = persist_directory
        self.kb_version = "v8-forge"

        # 1. voyage-code-3 embedding model
        print(f"[SmartRAG v7.1] Loading voyage-code-3 embedding model...")
        self.embedding = VoyageCodeEmbeddings()

        # 2. Qdrant vector database (local mode, no Docker)
        print(f"[SmartRAG v7.1] Connecting to Qdrant at {persist_directory}...")
        self.qdrant = QdrantClient(path=persist_directory)

        # Check collections
        collections = [c.name for c in self.qdrant.get_collections().collections]
        self.total_entries = 0

        if FORGE_COLLECTION in collections:
            fc_info = self.qdrant.get_collection(FORGE_COLLECTION)
            self.total_entries += fc_info.points_count
            print(f"[SmartRAG v7.1] forge_curated: {fc_info.points_count} points")
        else:
            print(f"[SmartRAG v7.1] WARNING: Collection '{FORGE_COLLECTION}' not found!")

        if AWR_COLLECTION in collections:
            awr_info = self.qdrant.get_collection(AWR_COLLECTION)
            self.total_entries += awr_info.points_count
            print(f"[SmartRAG v7.1] audits_with_reasons: {awr_info.points_count} points")
        else:
            print(f"[SmartRAG v7.1] WARNING: Collection '{AWR_COLLECTION}' not found!")

        if self.total_entries > 0:
            self.kb_version = "v8-forge-voyage-code-3"

        # 3. voyage-rerank-2.5 reranker
        print(f"[SmartRAG v7.1] Loading voyage-rerank-2.5 reranker...")
        self.reranker = VoyageReranker()

        # 4. CRAG evaluator
        self.crag = CRAGEvaluator()

        print(f"[SmartRAG v7.1] Ready! ({self.total_entries} total points)")

    def get_stats(self) -> Dict:
        """Return stats for health check"""
        return {
            "total_cases": self.total_entries,
            "version": self.kb_version,
            "collection": f"{FORGE_COLLECTION} + {AWR_COLLECTION}",
            "categories": "All vulnerability types (FORGE-Curated 208 audit reports + audits-with-reasons 2472 entries)",
            "source": "FORGE-Curated + audits-with-reasons (21,032 points)",
            "embedding": "voyage-code-3 (Voyage AI, 1024d)",
            "vector_db": "Qdrant (local mode)",
            "reranker": "voyage-rerank-2.5 (Voyage AI)",
            "crag": "CRAG evaluator (relevance_score gating)",
        }

    # ─── Field Mapping Helpers ────────────────────────────────────────

    @staticmethod
    def _format_forge_description(payload: dict, score: float) -> Dict:
        """Map forge_curated description payload → standard output format."""
        return {
            "vulnerability_type": payload.get("title", "Unknown"),
            "swc_id": SmartRAGSystem._cwe_to_swc(payload.get("cwe_ids", "")),
            "severity": payload.get("severity", "Unknown"),
            "similarity": round(float(score), 4),
            "function": "N/A",
            "line_number": payload.get("location", "N/A"),
            "audit_company": payload.get("project", "N/A"),
            "code_snippet_vulnerable": "",
            "source_file": "N/A",
            "root_cause": payload.get("description", "")[:2000],
            "trigger_condition": "",
            "fix_solution": "",
            "doc_source": "forge_description",
        }

    @staticmethod
    def _format_forge_code(payload: dict, score: float) -> Dict:
        """Map forge_curated code payload → standard output format."""
        start = payload.get("start_line", "?")
        end = payload.get("end_line", "?")
        return {
            "vulnerability_type": payload.get("finding_title", "Unknown"),
            "swc_id": SmartRAGSystem._cwe_to_swc(payload.get("cwe_ids", "")),
            "severity": payload.get("severity", "Unknown"),
            "similarity": round(float(score), 4),
            "function": payload.get("function_name", "N/A"),
            "line_number": f"L{start}-L{end}",
            "audit_company": payload.get("project", "N/A"),
            "code_snippet_vulnerable": payload.get("code_content", "")[:3000],
            "source_file": payload.get("file", "N/A"),
            "root_cause": payload.get("description", "")[:2000],
            "trigger_condition": "",
            "fix_solution": "",
            "doc_source": "forge_code",
        }

    @staticmethod
    def _format_awr(payload: dict, score: float) -> Dict:
        """Map audits_with_reasons payload → standard output format."""
        vuln_type = payload.get("type", "unknown")
        is_vulnerable = payload.get("is_vulnerable", True)
        return {
            "vulnerability_type": vuln_type if is_vulnerable else f"SAFE ({vuln_type})",
            "swc_id": SmartRAGSystem._vuln_type_to_swc(vuln_type),
            "severity": "High" if is_vulnerable else "Safe",
            "similarity": round(float(score), 4),
            "function": "N/A",
            "line_number": "N/A",
            "audit_company": "audits-with-reasons",
            "code_snippet_vulnerable": payload.get("code", "")[:3000],
            "source_file": "N/A",
            "root_cause": payload.get("description", "")[:2000] if is_vulnerable else "",
            "trigger_condition": payload.get("functionality", "")[:1000],
            "fix_solution": payload.get("recommendation", "")[:1000] if is_vulnerable else "",
            "doc_source": "awr",
            "is_vulnerable": is_vulnerable,
        }

    @staticmethod
    def _cwe_to_swc(cwe_str: str) -> str:
        """Map CWE IDs to the closest SWC ID for backward compatibility.

        Extracts individual CWE numbers and maps to SWC using priority order.
        """
        if not cwe_str or cwe_str == "none":
            return "N/A"

        # Extract all CWE numbers from the string (e.g., "CWE-691, CWE-1265" → [691, 1265])
        cwe_numbers = set()
        for match in re.finditer(r'(\d+)', cwe_str):
            cwe_numbers.add(int(match.group(1)))

        # Priority mapping: check in order of importance
        # Reentrancy
        if cwe_numbers & {691, 1265}:
            return "SWC-107"
        # Integer Overflow
        if cwe_numbers & {682, 190, 191}:
            return "SWC-101"
        # Unchecked Return Value
        if cwe_numbers & {252, 754}:
            return "SWC-104"
        # Access Control
        if cwe_numbers & {284, 285, 862, 269, 250}:
            return "SWC-115"
        # Input Validation
        if 20 in cwe_numbers:
            return "SWC-123"
        # DoS
        if cwe_numbers & {400, 770}:
            return "SWC-128"
        # Timestamp Dependence
        if 362 in cwe_numbers:
            return "SWC-116"

        # Fallback: return first CWE as-is
        return f"CWE-{sorted(cwe_numbers)[0]}" if cwe_numbers else "N/A"

    @staticmethod
    def _vuln_type_to_swc(vuln_type: str) -> str:
        """Map audits-with-reasons vulnerability type to SWC ID."""
        if not vuln_type:
            return "N/A"
        vt = vuln_type.lower()
        if "reentran" in vt:
            return "SWC-107"
        if "overflow" in vt or "underflow" in vt or "arithmetic" in vt or "integer" in vt:
            return "SWC-101"
        if "unchecked" in vt or "return value" in vt:
            return "SWC-104"
        if "access" in vt or "authorization" in vt:
            return "SWC-115"
        if "no vulnerability" in vt:
            return "N/A"
        return "N/A"

    # ─── Vector Search ────────────────────────────────────────────────

    def search_similar(self, code: str, top_k: int = 5, filter_type: str = None) -> List[Dict]:
        """
        Search for similar vulnerability cases across both collections.

        Queries:
        1. forge_curated (descriptions) — expert audit knowledge
        2. forge_curated (code) — similar vulnerable code patterns
        3. audits_with_reasons (code) — labeled examples (vuln + safe)

        Results are merged, deduplicated, and returned in standard format.

        Args:
            code: Solidity code to search for
            top_k: Number of results to return per source
            filter_type: Optional filter (currently unused with new DB,
                        kept for API compatibility)

        Returns:
            List of dicts with vulnerability_type, swc_id, severity, etc.
        """
        if self.total_entries == 0:
            return []

        try:
            query_vector = self.embedding.embed_query(code)
            formatted = []
            n_desc, n_code, n_awr = 0, 0, 0

            # 1. forge_curated — descriptions (expert findings)
            try:
                r_desc = self.qdrant.query_points(
                    collection_name=FORGE_COLLECTION,
                    query=query_vector,
                    query_filter=Filter(
                        must=[FieldCondition(key="doc_type", match=MatchValue(value="description"))]
                    ),
                    limit=top_k,
                    with_payload=True,
                    score_threshold=0.15,
                )
                n_desc = len(r_desc.points)
                for point in r_desc.points:
                    formatted.append(self._format_forge_description(point.payload, point.score))
            except Exception as e:
                print(f"[SmartRAG v7.1] forge_curated descriptions error: {e}")

            # 2. forge_curated — code (vulnerable code from real audits)
            try:
                r_code = self.qdrant.query_points(
                    collection_name=FORGE_COLLECTION,
                    query=query_vector,
                    query_filter=Filter(
                        must=[FieldCondition(key="doc_type", match=MatchValue(value="code"))]
                    ),
                    limit=top_k,
                    with_payload=True,
                    score_threshold=0.15,
                )
                n_code = len(r_code.points)
                for point in r_code.points:
                    formatted.append(self._format_forge_code(point.payload, point.score))
            except Exception as e:
                print(f"[SmartRAG v7.1] forge_curated code error: {e}")

            # 3. audits_with_reasons — code (labeled vuln + safe examples)
            try:
                r_awr = self.qdrant.query_points(
                    collection_name=AWR_COLLECTION,
                    query=query_vector,
                    query_filter=Filter(
                        must=[FieldCondition(key="doc_type", match=MatchValue(value="code"))]
                    ),
                    limit=top_k,
                    with_payload=True,
                    score_threshold=0.15,
                )
                n_awr = len(r_awr.points)
                for point in r_awr.points:
                    formatted.append(self._format_awr(point.payload, point.score))
            except Exception as e:
                print(f"[SmartRAG v7.1] audits_with_reasons error: {e}")

            # Sort by similarity score (descending)
            formatted = sorted(formatted, key=lambda x: x["similarity"], reverse=True)

            print(f"[SmartRAG v7.1] Retrieved: {len(formatted)} results "
                  f"(desc={n_desc}, code={n_code}, awr={n_awr})")

            return formatted

        except Exception as e:
            print(f"[SmartRAG v7.1] Search error: {e}")
            return []


if __name__ == "__main__":
    rag = SmartRAGSystem()
    stats = rag.get_stats()
    print(f"Stats: {stats}")
