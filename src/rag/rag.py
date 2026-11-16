
import json
import pickle
import re
from pathlib import Path

import faiss
import numpy as np
import ollama
from sentence_transformers import SentenceTransformer


# ==========================================
# 1. PROJECT PATHS AND SETTINGS
# ==========================================

ROOT = Path(__file__).resolve().parents[2]

FAISS_FILE = ROOT / "embeddings" / "cve_faiss.index"
BM25_FILE = ROOT / "embeddings" / "bm25_index.pkl"
METADATA_FILE = ROOT / "embeddings" / "cve_metadata.jsonl"

MODEL_NAME = "all-MiniLM-L6-v2"
LLM_NAME = "llama3.2"

TOP_K = 5
CANDIDATE_K = 50
RRF_K = 60


# ==========================================
# 2. TOKENIZATION
# ==========================================

def tokenize(text):
    return re.findall(r"[a-z0-9]+", text.lower())


STOP_WORDS = {
    "find", "show", "give", "me", "the", "a", "an",
    "in", "on", "of", "for", "to", "and", "or",
    "what", "are", "is", "about", "which", "that",
    "with", "how", "can", "could", "would",
    "vulnerability", "vulnerabilities", "related"
}


def get_query_terms(query):
    return [
        word for word in tokenize(query)
        if word not in STOP_WORDS
    ]


# ==========================================
# 3. LOAD MODEL
# ==========================================

print("Loading MiniLM model...")

model = SentenceTransformer(MODEL_NAME)


# ==========================================
# 4. LOAD FAISS INDEX
# ==========================================

print("Loading FAISS index...")

faiss_index = faiss.read_index(str(FAISS_FILE))


# ==========================================
# 5. LOAD BM25 INDEX
# ==========================================

print("Loading BM25 index...")

with open(BM25_FILE, "rb") as file:
    bm25 = pickle.load(file)


# ==========================================
# 6. LOAD CVE METADATA
# ==========================================

print("Loading CVE metadata...")

metadata = []

with open(METADATA_FILE, "r", encoding="utf-8") as file:
    for line in file:
        metadata.append(json.loads(line))

print("CVE records loaded:", len(metadata))


# ==========================================
# 7. VERIFY INDEX ALIGNMENT
# ==========================================

if faiss_index.ntotal != len(metadata):
    raise ValueError("FAISS and metadata counts do not match!")

if bm25.corpus_size != len(metadata):
    raise ValueError("BM25 and metadata counts do not match!")

if faiss_index.d != 384:
    raise ValueError("Unexpected FAISS embedding dimension!")

print("All indexes loaded successfully!")


# ==========================================
# 8. EXACT CVE LOOKUP
# ==========================================

def exact_cve_lookup(query):

    match = re.search(
        r"CVE-\d{4}-\d{4,}",
        query,
        re.IGNORECASE
    )

    if not match:
        return None

    cve_id = match.group(0).upper()

    for cve in metadata:
        if cve.get("cve_id", "").upper() == cve_id:
            return [cve.copy()]

    return []


# ==========================================
# 9. RELEVANCE CHECK
# ==========================================

def check_relevance(query, cve, faiss_score):

    query_terms = set(get_query_terms(query))

    if not query_terms:
        return True

    description = cve.get("description") or ""

    products = cve.get("products") or []

    if isinstance(products, str):
        products = [products]

    searchable_text = (
        description + " " +
        " ".join(str(p) for p in products)
    ).lower()

    searchable_terms = set(tokenize(searchable_text))

    matched_terms = query_terms.intersection(searchable_terms)

    overlap = len(matched_terms) / len(query_terms)

    # Require at least two matching terms for longer queries.
    required_matches = min(2, len(query_terms))

    lexical_match = len(matched_terms) >= required_matches

    # Semantic fallback for related wording.
    semantic_match = faiss_score >= 0.55

    return lexical_match or semantic_match


# ==========================================
# 10. HYBRID RETRIEVAL
# ==========================================

def retrieve_cves(query):

    print("\nStarting CVE retrieval...")

    # First check for an exact CVE ID.
    exact_results = exact_cve_lookup(query)

    if exact_results is not None:

        if exact_results:
            print("Exact CVE match found!")
        else:
            print("Exact CVE ID not found.")

        return exact_results

    # --------------------------------------
    # FAISS semantic search
    # --------------------------------------

    print("Performing FAISS semantic search...")

    query_embedding = model.encode(
        [query],
        normalize_embeddings=True
    )

    query_embedding = np.asarray(
        query_embedding,
        dtype="float32"
    )

    candidate_count = min(
        CANDIDATE_K,
        faiss_index.ntotal
    )

    faiss_scores, faiss_indices = faiss_index.search(
        query_embedding,
        candidate_count
    )

    faiss_results = []

    faiss_score_map = {}

    for score, idx in zip(
        faiss_scores[0],
        faiss_indices[0]
    ):

        if idx < 0:
            continue

        idx = int(idx)

        faiss_results.append(idx)
        faiss_score_map[idx] = float(score)

    # --------------------------------------
    # BM25 keyword search
    # --------------------------------------

    print("Performing BM25 keyword search...")

    query_tokens = tokenize(query)

    bm25_scores = bm25.get_scores(query_tokens)

    bm25_indices = np.argsort(
        bm25_scores
    )[::-1][:candidate_count]

    bm25_results = [
        int(idx)
        for idx in bm25_indices
        if bm25_scores[idx] > 0
    ]

    # --------------------------------------
    # Reciprocal Rank Fusion
    # --------------------------------------

    print("Combining FAISS and BM25 results...")

    rrf_scores = {}

    for rank, idx in enumerate(faiss_results, start=1):

        rrf_scores[idx] = rrf_scores.get(idx, 0) + (
            1 / (RRF_K + rank)
        )

    for rank, idx in enumerate(bm25_results, start=1):

        rrf_scores[idx] = rrf_scores.get(idx, 0) + (
            1 / (RRF_K + rank)
        )

    ranked_results = sorted(
        rrf_scores.items(),
        key=lambda item: item[1],
        reverse=True
    )

    # --------------------------------------
    # Relevance filtering
    # --------------------------------------

    print("Checking CVE relevance...")

    relevant_results = []

    for idx, rrf_score in ranked_results:

        cve = metadata[idx]

        faiss_score = faiss_score_map.get(idx, 0.0)

        if check_relevance(query, cve, faiss_score):

            record = cve.copy()

            record["rrf_score"] = rrf_score
            record["faiss_score"] = faiss_score

            relevant_results.append(record)

        if len(relevant_results) >= TOP_K:
            break

    return relevant_results


# ==========================================
# 11. DISPLAY RETRIEVED CVEs
# ==========================================

def display_results(results):

    print("\n========== HYBRID SEARCH RESULTS ==========")

    for rank, cve in enumerate(results, start=1):

        print("\nRank:", rank)
        print("CVE ID:", cve.get("cve_id"))
        print("Severity:", cve.get("severity"))
        print("CVSS Score:", cve.get("cvss_score"))
        print("RRF Score:", round(cve.get("rrf_score", 0), 5))

    print("\n========== RETRIEVED CVE EVIDENCE ==========")

    for rank, cve in enumerate(results, start=1):

        products = cve.get("products") or ["Not available"]

        print("\nRank:", rank)
        print("CVE ID:", cve.get("cve_id"))
        print("Description:", cve.get("description"))
        print("Severity:", cve.get("severity"))
        print("CVSS Score:", cve.get("cvss_score"))
        print("Affected Products:", products)


# ==========================================
# 12. GENERATE GROUNDED RAG ANSWER
# ==========================================

def generate_answer(query, results):

    if not results:

        print("\nNo sufficiently relevant CVE evidence found.")
        print("Try using a more specific cybersecurity query.")

        return

    context_parts = []

    for cve in results:

        evidence = f"""
CVE ID: {cve.get("cve_id", "Not available")}
Description: {cve.get("description", "Not available")}
Severity: {cve.get("severity", "Not available")}
CVSS Score: {cve.get("cvss_score", "Not available")}
Affected Products: {cve.get("products") or "Not available"}
"""

        context_parts.append(evidence)

    context = "\n".join(context_parts)

    prompt = f"""
You are a cybersecurity vulnerability analysis assistant.

USER QUESTION:
{query}

RETRIEVED CVE EVIDENCE:
{context}

RULES:

1. Use only the supplied CVE records for CVE-specific facts.
2. Do not invent CVE IDs or vulnerability details.
3. Explain each relevant CVE separately.
4. Include the exact severity and CVSS score.
5. Mention products only when available in the evidence.
6. Do not claim a CVE is related to the question
   unless its description supports that connection.
7. If the evidence does not answer the question,
   clearly say so.
8. Separate general security advice from CVE facts.

ANSWER FORMAT:

A. Overview
B. Relevant CVE Analysis
C. Potential Impact
D. Security Recommendations

Use simple, clear language.
"""

    print("\nGenerating answer using Llama 3.2...")

    response = ollama.chat(
        model=LLM_NAME,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    print("\n========== HYBRID RAG ANSWER ==========")

    print(response["message"]["content"])


# ==========================================
# 13. MAIN PROGRAM
# ==========================================

def main():

    print("\n======================================")
    print("       SENTINEL AI - HYBRID RAG")
    print("======================================")

    query = input(
        "\nAsk a cybersecurity question: "
    ).strip()

    if not query:
        print("Please enter a question.")
        return

    results = retrieve_cves(query)

    if results:
        display_results(results)

    generate_answer(query, results)

    print("\n========== RAG COMPLETED ==========")


if __name__ == "__main__":
    main()
