
import json
import pickle
import re
from pathlib import Path

import faiss
import numpy as np
import ollama
from sentence_transformers import SentenceTransformer


# ==========================================
# 1. PROJECT PATHS
# ==========================================

ROOT = Path(__file__).resolve().parents[2]

FAISS_FILE = ROOT / "embeddings" / "cve_faiss.index"
BM25_FILE = ROOT / "embeddings" / "bm25_index.pkl"
METADATA_FILE = ROOT / "embeddings" / "cve_metadata.jsonl"


# ==========================================
# 2. TOKENIZATION FUNCTION
# ==========================================

def tokenize(text):
    return re.findall(r"[a-zA-Z0-9_.-]+", text.lower())


# ==========================================
# 3. LOAD MINI LM MODEL
# ==========================================

print("Loading MiniLM model...")

model = SentenceTransformer("all-MiniLM-L6-v2")


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
    raise ValueError("FAISS index and metadata counts do not match!")

if bm25.corpus_size != len(metadata):
    raise ValueError("BM25 index and metadata counts do not match!")

print("All indexes loaded successfully!")


# ==========================================
# 8. GET USER QUERY
# ==========================================

query = input("\nAsk a cybersecurity question: ").strip()

if not query:
    raise ValueError("Please enter a question.")


# ==========================================
# 9. FAISS SEMANTIC SEARCH
# ==========================================

print("\nPerforming FAISS semantic search...")

query_embedding = model.encode(
    [query],
    normalize_embeddings=True
)

query_embedding = np.asarray(
    query_embedding,
    dtype="float32"
)

faiss_scores, faiss_indices = faiss_index.search(
    query_embedding,
    20
)

faiss_results = [
    int(idx)
    for idx in faiss_indices[0]
    if idx >= 0
]


# ==========================================
# 10. BM25 KEYWORD SEARCH
# ==========================================

print("Performing BM25 keyword search...")

query_tokens = tokenize(query)

bm25_scores = bm25.get_scores(query_tokens)

bm25_indices = np.argsort(bm25_scores)[::-1][:20]

bm25_results = [
    int(idx)
    for idx in bm25_indices
    if bm25_scores[idx] > 0
]


# ==========================================
# 11. RECIPROCAL RANK FUSION (RRF)
# ==========================================

print("Combining FAISS and BM25 results...")

RRF_K = 60

rrf_scores = {}

# Add FAISS rankings
for rank, idx in enumerate(faiss_results, start=1):

    rrf_scores[idx] = rrf_scores.get(idx, 0) + (
        1 / (RRF_K + rank)
    )


# Add BM25 rankings
for rank, idx in enumerate(bm25_results, start=1):

    rrf_scores[idx] = rrf_scores.get(idx, 0) + (
        1 / (RRF_K + rank)
    )


# Sort results by combined RRF score
ranked_results = sorted(
    rrf_scores.items(),
    key=lambda item: item[1],
    reverse=True
)

top_results = ranked_results[:5]


# ==========================================
# 12. GET RETRIEVED CVE RECORDS
# ==========================================

retrieved_cves = []

for idx, score in top_results:

    cve = metadata[idx].copy()

    cve["rrf_score"] = score

    retrieved_cves.append(cve)


# ==========================================
# 13. DISPLAY HYBRID SEARCH RESULTS
# ==========================================

print("\n========== HYBRID SEARCH RESULTS ==========")

for rank, cve in enumerate(retrieved_cves, start=1):

    print("\nRank:", rank)
    print("CVE ID:", cve.get("cve_id", "Unknown"))
    print("Severity:", cve.get("severity", "Unknown"))
    print("CVSS Score:", cve.get("cvss_score", "Not available"))
    print("RRF Score:", round(cve["rrf_score"], 5))


# ==========================================
# 14. PREPARE CVE EVIDENCE FOR RAG
# ==========================================

print("\n========== RETRIEVED CVE EVIDENCE ==========")

context_parts = []

for rank, cve in enumerate(retrieved_cves, start=1):

    cve_id = cve.get("cve_id", "Unknown")

    description = cve.get("description") or "Not available"

    severity = cve.get("severity") or "Not available"

    cvss_score = cve.get("cvss_score")

    if cvss_score is None:
        cvss_score = "Not available"

    products = cve.get("products") or ["Not available"]

    print(f"\nRank: {rank}")
    print("CVE ID:", cve_id)
    print("Description:", description)
    print("Severity:", severity)
    print("CVSS Score:", cvss_score)
    print("Affected Products:", products)

    evidence = f"""
CVE ID: {cve_id}
Description: {description}
Severity: {severity}
CVSS Score: {cvss_score}
Affected Products: {products}
"""

    context_parts.append(evidence)


context = "\n".join(context_parts)


# ==========================================
# 15. CREATE RAG PROMPT
# ==========================================

prompt = f"""
You are a cybersecurity vulnerability analysis assistant.

Answer the user's question using the retrieved CVE evidence below.

USER QUESTION:
{query}

RETRIEVED CVE EVIDENCE:
{context}

IMPORTANT RULES:

1. Use only the supplied CVE records for CVE-specific facts.
2. Explain each retrieved CVE separately.
3. Mention each CVE ID exactly as provided.
4. Summarize its actual description clearly.
5. Include the exact severity and CVSS score provided.
6. Mention affected products only when provided.
7. Never invent CVE IDs, descriptions, severity, scores,
   or affected products.
8. If information is missing, write "Not available".
9. Do not claim a CVE is related to the user's question
   unless its description supports that connection.
10. Clearly distinguish general security advice from
    facts found in the retrieved records.

ANSWER FORMAT:

A. Overview
Explain the topic in simple language.

B. Retrieved CVE Analysis
For every retrieved CVE, include:
- CVE ID
- Vulnerability description
- Severity
- CVSS score
- Affected products

C. Potential Impact
Explain the possible impact supported by the evidence.

D. Security Recommendations
Give relevant general security recommendations.

Use clear and simple language.
"""


# ==========================================
# 16. GENERATE ANSWER USING OLLAMA
# ==========================================

print("\nGenerating answer using Llama 3.2...")

response = ollama.chat(
    model="llama3.2",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ]
)


# ==========================================
# 17. DISPLAY FINAL RAG ANSWER
# ==========================================

print("\n========== HYBRID RAG ANSWER ==========")

print(response["message"]["content"])

print("\n========== RAG COMPLETED ==========")
