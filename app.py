
import json
import re
import pickle
import faiss
import numpy as np
import ollama
import streamlit as st
import pandas as pd
from sentence_transformers import SentenceTransformer

# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Sentinel AI",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# CUSTOM CSS
# ==========================================

st.markdown("""
<style>

.stApp {
    background-color: #0b1220;
    color: #ffffff;
}

[data-testid="stSidebar"] {
    background-color: #111b2a;
}

h1, h2, h3 {
    color: #ffffff;
}

p, label, span {
    color: #d1d5db;
}

.stTextInput input,
.stTextArea textarea {
    background-color: #111b2a !important;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    border: 1px solid #4ade80 !important;
    border-radius: 8px !important;
    caret-color: #4ade80 !important;
}

.stTextInput input::placeholder,
.stTextArea textarea::placeholder {
    color: #94a3b8 !important;
    -webkit-text-fill-color: #94a3b8 !important;
}

.stTextInput input::selection,
.stTextArea textarea::selection {
    background-color: #166534 !important;
    color: white !important;
}

.stButton button {
    background-color: #16a34a;
    color: white;
    border-radius: 8px;
    border: none;
}

.stButton button:hover {
    background-color: #15803d;
    color: white;
}

.metric-card {
    background-color: #111b2a;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #263449;
}

.metric-title {
    color: #94a3b8;
    font-size: 14px;
}

.metric-value {
    color: #4ade80;
    font-size: 30px;
    font-weight: bold;
}

.result-card {
    background-color: #111b2a;
    padding: 15px;
    border-radius: 10px;
    border-left: 4px solid #4ade80;
    margin-bottom: 12px;
}

.answer-card {
    background-color: #111b2a;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #263449;
}

</style>
""", unsafe_allow_html=True)


# ==========================================
# LOAD MODELS AND DATA
# ==========================================

@st.cache_resource
def load_resources():
    """Load the embedding model, FAISS index, BM25 index, and CVE metadata."""

    model = SentenceTransformer("all-MiniLM-L6-v2")

    index = faiss.read_index(
        "embeddings/cve_faiss.index"
    )

    with open("embeddings/bm25_index.pkl", "rb") as file:
        bm25 = pickle.load(file)

    metadata = []

    with open(
        "embeddings/cve_metadata.jsonl",
        "r",
        encoding="utf-8"
    ) as file:
        for line in file:
            if line.strip():
                metadata.append(json.loads(line))

    if index.ntotal != len(metadata):
        raise ValueError(
            f"FAISS index has {index.ntotal} vectors, "
            f"but metadata has {len(metadata)} records."
        )

    if bm25.corpus_size != len(metadata):
        raise ValueError(
            f"BM25 index has {bm25.corpus_size} documents, "
            f"but metadata has {len(metadata)} records."
        )

    if index.d != 384:
        raise ValueError(
            f"Expected 384-dimensional FAISS vectors, got {index.d}."
        )

    return model, index, bm25, metadata


# ==========================================
# LOAD RESOURCES
# ==========================================

try:
    with st.spinner("Loading Sentinel AI models and indexes..."):
        model, index, bm25, metadata = load_resources()

except Exception as error:
    st.error(f"Unable to load project resources: {error}")
    st.stop()


# ==========================================
# HEADER
# ==========================================

st.markdown(
    "<h1 style='color:#4ade80;'>🛡️ Sentinel AI</h1>",
    unsafe_allow_html=True
)

st.markdown(
    "### Intelligent Common Vulnerabilities and Exposures Analysis"
)

st.markdown(
    "<p style='color:#94a3b8;'>"
    "THREAT INTELLIGENCE PLATFORM"
    "</p>",
    unsafe_allow_html=True
)

st.divider()


# ==========================================
# SIDEBAR
# ==========================================

st.sidebar.title("🛡️ Sentinel AI")

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "AI Vulnerability Analyzer",
        "CVE Explorer"
    ]
)

st.sidebar.divider()

st.sidebar.caption(
    "Powered by MiniLM · FAISS · BM25 · RRF · Llama 3.2 · NVD"
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def get_severity_count(severity):

    return sum(
        1 for cve in metadata
        if str(cve.get("severity", "")).upper() == severity
    )


def tokenize(text):
    """Use the same tokenization approach as the BM25 index builder."""
    return re.findall(r"[a-z0-9]+", str(text).lower())


STOP_WORDS = {
    "a", "an", "the", "is", "are", "was", "were", "in", "on", "of",
    "to", "for", "and", "or", "with", "from", "by", "about", "what",
    "which", "who", "how", "find", "show", "list", "search", "related",
    "vulnerability", "vulnerabilities", "cve", "please"
}


def get_product_text(cve):
    """Return readable product names, with legacy CPE data as fallback."""

    products = cve.get("products")

    if isinstance(products, list) and products:
        return " ".join(str(item) for item in products)

    affected_products = cve.get("affected_products", [])

    if isinstance(affected_products, list):
        return " ".join(str(item) for item in affected_products)

    return str(affected_products or "")


def retrieve_cves(query, top_k=5):
    """Retrieve CVEs using exact lookup or FAISS + BM25 + RRF."""

    # STEP 1: Exact CVE ID lookup

    cve_ids = re.findall(
        r"\bCVE-\d{4}-\d{4,}\b",
        query,
        re.IGNORECASE
    )

    if cve_ids:
        requested_ids = {cve_id.upper() for cve_id in cve_ids}
        exact_results = []

        for cve in metadata:
            stored_id = str(cve.get("cve_id", "")).upper()

            if stored_id in requested_ids:
                exact_results.append({
                    "cve": cve,
                    "similarity": 1.0,
                    "method": "Exact CVE ID"
                })

        return exact_results

    if index.ntotal == 0 or not query.strip():
        return []

    # STEP 2: FAISS semantic retrieval

    query_vector = model.encode(
        [query],
        convert_to_numpy=True,
        normalize_embeddings=True
    )

    query_vector = np.asarray(query_vector, dtype="float32")

    candidate_count = min(50, index.ntotal)

    faiss_scores, faiss_indices = index.search(
        query_vector,
        candidate_count
    )

    # STEP 3: BM25 keyword retrieval

    query_tokens = tokenize(query)
    bm25_scores = bm25.get_scores(query_tokens)

    bm25_count = min(50, len(bm25_scores))

    bm25_indices = np.argsort(bm25_scores)[::-1][:bm25_count]

    # STEP 4: Reciprocal Rank Fusion (RRF)

    rrf_scores = {}
    faiss_similarity = {}
    rrf_k = 60

    for rank, position in enumerate(faiss_indices[0], start=1):

        position = int(position)

        if position < 0 or position >= len(metadata):
            continue

        rrf_scores[position] = rrf_scores.get(position, 0.0) + (
            1.0 / (rrf_k + rank)
        )

        faiss_similarity[position] = float(
            faiss_scores[0][rank - 1]
        )

    for rank, position in enumerate(bm25_indices, start=1):

        position = int(position)

        if position < 0 or position >= len(metadata):
            continue

        # Ignore zero-score BM25 results.

        if float(bm25_scores[position]) <= 0:
            continue

        rrf_scores[position] = rrf_scores.get(position, 0.0) + (
            1.0 / (rrf_k + rank)
        )

    ranked_positions = sorted(
        rrf_scores,
        key=rrf_scores.get,
        reverse=True
    )

    # STEP 5: Remove results with no meaningful query relevance

    query_terms = {
        token for token in query_tokens
        if token not in STOP_WORDS and len(token) > 1
    }

    required_overlap = min(2, len(query_terms))

    final_results = []

    for position in ranked_positions:

        cve = metadata[position]

        searchable_text = (
            str(cve.get("description", "")) + " " +
            get_product_text(cve)
        ).lower()

        record_tokens = set(tokenize(searchable_text))

        overlap = len(query_terms.intersection(record_tokens))

        semantic_score = faiss_similarity.get(position, 0.0)

        if required_overlap > 0:
            if overlap < required_overlap and semantic_score < 0.55:
                continue

        final_results.append({
            "cve": cve,
            "similarity": float(rrf_scores[position]),
            "method": "Hybrid (FAISS + BM25 + RRF)"
        })

        if len(final_results) >= top_k:
            break

    return final_results


# ==========================================
# RAG ANSWER GENERATION
# ==========================================

def generate_rag_answer(query, results):

    context = ""

    for number, result in enumerate(results, start=1):

        cve = result["cve"]

        context += f"""
RECORD {number}
CVE ID: {cve.get('cve_id', 'Not available')}
Description: {cve.get('description', 'Not available')}
Severity: {cve.get('severity', 'Not available')}
CVSS Score: {cve.get('cvss_score', 'Not available')}
Affected products: {get_product_text(cve) or 'Not available'}
CWE: {cve.get('cwe_id', 'Not available')}

"""

    retrieved_count = len(results)

    prompt = f"""
You are a professional cybersecurity vulnerability analyst.

Answer the user's question using the retrieved CVE records.

STRICT RULES:

1. Exactly {retrieved_count} CVE records were retrieved.
   Do not report a different number.

2. Mention only CVE IDs present in the retrieved records.

3. Mention every retrieved CVE exactly once in the
   retrieved-records section.

4. Never invent CVE IDs, severity levels, CVSS scores,
   descriptions, or vulnerability impacts.

5. For each specific CVE, report only facts stated
   in its description.

6. Do not assume that a vulnerability affects confidentiality,
   integrity, or availability unless the description supports it.

7. If an impact is not stated, write:
   "The retrieved description does not specify this impact."

8. Similarity scores are not accuracy percentages.

9. Explain in simple English.

10. Separate the answer into these sections:

A. What is the vulnerability?
B. Retrieved CVE records
C. Confirmed impacts from the descriptions
D. General security recommendations

11. In section C, do not add general cybersecurity impacts
    as if they were confirmed impacts of these CVEs.

12. General recommendations may use general cybersecurity
    knowledge. Label them as general advice.

USER QUESTION:
{query}

NUMBER OF RETRIEVED RECORDS:
{retrieved_count}

RETRIEVED CVE INFORMATION:
{context}

Generate a clear and accurate answer.
"""

    response = ollama.chat(
        model="llama3.2",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response["message"]["content"]


# ==========================================
# DASHBOARD
# ==========================================

if page == "Dashboard":

    st.header("📊 Security Dashboard")

    total = len(metadata)

    critical = get_severity_count("CRITICAL")
    high = get_severity_count("HIGH")
    medium = get_severity_count("MEDIUM")
    low = get_severity_count("LOW")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Total CVEs</div>
                <div class="metric-value">{total:,}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Critical</div>
                <div class="metric-value">{critical:,}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">High</div>
                <div class="metric-value">{high:,}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Medium</div>
                <div class="metric-value">{medium:,}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.divider()

    st.subheader("Vulnerability Severity Distribution")

    severity_data = pd.DataFrame({
        "Severity": [
            "Critical",
            "High",
            "Medium",
            "Low"
        ],
        "Count": [
            critical,
            high,
            medium,
            low
        ]
    })

    st.bar_chart(
        severity_data.set_index("Severity")
    )

    st.subheader("Recent Vulnerabilities")

    recent = sorted(
        metadata,
        key=lambda x: x.get("published_date", ""),
        reverse=True
    )[:10]

    for cve in recent:

        st.markdown(
            f"""
            <div class="result-card">
                <b>{cve.get('cve_id', 'Unknown')}</b>
                &nbsp; | &nbsp;
                {cve.get('severity', 'Unknown')}
                &nbsp; | &nbsp;
                CVSS: {cve.get('cvss_score', 'N/A')}
                <br><br>
                {cve.get('description', 'No description')}
            </div>
            """,
            unsafe_allow_html=True
        )


# ==========================================
# AI VULNERABILITY ANALYZER
# ==========================================

elif page == "AI Vulnerability Analyzer":

    st.header("🤖 AI Vulnerability Analyzer")

    st.write(
        "Ask questions about cybersecurity vulnerabilities."
    )

    query = st.text_area(
        "Enter your cybersecurity question",
        placeholder="Example: SQL injection vulnerability in web applications",
        height=100
    )

    if st.button("Analyze Vulnerability", type="primary"):

        if not query.strip():

            st.warning("Please enter a question.")

        else:

            try:

                with st.spinner(
                    "Searching CVEs and generating AI analysis..."
                ):

                    results = retrieve_cves(query, 5)

                    if not results:

                        st.warning(
                            "No matching CVE ID was found in your database. "
                            "Please check the CVE ID."
                        )

                    else:

                        answer = generate_rag_answer(
                            query,
                            results
                        )

                        st.subheader("🧠 AI Analysis")

                        st.markdown(
                            """
                            <div class="answer-card">
                            """,
                            unsafe_allow_html=True
                        )

                        st.markdown(answer)

                        st.markdown(
                            "</div>",
                            unsafe_allow_html=True
                        )

                        st.divider()

                        st.subheader("🔎 Retrieved CVE Records")

                        for result in results:

                            cve = result["cve"]
                            score = result["similarity"]

                            st.markdown(
                                f"""
                                <div class="result-card">
                                    <b>{cve.get('cve_id')}</b>
                                    &nbsp; | &nbsp;
                                    {cve.get('severity', 'Unknown')}
                                    &nbsp; | &nbsp;
                                    CVSS: {cve.get('cvss_score', 'N/A')}
                                    <br>
                                    RRF ranking score: {score:.4f}
                                    <br>
                                    Products: {get_product_text(cve) or 'Not available'}
                                    <br><br>
                                    {cve.get('description', 'No description')}
                                </div>
                                """,
                                unsafe_allow_html=True
                            )

            except Exception as error:

                st.error(f"Analysis failed: {error}")


# ==========================================
# CVE EXPLORER
# ==========================================

elif page == "CVE Explorer":

    st.header("🔎 CVE Explorer")

    st.write(
        "Search and filter vulnerabilities from your CVE database."
    )

    col1, col2 = st.columns(2)

    with col1:

        severity_filter = st.selectbox(
            "Severity",
            [
                "ALL",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ]
        )

        year_filter = st.selectbox(
            "Published Year",
            [
                "ALL",
                "2022",
                "2023",
                "2024",
                "2025",
                "2026"
            ]
        )

    with col2:

        min_cvss = st.slider(
            "Minimum CVSS Score",
            min_value=0.0,
            max_value=10.0,
            value=0.0,
            step=0.1
        )

        product_filter = st.text_input(
            "Product name",
            placeholder="Example: dolibarr"
        )

    search_text = st.text_input(
        "Search CVE ID or description",
        placeholder="Example: SQL injection"
    )

    if st.button("Apply Filters"):

        filtered = []

        for cve in metadata:

            severity = str(
                cve.get("severity", "")
            ).upper()

            score = cve.get("cvss_score")

            if score is None:
                score = 0

            try:
                score = float(score)
            except (ValueError, TypeError):
                score = 0

            published_date = str(
                cve.get("published_date", "")
            )

            products = get_product_text(cve).lower()

            description = str(
                cve.get("description", "")
            ).lower()

            cve_id = str(
                cve.get("cve_id", "")
            ).lower()

            if severity_filter != "ALL":
                if severity != severity_filter:
                    continue
            if year_filter != "ALL":
                try:
                    published_year = published_date[:4]

                    if published_year != year_filter:
                         continue

                except (ValueError, TypeError):
                     continue
            
            if score < min_cvss:
                continue

            if product_filter.strip():
                if product_filter.lower() not in products:
                    continue

            if search_text.strip():
                search = search_text.lower()

                if (
                    search not in description
                    and search not in cve_id
                ):
                    continue

            filtered.append(cve)

        filtered.sort(
            key=lambda x: (
                x.get("cvss_score")
                if x.get("cvss_score") is not None
                else -1
            ),
            reverse=True
        )

        st.success(
            f"Total matching CVEs: {len(filtered):,}"
        )

        for cve in filtered[:50]:

            st.markdown(
                f"""
                <div class="result-card">
                    <b>{cve.get('cve_id')}</b>
                    &nbsp; | &nbsp;
                    {cve.get('severity', 'Unknown')}
                    &nbsp; | &nbsp;
                    CVSS: {cve.get('cvss_score', 'N/A')}
                    <br>
                    Products: {get_product_text(cve) or 'Not available'}
                    <br>
                    CWE: {cve.get('cwe_id', 'Not available')}
                    <br><br>
                    {cve.get('description', 'No description')}
                </div>
                """,
                unsafe_allow_html=True
            )

        if len(filtered) > 50:

            st.info(
                "Showing the first 50 matching records."
            )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.markdown(
    """
    <div style="text-align:center;color:#64748b;">
        SENTINEL AI · Cybersecurity Intelligence Platform
        <br>
        Powered by MiniLM · FAISS · BM25 · RRF · Llama 3.2 · NVD
    </div>
    """,
    unsafe_allow_html=True
)
