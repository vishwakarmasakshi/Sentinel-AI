# 🛡️ Sentinel AI
### Intelligent Common Vulnerabilities and Exposures (CVE) Analyzer

Sentinel AI is an AI-powered cybersecurity application designed to help users search, explore, and understand Common Vulnerabilities and Exposures (CVEs).

It uses Retrieval-Augmented Generation (RAG), semantic search, and hybrid retrieval to find relevant vulnerability information from a large CVE dataset and generate context-based explanations.

## 🚀 Key Features

### 1. CVE Dashboard
- Displays the total number of CVE records.
- Shows vulnerability distribution by severity.
- Displays recently published vulnerabilities.

### 2. AI Vulnerability Analyzer
- Accepts natural-language cybersecurity questions.
- Retrieves relevant CVE records.
- Generates explanations using Llama 3.2.
- Provides vulnerability details and security recommendations.

### 3. Hybrid Search
Combines multiple retrieval techniques:
- **FAISS:** Semantic similarity search.
- **BM25:** Keyword-based retrieval.
- **Reciprocal Rank Fusion (RRF):** Combines results from both retrieval methods.

### 4. CVE Explorer
Allows users to explore and filter vulnerabilities using:
- Severity
- Publication year
- Minimum CVSS score
- Product name
- CVE ID or description

### 5. Exact CVE Lookup
Users can search for a specific CVE ID to retrieve its vulnerability information.

### 6. NVD Data Updates
Includes scripts to fetch recent CVE information from the National Vulnerability Database (NVD) and process new records.

## 🧠 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Streamlit | Web application interface |
| Sentence Transformers | Text embeddings |
| all-MiniLM-L6-v2 | Semantic embedding model |
| FAISS | Vector similarity search |
| BM25 | Keyword-based retrieval |
| RRF | Hybrid result ranking |
| Llama 3.2 | Natural-language answer generation |
| NVD | CVE vulnerability data |
| Pandas & NumPy | Data processing |

## 🏗️ Project Architecture

1. Collect CVE records from NVD.
2. Preprocess and structure vulnerability data.
3. Generate text embeddings using MiniLM.
4. Store and search embeddings using FAISS.
5. Build a BM25 keyword search index.
6. Combine retrieval results using RRF.
7. Pass relevant CVE context to the language model.
8. Display vulnerability explanations through Streamlit.

## 📂 Project Structure

```text
cvc_final_folder/
│
├── app.py
├── README.md
├── requirements.txt
│
├── data/
│   ├── raw/
│   └── processed/
│
├── embeddings/
│
├── scripts/
│   ├── data_collection/
│   ├── embedding/
│   ├── indexing/
│   ├── preprocessing/
│   └── updating/
│
└── src/
    ├── rag/
    ├── retrieval/
    └── utils/
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/Sentinel-AI.git
cd Sentinel-AI
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

### 3. Activate the environment

For macOS/Linux:

```bash
source venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Prepare project data and indexes

The CVE dataset and generated embedding/index files are not included in this repository because of their size.

Prepare the required data, metadata, FAISS index, and BM25 index before launching the application.

### 6. Run the application

```bash
streamlit run app.py
```

The application will open in your browser.

## 📊 Dataset

The project uses CVE information from the **National Vulnerability Database (NVD)**.

Official source: https://nvd.nist.gov/

The project processes historical CVE records and supports fetching recent vulnerability updates through the NVD API.

## 🎯 Project Objective

The main objective of Sentinel AI is to make vulnerability research easier by combining semantic search, keyword retrieval, and AI-generated explanations.

Instead of manually searching through large numbers of vulnerability reports, users can ask questions and explore relevant CVE information through a single interface.

## 🔮 Future Improvements

- Improve retrieval accuracy and relevance.
- Add more detailed vulnerability evaluation.
- Improve source citations and evidence display.
- Expand vulnerability analysis and reporting.

## 👩‍💻 Author

**Sakshi Vishwakarma**

AI and Cybersecurity Project

---

*Sentinel AI — Making vulnerability analysis easier with AI.*