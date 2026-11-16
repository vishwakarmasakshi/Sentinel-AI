# 🛡️ Sentinel AI
## Intelligent CVE Vulnerability Analyzer

Sentinel AI is an AI-powered cybersecurity application designed to help users search, explore, and understand Common Vulnerabilities and Exposures (CVEs).

The application uses **Retrieval-Augmented Generation (RAG)** and a hybrid information retrieval system combining semantic search and keyword-based search. It retrieves relevant vulnerability records and uses Llama 3.2 to generate context-aware explanations.

---

## 🚀 Key Features

### 1. CVE Dashboard
- Displays the total number of CVE records.
- Shows vulnerability distribution by severity.
- Provides an overview of the vulnerability dataset.

### 2. AI Vulnerability Analyzer
- Accepts natural-language cybersecurity questions.
- Retrieves relevant CVE information.
- Generates context-based explanations using Llama 3.2.
- Provides relevant vulnerability details and security recommendations.

### 3. Hybrid Retrieval System

Sentinel AI combines multiple retrieval techniques to improve search relevance.

- **FAISS:** Performs semantic similarity search using vector embeddings.
- **BM25:** Performs keyword-based information retrieval.
- **Reciprocal Rank Fusion (RRF):** Combines the rankings from FAISS and BM25 to produce a unified result list.

### 4. CVE Explorer
Allows users to explore and filter vulnerability records using:
- Severity
- Publication year
- Minimum CVSS score
- Product name
- CVE ID and description

### 5. Exact CVE Lookup
Users can enter a specific CVE ID to retrieve its vulnerability information from the dataset.

### 6. Automated CVE Data Updates
The project includes scripts for:
- Fetching recent CVE records from the NVD API.
- Identifying duplicate records.
- Processing and enriching vulnerability metadata.
- Generating embeddings for new records.
- Integrating new records into the existing dataset and indexes.

---

## 🧠 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Streamlit | Web application interface |
| Sentence Transformers | Text embedding generation |
| all-MiniLM-L6-v2 | Embedding model |
| FAISS | Vector similarity search |
| BM25 | Keyword-based retrieval |
| Reciprocal Rank Fusion | Hybrid ranking |
| Llama 3.2 | Natural-language answer generation |
| Ollama | Local language model runtime |
| NVD API | CVE data collection |
| Pandas | Data processing |
| NumPy | Numerical operations |

---

## 🏗️ System Architecture

The application follows a Retrieval-Augmented Generation workflow.

1. **Data Collection:** CVE records are collected from the National Vulnerability Database (NVD).
2. **Preprocessing:** Vulnerability descriptions and metadata are processed and structured.
3. **Embedding Generation:** The all-MiniLM-L6-v2 model converts CVE descriptions into numerical vectors.
4. **Vector Retrieval:** FAISS retrieves semantically similar vulnerability records.
5. **Keyword Retrieval:** BM25 retrieves records based on keyword relevance.
6. **Hybrid Ranking:** Reciprocal Rank Fusion combines both retrieval result lists.
7. **Context Preparation:** Relevant CVE records are selected as context.
8. **Answer Generation:** Llama 3.2 generates an explanation using the retrieved context.
9. **User Interface:** Streamlit displays the results through an interactive dashboard.

---

## 📂 Project Structure

```text
Sentinel-AI/
│
├── app.py
├── README.md
├── requirements.txt
├── .gitignore
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

**Note:** The large CVE dataset, generated embeddings, indexes, and virtual environment are excluded from the GitHub repository.

---

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/vishwakarmasakshi/Sentinel-AI.git

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

### 5. Prepare the dataset and indexes

The CVE dataset, metadata, embeddings, FAISS index, and BM25 index are not included in the repository because of their size.

Prepare the required files using the data collection, preprocessing, embedding, and indexing scripts in the `scripts/` directory.

The application requires these files in their expected locations before it can run.

### 6. Set up Llama 3.2

Install Ollama and download the Llama 3.2 model:

```bash
ollama pull llama3.2
```

Ensure the Ollama service is running before using the AI Vulnerability Analyzer.

### 7. Launch the application

```bash
streamlit run app.py
```

The application will open in your browser.

---

## 📊 Dataset

Sentinel AI uses vulnerability information from the **National Vulnerability Database (NVD)**.

Official source: https://nvd.nist.gov/

The project processes historical CVE records and supports fetching recent vulnerability updates through the NVD API.

---

## 🎯 Project Objective

The main objective of Sentinel AI is to simplify cybersecurity vulnerability research and analysis.

Traditional vulnerability research often requires users to manually search through large numbers of vulnerability reports.

Sentinel AI provides a unified platform where users can:
- Search for specific vulnerabilities.
- Explore CVE records using filters.
- Ask natural-language questions about cybersecurity vulnerabilities.
- Retrieve relevant information through hybrid search.
- Understand vulnerabilities through AI-generated explanations.

By combining semantic retrieval, keyword-based search, and Retrieval-Augmented Generation, Sentinel AI makes vulnerability information easier to explore and understand.

---

## 👩‍💻 Author

**Sakshi Vishwakarma**

AI & Cybersecurity Project

---

*Sentinel AI — Intelligent Vulnerability Analysis Using AI.*