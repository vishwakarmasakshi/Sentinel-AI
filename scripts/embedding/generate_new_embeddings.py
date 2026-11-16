 
import json
import numpy as np

from pathlib import Path
from sentence_transformers import SentenceTransformer

# ==========================================
# 1. PROJECT DIRECTORIES
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    PROJECT_ROOT / "data" / "processed" / "unique-new-cves.jsonl"
)

OUTPUT_DIR = PROJECT_ROOT / "embeddings"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "new_cve_embeddings.npy"

# ==========================================
# 2. LOAD NEW CVE RECORDS
# ==========================================

if not INPUT_FILE.exists():
    raise FileNotFoundError(f"File not found: {INPUT_FILE}")

records = []

with open(INPUT_FILE, "r", encoding="utf-8") as file:
    for line in file:
        if line.strip():
            cve = json.loads(line)

            if cve.get("description", "").strip():
                records.append(cve)

print("New CVEs loaded:", len(records))

if not records:
    print("No new CVEs available for embedding.")
    raise SystemExit(0)

# ==========================================
# 3. LOAD MINILM MODEL
# ==========================================

print("\nLoading MiniLM model...")

model = SentenceTransformer("all-MiniLM-L6-v2")

# ==========================================
# 4. EXTRACT DESCRIPTIONS
# ==========================================

descriptions = [
    cve["description"]
    for cve in records
]

# ==========================================
# 5. GENERATE EMBEDDINGS
# ==========================================

print("\nGenerating embeddings...")

embeddings = model.encode(
    descriptions,
    batch_size=64,
    convert_to_numpy=True,
    normalize_embeddings=True,
    show_progress_bar=True
)

# ==========================================
# 6. VERIFY EMBEDDINGS
# ==========================================

if len(embeddings) != len(records):
    raise ValueError("CVE and embedding counts do not match!")

# ==========================================
# 7. SAVE EMBEDDINGS
# ==========================================

np.save(OUTPUT_FILE, embeddings)

print("\n========== COMPLETED ==========")
print("Total embeddings:", len(embeddings))
print("Embedding shape:", embeddings.shape)
print("Saved file:", OUTPUT_FILE)
