
from pathlib import Path

import numpy as np
import faiss

# 1. Find project directory
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# 2. Define file paths
EMBEDDING_FILE = PROJECT_ROOT / "embeddings" / "cve_embeddings.npy"
INDEX_FILE = PROJECT_ROOT / "embeddings" / "cve_faiss.index"

# 3. Check whether embeddings exist
if not EMBEDDING_FILE.exists():
    raise FileNotFoundError(
        f"Embeddings file not found: {EMBEDDING_FILE}"
    )

print("Loading embeddings...")

embeddings = np.load(
    EMBEDDING_FILE,
    mmap_mode="r"
)

print("Embedding shape:", embeddings.shape)

# 4. Check embedding dimensions
if embeddings.ndim != 2 or embeddings.shape[0] == 0:
    raise ValueError("Invalid or empty embeddings file.")

dimension = embeddings.shape[1]

# 5. Create FAISS index
index = faiss.IndexFlatIP(dimension)

print("FAISS index created!")

# 6. Add embeddings in batches
batch_size = 5000
total = embeddings.shape[0]

for start in range(0, total, batch_size):

    end = min(start + batch_size, total)

    batch = np.asarray(
        embeddings[start:end],
        dtype=np.float32
    )

    index.add(batch)

    print(f"Indexed: {end}/{total}")

# 7. Save FAISS index
faiss.write_index(index, str(INDEX_FILE))

print("\n========== COMPLETED ==========")
print("Total vectors:", index.ntotal)
print("Index saved:", INDEX_FILE)
