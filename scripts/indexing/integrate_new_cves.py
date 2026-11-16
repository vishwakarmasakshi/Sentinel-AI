
import json
import os
import shutil
from pathlib import Path

import numpy as np
import faiss


# ==========================================
# 1. PROJECT PATHS
# ==========================================

ROOT = Path(__file__).resolve().parents[2]

EMBEDDINGS_DIR = ROOT / "embeddings"
DATA_DIR = ROOT / "data" / "processed"

metadata_file = EMBEDDINGS_DIR / "cve_metadata.jsonl"
embedding_file = EMBEDDINGS_DIR / "cve_embeddings.npy"
index_file = EMBEDDINGS_DIR / "cve_faiss.index"

new_data_file = DATA_DIR / "unique-new-cves.jsonl"
new_embedding_file = EMBEDDINGS_DIR / "new_cve_embeddings.npy"

temp_metadata = EMBEDDINGS_DIR / "cve_metadata.tmp.jsonl"
temp_embeddings = EMBEDDINGS_DIR / "cve_embeddings.tmp.npy"
temp_index = EMBEDDINGS_DIR / "cve_faiss.tmp.index"


# ==========================================
# 2. CHECK REQUIRED FILES
# ==========================================

required_files = [
    metadata_file,
    embedding_file,
    index_file,
    new_data_file,
    new_embedding_file
]

for path in required_files:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")

print("All required files found!")


# ==========================================
# 3. LOAD NEW CVE RECORDS
# ==========================================

print("\nLoading new CVE records...")

new_records = []

with open(new_data_file, "r", encoding="utf-8") as file:
    for line in file:
        if line.strip():
            new_records.append(json.loads(line))

print("New records:", len(new_records))

if not new_records:
    print("No new CVEs available.")
    raise SystemExit(0)


# ==========================================
# 4. LOAD NEW EMBEDDINGS
# ==========================================

print("\nLoading new embeddings...")

new_embeddings = np.load(new_embedding_file)

print("New embedding shape:", new_embeddings.shape)

if new_embeddings.ndim != 2:
    raise ValueError("New embeddings must be 2D!")

if len(new_records) != len(new_embeddings):
    raise ValueError("Record and embedding counts do not match!")

if not np.isfinite(new_embeddings).all():
    raise ValueError("New embeddings contain invalid values!")

new_embeddings = np.ascontiguousarray(
    new_embeddings,
    dtype=np.float32
)

new_norms = np.linalg.norm(new_embeddings, axis=1)

if not np.allclose(new_norms, 1.0, atol=1e-5):
    raise ValueError("New embeddings are not normalized!")

print("New embedding validation passed!")


# ==========================================
# 5. LOAD EXISTING EMBEDDINGS
# ==========================================

print("\nLoading existing embeddings...")

old_embeddings = np.load(
    embedding_file,
    mmap_mode="r"
)

old_count = len(old_embeddings)

print("Old embedding shape:", old_embeddings.shape)

if old_embeddings.ndim != 2:
    raise ValueError("Old embeddings must be 2D!")

if not np.isfinite(old_embeddings).all():
    raise ValueError("Old embeddings contain invalid values!")

if old_embeddings.shape[1] != new_embeddings.shape[1]:
    raise ValueError("Embedding dimensions do not match!")


# ==========================================
# 6. VERIFY OLD VECTOR NORMALIZATION
# ==========================================

print("\nChecking existing vector normalization...")

for start in range(0, old_count, 5000):
    end = min(start + 5000, old_count)

    batch = old_embeddings[start:end]
    norms = np.linalg.norm(batch, axis=1)

    if not np.allclose(norms, 1.0, atol=1e-5):
        raise ValueError(
            f"Old embeddings are not normalized near row {start}!"
        )

print("Existing vectors are normalized!")


# ==========================================
# 7. LOAD FAISS INDEX
# ==========================================

print("\nLoading FAISS index...")

index = faiss.read_index(str(index_file))

print("Existing FAISS vectors:", index.ntotal)

if index.ntotal != old_count:
    raise ValueError("FAISS and embedding counts do not match!")

if index.d != old_embeddings.shape[1]:
    raise ValueError("FAISS dimension mismatch!")

if index.metric_type != faiss.METRIC_INNER_PRODUCT:
    raise ValueError("Expected an inner-product FAISS index!")


# ==========================================
# 8. READ EXISTING CVE IDS
# ==========================================

print("\nReading existing metadata...")

existing_ids = set()
metadata_count = 0

with open(metadata_file, "r", encoding="utf-8") as file:
    for line in file:
        if not line.strip():
            continue

        record = json.loads(line)

        cve_id = record.get("cve_id") or record.get("id")

        if not cve_id:
            raise ValueError("Existing metadata has a missing CVE ID!")

        if cve_id in existing_ids:
            raise ValueError(f"Duplicate existing CVE ID: {cve_id}")

        existing_ids.add(cve_id)
        metadata_count += 1

if metadata_count != old_count:
    raise ValueError("Metadata and embedding counts do not match!")

print("Existing CVEs:", metadata_count)


# ==========================================
# 9. REMOVE DUPLICATES
# ==========================================

print("\nChecking new CVE IDs...")

unique_records = []
unique_vectors = []

seen_ids = set(existing_ids)

for record, vector in zip(new_records, new_embeddings):

    cve_id = record.get("cve_id")

    if not cve_id:
        raise ValueError("New record has a missing CVE ID!")

    if cve_id in seen_ids:
        continue

    seen_ids.add(cve_id)

    unique_records.append(record)
    unique_vectors.append(vector)

if not unique_records:
    print("No new CVEs to integrate.")
    raise SystemExit(0)

unique_vectors = np.ascontiguousarray(
    np.asarray(unique_vectors, dtype=np.float32)
)

new_count = len(unique_records)
expected_count = old_count + new_count

print("New unique CVEs:", new_count)
print("Expected total CVEs:", expected_count)


# ==========================================
# 10. REMOVE OLD TEMPORARY FILES
# ==========================================

for path in [temp_metadata, temp_embeddings, temp_index]:
    if path.exists():
        path.unlink()


# ==========================================
# 11. CREATE UPDATED EMBEDDINGS
# ==========================================

print("\nCreating updated embeddings...")

updated = np.lib.format.open_memmap(
    str(temp_embeddings),
    mode="w+",
    dtype=np.float32,
    shape=(expected_count, old_embeddings.shape[1])
)

batch_size = 5000

for start in range(0, old_count, batch_size):
    end = min(start + batch_size, old_count)
    updated[start:end] = old_embeddings[start:end]

updated[old_count:] = unique_vectors

updated.flush()
del updated

print("Updated embeddings saved temporarily!")


# ==========================================
# 12. CREATE UPDATED METADATA
# ==========================================

print("\nCreating updated metadata...")

shutil.copyfile(metadata_file, temp_metadata)

with open(temp_metadata, "ab") as file:

    # Ensure the old file ends with a newline.
    if temp_metadata.stat().st_size > 0:
        with open(temp_metadata, "rb") as old_file:
            old_file.seek(-1, os.SEEK_END)
            last_byte = old_file.read(1)

        if last_byte != b"\n":
            file.write(b"\n")

    for record in unique_records:
        file.write(
            (json.dumps(record) + "\n").encode("utf-8")
        )

print("Updated metadata saved temporarily!")


# ==========================================
# 13. UPDATE FAISS INDEX
# ==========================================

print("\nUpdating FAISS index...")

index.add(unique_vectors)

faiss.write_index(index, str(temp_index))

print("Updated FAISS index saved temporarily!")


# ==========================================
# 14. VERIFY ALL TEMPORARY FILES
# ==========================================

print("\nVerifying updated files...")

check_embeddings = np.load(
    temp_embeddings,
    mmap_mode="r"
)

check_index = faiss.read_index(str(temp_index))

if len(check_embeddings) != expected_count:
    raise ValueError("Embedding count verification failed!")

if check_index.ntotal != expected_count:
    raise ValueError("FAISS count verification failed!")

if check_index.d != check_embeddings.shape[1]:
    raise ValueError("Updated FAISS dimension mismatch!")

metadata_count = 0
verified_ids = set()

with open(temp_metadata, "r", encoding="utf-8") as file:
    for line in file:
        if not line.strip():
            continue

        record = json.loads(line)
        cve_id = record.get("cve_id")

        if not cve_id or cve_id in verified_ids:
            raise ValueError("Metadata contains missing or duplicate IDs!")

        verified_ids.add(cve_id)
        metadata_count += 1

if metadata_count != expected_count:
    raise ValueError("Metadata count verification failed!")

print("All verification checks passed!")


# ==========================================
# 15. REPLACE ORIGINAL FILES
# ==========================================

print("\nReplacing original files...")

os.replace(temp_embeddings, embedding_file)
os.replace(temp_metadata, metadata_file)
os.replace(temp_index, index_file)


# ==========================================
# 16. FINAL RESULT
# ==========================================

print("\n========== UPDATE COMPLETED ==========")

print("New CVEs added:", new_count)
print("Previous CVEs:", old_count)
print("Total CVEs:", expected_count)

print("Embeddings updated!")
print("Metadata updated!")
print("FAISS index updated!")
