
import json
import ijson
import numpy as np

from pathlib import Path
from sentence_transformers import SentenceTransformer


# 1. Project directories
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed"
EMBEDDING_DIR = PROJECT_ROOT / "embeddings"

EMBEDDING_DIR.mkdir(parents=True, exist_ok=True)


# 2. Years to process
YEARS = [2022, 2023, 2024, 2025, 2026]

BATCH_SIZE = 100
EMBEDDING_DIMENSION = 384


# 3. Count all CVEs before generating embeddings
def count_cves():

    total = 0

    for year in YEARS:

        filename = DATA_DIR / f"clean-cves-{year}.json"

        if not filename.exists():
            raise FileNotFoundError(
                f"Dataset not found: {filename}"
            )

        with open(filename, "rb") as file:

            for _ in ijson.items(file, "item"):
                total += 1

        print(f"{year}: Dataset counted")

    return total


# 4. Load MiniLM model
print("Loading MiniLM model...")

model = SentenceTransformer("all-MiniLM-L6-v2")


# 5. Calculate actual dataset size
total_cves = count_cves()

print("Total clean CVEs:", total_cves)


# 6. Create output files
embedding_file = EMBEDDING_DIR / "cve_embeddings.npy"
metadata_file = EMBEDDING_DIR / "cve_metadata.jsonl"

temp_embedding_file = EMBEDDING_DIR / "cve_embeddings.tmp.npy"
temp_metadata_file = EMBEDDING_DIR / "cve_metadata.tmp.jsonl"

embeddings = np.lib.format.open_memmap(
    temp_embedding_file,
    mode="w+",
    dtype="float32",
    shape=(total_cves, EMBEDDING_DIMENSION)
)


# 7. Process CVE descriptions in batches
processed = 0
texts = []
metadata_batch = []


with open(temp_metadata_file, "w", encoding="utf-8") as metadata_out:

    for year in YEARS:

        filename = DATA_DIR / f"clean-cves-{year}.json"

        print(f"\nProcessing year: {year}")

        with open(filename, "rb") as file:

            for cve in ijson.items(file, "item"):

                description = cve.get("description") or ""

                texts.append(description)

                metadata_batch.append({
                    "cve_id": cve.get("cve_id"),
                    "description": description,
                    "severity": cve.get("severity"),
                    "cvss_score": cve.get("cvss_score")
                })

                if len(texts) == BATCH_SIZE:

                    vectors = model.encode(
                        texts,
                        convert_to_numpy=True,
                        normalize_embeddings=True,
                        show_progress_bar=False
                    )

                    start = processed
                    end = start + len(vectors)

                    embeddings[start:end] = vectors

                    for item in metadata_batch:
                        metadata_out.write(
                            json.dumps(item) + "\n"
                        )

                    processed = end

                    print(
                        f"Processed: {processed}/{total_cves}"
                    )

                    texts = []
                    metadata_batch = []


    # Process remaining CVEs
    if texts:

        vectors = model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True
        )

        start = processed
        end = start + len(vectors)

        embeddings[start:end] = vectors

        for item in metadata_batch:
            metadata_out.write(
                json.dumps(item) + "\n"
            )

        processed = end


# 8. Save embeddings
embeddings.flush()
del embeddings


# 9. Verify and finalize
if processed != total_cves:

    raise ValueError(
        f"Count mismatch: expected {total_cves}, "
        f"processed {processed}"
    )

temp_embeddings = np.load(temp_embedding_file, mmap_mode="r")

assert temp_embeddings.shape == (
    total_cves,
    EMBEDDING_DIMENSION
)

del temp_embeddings

temp_embedding_file.replace(embedding_file)
temp_metadata_file.replace(metadata_file)


print("\n========== COMPLETED ==========")
print("Total embeddings:", processed)
print("Embedding dimension:", EMBEDDING_DIMENSION)
print("Saved:", embedding_file)
print("Saved:", metadata_file)
print("SUCCESS: All CVEs processed!")


