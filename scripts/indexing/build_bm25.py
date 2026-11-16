
import json
import pickle
import re
from pathlib import Path
from rank_bm25 import BM25Okapi

ROOT = Path(__file__).resolve().parents[2]

METADATA_FILE = ROOT / "embeddings" / "cve_metadata.jsonl"
OUTPUT_FILE = ROOT / "embeddings" / "bm25_index.pkl"


def tokenize(text):
    return re.findall(r"[a-z0-9]+", text.lower())


print("Loading CVE metadata...")

metadata = []

with open(METADATA_FILE, "r", encoding="utf-8") as file:
    for line in file:
        metadata.append(json.loads(line))

print("Total CVEs:", len(metadata))


print("Preparing searchable text...")

corpus = []

for cve in metadata:

    description = cve.get("description") or ""

    products = cve.get("products") or []

    if isinstance(products, str):
        products = [products]

    searchable_text = description + " " + " ".join(
        str(product) for product in products
    )

    corpus.append(tokenize(searchable_text))


print("Building BM25 index...")

bm25 = BM25Okapi(corpus)

with open(OUTPUT_FILE, "wb") as file:
    pickle.dump(bm25, file)

print("BM25 index saved:", OUTPUT_FILE)
print("BM25 indexing completed!")
