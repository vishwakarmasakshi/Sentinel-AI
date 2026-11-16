
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

METADATA_FILE = ROOT / "embeddings" / "cve_metadata.jsonl"
BACKUP_FILE = ROOT / "backup" / "cve_metadata_before_products.jsonl"
TEMP_FILE = ROOT / "embeddings" / "cve_metadata_temp.jsonl"


def clean_cpe_value(value):
    """Remove CPE escape characters and improve readability."""
    value = re.sub(r"\\(.)", r"\1", value)
    return value.replace("_", " ").strip()


def extract_products(affected_products):
    products = set()

    for cpe in affected_products:
        if not isinstance(cpe, str):
            continue

        parts = cpe.split(":")

        # CPE 2.3 format:
        # cpe:2.3:a:vendor:product:version:...

        if len(parts) < 5:
            continue

        if parts[0] != "cpe" or parts[1] != "2.3":
            continue

        vendor = parts[3]
        product = parts[4]

        if vendor in ("*", "-") or product in ("*", "-"):
            continue

        vendor = clean_cpe_value(vendor)
        product = clean_cpe_value(product)

        if vendor and product:
            products.add(f"{vendor} {product}")

    return sorted(products)


def main():
    if not METADATA_FILE.exists():
        print("Metadata file not found!")
        return

    if BACKUP_FILE.exists():
        print("Backup already exists. Stopping to protect it:")
        print(BACKUP_FILE)
        return

    print("Creating metadata backup...")
    BACKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(METADATA_FILE, BACKUP_FILE)

    total = 0
    products_found = 0

    print("Enriching metadata...")

    try:
        with open(METADATA_FILE, "r", encoding="utf-8") as source:
            with open(TEMP_FILE, "w", encoding="utf-8") as target:

                for line in source:
                    if not line.strip():
                        continue

                    record = json.loads(line)

                    affected_products = record.get(
                        "affected_products", []
                    )

                    products = extract_products(affected_products)

                    record["products"] = products

                    if products:
                        products_found += 1

                    target.write(
                        json.dumps(record, ensure_ascii=False) + "\n"
                    )

                    total += 1

        # Replace original only after successful processing
        TEMP_FILE.replace(METADATA_FILE)

    except Exception:
        if TEMP_FILE.exists():
            TEMP_FILE.unlink()

        print("Error occurred. Original metadata was not replaced.")
        print("Your backup is available at:", BACKUP_FILE)
        raise

    print("\n----- Enrichment Summary -----")
    print("Total CVE records:", total)
    print("Records with extracted products:", products_found)
    print("Records without products:", total - products_found)
    print("Backup saved:", BACKUP_FILE)
    print("Updated metadata:", METADATA_FILE)


if __name__ == "__main__":
    main()
