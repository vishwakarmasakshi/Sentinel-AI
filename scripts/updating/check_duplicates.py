
import json
import re
from pathlib import Path


# --------------------------------------------------
# 1. Project paths
# --------------------------------------------------

ROOT = Path(__file__).resolve().parents[2]

EXISTING_METADATA = ROOT / "embeddings" / "cve_metadata.jsonl"
RAW_FILE = ROOT / "data" / "raw" / "cve_data.json"
OUTPUT_FILE = ROOT / "data" / "processed" / "unique-new-cves.jsonl"


# --------------------------------------------------
# 2. Load existing CVE IDs
# --------------------------------------------------

def load_existing_ids():
    existing_ids = set()

    if not EXISTING_METADATA.exists():
        print("Existing metadata file not found!")
        return existing_ids

    with open(EXISTING_METADATA, "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                record = json.loads(line)
                cve_id = record.get("cve_id") or record.get("id")

                if cve_id:
                    existing_ids.add(cve_id)

            except json.JSONDecodeError:
                continue

    return existing_ids


# --------------------------------------------------
# 3. Extract description
# --------------------------------------------------

def get_description(cve):
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "").strip()

    return ""


# --------------------------------------------------
# 4. Extract CVSS score and severity
# --------------------------------------------------

def get_cvss(cve):
    metrics = cve.get("metrics", {})

    metric_types = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]

    for metric_type in metric_types:
        metric_list = metrics.get(metric_type, [])

        if not metric_list:
            continue

        for metric in metric_list:
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")

            if score is not None:
                severity = (
                    cvss_data.get("baseSeverity")
                    or metric.get("baseSeverity")
                    or "UNKNOWN"
                )

                return float(score), severity.upper()

    return None, "UNKNOWN"


# --------------------------------------------------
# 5. Extract CWE
# --------------------------------------------------

def get_cwe(cve):
    cwe_ids = set()

    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value", "")

            if value.startswith("CWE-"):
                cwe_ids.add(value)

    return sorted(cwe_ids)


# --------------------------------------------------
# 6. Extract products from CPE configurations
# --------------------------------------------------

def extract_products_from_cpe(configurations):
    products = set()

    def search_nodes(nodes):
        for node in nodes:
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")

                parts = criteria.split(":")

                # CPE 2.3:
                # cpe:2.3:a:vendor:product:version:...

                if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                    vendor = parts[3]
                    product = parts[4]

                    if vendor != "*" and product != "*":
                        vendor = vendor.replace("_", " ")
                        product = product.replace("_", " ")

                        products.add(f"{vendor} {product}")

            search_nodes(node.get("children", []))

    for configuration in configurations:
        search_nodes(configuration.get("nodes", []))

    return sorted(products)


# --------------------------------------------------
# 7. Description-based fallback
# --------------------------------------------------

def extract_product_candidates(description):
    """
    Best-effort extraction of named products from descriptions.
    These candidates are not confirmed CPE matches.
    """

    candidates = set()

    patterns = [
        r"\b(WordPress(?:\s+[\w.-]+){0,5})",
        r"\b(Drupal(?:\s+[\w.-]+){0,5})",
        r"\b(Joomla(?:\s+[\w.-]+){0,5})",
        r"\b(Chrome|Firefox|Safari|Edge)\b",
        r"\b(Apache(?:\s+[\w.-]+){0,4})",
        r"\b(Microsoft\s+[\w.-]+(?:\s+[\w.-]+){0,3})",
        r"\b(Windows(?:\s+[\w.-]+){0,3})",
        r"\b(Linux(?:\s+[\w.-]+){0,3})"
    ]

    for pattern in patterns:
        matches = re.findall(pattern, description, flags=re.IGNORECASE)

        for match in matches:
            if isinstance(match, tuple):
                match = next((part for part in match if part), "")

            product = " ".join(match.split()).strip(" .,;:")

            if product:
                candidates.add(product)

    return sorted(candidates)


# --------------------------------------------------
# 8. Process CVE record
# --------------------------------------------------

def process_cve(vulnerability):
    cve = vulnerability.get("cve", {})

    cve_id = cve.get("id", "")
    description = get_description(cve)

    if not cve_id or not description:
        return None

    cvss_score, severity = get_cvss(cve)

    # Prefer structured CPE matches
    products = extract_products_from_cpe(
        cve.get("configurations", [])
    )

    product_source = "CPE" if products else "Not available"

    # Fallback: description-based candidates
    if not products:
        products = extract_product_candidates(description)

        if products:
            product_source = "Description (inferred)"

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "cwe_id": get_cwe(cve),
        "products": products,
        "product_source": product_source
    }


# --------------------------------------------------
# 9. Main function
# --------------------------------------------------

def main():
    print("Loading existing CVE IDs...")

    existing_ids = load_existing_ids()
    print("Existing CVEs:", len(existing_ids))

    if not RAW_FILE.exists():
        print("Raw CVE file not found:", RAW_FILE)
        return

    print("\nLoading recently fetched CVEs...")

    with open(RAW_FILE, "r", encoding="utf-8") as file:
        raw_data = json.load(file)

    vulnerabilities = raw_data.get("vulnerabilities", [])

    print("Fetched CVE records:", len(vulnerabilities))

    new_records = []
    seen_ids = set()

    duplicate_count = 0
    invalid_count = 0

    for vulnerability in vulnerabilities:
        record = process_cve(vulnerability)

        if record is None:
            invalid_count += 1
            continue

        cve_id = record["cve_id"]

        if cve_id in existing_ids or cve_id in seen_ids:
            duplicate_count += 1
            continue

        seen_ids.add(cve_id)
        new_records.append(record)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        for record in new_records:
            file.write(json.dumps(record) + "\n")

    cpe_count = sum(
        record["product_source"] == "CPE"
        for record in new_records
    )

    inferred_count = sum(
        record["product_source"] == "Description (inferred)"
        for record in new_records
    )

    print("\n----- Processing Summary -----")
    print("Fetched records:", len(vulnerabilities))
    print("New valid CVEs:", len(new_records))
    print("Duplicates skipped:", duplicate_count)
    print("Invalid records skipped:", invalid_count)
    print("Products from CPE:", cpe_count)
    print("Products inferred from descriptions:", inferred_count)
    print("Output saved:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
