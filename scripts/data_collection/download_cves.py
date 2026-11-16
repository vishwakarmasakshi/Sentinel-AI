
import requests
import gzip
import json
import ijson
from pathlib import Path
import os

# Project directories
PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
RAW_DIR = PROJECT_ROOT / "data" / "raw"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(parents=True, exist_ok=True)

# Years to download
YEARS = [2022, 2023, 2024, 2025, 2026]

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/"

def extract_products(nodes):
    """Extract CPE products, including nested configuration nodes."""

    products = []

    for node in nodes:
        for match in node.get("cpeMatch", []):
            criteria = match.get("criteria")

            if criteria:
                products.append(criteria)

        products.extend(
            extract_products(node.get("children", []))
        )

    return products


def process_year(year):

    print(f"\n========== {year} ==========")

    output_file = PROCESSED_DIR / f"cves-{year}.json"
    clean_file = PROCESSED_DIR / f"clean-cves-{year}.json"
    gzip_file = RAW_DIR / f"nvdcve-2.0-{year}.json.gz"

    # Skip already processed years
    if output_file.exists() and clean_file.exists():
        print(f"{year} already processed. Skipping.")
        return

    url = f"{BASE_URL}nvdcve-2.0-{year}.json.gz"

    try:
        print("Downloading...")

        with requests.get(url, stream=True, timeout=180) as response:
            response.raise_for_status()

            with open(gzip_file, "wb") as file:
                for chunk in response.iter_content(
                    chunk_size=1024 * 1024
                ):
                    if chunk:
                        file.write(chunk)

        print("Download completed!")

        total = 0
        rejected = 0

        temp_output = Path(str(output_file) + ".tmp")
        temp_clean = Path(str(clean_file) + ".tmp")

        try:
            with gzip.open(gzip_file, "rb") as compressed:

                with open(temp_output, "w", encoding="utf-8") as original, \
                     open(temp_clean, "w", encoding="utf-8") as clean:

                    original.write("[")
                    clean.write("[")

                    first_original = True
                    first_clean = True

                    for item in ijson.items(
                        compressed, "vulnerabilities.item"
                    ):

                        cve = item["cve"]

                        description = next(
                            (
                                d["value"]
                                for d in cve.get("descriptions", [])
                                if d.get("lang") == "en"
                            ),
                            ""
                        )

                        severity = "Unknown"
                        cvss_score = None

                        metrics = cve.get("metrics", {})

                        for metric_type in [
                            "cvssMetricV40",
                            "cvssMetricV31",
                            "cvssMetricV30",
                            "cvssMetricV2"
                        ]:

                            if metrics.get(metric_type):

                                metric = metrics[metric_type][0]
                                cvss_data = metric.get("cvssData", {})

                                severity = (
                                    cvss_data.get("baseSeverity")
                                    or metric.get("baseSeverity")
                                    or "Unknown"
                                )

                                score = cvss_data.get("baseScore")

                                if score is not None:
                                    cvss_score = float(score)

                                break

                        affected_products = extract_products(
                            cve.get("configurations", [])
                        )

                        references = [
                            ref.get("url", "")
                            for ref in cve.get("references", [])
                        ]

                        processed_cve = {
                            "cve_id": cve.get("id"),
                            "description": description,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "published_date": cve.get("published"),
                            "last_modified_date": cve.get("lastModified"),
                            "affected_products": affected_products,
                            "references": references
                        }

                        if not first_original:
                            original.write(",")

                        json.dump(processed_cve, original)
                        first_original = False

                        total += 1

                        is_rejected = description.startswith(
                            "Rejected reason:"
                        )

                        if is_rejected:
                            rejected += 1
                        else:
                            if not first_clean:
                                clean.write(",")

                            json.dump(processed_cve, clean)
                            first_clean = False

                    original.write("]")
                    clean.write("]")

            os.replace(temp_output, output_file)
            os.replace(temp_clean, clean_file)

        finally:
            temp_output.unlink(missing_ok=True)
            temp_clean.unlink(missing_ok=True)

        gzip_file.unlink(missing_ok=True)

        print("Total CVEs:", total)
        print("Rejected CVEs:", rejected)
        print("Clean CVEs:", total - rejected)
        print("Saved:", output_file)
        print("Saved:", clean_file)

    except (requests.RequestException, OSError, ValueError, KeyError) as error:
        print(f"Processing failed for {year}: {error}")


def main():

    for year in YEARS:
        process_year(year)

    print("\nHistorical CVE processing completed!")


if __name__ == "__main__":
    main()
