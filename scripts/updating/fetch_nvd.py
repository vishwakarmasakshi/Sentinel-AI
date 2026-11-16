
import os
import json
import time
import requests

from pathlib import Path
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv


# ==========================================
# 1. PROJECT DIRECTORY
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("NVD_API_KEY")

if not API_KEY:
    raise ValueError("NVD API key not found in .env file!")


# ==========================================
# 2. NVD API SETTINGS
# ==========================================

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "apiKey": API_KEY
}

RESULTS_PER_PAGE = 2000

MAX_RETRIES = 5

# Avoid sending requests too quickly.
REQUEST_DELAY = 0.7


# ==========================================
# 3. SET DATE RANGE (LAST 7 DAYS)
# ==========================================

end_date = datetime.now(timezone.utc)

start_date = end_date - timedelta(days=7)

start_date_str = start_date.strftime(
    "%Y-%m-%dT%H:%M:%S.000Z"
)

end_date_str = end_date.strftime(
    "%Y-%m-%dT%H:%M:%S.000Z"
)

print("Date range:", start_date_str, "to", end_date_str)


# ==========================================
# 4. FUNCTION TO FETCH CVE DATA
# ==========================================

def fetch_cves(date_type):

    all_vulnerabilities = []

    start_index = 0

    print(f"\nFetching recently {date_type} CVEs...")

    while True:

        # Select the correct NVD date parameters
        if date_type == "published":

            date_params = {
                "pubStartDate": start_date_str,
                "pubEndDate": end_date_str
            }

        elif date_type == "modified":

            date_params = {
                "lastModStartDate": start_date_str,
                "lastModEndDate": end_date_str
            }

        else:
            raise ValueError("Invalid date type!")

        params = {
            **date_params,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index
        }

        # ======================================
        # API REQUEST WITH RETRY HANDLING
        # ======================================

        for attempt in range(MAX_RETRIES):

            try:

                response = requests.get(
                    URL,
                    headers=HEADERS,
                    params=params,
                    timeout=60
                )

                # Handle rate limits and temporary server errors
                if response.status_code in (403, 429, 500, 502, 503, 504):

                    if attempt == MAX_RETRIES - 1:
                        response.raise_for_status()

                    wait_time = 2 ** (attempt + 1)

                    print(
                        f"API error {response.status_code}. "
                        f"Retrying in {wait_time} seconds..."
                    )

                    time.sleep(wait_time)

                    continue

                response.raise_for_status()

                data = response.json()

                break

            except requests.RequestException as error:

                if attempt == MAX_RETRIES - 1:
                    raise RuntimeError(
                        f"NVD API request failed: {error}"
                    ) from error

                wait_time = 2 ** (attempt + 1)

                print(
                    f"Request failed. Retrying in {wait_time} seconds..."
                )

                time.sleep(wait_time)

            except ValueError as error:

                if attempt == MAX_RETRIES - 1:
                    raise RuntimeError(
                        f"Invalid JSON response from NVD: {error}"
                    ) from error

                time.sleep(2 ** (attempt + 1))

        else:
            raise RuntimeError("Maximum API retries exceeded!")

        # ======================================
        # EXTRACT CVE RECORDS
        # ======================================

        vulnerabilities = data.get("vulnerabilities", [])

        all_vulnerabilities.extend(vulnerabilities)

        total_results = data.get("totalResults", 0)

        print(
            f"Downloaded: {len(all_vulnerabilities)} / {total_results}"
        )

        # ======================================
        # PAGINATION
        # ======================================

        start_index += len(vulnerabilities)

        if not vulnerabilities or start_index >= total_results:
            break

        # Respect the API request rate
        time.sleep(REQUEST_DELAY)

    print(
        f"Total recently {date_type} CVEs:",
        len(all_vulnerabilities)
    )

    return all_vulnerabilities


# ==========================================
# 5. FETCH PUBLISHED CVEs
# ==========================================

published_cves = fetch_cves("published")


# ==========================================
# 6. FETCH MODIFIED CVEs
# ==========================================

modified_cves = fetch_cves("modified")


# ==========================================
# 7. REMOVE DUPLICATES
# ==========================================

print("\nRemoving duplicate CVE records...")

unique_cves = {}

# Add recently published CVEs
for item in published_cves:

    cve_id = item.get("cve", {}).get("id")

    if cve_id:
        unique_cves[cve_id] = item


# Add recently modified CVEs
# If an ID already exists, keep its latest modified record.
for item in modified_cves:

    cve_id = item.get("cve", {}).get("id")

    if cve_id:
        unique_cves[cve_id] = item


all_vulnerabilities = list(unique_cves.values())


# ==========================================
# 8. SAVE RAW CVE DATA
# ==========================================

output_dir = PROJECT_ROOT / "data" / "raw"

output_dir.mkdir(parents=True, exist_ok=True)

output_file = output_dir / "cve_data.json"

with open(output_file, "w", encoding="utf-8") as file:

    json.dump(
        {
            "vulnerabilities": all_vulnerabilities
        },
        file,
        indent=4
    )


# ==========================================
# 9. FINAL RESULT
# ==========================================

print("\n========== UPDATE FETCH COMPLETED ==========")

print("Recently published:", len(published_cves))

print("Recently modified:", len(modified_cves))

print("Total unique CVEs:", len(all_vulnerabilities))

print("Saved file:", output_file)
