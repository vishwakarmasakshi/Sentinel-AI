
import json
from pathlib import Path

# Project directory
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Dataset folder
DATA_DIR = PROJECT_ROOT / "data" / "processed"

# Years to process
YEARS = [2022, 2023, 2024, 2025, 2026]


def clean_cve_data(year):

    input_file = DATA_DIR / f"cves-{year}.json"
    output_file = DATA_DIR / f"clean-cves-{year}.json"

    # Check whether input file exists
    if not input_file.exists():
        print(f"{year}: Dataset not found. Skipping.")
        return

    # Read original dataset
    with open(input_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Remove rejected CVEs
    clean_data = [
        cve for cve in data
        if not cve.get("description", "").startswith(
            "Rejected reason:"
        )
    ]

    # Save clean dataset
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(clean_data, file, ensure_ascii=False)

    # Display results
    print(f"\nYear: {year}")
    print("Original CVEs:", len(data))
    print("Clean CVEs:", len(clean_data))
    print("Rejected CVEs removed:", len(data) - len(clean_data))


def main():

    for year in YEARS:
        clean_cve_data(year)

    print("\nAll years processed successfully!")


if __name__ == "__main__":
    main()
