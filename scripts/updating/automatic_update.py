
import subprocess
import sys
from pathlib import Path

# ==========================================
# 1. PROJECT DIRECTORY
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PYTHON = sys.executable

# ==========================================
# 2. UPDATE PIPELINE SCRIPTS
# ==========================================

scripts = [
    PROJECT_ROOT / "scripts" / "updating" / "fetch_nvd.py",

    PROJECT_ROOT / "scripts" / "updating" / "check_duplicates.py",

    PROJECT_ROOT / "scripts" / "embedding" / "generate_new_embeddings.py",

    PROJECT_ROOT / "scripts" / "indexing" / "integrate_new_cves.py"
]

# ==========================================
# 3. RUN AUTOMATIC UPDATE
# ==========================================

print("\n========== SENTINEL AI AUTOMATIC UPDATE ==========\n")

for script in scripts:

    print(f"\nRunning: {script.name}")

    if not script.exists():
        print(f"ERROR: Script not found: {script}")
        sys.exit(1)

    try:

        subprocess.run(
            [PYTHON, str(script)],
            cwd=PROJECT_ROOT,
            check=True
        )

        print(f"\n{script.name} completed successfully!")

    except subprocess.CalledProcessError as error:

        print(f"\nERROR: {script.name} failed.")
        print("Update stopped. Fix the error before continuing.")

        sys.exit(error.returncode)

# ==========================================
# 4. FINAL RESULT
# ==========================================

print("\n========== UPDATE COMPLETED ==========")
print("Sentinel AI database is updated!")
