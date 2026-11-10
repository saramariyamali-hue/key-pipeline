"""
Weekly threat-data pipeline: CISA Known Exploited Vulnerabilities (KEV)

Steps:  1) Extract  - download the latest KEV catalog (public source)
        2) Validate - check the file looks right before trusting it
        3) Transform- clean it and add analysis columns
        4) Load     - write CSV (for Google Sheets / Looker Studio) and SQLite
        5) Log      - record what changed on every run
"""
import io
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

# Primary source first, mirror as fallback (both publish the same KEV catalog)
SOURCES = [
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.csv",
]
DATA_DIR = Path(__file__).parent / "data"
CSV_OUT = DATA_DIR / "kev_clean.csv"
DB_OUT = DATA_DIR / "kev.db"
LOG_OUT = DATA_DIR / "run_log.csv"
REQUIRED = ["cveID", "vendorProject", "product", "dateAdded", "dueDate",
            "knownRansomwareCampaignUse", "cwes"]


def extract() -> pd.DataFrame:
    """Download the CSV, trying each source in order."""
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=60, headers={"User-Agent": "kev-pipeline/1.0"})
            r.raise_for_status()
            df = pd.read_csv(io.StringIO(r.text))
            print(f"Downloaded {len(df)} rows from {url}")
            return df
        except Exception as e:  # try the next source
            print(f"Source failed ({url}): {e}")
    sys.exit("ERROR: all sources failed")


def validate(df: pd.DataFrame, previous_rows: int) -> None:
    """Stop the run (and keep yesterday's good data) if the download looks wrong."""
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        sys.exit(f"ERROR: missing columns {missing}")
    if df["cveID"].duplicated().any():
        sys.exit("ERROR: duplicate CVE IDs found")
    if previous_rows and len(df) < previous_rows * 0.95:
        sys.exit(f"ERROR: row count dropped from {previous_rows} to {len(df)}")


def transform(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["dateAdded"] = pd.to_datetime(df["dateAdded"])
    df["dueDate"] = pd.to_datetime(df["dueDate"], errors="coerce")
    df["year"] = df["dateAdded"].dt.year
    df["month"] = df["dateAdded"].dt.strftime("%Y-%m")
    df["ransomware_flag"] = df["knownRansomwareCampaignUse"].where(
        df["knownRansomwareCampaignUse"].isin(["Known", "Unknown"]), "Unknown")
    df["primary_cwe"] = (df["cwes"].fillna("").str.split(",").str[0].str.strip()
                         .replace("", "Not Listed"))
    df["days_to_due"] = (df["dueDate"] - df["dateAdded"]).dt.days
    df = df.drop(columns=[c for c in ["notes", "forensicTriage"] if c in df.columns])
    df["dateAdded"] = df["dateAdded"].dt.strftime("%Y-%m-%d")
    df["dueDate"] = df["dueDate"].dt.strftime("%Y-%m-%d")
    return df.sort_values("dateAdded", ascending=False).reset_index(drop=True)


def load(df: pd.DataFrame) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    df.to_csv(CSV_OUT, index=False)
    with sqlite3.connect(DB_OUT) as con:
        df.to_sql("kev", con, if_exists="replace", index=False)


def main() -> None:
    old_ids, previous_rows = set(), 0
    if CSV_OUT.exists():
        old = pd.read_csv(CSV_OUT)
        old_ids, previous_rows = set(old["cveID"]), len(old)

    raw = extract()
    validate(raw, previous_rows)
    clean = transform(raw)
    new = clean[~clean["cveID"].isin(old_ids)] if old_ids else clean.iloc[0:0]
    load(clean)

    # Run log: one line per run
    entry = pd.DataFrame([{
        "run_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "total_rows": len(clean),
        "new_rows": len(new),
        "latest_date_added": clean["dateAdded"].max(),
    }])
    entry.to_csv(LOG_OUT, mode="a", header=not LOG_OUT.exists(), index=False)

    print(f"Done. Total: {len(clean)} | New this run: {len(new)}")
    for _, r in new.head(10).iterrows():
        print(f"  NEW  {r['cveID']}  {r['vendorProject']} {r['product']}")


if __name__ == "__main__":
    main()
