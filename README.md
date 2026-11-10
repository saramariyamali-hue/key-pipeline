# Automated Threat Dashboard Pipeline

Refreshes a cybersecurity dashboard every week from a public source
(CISA Known Exploited Vulnerabilities catalog) with no manual work.

## How it works

CISA KEV catalog (public)
  -> GitHub Actions runs `pipeline.py` every Monday
  -> data/kev_clean.csv + data/kev.db updated, committed to this repo
  -> Google Sheet reads the CSV with IMPORTDATA
  -> Looker Studio dashboard reads the Sheet

## What pipeline.py does

1. Extract: downloads the latest catalog (CISA first, mirror as fallback)
2. Validate: checks columns, duplicates, and a sudden drop in rows; a bad download stops the run and keeps the last good data
3. Transform: parses dates, adds year, month, ransomware_flag, primary_cwe, days_to_due
4. Load: writes a CSV (for the Sheet) and a SQLite database (for SQL analysis)
5. Log: appends a line to data/run_log.csv with total rows and new rows

## Run it yourself

    pip install -r requirements.txt
    python pipeline.py

## Schedule

.github/workflows/weekly.yml runs it every Monday 06:00 UTC.
It can also be started by hand from the repo's Actions tab.

## Connect the dashboard

In a Google Sheet, cell A1:

    =IMPORTDATA("https://raw.githubusercontent.com/YOUR-USERNAME/YOUR-REPO/main/data/kev_clean.csv")

Then in Looker Studio: Add data -> Google Sheets -> pick that sheet.
