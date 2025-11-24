#!/usr/bin/env python3
"""
Threat‑Intel Processor – fetches the latest AbuseIPDB blacklist,
stores it in a local SQLite DB, and checks a log file for malicious IPs.
"""

import requests
import sqlite3
import sys

# ----------------------------------------------------------------------
# --- CONFIGURATION -----------------------------------------------
# ----------------------------------------------------------------------
API_KEY = 'YOUR_API_KEY_HERE'  # <-- keep your real key safe; consider env‑vars for production
DB_FILE = "threat_intel.db"


# ----------------------------------------------------------------------
# --- DATABASE SETUP ---------------------------------------------------
# ----------------------------------------------------------------------
def setup_database() -> None:
    """Create the SQLite DB and the iocs table if they do not exist."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS iocs (
            ip_address      TEXT PRIMARY KEY,
            abuse_confidence INTEGER,
            country_code    TEXT
        )
        """
    )
    conn.commit()
    conn.close()


# ----------------------------------------------------------------------
# --- FETCH THREAT FEED ------------------------------------------------
# ----------------------------------------------------------------------
def fetch_threat_feed(limit: int = 1000) -> list[dict] | None:
    """Download the latest blacklist from AbuseIPDB.

    Returns a list of record dictionaries or ``None`` on failure.
    """
    print("Fetching latest threat intelligence…")
    headers = {"Accept": "application/json", "Key": API_KEY}
    params = {"limit": limit}

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers=headers,
            params=params,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("data", [])
    except requests.exceptions.RequestException as exc:
        print(f"Error fetching data: {exc}")
        return None


# ----------------------------------------------------------------------
# --- STORE INDICATORS -------------------------------------------------
# ----------------------------------------------------------------------
def store_iocs(records: list[dict]) -> int:
    """Insert the fetched IoCs into the DB, ignoring duplicates.

    Returns the number of newly inserted rows.
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    added = 0

    for rec in records:
        cur.execute(
            """
            INSERT OR IGNORE INTO iocs (ip_address, abuse_confidence, country_code)
            VALUES (?, ?, ?)
            """,
            (rec["ipAddress"], rec["abuseConfidenceScore"], rec["countryCode"]),
        )
        if cur.rowcount:          # rowcount > 0 means a new row was added
            added += 1

    conn.commit()
    conn.close()
    return added


# ----------------------------------------------------------------------
# --- LOG CORRELATION --------------------------------------------------
# ----------------------------------------------------------------------
def check_logs(log_file: str) -> None:
    """Read a file containing one IP per line and alert on matches."""
    print(f"\nScanning log file: {log_file}…")
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    try:
        with open(log_file, "r") as fh:
            for line in fh:
                ip = line.strip()
                if not ip:
                    continue
                cur.execute(
                    "SELECT abuse_confidence FROM iocs WHERE ip_address = ?", (ip,)
                )
                row = cur.fetchone()
                if row:
                    print(
                        f" [!] ALERT: Malicious IP found – {ip} (Confidence: {row[0]}%)"
                    )
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    finally:
        conn.close()


# ----------------------------------------------------------------------
# --- MAIN -------------------------------------------------------------
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # 1️⃣ Initialise DB
    setup_database()

    # 2️⃣ Pull the latest blacklist
    feed = fetch_threat_feed()
    if feed is None:
        sys.exit(1)                     # abort if we couldn't download data

    # 3️⃣ Store new indicators
    new_count = store_iocs(feed)
    print(f"Database updated. Added {new_count} new IP(s).")

    # 4️⃣ Optionally check a log file (pass path as first CLI argument)
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
    else:
        # Create a tiny demo log if the user didn't supply one
        log_path = "access.log"
        with open(log_path, "w") as demo:
            demo.writelines(
                ["192.168.1.10\n", "185.191.171.12\n", "8.8.8.8\n"]
            )
        print(f"[i] Demo log created at '{log_path}'")

    check_logs(log_path)
