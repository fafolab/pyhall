"""
setup_audit_db.py — Initialize pyhall_audit.db with hash-chained tables.

Run once: python tools/audit/setup_audit_db.py
DB location: /mnt/fafolab/dev/pyhall/pyhall_audit.db (never in git)
"""
import hashlib
import sqlite3
from datetime import datetime, UTC
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent.parent / "pyhall_audit.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS attestation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id TEXT NOT NULL,
    species_id TEXT NOT NULL,
    registered_hash TEXT,
    current_hash TEXT,
    matched INTEGER NOT NULL,  -- 1=match, 0=mismatch
    checked_at TEXT NOT NULL,  -- ISO8601 UTC
    entry_hash TEXT NOT NULL   -- hash chain
);

CREATE TABLE IF NOT EXISTS qc_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id TEXT NOT NULL,
    run_at TEXT NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    passed INTEGER NOT NULL,  -- 1=pass, 0=fail
    report_path TEXT,
    entry_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS qc_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES qc_runs(id),
    severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'error')),
    file_path TEXT,
    finding_type TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hash_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_hash TEXT NOT NULL UNIQUE,
    previous_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    entry_type TEXT NOT NULL,  -- attestation_log | qc_runs
    entry_id INTEGER NOT NULL
);
"""

def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"pyhall_audit.db initialized at {DB_PATH}")

if __name__ == "__main__":
    main()
