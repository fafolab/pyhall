"""audit_writer.py — Write hash-chained entries to pyhall_audit.db."""
import hashlib
import json
import sqlite3
from datetime import datetime, UTC
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent.parent / "pyhall_audit.db"


def _get_previous_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT entry_hash FROM hash_chain ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else "0" * 64


def _chain_hash(content: dict, previous_hash: str, timestamp: str) -> str:
    data = json.dumps(content, sort_keys=True) + previous_hash + timestamp
    return hashlib.sha256(data.encode()).hexdigest()


def write_attestation(correlation_id: str, species_id: str,
                      registered_hash: str | None, current_hash: str | None,
                      matched: bool) -> str:
    """Write an attestation check result to the audit log. Returns entry_hash."""
    conn = sqlite3.connect(DB_PATH)
    ts = datetime.now(UTC).isoformat()
    previous = _get_previous_hash(conn)
    content = {
        "type": "attestation_log",
        "correlation_id": correlation_id,
        "species_id": species_id,
        "registered_hash": registered_hash,
        "current_hash": current_hash,
        "matched": matched,
    }
    entry_hash = _chain_hash(content, previous, ts)
    cursor = conn.execute(
        "INSERT INTO attestation_log (correlation_id, species_id, registered_hash, current_hash, matched, checked_at, entry_hash) VALUES (?,?,?,?,?,?,?)",
        (correlation_id, species_id, registered_hash, current_hash, int(matched), ts, entry_hash)
    )
    entry_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO hash_chain (entry_hash, previous_hash, timestamp, entry_type, entry_id) VALUES (?,?,?,?,?)",
        (entry_hash, previous, ts, "attestation_log", entry_id)
    )
    conn.commit()
    conn.close()
    return entry_hash


def write_qc_run(worker_id: str, findings_count: int, passed: bool,
                 report_path: str | None = None) -> tuple[int, str]:
    """Write a QC run result. Returns (run_id, entry_hash)."""
    conn = sqlite3.connect(DB_PATH)
    ts = datetime.now(UTC).isoformat()
    previous = _get_previous_hash(conn)
    content = {
        "type": "qc_runs",
        "worker_id": worker_id,
        "findings_count": findings_count,
        "passed": passed,
    }
    entry_hash = _chain_hash(content, previous, ts)
    cursor = conn.execute(
        "INSERT INTO qc_runs (worker_id, run_at, findings_count, passed, report_path, entry_hash) VALUES (?,?,?,?,?,?)",
        (worker_id, ts, findings_count, int(passed), report_path, entry_hash)
    )
    run_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO hash_chain (entry_hash, previous_hash, timestamp, entry_type, entry_id) VALUES (?,?,?,?,?)",
        (entry_hash, previous, ts, "qc_runs", run_id)
    )
    conn.commit()
    conn.close()
    return run_id, entry_hash


def write_qc_findings(run_id: int, findings: list[dict]) -> None:
    """Write individual findings for a QC run."""
    if not findings:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.executemany(
        "INSERT INTO qc_findings (run_id, severity, file_path, finding_type, detail) VALUES (?,?,?,?,?)",
        [(run_id, f["severity"], f.get("file_path"), f["finding_type"], f["detail"]) for f in findings]
    )
    conn.commit()
    conn.close()
