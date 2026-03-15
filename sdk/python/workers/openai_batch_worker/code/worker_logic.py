#!/usr/bin/env python3
"""
worker_logic.py — Batch for OpenAI Worker (WCP v0.3.0)

Submits, monitors, and retrieves results from the OpenAI Batch API.
Full WCP-compliant worker package: attested, fail-closed policy gate,
append-only evidence log, deterministic traceability via correlation IDs.

Batch API flow:
    1. Upload a JSONL file of requests via Files API
    2. Create a batch job referencing that file ID
    3. Poll for completion (validating → in_progress → finalizing → completed)
    4. Download the output file for results

Setup:
    Set OPENAI_API_KEY environment variable before running.
    DB is auto-created at first use: ~/.local/share/pyhall/openai_batch_worker.db

All timestamps stored as UTC ISO 8601. Human-facing log output uses Central Time.
"""

from __future__ import annotations

# ============================================================================
# SECTION 1: HEADER + IDENTITY + WCP DECLARATIONS
# ============================================================================

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID         = "org.pyhall.openai-batch.instance-1"
WORKER_SPECIES_ID = "wrk.pyhall.openai-batch"
WORKER_NAME       = "Batch for OpenAI Worker (WCP v0.3.0)"
WORKER_VERSION    = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.openai_batch.submit",
    "cap.pyhall.openai_batch.read",
    "cap.pyhall.openai_batch.manage",
]

ALLOWED_OPS = {
    "create_batch",
    "get_batch_status",
    "list_batches",
    "get_batch_results",
    "cancel_batch",
    "upload_file",
    "get_file_content",
    "validate_requests",
}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

ALLOWED_ENVS = {"dev", "stage", "prod"}


# ============================================================================
# SECTION 2: CORE MODELS
# ============================================================================

@dataclass(frozen=True)
class WCPContext:
    correlation_id: str
    env: str
    capability_id: str
    data_label: str
    tenant_risk: str
    qos_class: str
    requested_at_utc: str


@dataclass(frozen=True)
class WCPDecision:
    allowed: bool
    deny_code: Optional[str]
    deny_message: Optional[str]
    policy_version: str
    matched_rule_id: Optional[str]
    selected_worker_species_id: Optional[str]


@dataclass(frozen=True)
class WorkerResult:
    status: str
    output: Dict[str, Any]
    telemetry_events: List[Dict[str, Any]]
    evidence_receipts: List[Dict[str, Any]]


@dataclass
class BatchRecord:
    """Local record of a submitted batch job."""
    batch_id: str
    input_file_id: str
    output_file_id: Optional[str]
    status: str
    request_count: int
    created_at: str
    completed_at: Optional[str]
    notes: Optional[str]


# ============================================================================
# SECTION 3: UTILS
# ============================================================================

_CT = ZoneInfo("America/Chicago")


def utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string with Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def now_ct() -> str:
    """Return current Central Time as human-readable string."""
    return datetime.now(_CT).strftime("%Y-%m-%d %H:%M:%S CT")


def log(msg: str) -> None:
    """Print a message with Central Time timestamp."""
    print(f"[{now_ct()}] {msg}")


def sha256_hex_bytes(b: bytes) -> str:
    """Return SHA-256 hex digest of bytes."""
    return hashlib.sha256(b).hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


# ============================================================================
# SECTION 4: PACKAGE ATTESTATION + SIGNATURE VERIFICATION
# ============================================================================
# required for PyHall APP.
# not strictly required in-file for API-only usage.
# if this worker file changes, a new attestation is required.


def _run_startup_attestation(package_root: Path, manifest_path: Path) -> Dict[str, Any]:
    """
    Run full package attestation using the pyhall PackageAttestationVerifier.

    In dev (PYHALL_ENV != 'prod') and WCP_ATTEST_HMAC_KEY not set:
      - logs a WARNING but does not block execution.
    In prod, any attestation failure raises SystemExit(2).

    Returns attest_meta dict on success (may be empty dict in dev skip).
    """
    env = os.environ.get("PYHALL_ENV", "dev")
    hmac_key_set = bool(os.environ.get("WCP_ATTEST_HMAC_KEY", "").strip())

    try:
        from pyhall.attestation import PackageAttestationVerifier
    except ImportError as exc:
        msg = f"Cannot import pyhall PackageAttestationVerifier: {exc}"
        if env == "prod":
            log(f"FATAL: {msg}")
            raise SystemExit(2)
        log(f"WARNING: {msg} — skipping attestation in dev")
        return {"dev_skip": True, "reason": msg}

    if not hmac_key_set:
        msg = "WCP_ATTEST_HMAC_KEY not set"
        if env == "prod":
            log(f"FATAL: {msg} — attestation requires signing key in prod")
            raise SystemExit(2)
        log(f"WARNING: {msg} — skipping signature verification in dev")
        return {"dev_skip": True, "reason": msg}

    verifier = PackageAttestationVerifier(
        package_root=package_root,
        manifest_path=manifest_path,
        worker_id=WORKER_ID,
        worker_species_id=WORKER_SPECIES_ID,
    )
    ok, deny_code, attest_meta = verifier.verify()

    if not ok:
        msg = f"Package attestation failed: {deny_code} meta={attest_meta}"
        if env == "prod":
            log(f"FATAL: {msg}")
            raise SystemExit(2)
        log(f"WARNING: {msg} — continuing in dev (non-prod env)")
        return {"dev_skip": True, "deny_code": deny_code, "meta": attest_meta}

    log(f"Attestation OK — {attest_meta.get('trust_statement', '')}")
    return attest_meta


# Derive paths from this file's location:
#   code/worker_logic.py → package root is two levels up (openai_batch_worker/)
_THIS_FILE    = Path(__file__).resolve()
_PACKAGE_ROOT = _THIS_FILE.parent.parent   # .../openai_batch_worker/
_MANIFEST_PATH = _PACKAGE_ROOT / "manifest.json"


# ============================================================================
# SECTION 5: POLICY GATE (FAIL-CLOSED)
# ============================================================================

class PolicyGate:
    """
    Local fail-closed WCP policy gate.

    Evaluates a WCPContext + operation dict. Returns WCPDecision.
    Deny is the default — every check must pass to allow.
    """

    policy_version = "policy.v0.3.0"

    def evaluate(self, ctx: WCPContext, operation: Dict[str, Any]) -> WCPDecision:
        if ctx.env not in ALLOWED_ENVS:
            return WCPDecision(
                False, "ENV_NOT_ALLOWED",
                f"env={ctx.env!r} not in ALLOWED_ENVS",
                self.policy_version, None, None,
            )

        if ctx.capability_id not in CAPABILITIES:
            return WCPDecision(
                False, "CAPABILITY_NOT_ALLOWED",
                f"capability={ctx.capability_id!r} not declared",
                self.policy_version, None, None,
            )

        op = operation.get("op", "")
        if op not in ALLOWED_OPS:
            return WCPDecision(
                False, "OP_NOT_ALLOWED",
                f"op={op!r} not in ALLOWED_OPS",
                self.policy_version, None, None,
            )

        if not ctx.correlation_id:
            return WCPDecision(
                False, "CORRELATION_ID_REQUIRED",
                "missing correlation_id",
                self.policy_version, None, None,
            )

        rule_id = f"rr_openai_batch_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = Path.home() / ".local" / "share" / "pyhall" / "evidence" / "wrk_pyhall_openai_batch_chain.log"


class AppendOnlyEvidenceLog:
    """
    Hash-chained append-only local evidence log.

    Each entry records: prev_hash, entry_hash (prev_hash + payload), receipt dict.
    Writes are best-effort — will not crash if directory is absent.
    """

    def __init__(self, log_path: Path):
        self.log_path = log_path

    def emit_evidence(self, receipt: Dict[str, Any]) -> None:
        """Append a receipt to the hash-chained evidence log."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

            prev_hash = "GENESIS"
            if self.log_path.exists() and self.log_path.stat().st_size > 0:
                lines = self.log_path.read_text(encoding="utf-8").strip().splitlines()
                if lines:
                    try:
                        prev = json.loads(lines[-1])
                        prev_hash = prev.get("entry_hash", "GENESIS")
                    except Exception:
                        prev_hash = "GENESIS"

            payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
            entry_hash = sha256_hex_bytes(prev_hash.encode("utf-8") + payload)
            row = {"prev_hash": prev_hash, "entry_hash": entry_hash, "receipt": receipt}

            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, sort_keys=True) + "\n")
        except Exception as exc:
            log(f"WARNING: evidence log write failed (best-effort): {exc}")


def build_evidence_receipt(
    ctx: WCPContext,
    decision: WCPDecision,
    status: str,
    detail: str,
    op: str,
    attest_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a WCP evidence receipt dict."""
    payload_hash = sha256_hex_bytes(
        json.dumps({"op": op, "worker_id": WORKER_ID}, sort_keys=True).encode("utf-8")
    )
    return {
        "receipt_type": "wcp_execution_receipt",
        "schema_version": "wcp-receipt.v1",
        "dispatched_at_utc": utc_now_iso(),
        "worker_id": WORKER_ID,
        "worker_species_id": WORKER_SPECIES_ID,
        "capability_id": ctx.capability_id,
        "operation": op,
        "correlation_id": ctx.correlation_id,
        "policy_decision": {
            "allowed": decision.allowed,
            "policy_version": decision.policy_version,
            "matched_rule_id": decision.matched_rule_id,
            "selected_worker_species_id": decision.selected_worker_species_id,
        },
        "controls_verified": REQUIRED_CONTROLS,
        "request_payload_sha256": payload_hash,
        "attested_package_hash": (attest_meta or {}).get("package_hash", "unverified"),
        "status": status,
        "detail": detail,
    }


# Module-level singletons
_policy_gate  = PolicyGate()
_evidence_log = AppendOnlyEvidenceLog(_EVIDENCE_LOG_PATH)
_attest_meta: Dict[str, Any] = {}  # populated by run() at startup


def _cap_for_op(op: str) -> str:
    """Map an operation to its capability ID."""
    if op in ("get_batch_status", "list_batches", "get_batch_results", "get_file_content", "validate_requests"):
        return "cap.pyhall.openai_batch.read"
    if op in ("cancel_batch",):
        return "cap.pyhall.openai_batch.manage"
    # create_batch, upload_file
    return "cap.pyhall.openai_batch.submit"


def _make_ctx(op: str, capability_id: Optional[str] = None) -> WCPContext:
    """Build a WCPContext for the given operation."""
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=capability_id or _cap_for_op(op),
        data_label="INTERNAL",
        tenant_risk="low",
        qos_class="P2",
        requested_at_utc=utc_now_iso(),
    )


def _gate_and_emit(op: str, capability_id: Optional[str] = None) -> Tuple[WCPContext, WCPDecision]:
    """Run the policy gate for an operation and emit a deny receipt if blocked."""
    ctx = _make_ctx(op, capability_id)
    decision = _policy_gate.evaluate(ctx, {"op": op})
    if not decision.allowed:
        receipt = build_evidence_receipt(
            ctx, decision, "denied", decision.deny_message or "policy deny", op, _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        log(f"POLICY DENY [{decision.deny_code}]: {decision.deny_message}")
        raise SystemExit(1)
    return ctx, decision


# ============================================================================
# SECTION 7: DOMAIN LOGIC — OPENAI BATCH API
# ============================================================================

# --- Configuration ---

_DEFAULT_DB_PATH = Path.home() / ".local" / "share" / "pyhall" / "openai_batch_worker.db"
_DEFAULT_MODEL   = "gpt-4o"


def _get_api_key() -> str:
    """
    Resolve the OpenAI API key from environment.
    Honors the api_key_env config option (default: OPENAI_API_KEY).
    Raises RuntimeError if not set — all callers must handle gracefully.
    """
    env_var = os.environ.get("OPENAI_API_KEY_ENV_VAR", "OPENAI_API_KEY")
    key = os.environ.get(env_var, "").strip()
    if not key:
        raise RuntimeError(
            f"OpenAI API key not set. Export {env_var}=<your-key> and retry."
        )
    return key


def _get_client():
    """Return an authenticated openai.OpenAI client."""
    try:
        import openai
    except ImportError as exc:
        raise RuntimeError(
            "openai package not installed. Run: pip install openai>=1.30.0"
        ) from exc
    api_key = _get_api_key()
    return openai.OpenAI(api_key=api_key)


# --- Database ---

def _get_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Return a sqlite3 Connection, auto-creating schema on first use."""
    path = db_path or Path(os.environ.get("PYHALL_BATCH_DB_PATH", str(_DEFAULT_DB_PATH)))
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path))
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS batches (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id        TEXT    NOT NULL UNIQUE,
            input_file_id   TEXT    NOT NULL,
            output_file_id  TEXT,
            status          TEXT    NOT NULL,
            request_count   INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL,
            completed_at    TEXT,
            notes           TEXT
        )
    """)
    db.commit()
    return db


def _upsert_batch(db: sqlite3.Connection, record: Dict[str, Any]) -> None:
    """Insert or update a batch record in the local DB."""
    db.execute("""
        INSERT INTO batches (batch_id, input_file_id, output_file_id, status, request_count, created_at, completed_at, notes)
        VALUES (:batch_id, :input_file_id, :output_file_id, :status, :request_count, :created_at, :completed_at, :notes)
        ON CONFLICT(batch_id) DO UPDATE SET
            output_file_id = excluded.output_file_id,
            status         = excluded.status,
            completed_at   = excluded.completed_at
    """, record)
    db.commit()


# --- Domain operations ---

def upload_file(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Serialize a list of request dicts to JSONL and upload via the OpenAI Files API.

    Each request must be: {"custom_id": str, "method": "POST", "url": "/v1/chat/completions", "body": {...}}
    Returns: {"file_id": str, "filename": str, "bytes": int, "created_at": int}
    """
    ctx, decision = _gate_and_emit("upload_file")

    try:
        client = _get_client()
    except RuntimeError as exc:
        receipt = build_evidence_receipt(ctx, decision, "error", str(exc), "upload_file", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {exc}")
        raise SystemExit(1)

    # Build JSONL bytes
    lines = [json.dumps(r, separators=(",", ":")) for r in requests]
    jsonl_bytes = "\n".join(lines).encode("utf-8")
    filename = f"batch_input_{utc_now_iso().replace(':', '-').replace('Z', '')}.jsonl"

    import io
    file_tuple = (filename, io.BytesIO(jsonl_bytes), "application/jsonl")

    log(f"Uploading {len(requests)} requests ({len(jsonl_bytes)} bytes) to Files API...")
    file_obj = client.files.create(file=file_tuple, purpose="batch")

    result = {
        "file_id": file_obj.id,
        "filename": file_obj.filename,
        "bytes": file_obj.bytes,
        "created_at": file_obj.created_at,
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"upload_file: {len(requests)} requests → file_id={file_obj.id}",
        "upload_file", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"Uploaded: file_id={file_obj.id}")
    return result


def create_batch(
    file_id: str,
    endpoint: str = "/v1/chat/completions",
    completion_window: str = "24h",
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a batch job referencing an uploaded file ID.

    Returns dict with batch_id, status, and request_counts.
    Also persists a BatchRecord to the local SQLite DB.
    """
    ctx, decision = _gate_and_emit("create_batch")

    try:
        client = _get_client()
    except RuntimeError as exc:
        receipt = build_evidence_receipt(ctx, decision, "error", str(exc), "create_batch", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {exc}")
        raise SystemExit(1)

    log(f"Creating batch: file_id={file_id}, endpoint={endpoint}, window={completion_window}")
    batch = client.batches.create(
        input_file_id=file_id,
        endpoint=endpoint,
        completion_window=completion_window,
    )

    created_utc = utc_now_iso()
    counts = batch.request_counts
    total = counts.total if counts else 0

    db = _get_db()
    try:
        _upsert_batch(db, {
            "batch_id":       batch.id,
            "input_file_id":  file_id,
            "output_file_id": None,
            "status":         batch.status,
            "request_count":  total,
            "created_at":     created_utc,
            "completed_at":   None,
            "notes":          notes,
        })
    finally:
        db.close()

    result = {
        "batch_id":          batch.id,
        "status":            batch.status,
        "input_file_id":     file_id,
        "endpoint":          endpoint,
        "completion_window": completion_window,
        "request_counts": {
            "total":     counts.total     if counts else 0,
            "completed": counts.completed if counts else 0,
            "failed":    counts.failed    if counts else 0,
        },
        "created_at": created_utc,
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_batch: batch_id={batch.id} status={batch.status}",
        "create_batch", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"Batch created: {batch.id} (status={batch.status})")
    return result


def get_batch_status(batch_id: str) -> Dict[str, Any]:
    """
    Retrieve current status of a batch job.

    Returns dict with: id, status, request_counts, created_at, completed_at,
    output_file_id, error_file_id.
    Also updates the local DB record.
    """
    ctx, decision = _gate_and_emit("get_batch_status")

    try:
        client = _get_client()
    except RuntimeError as exc:
        receipt = build_evidence_receipt(ctx, decision, "error", str(exc), "get_batch_status", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {exc}")
        raise SystemExit(1)

    batch = client.batches.retrieve(batch_id)
    counts = batch.request_counts

    # Sync to local DB
    db = _get_db()
    try:
        db.execute("""
            UPDATE batches
            SET status=?, output_file_id=?, completed_at=?
            WHERE batch_id=?
        """, (
            batch.status,
            batch.output_file_id,
            utc_now_iso() if batch.status in ("completed", "failed", "expired", "cancelled") else None,
            batch_id,
        ))
        db.commit()
    finally:
        db.close()

    result = {
        "id":             batch.id,
        "status":         batch.status,
        "request_counts": {
            "total":     counts.total     if counts else 0,
            "completed": counts.completed if counts else 0,
            "failed":    counts.failed    if counts else 0,
        },
        "created_at":      batch.created_at,
        "completed_at":    batch.completed_at,
        "output_file_id":  batch.output_file_id,
        "error_file_id":   batch.error_file_id,
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_batch_status: {batch_id} → {batch.status}",
        "get_batch_status", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"Batch {batch_id}: status={batch.status}")
    return result


def list_batches(limit: int = 20) -> Dict[str, Any]:
    """
    List recent batches from the OpenAI API (up to `limit` results).

    Returns dict with "batches" list (id, status, created_at, request_counts).
    """
    ctx, decision = _gate_and_emit("list_batches")

    try:
        client = _get_client()
    except RuntimeError as exc:
        receipt = build_evidence_receipt(ctx, decision, "error", str(exc), "list_batches", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {exc}")
        raise SystemExit(1)

    page = client.batches.list(limit=limit)
    items = []
    for batch in page.data:
        counts = batch.request_counts
        items.append({
            "id":              batch.id,
            "status":          batch.status,
            "created_at":      batch.created_at,
            "completed_at":    batch.completed_at,
            "output_file_id":  batch.output_file_id,
            "request_counts": {
                "total":     counts.total     if counts else 0,
                "completed": counts.completed if counts else 0,
                "failed":    counts.failed    if counts else 0,
            },
        })

    result = {"batches": items, "count": len(items)}

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_batches: {len(items)} returned (limit={limit})",
        "list_batches", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"Listed {len(items)} batches")
    return result


def get_batch_results(batch_id: str) -> Dict[str, Any]:
    """
    Download and parse results for a completed batch.

    Fetches the output_file_id from the batch status, then downloads
    the JSONL results file. Returns list of result dicts plus a summary.
    Errors if the batch is not yet completed.
    """
    ctx, decision = _gate_and_emit("get_batch_results")

    try:
        client = _get_client()
    except RuntimeError as exc:
        receipt = build_evidence_receipt(ctx, decision, "error", str(exc), "get_batch_results", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {exc}")
        raise SystemExit(1)

    # Fetch batch to get output_file_id
    batch = client.batches.retrieve(batch_id)
    if batch.status != "completed":
        msg = f"Batch {batch_id} is not completed (status={batch.status}). Cannot retrieve results."
        receipt = build_evidence_receipt(ctx, decision, "error", msg, "get_batch_results", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {msg}")
        raise SystemExit(1)

    if not batch.output_file_id:
        msg = f"Batch {batch_id} has no output_file_id despite completed status."
        receipt = build_evidence_receipt(ctx, decision, "error", msg, "get_batch_results", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {msg}")
        raise SystemExit(1)

    log(f"Downloading results from file_id={batch.output_file_id}...")
    raw_content = client.files.content(batch.output_file_id)
    text = raw_content.text

    results = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError as exc:
                log(f"WARNING: Failed to parse result line: {exc}")

    counts = batch.request_counts
    result = {
        "batch_id":       batch_id,
        "output_file_id": batch.output_file_id,
        "results":        results,
        "result_count":   len(results),
        "request_counts": {
            "total":     counts.total     if counts else 0,
            "completed": counts.completed if counts else 0,
            "failed":    counts.failed    if counts else 0,
        },
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_batch_results: {batch_id} → {len(results)} results downloaded",
        "get_batch_results", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"Downloaded {len(results)} results for batch {batch_id}")
    return result


def cancel_batch(batch_id: str) -> Dict[str, Any]:
    """
    Cancel an in-progress batch job.

    Returns dict with batch_id and new status.
    """
    ctx, decision = _gate_and_emit("cancel_batch")

    try:
        client = _get_client()
    except RuntimeError as exc:
        receipt = build_evidence_receipt(ctx, decision, "error", str(exc), "cancel_batch", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {exc}")
        raise SystemExit(1)

    log(f"Cancelling batch: {batch_id}")
    batch = client.batches.cancel(batch_id)

    # Update local DB
    db = _get_db()
    try:
        db.execute(
            "UPDATE batches SET status=? WHERE batch_id=?",
            (batch.status, batch_id),
        )
        db.commit()
    finally:
        db.close()

    result = {
        "batch_id": batch_id,
        "status":   batch.status,
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"cancel_batch: {batch_id} → status={batch.status}",
        "cancel_batch", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"Cancelled batch {batch_id}: status={batch.status}")
    return result


def get_file_content(file_id: str) -> Dict[str, Any]:
    """
    Download raw content of a file from the OpenAI Files API.

    Returns dict with file_id and raw text content.
    """
    ctx, decision = _gate_and_emit("get_file_content")

    try:
        client = _get_client()
    except RuntimeError as exc:
        receipt = build_evidence_receipt(ctx, decision, "error", str(exc), "get_file_content", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {exc}")
        raise SystemExit(1)

    log(f"Fetching file content: {file_id}")
    raw = client.files.content(file_id)
    content = raw.text

    result = {
        "file_id":       file_id,
        "content":       content,
        "content_bytes": len(content.encode("utf-8")),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_file_content: {file_id} → {len(content.encode('utf-8'))} bytes",
        "get_file_content", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"Retrieved {len(content.encode('utf-8'))} bytes from file {file_id}")
    return result


def validate_requests(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate a list of JSONL batch request dicts.

    Checks each entry for required fields: custom_id (str), method (POST),
    url (/v1/chat/completions), body (dict with model + messages).
    Returns {"valid": bool, "errors": [...], "checked": int}.
    No API call is made — this is a local validation.
    """
    ctx, decision = _gate_and_emit("validate_requests")

    errors: List[str] = []
    seen_ids: set = set()

    for i, req in enumerate(requests):
        prefix = f"[{i}]"

        # custom_id
        cid = req.get("custom_id")
        if not isinstance(cid, str) or not cid.strip():
            errors.append(f"{prefix} missing or invalid 'custom_id' (must be non-empty string)")
        elif cid in seen_ids:
            errors.append(f"{prefix} duplicate 'custom_id': {cid!r}")
        else:
            seen_ids.add(cid)

        # method
        method = req.get("method")
        if method != "POST":
            errors.append(f"{prefix} 'method' must be 'POST', got {method!r}")

        # url
        url = req.get("url")
        if url != "/v1/chat/completions":
            errors.append(f"{prefix} 'url' must be '/v1/chat/completions', got {url!r}")

        # body
        body = req.get("body")
        if not isinstance(body, dict):
            errors.append(f"{prefix} 'body' must be a dict")
        else:
            if not body.get("model"):
                errors.append(f"{prefix} body missing 'model'")
            if not isinstance(body.get("messages"), list) or not body["messages"]:
                errors.append(f"{prefix} body missing or empty 'messages' list")

    valid = len(errors) == 0
    result = {
        "valid":   valid,
        "errors":  errors,
        "checked": len(requests),
    }

    status_str = "ok" if valid else "validation_failed"
    receipt = build_evidence_receipt(
        ctx, decision, status_str,
        f"validate_requests: {len(requests)} checked, {len(errors)} errors",
        "validate_requests", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    if valid:
        log(f"Validation passed: {len(requests)} requests OK")
    else:
        log(f"Validation failed: {len(errors)} error(s) across {len(requests)} requests")

    return result


def _dispatch(op: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Route CLI args to domain functions."""

    if op == "upload_file":
        # Reads JSONL from --input-file
        input_path = Path(args.input_file)
        if not input_path.exists():
            log(f"ERROR: input file not found: {input_path}")
            raise SystemExit(1)
        requests_list = []
        for line in input_path.read_text(encoding="utf-8").strip().splitlines():
            line = line.strip()
            if line:
                requests_list.append(json.loads(line))
        return upload_file(requests_list)

    elif op == "create_batch":
        return create_batch(
            file_id=args.file_id,
            endpoint=getattr(args, "endpoint", "/v1/chat/completions"),
            completion_window=getattr(args, "completion_window", "24h"),
            notes=getattr(args, "notes", None),
        )

    elif op == "get_batch_status":
        return get_batch_status(args.batch_id)

    elif op == "list_batches":
        return list_batches(limit=getattr(args, "limit", 20))

    elif op == "get_batch_results":
        return get_batch_results(args.batch_id)

    elif op == "cancel_batch":
        return cancel_batch(args.batch_id)

    elif op == "get_file_content":
        return get_file_content(args.file_id)

    elif op == "validate_requests":
        input_path = Path(args.input_file)
        if not input_path.exists():
            log(f"ERROR: input file not found: {input_path}")
            raise SystemExit(1)
        requests_list = []
        for line in input_path.read_text(encoding="utf-8").strip().splitlines():
            line = line.strip()
            if line:
                requests_list.append(json.loads(line))
        return validate_requests(requests_list)

    else:
        log(f"ERROR: unknown op={op!r}")
        raise SystemExit(1)


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        epilog=(
            "Examples:\n"
            "  python3 bootstrap.py upload_file --input-file requests.jsonl\n"
            "  python3 bootstrap.py create_batch --file-id file-abc123\n"
            "  python3 bootstrap.py get_batch_status --batch-id batch-xyz\n"
            "  python3 bootstrap.py list_batches --limit 10\n"
            "  python3 bootstrap.py get_batch_results --batch-id batch-xyz\n"
            "  python3 bootstrap.py cancel_batch --batch-id batch-xyz\n"
            "  python3 bootstrap.py get_file_content --file-id file-abc123\n"
            "  python3 bootstrap.py validate_requests --input-file requests.jsonl\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("op", choices=sorted(ALLOWED_OPS), help="Operation to perform")

    # File/batch identifiers
    p.add_argument("--file-id", dest="file_id", metavar="FILE_ID",
                   help="OpenAI file ID (for create_batch, get_file_content)")
    p.add_argument("--batch-id", dest="batch_id", metavar="BATCH_ID",
                   help="OpenAI batch ID (for get_batch_status, get_batch_results, cancel_batch)")
    p.add_argument("--input-file", dest="input_file", metavar="PATH",
                   help="Path to JSONL file (for upload_file, validate_requests)")

    # Batch creation options
    p.add_argument("--endpoint", default="/v1/chat/completions",
                   help="Batch endpoint (default: /v1/chat/completions)")
    p.add_argument("--completion-window", dest="completion_window", default="24h",
                   help="Completion window (default: 24h)")
    p.add_argument("--notes", default=None,
                   help="Optional notes to store with the batch record")

    # Listing
    p.add_argument("--limit", type=int, default=20,
                   help="Max results for list_batches (default: 20)")

    return p


def run() -> None:
    """WCP worker entry point. Called from bootstrap.py."""
    global _attest_meta

    # Run startup attestation — warns in dev, hard-fails in prod
    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = _build_arg_parser()
    args = parser.parse_args()
    op = args.op

    # Validate required args per op before hitting the API
    _requires_batch_id  = {"get_batch_status", "get_batch_results", "cancel_batch"}
    _requires_file_id   = {"create_batch", "get_file_content"}
    _requires_input_file = {"upload_file", "validate_requests"}

    if op in _requires_batch_id and not args.batch_id:
        parser.error(f"op '{op}' requires --batch-id")
    if op in _requires_file_id and not args.file_id:
        parser.error(f"op '{op}' requires --file-id")
    if op in _requires_input_file and not args.input_file:
        parser.error(f"op '{op}' requires --input-file")

    result = _dispatch(op, args)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    run()
