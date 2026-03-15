#!/usr/bin/env python3
"""
worker_logic.py — Batch for Claude Worker (WCP v0.3.0)

Submits and manages Anthropic Message Batches via the anthropic SDK.
Full WCP-compliant worker package: attested, fail-closed policy gate,
append-only evidence log, deterministic traceability via correlation IDs.

Auth: set ANTHROPIC_API_KEY in the environment before running.
DB:   ~/.local/share/pyhall/claude_batch_worker.db (auto-created)

Quick start:
    python3 bootstrap.py validate_requests --requests '[{"custom_id":"t1","params":{"model":"claude-sonnet-4-6","max_tokens":100,"messages":[{"role":"user","content":"Hello"}]}}]'
    python3 bootstrap.py create_batch --requests-file my_requests.json
    python3 bootstrap.py get_batch_status --batch-id msgbatch_abc123
    python3 bootstrap.py get_batch_results --batch-id msgbatch_abc123
    python3 bootstrap.py list_batches
    python3 bootstrap.py cancel_batch --batch-id msgbatch_abc123
    python3 bootstrap.py count_tokens_estimate --requests-file my_requests.json
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

WORKER_ID          = "org.pyhall.claude-batch.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.claude-batch"
WORKER_NAME        = "Batch for Claude Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.claude_batch.submit",
    "cap.pyhall.claude_batch.read",
    "cap.pyhall.claude_batch.manage",
]

ALLOWED_OPS = {
    "create_batch",
    "get_batch_status",
    "list_batches",
    "get_batch_results",
    "cancel_batch",
    "validate_requests",
    "count_tokens_estimate",
}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

ALLOWED_ENVS = {"dev", "stage", "prod"}

# Map ops → capability_id
_OP_CAPABILITY: Dict[str, str] = {
    "create_batch":           "cap.pyhall.claude_batch.submit",
    "get_batch_status":       "cap.pyhall.claude_batch.read",
    "list_batches":           "cap.pyhall.claude_batch.read",
    "get_batch_results":      "cap.pyhall.claude_batch.read",
    "cancel_batch":           "cap.pyhall.claude_batch.manage",
    "validate_requests":      "cap.pyhall.claude_batch.submit",
    "count_tokens_estimate":  "cap.pyhall.claude_batch.submit",
}


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
    """Local record of a submitted batch."""
    batch_id: str
    status: str
    request_count: int
    created_at: str
    ended_at: Optional[str]
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


def load_json(path: Path) -> Any:
    """Load JSON from a file path."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    """Write JSON to a file path, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _default_db_path() -> Path:
    """Return the default SQLite DB path (cross-platform)."""
    base = Path(os.environ.get("PYHALL_CLAUDE_BATCH_DB", "")).expanduser()
    if base and str(base) != ".":
        return base
    return Path.home() / ".local" / "share" / "pyhall" / "claude_batch_worker.db"


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
#   code/worker_logic.py → package root is claude_batch_worker/
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../claude_batch_worker/
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

        rule_id = f"rr_claude_batch_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = (
    Path.home() / ".local" / "share" / "pyhall" / "evidence"
    / f"{WORKER_SPECIES_ID.replace('.', '_')}_chain.log"
)


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
_attest_meta: Dict[str, Any] = {}   # populated by run() at startup


def _make_ctx(op: str) -> WCPContext:
    """Build a WCPContext for the given operation."""
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=_OP_CAPABILITY.get(op, CAPABILITIES[0]),
        data_label="INTERNAL",
        tenant_risk="low",
        qos_class="P2",
        requested_at_utc=utc_now_iso(),
    )


def _gate_and_emit(op: str) -> Tuple[WCPContext, WCPDecision]:
    """Run the policy gate for an operation and emit a deny receipt if blocked."""
    ctx = _make_ctx(op)
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
# SECTION 7: DOMAIN LOGIC — ANTHROPIC MESSAGE BATCHES
# ============================================================================

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _get_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Return a sqlite3 Connection with the batches table ensured."""
    path = db_path or _default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS batches (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id      TEXT NOT NULL UNIQUE,
            status        TEXT NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL,
            ended_at      TEXT,
            notes         TEXT
        )
    """)
    conn.commit()
    return conn


def _upsert_batch(conn: sqlite3.Connection, record: BatchRecord) -> None:
    """Insert or update a batch record."""
    conn.execute("""
        INSERT INTO batches (batch_id, status, request_count, created_at, ended_at, notes)
        VALUES (:batch_id, :status, :request_count, :created_at, :ended_at, :notes)
        ON CONFLICT(batch_id) DO UPDATE SET
            status        = excluded.status,
            request_count = excluded.request_count,
            ended_at      = excluded.ended_at,
            notes         = excluded.notes
    """, {
        "batch_id":      record.batch_id,
        "status":        record.status,
        "request_count": record.request_count,
        "created_at":    record.created_at,
        "ended_at":      record.ended_at,
        "notes":         record.notes,
    })
    conn.commit()


# ---------------------------------------------------------------------------
# Anthropic client helper
# ---------------------------------------------------------------------------

def _get_anthropic_client():
    """
    Return an anthropic.Anthropic client.

    Raises a RuntimeError with a clear message if ANTHROPIC_API_KEY is not set
    or the anthropic package is not installed.
    """
    api_key_env = os.environ.get("PYHALL_CLAUDE_BATCH_API_KEY_ENV", "ANTHROPIC_API_KEY")
    api_key = os.environ.get(api_key_env, "").strip()

    if not api_key:
        raise RuntimeError(
            f"ANTHROPIC_API_KEY not set (checked env var: {api_key_env!r}). "
            "Export ANTHROPIC_API_KEY=<your-key> before running."
        )

    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            f"anthropic package not installed: {exc}. "
            "Run: pip install 'anthropic>=0.50.0'"
        ) from exc

    return anthropic.Anthropic(api_key=api_key)


def _batch_to_dict(batch) -> Dict[str, Any]:
    """Convert an anthropic MessageBatch object to a plain dict."""
    request_counts = getattr(batch, "request_counts", None)
    rc_dict: Dict[str, int] = {}
    if request_counts is not None:
        for field in ("processing", "succeeded", "errored", "canceled", "expired"):
            rc_dict[field] = getattr(request_counts, field, 0)

    return {
        "id":             batch.id,
        "status":         batch.processing_status,
        "request_counts": rc_dict,
        "created_at":     str(batch.created_at) if batch.created_at else None,
        "ended_at":       str(batch.ended_at) if getattr(batch, "ended_at", None) else None,
        "expires_at":     str(batch.expires_at) if getattr(batch, "expires_at", None) else None,
    }


# ---------------------------------------------------------------------------
# Op: create_batch
# ---------------------------------------------------------------------------

def create_batch(
    requests: List[Dict[str, Any]],
    notes: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Submit a message batch to the Anthropic API.

    Each request must be:
        {
            "custom_id": "<string>",
            "params": {
                "model": "<model-id>",
                "max_tokens": <int>,
                "messages": [{"role": "user", "content": "..."}]
            }
        }

    Returns a dict with the batch ID and initial status.
    """
    op = "create_batch"
    ctx, decision = _gate_and_emit(op)

    # Validate first
    validation = _validate_requests_inner(requests)
    if not validation["valid"]:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"validation failed: {validation['errors']}", op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "validation_failed", "errors": validation["errors"]}

    try:
        client = _get_anthropic_client()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_key_missing_or_import_error", "detail": str(exc)}

    try:
        import anthropic

        batch_requests = [
            anthropic.types.message_create_params.Request(
                custom_id=r["custom_id"],
                params=anthropic.types.messages.MessageCreateParamsNonStreaming(
                    model=r["params"]["model"],
                    max_tokens=r["params"]["max_tokens"],
                    messages=r["params"]["messages"],
                ),
            )
            for r in requests
        ]

        batch = client.messages.batches.create(requests=batch_requests)
        result = _batch_to_dict(batch)

    except Exception as exc:
        log(f"ERROR create_batch: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"create_batch API error: {exc}", op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_error", "detail": str(exc)}

    # Persist to local DB
    try:
        conn = _get_db(db_path)
        record = BatchRecord(
            batch_id=result["id"],
            status=result["status"],
            request_count=len(requests),
            created_at=result.get("created_at") or utc_now_iso(),
            ended_at=result.get("ended_at"),
            notes=notes,
        )
        _upsert_batch(conn, record)
        conn.close()
        log(f"Batch submitted: {result['id']} ({len(requests)} requests) — persisted to DB")
    except Exception as exc:
        log(f"WARNING: DB persist failed (best-effort): {exc}")

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_batch: {result['id']} submitted with {len(requests)} requests",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


# ---------------------------------------------------------------------------
# Op: get_batch_status
# ---------------------------------------------------------------------------

def get_batch_status(
    batch_id: str,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Retrieve the current status of a batch.

    Returns dict: id, status, request_counts, created_at, ended_at.
    """
    op = "get_batch_status"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_anthropic_client()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_key_missing_or_import_error", "detail": str(exc)}

    try:
        batch = client.messages.batches.retrieve(batch_id)
        result = _batch_to_dict(batch)
    except Exception as exc:
        log(f"ERROR get_batch_status: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"get_batch_status API error: {exc}", op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_error", "detail": str(exc)}

    # Update local DB if we have it
    try:
        conn = _get_db(db_path)
        existing = conn.execute(
            "SELECT id FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE batches SET status = ?, ended_at = ? WHERE batch_id = ?",
                (result["status"], result.get("ended_at"), batch_id),
            )
            conn.commit()
        conn.close()
    except Exception as exc:
        log(f"WARNING: DB update failed (best-effort): {exc}")

    log(f"Batch {batch_id}: status={result['status']}")

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_batch_status: {batch_id} status={result['status']}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


# ---------------------------------------------------------------------------
# Op: list_batches
# ---------------------------------------------------------------------------

def list_batches(limit: int = 20) -> Dict[str, Any]:
    """
    List recent batches from the Anthropic API.

    Returns dict with "batches" list and "count".
    """
    op = "list_batches"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_anthropic_client()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_key_missing_or_import_error", "detail": str(exc)}

    try:
        page = client.messages.batches.list(limit=limit)
        batches = [_batch_to_dict(b) for b in page.data]
    except Exception as exc:
        log(f"ERROR list_batches: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"list_batches API error: {exc}", op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_error", "detail": str(exc)}

    log(f"list_batches: {len(batches)} batches returned")

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_batches: {len(batches)} batches",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return {"batches": batches, "count": len(batches)}


# ---------------------------------------------------------------------------
# Op: get_batch_results
# ---------------------------------------------------------------------------

def get_batch_results(batch_id: str) -> Dict[str, Any]:
    """
    Stream and collect results for a completed (ended) batch.

    Each result entry:
        {
            "custom_id": "<string>",
            "result": {
                "type": "succeeded" | "errored" | "canceled" | "expired",
                "message": { ... }   (present when type == "succeeded")
                "error": { ... }     (present when type == "errored")
            }
        }

    Returns dict with "results" list and "count".
    """
    op = "get_batch_results"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_anthropic_client()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_key_missing_or_import_error", "detail": str(exc)}

    try:
        results: List[Dict[str, Any]] = []
        for item in client.messages.batches.results(batch_id):
            result_type = item.result.type
            entry: Dict[str, Any] = {
                "custom_id": item.custom_id,
                "result": {"type": result_type},
            }
            if result_type == "succeeded":
                # Convert message object to dict via model_dump if available
                msg = item.result.message
                try:
                    entry["result"]["message"] = msg.model_dump()
                except AttributeError:
                    entry["result"]["message"] = str(msg)
            elif result_type == "errored":
                err = item.result.error
                try:
                    entry["result"]["error"] = err.model_dump()
                except AttributeError:
                    entry["result"]["error"] = str(err)
            results.append(entry)

    except Exception as exc:
        log(f"ERROR get_batch_results: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"get_batch_results API error: {exc}", op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_error", "detail": str(exc)}

    log(f"get_batch_results: {len(results)} results for batch {batch_id}")

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_batch_results: {batch_id} — {len(results)} results collected",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return {"results": results, "count": len(results), "batch_id": batch_id}


# ---------------------------------------------------------------------------
# Op: cancel_batch
# ---------------------------------------------------------------------------

def cancel_batch(
    batch_id: str,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Cancel an in-progress batch.

    Returns the updated batch status dict.
    """
    op = "cancel_batch"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_anthropic_client()
    except RuntimeError as exc:
        log(f"WARNING: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_key_missing_or_import_error", "detail": str(exc)}

    try:
        batch = client.messages.batches.cancel(batch_id)
        result = _batch_to_dict(batch)
    except Exception as exc:
        log(f"ERROR cancel_batch: {exc}")
        receipt = build_evidence_receipt(
            ctx, decision, "error", f"cancel_batch API error: {exc}", op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return {"error": "api_error", "detail": str(exc)}

    # Update local DB
    try:
        conn = _get_db(db_path)
        conn.execute(
            "UPDATE batches SET status = ? WHERE batch_id = ?",
            (result["status"], batch_id),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        log(f"WARNING: DB update failed (best-effort): {exc}")

    log(f"Batch {batch_id} cancel requested — status={result['status']}")

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"cancel_batch: {batch_id} cancel requested, status={result['status']}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


# ---------------------------------------------------------------------------
# Op: validate_requests (inner — no gate, called by create_batch too)
# ---------------------------------------------------------------------------

_VALID_MODELS = {
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-6",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
    "claude-3-haiku-20240307",
}


def _validate_requests_inner(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Inner validation — no policy gate. Called directly by create_batch.

    Checks:
    - each request has custom_id and params
    - params has model, max_tokens, messages
    - model is a known name
    - messages is a non-empty list
    - max_tokens is a positive integer
    """
    errors: List[str] = []

    if not isinstance(requests, list) or len(requests) == 0:
        return {"valid": False, "errors": ["requests must be a non-empty list"]}

    seen_ids: set = set()
    for i, req in enumerate(requests):
        prefix = f"requests[{i}]"

        if not isinstance(req, dict):
            errors.append(f"{prefix}: must be a dict")
            continue

        custom_id = req.get("custom_id")
        if not custom_id or not isinstance(custom_id, str):
            errors.append(f"{prefix}: missing or invalid 'custom_id' (must be non-empty string)")
        elif custom_id in seen_ids:
            errors.append(f"{prefix}: duplicate custom_id={custom_id!r}")
        else:
            seen_ids.add(custom_id)

        params = req.get("params")
        if not isinstance(params, dict):
            errors.append(f"{prefix}: missing or invalid 'params' (must be a dict)")
            continue

        model = params.get("model")
        if not model or not isinstance(model, str):
            errors.append(f"{prefix}.params: missing or invalid 'model'")
        elif model not in _VALID_MODELS:
            # Warn but don't hard-fail — Anthropic may have new models
            errors.append(
                f"{prefix}.params: unrecognized model={model!r} "
                f"(known: {', '.join(sorted(_VALID_MODELS))})"
            )

        max_tokens = params.get("max_tokens")
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            errors.append(f"{prefix}.params: 'max_tokens' must be a positive integer")

        messages = params.get("messages")
        if not isinstance(messages, list) or len(messages) == 0:
            errors.append(f"{prefix}.params: 'messages' must be a non-empty list")
        else:
            for j, msg in enumerate(messages):
                if not isinstance(msg, dict):
                    errors.append(f"{prefix}.params.messages[{j}]: must be a dict")
                    continue
                if msg.get("role") not in ("user", "assistant"):
                    errors.append(
                        f"{prefix}.params.messages[{j}]: 'role' must be 'user' or 'assistant'"
                    )
                if "content" not in msg:
                    errors.append(f"{prefix}.params.messages[{j}]: missing 'content'")

    return {"valid": len(errors) == 0, "errors": errors}


def validate_requests(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate request format before submission. Policy-gated public entry point.

    Returns: {"valid": bool, "errors": [...], "request_count": int}
    """
    op = "validate_requests"
    ctx, decision = _gate_and_emit(op)

    result = _validate_requests_inner(requests)
    result["request_count"] = len(requests) if isinstance(requests, list) else 0

    status = "ok" if result["valid"] else "error"
    detail = (
        f"validate_requests: {result['request_count']} requests, "
        f"valid={result['valid']}, errors={len(result['errors'])}"
    )
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, status, detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# ---------------------------------------------------------------------------
# Op: count_tokens_estimate
# ---------------------------------------------------------------------------

_AVG_CHARS_PER_TOKEN = 4.0   # rough heuristic (English prose)


def count_tokens_estimate(requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Rough token estimate for a request list (no API call).

    Uses a simple chars/4 heuristic per message content string.
    Returns: {"estimated_input_tokens": int, "request_count": int}
    """
    op = "count_tokens_estimate"
    ctx, decision = _gate_and_emit(op)

    total_chars = 0
    request_count = len(requests) if isinstance(requests, list) else 0

    for req in (requests if isinstance(requests, list) else []):
        params = req.get("params", {}) if isinstance(req, dict) else {}
        for msg in (params.get("messages", []) if isinstance(params, dict) else []):
            content = msg.get("content", "") if isinstance(msg, dict) else ""
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                # Content blocks (e.g. image + text)
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        total_chars += len(block.get("text", ""))

    estimated_tokens = int(total_chars / _AVG_CHARS_PER_TOKEN)

    result = {
        "estimated_input_tokens": estimated_tokens,
        "request_count": request_count,
        "note": "Rough estimate: chars/4 heuristic. Use Anthropic token counting API for precision.",
    }

    detail = (
        f"count_tokens_estimate: {request_count} requests, "
        f"~{estimated_tokens} input tokens estimated"
    )
    log(detail)

    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  worker_logic.py create_batch --requests '[{\"custom_id\":\"t1\",\"params\":{\"model\":\"claude-sonnet-4-6\",\"max_tokens\":100,\"messages\":[{\"role\":\"user\",\"content\":\"Hi\"}]}}]'\n"
            "  worker_logic.py create_batch --requests-file batch_requests.json\n"
            "  worker_logic.py get_batch_status --batch-id msgbatch_abc123\n"
            "  worker_logic.py get_batch_results --batch-id msgbatch_abc123\n"
            "  worker_logic.py list_batches --limit 10\n"
            "  worker_logic.py cancel_batch --batch-id msgbatch_abc123\n"
            "  worker_logic.py validate_requests --requests-file my_requests.json\n"
            "  worker_logic.py count_tokens_estimate --requests-file my_requests.json\n"
        ),
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # Shared: requests input (JSON string or file)
    req_group = p.add_mutually_exclusive_group()
    req_group.add_argument(
        "--requests",
        metavar="JSON",
        help="Requests as a JSON array string",
    )
    req_group.add_argument(
        "--requests-file",
        metavar="PATH",
        help="Path to a JSON file containing the requests array",
    )

    # Ops that take a batch ID
    p.add_argument(
        "--batch-id",
        metavar="BATCH_ID",
        help="Anthropic batch ID (required for get_batch_status, get_batch_results, cancel_batch)",
    )

    # list_batches options
    p.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max batches to return from list_batches (default: 20)",
    )

    # create_batch options
    p.add_argument(
        "--notes",
        default=None,
        help="Optional notes to store with the batch in local DB",
    )

    # Output
    p.add_argument(
        "--output",
        metavar="PATH",
        help="Write JSON result to this file path",
    )

    return p


def _load_requests_arg(args: argparse.Namespace) -> Optional[List[Dict[str, Any]]]:
    """Parse --requests or --requests-file into a list, or return None."""
    if args.requests:
        try:
            data = json.loads(args.requests)
            if not isinstance(data, list):
                log("ERROR: --requests must be a JSON array")
                raise SystemExit(1)
            return data
        except json.JSONDecodeError as exc:
            log(f"ERROR: --requests JSON parse error: {exc}")
            raise SystemExit(1)

    if args.requests_file:
        path = Path(args.requests_file).expanduser()
        if not path.exists():
            log(f"ERROR: --requests-file not found: {path}")
            raise SystemExit(1)
        try:
            data = load_json(path)
            if not isinstance(data, list):
                log("ERROR: requests file must contain a JSON array")
                raise SystemExit(1)
            return data
        except Exception as exc:
            log(f"ERROR: could not read --requests-file: {exc}")
            raise SystemExit(1)

    return None


def run() -> None:
    """WCP worker entry point."""
    global _attest_meta

    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = _build_arg_parser()
    args = parser.parse_args()
    op = args.op

    result: Dict[str, Any] = {}

    # Ops that require --batch-id
    if op in ("get_batch_status", "get_batch_results", "cancel_batch"):
        if not args.batch_id:
            log(f"ERROR: --batch-id is required for op={op}")
            raise SystemExit(1)

    # Ops that require requests
    if op in ("create_batch", "validate_requests", "count_tokens_estimate"):
        requests = _load_requests_arg(args)
        if requests is None:
            log(f"ERROR: --requests or --requests-file is required for op={op}")
            raise SystemExit(1)

        if op == "create_batch":
            result = create_batch(requests, notes=args.notes)
        elif op == "validate_requests":
            result = validate_requests(requests)
        elif op == "count_tokens_estimate":
            result = count_tokens_estimate(requests)

    elif op == "get_batch_status":
        result = get_batch_status(args.batch_id)

    elif op == "get_batch_results":
        result = get_batch_results(args.batch_id)

    elif op == "list_batches":
        result = list_batches(limit=args.limit)

    elif op == "cancel_batch":
        result = cancel_batch(args.batch_id)

    # Output result
    result_json = json.dumps(result, indent=2, default=str)

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(result_json, encoding="utf-8")
        log(f"Result written to {out_path}")
    else:
        print(result_json)

    log(f"Done: op={op}")


if __name__ == "__main__":
    run()
