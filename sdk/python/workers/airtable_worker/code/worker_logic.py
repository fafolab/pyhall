#!/usr/bin/env python3
"""
worker_logic.py — Airtable Database Worker (WCP v0.3.0)

Full read/write/manage access to Airtable bases, tables, records, and fields
via the Airtable REST API v0.

Authentication: Personal Access Token (PAT). Set AIRTABLE_PAT environment
variable to your token value (starts with pat...).

To create a PAT:
    1. Go to https://airtable.com/create/tokens
    2. Create a new token
    3. Grant scopes: data.records:read, data.records:write,
       schema.bases:read, schema.bases:write
    4. Add the bases or workspaces you want to access
    5. export AIRTABLE_PAT=<your_token>

Rate limit: Airtable enforces 5 requests/second per base. This worker
implements _rate_limit_wait() using time.monotonic() to stay under the limit.

Capabilities:
    cap.pyhall.airtable.read     — list_bases, list_tables, list_fields,
                                   list_records, get_record, search_records
    cap.pyhall.airtable.write    — create_record, update_record, delete_record,
                                   bulk_create_records, bulk_update_records
    cap.pyhall.airtable.manage   — create_field

All operations:
    list_bases, list_tables, list_records, get_record,
    create_record, update_record, delete_record, search_records,
    list_fields, create_field, bulk_create_records, bulk_update_records

Cross-platform: uses pathlib.Path throughout. No hardcoded POSIX separators.
All timestamps stored UTC ISO 8601, logged Central Time.
"""

from __future__ import annotations

# ============================================================================
# SECTION 1: HEADER + IDENTITY + WCP DECLARATIONS
# ============================================================================

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.airtable.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.airtable"
WORKER_NAME        = "Airtable Database Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.airtable.read",
    "cap.pyhall.airtable.write",
    "cap.pyhall.airtable.manage",
]

ALLOWED_OPS = {
    "list_bases",
    "list_tables",
    "list_records",
    "get_record",
    "create_record",
    "update_record",
    "delete_record",
    "search_records",
    "list_fields",
    "create_field",
    "bulk_create_records",
    "bulk_update_records",
}

# Capability routing: which capability covers each op
_OP_CAPABILITY: Dict[str, str] = {
    "list_bases":          "cap.pyhall.airtable.read",
    "list_tables":         "cap.pyhall.airtable.read",
    "list_records":        "cap.pyhall.airtable.read",
    "get_record":          "cap.pyhall.airtable.read",
    "search_records":      "cap.pyhall.airtable.read",
    "list_fields":         "cap.pyhall.airtable.read",
    "create_record":       "cap.pyhall.airtable.write",
    "update_record":       "cap.pyhall.airtable.write",
    "delete_record":       "cap.pyhall.airtable.write",
    "bulk_create_records": "cap.pyhall.airtable.write",
    "bulk_update_records": "cap.pyhall.airtable.write",
    "create_field":        "cap.pyhall.airtable.manage",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

# Airtable API constants
_AIRTABLE_BASE_URL = "https://api.airtable.com/v0"
_AIRTABLE_META_URL = "https://api.airtable.com/v0/meta"
_RATE_LIMIT_RPS    = 5   # requests per second per base
_BULK_BATCH_SIZE   = 10  # max records per Airtable bulk request


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
class AirtableRecord:
    """Normalized representation of an Airtable record."""
    id: str
    created_time: str
    fields: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "createdTime": self.created_time,
            "fields": self.fields,
        }


@dataclass
class AirtableField:
    """Normalized representation of an Airtable field descriptor."""
    id: str
    name: str
    type: str
    options: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"id": self.id, "name": self.name, "type": self.type}
        if self.options is not None:
            d["options"] = self.options
        return d


# ============================================================================
# SECTION 3: UTILS
# ============================================================================

_CT = ZoneInfo("America/Chicago")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def now_ct() -> str:
    return datetime.now(_CT).strftime("%Y-%m-%d %H:%M:%S CT")


def log(msg: str) -> None:
    print(f"[{now_ct()}] {msg}")


def sha256_hex_bytes(b: bytes) -> str:
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
        log(f"WARNING: {msg} — continuing in dev")
        return {"dev_skip": True, "deny_code": deny_code, "meta": attest_meta}

    log(f"Attestation OK — {attest_meta.get('trust_statement', '')}")
    return attest_meta


_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # code/worker_logic.py → airtable_worker/
_MANIFEST_PATH = _PACKAGE_ROOT / "manifest.json"


# ============================================================================
# SECTION 5: POLICY GATE (FAIL-CLOSED)
# ============================================================================

class PolicyGate:
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

        rule_id = f"rr_airtable_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = (
    Path(os.path.expanduser("~"))
    / ".local" / "share" / "pyhall" / "evidence"
    / f"{WORKER_SPECIES_ID.replace('.', '_')}_chain.log"
)


class AppendOnlyEvidenceLog:
    def __init__(self, log_path: Path):
        self.log_path = log_path

    def emit_evidence(self, receipt: Dict[str, Any]) -> None:
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
_attest_meta: Dict[str, Any] = {}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]


def _make_ctx(op: str, capability_id: Optional[str] = None) -> WCPContext:
    cap = capability_id or _OP_CAPABILITY.get(op, CAPABILITIES[0])
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=cap,
        data_label="INTERNAL",
        tenant_risk="low",
        qos_class="P2",
        requested_at_utc=utc_now_iso(),
    )


def _gate_and_emit(op: str, capability_id: Optional[str] = None) -> Tuple[WCPContext, WCPDecision]:
    ctx = _make_ctx(op, capability_id)
    decision = _policy_gate.evaluate(ctx, {"op": op})
    if not decision.allowed:
        receipt = build_evidence_receipt(
            ctx, decision, "denied", decision.deny_message or "policy deny", op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"POLICY DENY [{decision.deny_code}]: {decision.deny_message}")
        raise SystemExit(1)
    return ctx, decision


# ============================================================================
# SECTION 7: DOMAIN LOGIC — AIRTABLE REST API v0
# ============================================================================

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get_pat() -> str:
    """Read PAT from env. Raise SystemExit(1) if missing."""
    pat_env = os.environ.get("AIRTABLE_PAT_ENV", "AIRTABLE_PAT")
    pat = os.environ.get(pat_env, "").strip()
    if not pat:
        log(f"ERROR: {pat_env} env var not set. Export your Airtable Personal Access Token.")
        raise SystemExit(1)
    return pat


def _get_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {_get_pat()}",
        "Content-Type": "application/json",
    }


def _check_requests_available() -> bool:
    """Return True if the requests library is importable."""
    try:
        import requests  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Rate limiting — 5 req/sec per base (global token bucket via monotonic clock)
# ---------------------------------------------------------------------------

# Track last request timestamp per base_id so we respect the per-base limit.
_last_request_time: Dict[str, float] = {}
_MIN_INTERVAL = 1.0 / _RATE_LIMIT_RPS   # 0.2 seconds between requests per base


def _rate_limit_wait(base_id: str = "__global__") -> None:
    """Sleep if needed to stay under 5 req/sec for the given base_id."""
    now = time.monotonic()
    last = _last_request_time.get(base_id, 0.0)
    elapsed = now - last
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_request_time[base_id] = time.monotonic()


def _airtable_request(
    method: str,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    base_id: str = "__global__",
) -> Dict[str, Any]:
    """
    Execute a rate-limited request to the Airtable API.

    Returns the parsed JSON response dict.
    Raises RuntimeError on HTTP errors (4xx/5xx).
    """
    import requests

    _rate_limit_wait(base_id)

    headers = _get_headers()
    response = requests.request(
        method,
        url,
        headers=headers,
        params=params or {},
        json=json_body,
        timeout=30,
    )

    if not response.ok:
        try:
            err_body = response.json()
        except Exception:
            err_body = response.text
        raise RuntimeError(
            f"Airtable API error {response.status_code}: {err_body}"
        )

    # DELETE 200 may return {"deleted": true, "id": "..."} or empty body
    if response.content:
        return response.json()
    return {}


def _normalize_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return a clean record dict with id, createdTime, fields."""
    return {
        "id": raw.get("id", ""),
        "createdTime": raw.get("createdTime", ""),
        "fields": raw.get("fields", {}),
    }


# ---------------------------------------------------------------------------
# Op: list_bases
# ---------------------------------------------------------------------------

def list_bases() -> List[Dict[str, Any]]:
    """
    List all Airtable bases accessible to this PAT.

    Returns:
        List of base summary dicts: id, name, permissionLevel.

    Evidence receipt includes base count.
    """
    op = "list_bases"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_META_URL}/bases"
        data = _airtable_request("GET", url)
        raw_bases = data.get("bases", [])
        bases = [
            {
                "id": b.get("id", ""),
                "name": b.get("name", ""),
                "permissionLevel": b.get("permissionLevel", ""),
            }
            for b in raw_bases
        ]
        log(f"list_bases: {len(bases)} bases accessible")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"list_bases failed: {exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR list_bases: {exc}")
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_bases: count={len(bases)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return bases


# ---------------------------------------------------------------------------
# Op: list_tables
# ---------------------------------------------------------------------------

def list_tables(base_id: str) -> List[Dict[str, Any]]:
    """
    List all tables in a base, including their field schemas.

    Args:
        base_id: Airtable base ID (starts with app...).

    Returns:
        List of table dicts: id, name, fields (each with id, name, type).

    Evidence receipt includes base_id and table count.
    """
    op = "list_tables"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_META_URL}/bases/{base_id}/tables"
        data = _airtable_request("GET", url, base_id=base_id)
        raw_tables = data.get("tables", [])
        tables = [
            {
                "id": t.get("id", ""),
                "name": t.get("name", ""),
                "fields": [
                    {"id": f.get("id", ""), "name": f.get("name", ""), "type": f.get("type", "")}
                    for f in t.get("fields", [])
                ],
            }
            for t in raw_tables
        ]
        log(f"list_tables: base_id={base_id} tables={len(tables)}")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"list_tables failed: base_id={base_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR list_tables: {exc}")
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_tables: base_id={base_id} count={len(tables)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return tables


# ---------------------------------------------------------------------------
# Op: list_fields
# ---------------------------------------------------------------------------

def list_fields(base_id: str, table_id: str) -> List[Dict[str, Any]]:
    """
    List all fields for a specific table.

    Calls list_tables() internally and extracts the matching table's fields.

    Args:
        base_id:  Airtable base ID.
        table_id: Airtable table ID (tbl...) or table name.

    Returns:
        List of field dicts: id, name, type.

    Evidence receipt includes base_id, table_id, and field count.
    """
    op = "list_fields"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_META_URL}/bases/{base_id}/tables"
        data = _airtable_request("GET", url, base_id=base_id)
        raw_tables = data.get("tables", [])

        # Match by id or name
        target_table: Optional[Dict[str, Any]] = None
        for t in raw_tables:
            if t.get("id") == table_id or t.get("name") == table_id:
                target_table = t
                break

        if target_table is None:
            raise ValueError(f"Table '{table_id}' not found in base '{base_id}'")

        fields = [
            {"id": f.get("id", ""), "name": f.get("name", ""), "type": f.get("type", "")}
            for f in target_table.get("fields", [])
        ]
        log(f"list_fields: base_id={base_id} table_id={table_id} fields={len(fields)}")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"list_fields failed: base_id={base_id} table_id={table_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR list_fields: {exc}")
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_fields: base_id={base_id} table_id={table_id} count={len(fields)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return fields


# ---------------------------------------------------------------------------
# Op: list_records
# ---------------------------------------------------------------------------

def list_records(
    base_id: str,
    table_id: str,
    view: Optional[str] = None,
    max_records: int = 100,
    filter_formula: Optional[str] = None,
    sort: Optional[List[Dict[str, str]]] = None,
) -> List[Dict[str, Any]]:
    """
    List records from a table, with auto-pagination via Airtable's offset cursor.

    Args:
        base_id:        Airtable base ID.
        table_id:       Table ID (tbl...) or table name.
        view:           Optional view name or ID to filter/sort by.
        max_records:    Maximum total records to return (default 100).
                        Pass 0 for no limit (retrieves all records).
        filter_formula: Airtable formula string, e.g. "AND({Status}='Active')".
        sort:           List of sort dicts: [{"field": "Name", "direction": "asc"}].

    Returns:
        List of record dicts: id, createdTime, fields.

    Evidence receipt includes base_id, table_id, and record count.
    """
    op = "list_records"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_BASE_URL}/{base_id}/{table_id}"
        all_records: List[Dict[str, Any]] = []
        offset: Optional[str] = None
        page_size = 100  # Airtable max per page

        while True:
            params: Dict[str, Any] = {"pageSize": page_size}
            if view:
                params["view"] = view
            if filter_formula:
                params["filterByFormula"] = filter_formula
            if offset:
                params["offset"] = offset
            if sort:
                # Airtable expects sort[0][field]=Name&sort[0][direction]=asc
                for i, s in enumerate(sort):
                    params[f"sort[{i}][field]"] = s.get("field", "")
                    params[f"sort[{i}][direction]"] = s.get("direction", "asc")
            if max_records > 0:
                remaining = max_records - len(all_records)
                if remaining <= 0:
                    break
                params["pageSize"] = min(page_size, remaining)

            data = _airtable_request("GET", url, params=params, base_id=base_id)
            records = [_normalize_record(r) for r in data.get("records", [])]
            all_records.extend(records)

            offset = data.get("offset")
            if not offset:
                break
            if max_records > 0 and len(all_records) >= max_records:
                break

        log(f"list_records: base_id={base_id} table_id={table_id} records={len(all_records)}")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"list_records failed: base_id={base_id} table_id={table_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR list_records: {exc}")
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_records: base_id={base_id} table_id={table_id} record_count={len(all_records)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return all_records


# ---------------------------------------------------------------------------
# Op: get_record
# ---------------------------------------------------------------------------

def get_record(base_id: str, table_id: str, record_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single record by ID.

    Args:
        base_id:   Airtable base ID.
        table_id:  Table ID or name.
        record_id: Record ID (rec...).

    Returns:
        Record dict with id, createdTime, fields. None on error.

    Evidence receipt includes base_id, table_id, record_id.
    """
    op = "get_record"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_BASE_URL}/{base_id}/{table_id}/{record_id}"
        raw = _airtable_request("GET", url, base_id=base_id)
        record = _normalize_record(raw)
        log(f"get_record: base_id={base_id} table_id={table_id} record_id={record_id}")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"get_record failed: record_id={record_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR get_record: {exc}")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_record: base_id={base_id} table_id={table_id} record_id={record_id}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return record


# ---------------------------------------------------------------------------
# Op: create_record
# ---------------------------------------------------------------------------

def create_record(
    base_id: str,
    table_id: str,
    fields: Dict[str, Any],
    typecast: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Create a single new record in a table.

    Args:
        base_id:   Airtable base ID.
        table_id:  Table ID or name.
        fields:    Dict mapping field names to values.
        typecast:  If True, Airtable will attempt to coerce value types.

    Returns:
        Created record dict with id, createdTime, fields. None on error.

    Evidence receipt includes base_id, table_id, and new record_id.
    """
    op = "create_record"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_BASE_URL}/{base_id}/{table_id}"
        body: Dict[str, Any] = {"fields": fields, "typecast": typecast}
        raw = _airtable_request("POST", url, json_body=body, base_id=base_id)
        record = _normalize_record(raw)
        log(f"create_record: base_id={base_id} table_id={table_id} new_record_id={record['id']}")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"create_record failed: base_id={base_id} table_id={table_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR create_record: {exc}")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_record: base_id={base_id} table_id={table_id} record_id={record['id']}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return record


# ---------------------------------------------------------------------------
# Op: update_record
# ---------------------------------------------------------------------------

def update_record(
    base_id: str,
    table_id: str,
    record_id: str,
    fields: Dict[str, Any],
    typecast: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Update fields on an existing record (PATCH — only specified fields are changed).

    Args:
        base_id:   Airtable base ID.
        table_id:  Table ID or name.
        record_id: Record ID (rec...).
        fields:    Dict of field names → new values.
        typecast:  If True, Airtable will attempt to coerce value types.

    Returns:
        Updated record dict. None on error.

    Evidence receipt includes base_id, table_id, record_id.
    """
    op = "update_record"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_BASE_URL}/{base_id}/{table_id}/{record_id}"
        body: Dict[str, Any] = {"fields": fields, "typecast": typecast}
        raw = _airtable_request("PATCH", url, json_body=body, base_id=base_id)
        record = _normalize_record(raw)
        log(f"update_record: base_id={base_id} table_id={table_id} record_id={record_id}")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"update_record failed: record_id={record_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR update_record: {exc}")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"update_record: base_id={base_id} table_id={table_id} record_id={record_id}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return record


# ---------------------------------------------------------------------------
# Op: delete_record
# ---------------------------------------------------------------------------

def delete_record(base_id: str, table_id: str, record_id: str) -> Dict[str, Any]:
    """
    Delete a single record.

    Args:
        base_id:   Airtable base ID.
        table_id:  Table ID or name.
        record_id: Record ID (rec...).

    Returns:
        Dict: {"deleted": True, "id": "<record_id>"} on success,
              {"deleted": False, "error": "<message>"} on failure.

    Evidence receipt includes base_id, table_id, record_id.
    """
    op = "delete_record"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_BASE_URL}/{base_id}/{table_id}/{record_id}"
        data = _airtable_request("DELETE", url, base_id=base_id)
        result = {"deleted": data.get("deleted", True), "id": record_id}
        log(f"delete_record: base_id={base_id} table_id={table_id} record_id={record_id} deleted={result['deleted']}")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"delete_record failed: record_id={record_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR delete_record: {exc}")
        return {"deleted": False, "error": str(exc)}

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"delete_record: base_id={base_id} table_id={table_id} record_id={record_id}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


# ---------------------------------------------------------------------------
# Op: search_records
# ---------------------------------------------------------------------------

def search_records(
    base_id: str,
    table_id: str,
    field_name: str,
    value: Any,
) -> List[Dict[str, Any]]:
    """
    Search for records where a field matches a value using filterByFormula.

    Builds the formula automatically:
      - Strings:  {FieldName}="value"
      - Numbers:  {FieldName}=123
      - Booleans: {FieldName}=TRUE() / FALSE()

    Args:
        base_id:    Airtable base ID.
        table_id:   Table ID or name.
        field_name: Exact name of the field to filter on.
        value:      Value to match.

    Returns:
        List of matching record dicts. Empty list on no matches or error.

    Evidence receipt includes base_id, table_id, field_name, and match count.
    """
    op = "search_records"
    ctx, decision = _gate_and_emit(op)

    # Build Airtable filterByFormula
    if isinstance(value, bool):
        formula_value = "TRUE()" if value else "FALSE()"
    elif isinstance(value, (int, float)):
        formula_value = str(value)
    else:
        # Escape any double-quotes in the value
        escaped = str(value).replace('"', '\\"')
        formula_value = f'"{escaped}"'
    formula = f"{{{field_name}}}={formula_value}"

    try:
        records = list_records(
            base_id=base_id,
            table_id=table_id,
            filter_formula=formula,
            max_records=0,  # return all matches
        )
        log(f"search_records: base_id={base_id} table_id={table_id} field={field_name!r} matches={len(records)}")
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"search_records failed: field={field_name!r} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR search_records: {exc}")
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"search_records: base_id={base_id} table_id={table_id} field={field_name!r} match_count={len(records)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return records


# ---------------------------------------------------------------------------
# Op: create_field
# ---------------------------------------------------------------------------

def create_field(
    base_id: str,
    table_id: str,
    name: str,
    field_type: str = "singleLineText",
    options: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Create a new field (column) in a table.

    Args:
        base_id:    Airtable base ID.
        table_id:   Table ID (tbl...) — must be the ID, not name.
        name:       Display name for the new field.
        field_type: Airtable field type string (default: "singleLineText").
                    Examples: "multilineText", "number", "checkbox", "date",
                    "singleSelect", "multipleSelects", "url", "email", "currency".
        options:    Optional field options dict (required for some types, e.g.
                    singleSelect needs {"choices": [{"name": "A"}, {"name": "B"}]}).

    Returns:
        Created field dict with id, name, type (and options if present).
        None on error.

    Evidence receipt includes base_id, table_id, field name, and new field_id.
    """
    op = "create_field"
    ctx, decision = _gate_and_emit(op)

    try:
        url = f"{_AIRTABLE_META_URL}/bases/{base_id}/tables/{table_id}/fields"
        body: Dict[str, Any] = {"name": name, "type": field_type}
        if options is not None:
            body["options"] = options
        raw = _airtable_request("POST", url, json_body=body, base_id=base_id)
        field_dict = {
            "id": raw.get("id", ""),
            "name": raw.get("name", name),
            "type": raw.get("type", field_type),
        }
        if "options" in raw:
            field_dict["options"] = raw["options"]
        log(
            f"create_field: base_id={base_id} table_id={table_id} "
            f"name={name!r} type={field_type} new_field_id={field_dict['id']}"
        )
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"create_field failed: base_id={base_id} table_id={table_id} name={name!r} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR create_field: {exc}")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_field: base_id={base_id} table_id={table_id} name={name!r} field_id={field_dict['id']}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return field_dict


# ---------------------------------------------------------------------------
# Op: bulk_create_records
# ---------------------------------------------------------------------------

def bulk_create_records(
    base_id: str,
    table_id: str,
    records: List[Dict[str, Any]],
    typecast: bool = False,
) -> List[Dict[str, Any]]:
    """
    Create multiple records, automatically batching at 10 per request.

    Args:
        base_id:   Airtable base ID.
        table_id:  Table ID or name.
        records:   List of field dicts (each is a plain {"field": value} dict,
                   NOT wrapped in {"fields": ...}).
        typecast:  If True, Airtable will attempt to coerce value types.

    Returns:
        List of created record dicts. Returns all successfully created records;
        on partial failure, logs error and returns what succeeded.

    Evidence receipt includes base_id, table_id, requested_count, and created_count.
    """
    op = "bulk_create_records"
    ctx, decision = _gate_and_emit(op)

    created: List[Dict[str, Any]] = []
    url = f"{_AIRTABLE_BASE_URL}/{base_id}/{table_id}"

    try:
        # Auto-batch in groups of BULK_BATCH_SIZE
        for batch_start in range(0, len(records), _BULK_BATCH_SIZE):
            batch = records[batch_start: batch_start + _BULK_BATCH_SIZE]
            body: Dict[str, Any] = {
                "records": [{"fields": r} for r in batch],
                "typecast": typecast,
            }
            data = _airtable_request("POST", url, json_body=body, base_id=base_id)
            batch_created = [_normalize_record(r) for r in data.get("records", [])]
            created.extend(batch_created)
            log(
                f"bulk_create_records: batch [{batch_start}–{batch_start + len(batch) - 1}] "
                f"created={len(batch_created)}"
            )

        log(
            f"bulk_create_records: base_id={base_id} table_id={table_id} "
            f"requested={len(records)} created={len(created)}"
        )
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"bulk_create_records failed: base_id={base_id} table_id={table_id} "
            f"requested={len(records)} created_so_far={len(created)} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR bulk_create_records: {exc}")
        return created  # return partial results

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"bulk_create_records: base_id={base_id} table_id={table_id} "
        f"requested_count={len(records)} created_count={len(created)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return created


# ---------------------------------------------------------------------------
# Op: bulk_update_records
# ---------------------------------------------------------------------------

def bulk_update_records(
    base_id: str,
    table_id: str,
    records: List[Dict[str, Any]],
    typecast: bool = False,
) -> List[Dict[str, Any]]:
    """
    Update multiple records, automatically batching at 10 per request.

    Args:
        base_id:   Airtable base ID.
        table_id:  Table ID or name.
        records:   List of update dicts. Each must include:
                   {"id": "rec...", "fields": {"FieldName": value, ...}}
        typecast:  If True, Airtable will attempt to coerce value types.

    Returns:
        List of updated record dicts. Returns all successfully updated records;
        on partial failure, logs error and returns what succeeded.

    Evidence receipt includes base_id, table_id, requested_count, and updated_count.
    """
    op = "bulk_update_records"
    ctx, decision = _gate_and_emit(op)

    updated: List[Dict[str, Any]] = []
    url = f"{_AIRTABLE_BASE_URL}/{base_id}/{table_id}"

    try:
        for batch_start in range(0, len(records), _BULK_BATCH_SIZE):
            batch = records[batch_start: batch_start + _BULK_BATCH_SIZE]
            body: Dict[str, Any] = {
                "records": [
                    {"id": r["id"], "fields": r.get("fields", {})}
                    for r in batch
                ],
                "typecast": typecast,
            }
            data = _airtable_request("PATCH", url, json_body=body, base_id=base_id)
            batch_updated = [_normalize_record(r) for r in data.get("records", [])]
            updated.extend(batch_updated)
            log(
                f"bulk_update_records: batch [{batch_start}–{batch_start + len(batch) - 1}] "
                f"updated={len(batch_updated)}"
            )

        log(
            f"bulk_update_records: base_id={base_id} table_id={table_id} "
            f"requested={len(records)} updated={len(updated)}"
        )
    except Exception as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"bulk_update_records failed: base_id={base_id} table_id={table_id} "
            f"requested={len(records)} updated_so_far={len(updated)} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR bulk_update_records: {exc}")
        return updated  # return partial results

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"bulk_update_records: base_id={base_id} table_id={table_id} "
        f"requested_count={len(records)} updated_count={len(updated)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return updated


# ============================================================================
# SECTION 8: ENTRY POINT + ARGPARSE DISPATCH
# ============================================================================

def _print_result(result: Any, op: str) -> None:
    """Pretty-print a result to stdout as JSON."""
    if result is None:
        print(f"[{op}] No result (see log for errors).")
        return
    try:
        print(json.dumps(result, indent=2, default=str))
    except (TypeError, ValueError):
        print(repr(result))


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        epilog=(
            "Examples:\n"
            "  python3 worker_logic.py list_bases\n"
            "  python3 worker_logic.py list_tables --base-id appXXXXXXXXXXXXXX\n"
            "  python3 worker_logic.py list_fields --base-id appXXX --table-id tblXXX\n"
            "  python3 worker_logic.py list_records --base-id appXXX --table-id tblXXX --max-records 50\n"
            "  python3 worker_logic.py get_record --base-id appXXX --table-id tblXXX --record-id recXXX\n"
            "  python3 worker_logic.py create_record --base-id appXXX --table-id tblXXX "
            "--fields '{\"Name\":\"Alice\",\"Status\":\"Active\"}'\n"
            "  python3 worker_logic.py update_record --base-id appXXX --table-id tblXXX "
            "--record-id recXXX --fields '{\"Status\":\"Done\"}'\n"
            "  python3 worker_logic.py delete_record --base-id appXXX --table-id tblXXX --record-id recXXX\n"
            "  python3 worker_logic.py search_records --base-id appXXX --table-id tblXXX "
            "--field-name Status --value Active\n"
            "  python3 worker_logic.py create_field --base-id appXXX --table-id tblXXX "
            "--field-name Priority --field-type singleSelect "
            "--field-options '{\"choices\":[{\"name\":\"High\"},{\"name\":\"Low\"}]}'\n"
            "  python3 worker_logic.py bulk_create_records --base-id appXXX --table-id tblXXX "
            "--records '[{\"Name\":\"A\"},{\"Name\":\"B\"}]'\n"
            "  python3 worker_logic.py bulk_update_records --base-id appXXX --table-id tblXXX "
            "--records '[{\"id\":\"recXXX\",\"fields\":{\"Status\":\"Done\"}}]'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # --- Shared identifiers ---
    p.add_argument(
        "--base-id", dest="base_id", default=None,
        help="Airtable base ID (app...)",
    )
    p.add_argument(
        "--table-id", dest="table_id", default=None,
        help="Table ID (tbl...) or table name",
    )
    p.add_argument(
        "--record-id", dest="record_id", default=None,
        help="Record ID (rec...) for single-record ops",
    )

    # --- list_records ---
    p.add_argument(
        "--view", dest="view", default=None,
        help="View name or ID (list_records)",
    )
    p.add_argument(
        "--max-records", dest="max_records", type=int, default=100,
        help="Max records to return from list_records (0 = all, default: 100)",
    )
    p.add_argument(
        "--filter-formula", dest="filter_formula", default=None,
        help="Airtable formula string for list_records, e.g. \"AND({Status}='Active')\"",
    )
    p.add_argument(
        "--sort-json", dest="sort_json", default=None,
        help=(
            "JSON list of sort objects for list_records: "
            "'[{\"field\":\"Name\",\"direction\":\"asc\"}]'"
        ),
    )

    # --- create_record / update_record ---
    p.add_argument(
        "--fields", dest="fields_json", default=None,
        help="JSON object of field name→value pairs for create/update ops",
    )
    p.add_argument(
        "--typecast", dest="typecast", action="store_true", default=False,
        help="Enable Airtable typecast coercion for create/update ops",
    )

    # --- search_records ---
    p.add_argument(
        "--field-name", dest="field_name", default=None,
        help="Field name to match on (search_records)",
    )
    p.add_argument(
        "--value", dest="value", default=None,
        help="Value to search for (search_records). Interpreted as number if parseable.",
    )

    # --- create_field ---
    # --field-name is declared above under search_records and is shared with create_field
    p.add_argument(
        "--field-type", dest="field_type", default="singleLineText",
        help="Airtable field type for create_field (default: singleLineText)",
    )
    p.add_argument(
        "--field-options", dest="field_options_json", default=None,
        help="JSON object of field options for create_field",
    )

    # --- bulk ops ---
    p.add_argument(
        "--records", dest="records_json", default=None,
        help=(
            "JSON array for bulk ops. "
            "bulk_create: [{\"Name\":\"A\"}, ...]. "
            "bulk_update: [{\"id\":\"recXXX\", \"fields\":{...}}, ...]."
        ),
    )

    return p


def run() -> None:
    """WCP worker entry point."""
    global _attest_meta

    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    if not _check_requests_available():
        log("ERROR: 'requests' library not installed. Run: pip install requests>=2.28.0")
        raise SystemExit(1)

    args = build_arg_parser().parse_args()
    op = args.op

    # --- Parse JSON args up front ---

    fields_dict: Optional[Dict[str, Any]] = None
    if getattr(args, "fields_json", None):
        try:
            fields_dict = json.loads(args.fields_json)
        except json.JSONDecodeError as e:
            log(f"ERROR: --fields is not valid JSON: {e}")
            raise SystemExit(1)

    sort_list: Optional[List[Dict[str, str]]] = None
    if getattr(args, "sort_json", None):
        try:
            sort_list = json.loads(args.sort_json)
        except json.JSONDecodeError as e:
            log(f"ERROR: --sort-json is not valid JSON: {e}")
            raise SystemExit(1)

    field_options: Optional[Dict[str, Any]] = None
    if getattr(args, "field_options_json", None):
        try:
            field_options = json.loads(args.field_options_json)
        except json.JSONDecodeError as e:
            log(f"ERROR: --field-options is not valid JSON: {e}")
            raise SystemExit(1)

    records_list: Optional[List[Dict[str, Any]]] = None
    if getattr(args, "records_json", None):
        try:
            records_list = json.loads(args.records_json)
        except json.JSONDecodeError as e:
            log(f"ERROR: --records is not valid JSON: {e}")
            raise SystemExit(1)

    # Helper: coerce --value to numeric if possible
    def _coerce_value(raw: Optional[str]) -> Any:
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            pass
        try:
            return float(raw)
        except ValueError:
            pass
        return raw

    # --- Dispatch ---

    if op == "list_bases":
        result = list_bases()
        _print_result(result, op)

    elif op == "list_tables":
        if not args.base_id:
            log("ERROR: --base-id required for list_tables")
            raise SystemExit(1)
        result = list_tables(base_id=args.base_id)
        _print_result(result, op)

    elif op == "list_fields":
        if not args.base_id:
            log("ERROR: --base-id required for list_fields")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for list_fields")
            raise SystemExit(1)
        result = list_fields(base_id=args.base_id, table_id=args.table_id)
        _print_result(result, op)

    elif op == "list_records":
        if not args.base_id:
            log("ERROR: --base-id required for list_records")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for list_records")
            raise SystemExit(1)
        result = list_records(
            base_id=args.base_id,
            table_id=args.table_id,
            view=args.view,
            max_records=args.max_records,
            filter_formula=args.filter_formula,
            sort=sort_list,
        )
        _print_result(result, op)

    elif op == "get_record":
        if not args.base_id:
            log("ERROR: --base-id required for get_record")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for get_record")
            raise SystemExit(1)
        if not args.record_id:
            log("ERROR: --record-id required for get_record")
            raise SystemExit(1)
        result = get_record(
            base_id=args.base_id,
            table_id=args.table_id,
            record_id=args.record_id,
        )
        _print_result(result, op)

    elif op == "create_record":
        if not args.base_id:
            log("ERROR: --base-id required for create_record")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for create_record")
            raise SystemExit(1)
        if not fields_dict:
            log("ERROR: --fields (JSON) required for create_record")
            raise SystemExit(1)
        result = create_record(
            base_id=args.base_id,
            table_id=args.table_id,
            fields=fields_dict,
            typecast=args.typecast,
        )
        _print_result(result, op)

    elif op == "update_record":
        if not args.base_id:
            log("ERROR: --base-id required for update_record")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for update_record")
            raise SystemExit(1)
        if not args.record_id:
            log("ERROR: --record-id required for update_record")
            raise SystemExit(1)
        if not fields_dict:
            log("ERROR: --fields (JSON) required for update_record")
            raise SystemExit(1)
        result = update_record(
            base_id=args.base_id,
            table_id=args.table_id,
            record_id=args.record_id,
            fields=fields_dict,
            typecast=args.typecast,
        )
        _print_result(result, op)

    elif op == "delete_record":
        if not args.base_id:
            log("ERROR: --base-id required for delete_record")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for delete_record")
            raise SystemExit(1)
        if not args.record_id:
            log("ERROR: --record-id required for delete_record")
            raise SystemExit(1)
        result = delete_record(
            base_id=args.base_id,
            table_id=args.table_id,
            record_id=args.record_id,
        )
        _print_result(result, op)

    elif op == "search_records":
        if not args.base_id:
            log("ERROR: --base-id required for search_records")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for search_records")
            raise SystemExit(1)
        if not args.field_name:
            log("ERROR: --field-name required for search_records")
            raise SystemExit(1)
        if args.value is None:
            log("ERROR: --value required for search_records")
            raise SystemExit(1)
        result = search_records(
            base_id=args.base_id,
            table_id=args.table_id,
            field_name=args.field_name,
            value=_coerce_value(args.value),
        )
        _print_result(result, op)

    elif op == "create_field":
        if not args.base_id:
            log("ERROR: --base-id required for create_field")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for create_field")
            raise SystemExit(1)
        if not args.field_name:
            log("ERROR: --field-name required for create_field")
            raise SystemExit(1)
        result = create_field(
            base_id=args.base_id,
            table_id=args.table_id,
            name=args.field_name,
            field_type=args.field_type,
            options=field_options,
        )
        _print_result(result, op)

    elif op == "bulk_create_records":
        if not args.base_id:
            log("ERROR: --base-id required for bulk_create_records")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for bulk_create_records")
            raise SystemExit(1)
        if not records_list:
            log("ERROR: --records (JSON array) required for bulk_create_records")
            raise SystemExit(1)
        result = bulk_create_records(
            base_id=args.base_id,
            table_id=args.table_id,
            records=records_list,
            typecast=args.typecast,
        )
        _print_result(result, op)

    elif op == "bulk_update_records":
        if not args.base_id:
            log("ERROR: --base-id required for bulk_update_records")
            raise SystemExit(1)
        if not args.table_id:
            log("ERROR: --table-id required for bulk_update_records")
            raise SystemExit(1)
        if not records_list:
            log("ERROR: --records (JSON array) required for bulk_update_records")
            raise SystemExit(1)
        result = bulk_update_records(
            base_id=args.base_id,
            table_id=args.table_id,
            records=records_list,
            typecast=args.typecast,
        )
        _print_result(result, op)

    else:
        log(f"ERROR: Unknown op={op!r}")
        raise SystemExit(1)


if __name__ == "__main__":
    run()
