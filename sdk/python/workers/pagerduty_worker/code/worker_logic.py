#!/usr/bin/env python3
"""
worker_logic.py — PagerDuty Worker (WCP v0.3.0)

Incident management, on-call queries, alert triggering, and service operations
via the PagerDuty REST API v2 and Events API v2.

Full WCP-compliant worker package: attested, fail-closed policy gate,
append-only evidence log, deterministic traceability via correlation IDs.

Setup:
    1. Set PAGERDUTY_API_KEY in environment (REST API key from PD admin)
    2. Set PAGERDUTY_ROUTING_KEY for trigger_alert (service integration key)
    3. Set PAGERDUTY_FROM_EMAIL for operations that require a From: header
    4. Optionally set PYHALL_ENV=prod to enforce hard attestation
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
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.pagerduty.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.pagerduty"
WORKER_NAME        = "PagerDuty Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.pagerduty.write",
    "cap.pyhall.pagerduty.read",
    "cap.pyhall.pagerduty.manage",
]

ALLOWED_OPS = {
    "list_incidents",
    "get_incident",
    "create_incident",
    "acknowledge_incident",
    "resolve_incident",
    "list_services",
    "get_service",
    "list_users",
    "get_on_call",
    "trigger_alert",
    "list_escalation_policies",
    "add_note",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# PagerDuty REST API v2 base URL
_PD_BASE_URL = "https://api.pagerduty.com"

# PagerDuty Events API v2 endpoint (used by trigger_alert only)
_PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


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
class PagerDutyIncident:
    incident_id: str
    incident_number: int
    title: str
    status: str
    urgency: str
    created_at: str
    html_url: str
    service_id: Optional[str]
    service_name: Optional[str]
    assigned_to: List[str] = field(default_factory=list)


@dataclass
class PagerDutyService:
    service_id: str
    name: str
    status: str
    description: Optional[str]
    escalation_policy_id: Optional[str]
    escalation_policy_name: Optional[str]


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
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))
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
#   code/worker_logic.py → package root is two levels up (pagerduty_worker/)
_THIS_FILE    = Path(__file__).resolve()
_PACKAGE_ROOT = _THIS_FILE.parent.parent       # .../pagerduty_worker/
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

        rule_id = f"rr_pagerduty_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = Path(os.path.expanduser("~")) / ".local" / "share" / "pyhall" / "evidence" / "wrk_pyhall_pagerduty_chain.log"


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
    """Map an operation to the most appropriate capability ID."""
    read_ops = {"list_incidents", "get_incident", "list_services", "get_service",
                "list_users", "get_on_call", "list_escalation_policies"}
    manage_ops = {"create_incident", "acknowledge_incident", "resolve_incident",
                  "trigger_alert", "add_note"}
    if op in read_ops:
        return "cap.pyhall.pagerduty.read"
    if op in manage_ops:
        return "cap.pyhall.pagerduty.manage"
    return "cap.pyhall.pagerduty.write"


def _make_ctx(op: str, capability_id: Optional[str] = None) -> WCPContext:
    """Build a WCPContext for the given operation."""
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=capability_id or _cap_for_op(op),
        data_label="INTERNAL",
        tenant_risk="medium",
        qos_class="P1",
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
# SECTION 7: DOMAIN LOGIC — PAGERDUTY REST API v2
# ============================================================================

# --- PagerDuty API Client ---

def _get_api_key() -> str:
    """Retrieve PagerDuty REST API key from environment. Fails loudly if missing."""
    key_env = os.environ.get("PAGERDUTY_API_KEY_ENV", "PAGERDUTY_API_KEY")
    key = os.environ.get(key_env, "").strip()
    if not key:
        log(f"ERROR: {key_env} not set — PagerDuty API key required")
        raise SystemExit(1)
    return key


def _get_routing_key() -> str:
    """Retrieve PagerDuty Events API routing key from environment."""
    key_env = os.environ.get("PAGERDUTY_ROUTING_KEY_ENV", "PAGERDUTY_ROUTING_KEY")
    key = os.environ.get(key_env, "").strip()
    if not key:
        log(f"ERROR: {key_env} not set — routing key required for trigger_alert")
        raise SystemExit(1)
    return key


def _get_from_email() -> str:
    """Retrieve From email for PagerDuty write operations."""
    email = os.environ.get("PAGERDUTY_FROM_EMAIL", "").strip()
    if not email:
        log("ERROR: PAGERDUTY_FROM_EMAIL not set — required for write operations")
        raise SystemExit(1)
    return email


def _pd_headers(api_key: str, from_email: Optional[str] = None) -> Dict[str, str]:
    """Build standard PagerDuty API v2 request headers."""
    headers = {
        "Authorization": f"Token token={api_key}",
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Content-Type": "application/json",
    }
    if from_email:
        headers["From"] = from_email
    return headers


def _pd_request(
    method: str,
    path: str,
    api_key: str,
    from_email: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Execute a PagerDuty REST API v2 request.

    Raises SystemExit(1) on 4xx errors, printing the PagerDuty error message.
    Raises SystemExit(1) on network/import errors.

    Returns parsed JSON response dict.
    """
    try:
        import requests
    except ImportError:
        log("ERROR: 'requests' package not installed. Run: pip install requests")
        raise SystemExit(1)

    url = f"{_PD_BASE_URL}{path}"
    headers = _pd_headers(api_key, from_email)

    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            params=params,
            json=body,
            timeout=30,
        )
    except requests.exceptions.ConnectionError as exc:
        log(f"ERROR: Connection failed to PagerDuty API: {exc}")
        raise SystemExit(1)
    except requests.exceptions.Timeout:
        log("ERROR: Request to PagerDuty API timed out (30s)")
        raise SystemExit(1)

    if resp.status_code >= 400:
        # Parse PagerDuty error envelope
        try:
            err_data = resp.json()
            pd_error = err_data.get("error", {})
            code = pd_error.get("code", resp.status_code)
            message = pd_error.get("message", resp.text[:200])
            errors = pd_error.get("errors", [])
            detail = f"{message}"
            if errors:
                detail += f" — {'; '.join(str(e) for e in errors)}"
        except Exception:
            code = resp.status_code
            detail = resp.text[:200]
        log(f"ERROR: PagerDuty API {resp.status_code} [{code}]: {detail}")
        raise SystemExit(1)

    if resp.status_code == 204:
        return {}

    return resp.json()


# --- Incident Operations ---

def list_incidents(
    status: Optional[str] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    """
    List incidents from PagerDuty.

    status: 'triggered' | 'acknowledged' | 'resolved' | None (all)
    limit:  max results to return (default 25)
    """
    ctx, decision = _gate_and_emit("list_incidents")
    api_key = _get_api_key()

    params: Dict[str, Any] = {"limit": limit, "sort_by": "created_at:desc"}
    if status:
        if status not in ("triggered", "acknowledged", "resolved"):
            log(f"ERROR: invalid status {status!r} — must be triggered/acknowledged/resolved")
            raise SystemExit(1)
        params["statuses[]"] = status

    log(f"list_incidents: status={status or 'all'} limit={limit}")
    data = _pd_request("GET", "/incidents", api_key, params=params)

    incidents = data.get("incidents", [])
    result: Dict[str, Any] = {
        "count": len(incidents),
        "incidents": [
            {
                "id": inc.get("id"),
                "incident_number": inc.get("incident_number"),
                "title": inc.get("title"),
                "status": inc.get("status"),
                "urgency": inc.get("urgency"),
                "created_at": inc.get("created_at"),
                "html_url": inc.get("html_url"),
                "service": inc.get("service", {}).get("summary"),
                "assigned_to": [
                    a.get("assignee", {}).get("summary")
                    for a in inc.get("assignments", [])
                ],
            }
            for inc in incidents
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_incidents: {len(incidents)} returned (status={status or 'all'})",
        "list_incidents", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(incidents)} incident(s) returned")
    return result


def get_incident(incident_id: str) -> Dict[str, Any]:
    """Fetch a single incident by ID."""
    ctx, decision = _gate_and_emit("get_incident")
    api_key = _get_api_key()

    if not incident_id:
        log("ERROR: incident_id is required")
        raise SystemExit(1)

    log(f"get_incident: {incident_id}")
    data = _pd_request("GET", f"/incidents/{incident_id}", api_key)
    inc = data.get("incident", {})

    result = {
        "id": inc.get("id"),
        "incident_number": inc.get("incident_number"),
        "title": inc.get("title"),
        "status": inc.get("status"),
        "urgency": inc.get("urgency"),
        "created_at": inc.get("created_at"),
        "resolved_at": inc.get("resolved_at"),
        "html_url": inc.get("html_url"),
        "service": {
            "id": inc.get("service", {}).get("id"),
            "name": inc.get("service", {}).get("summary"),
        },
        "assigned_to": [
            {
                "id": a.get("assignee", {}).get("id"),
                "name": a.get("assignee", {}).get("summary"),
            }
            for a in inc.get("assignments", [])
        ],
        "last_status_change_at": inc.get("last_status_change_at"),
        "description": inc.get("description", ""),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_incident: {incident_id} status={inc.get('status')}",
        "get_incident", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


def create_incident(
    title: str,
    service_id: str,
    urgency: str = "high",
    body: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new PagerDuty incident.

    title:      Incident title (required)
    service_id: PagerDuty service ID (required)
    urgency:    'high' | 'low' (default: 'high')
    body:       Optional incident details / description
    """
    ctx, decision = _gate_and_emit("create_incident")
    api_key = _get_api_key()
    from_email = _get_from_email()

    if not title:
        log("ERROR: title is required")
        raise SystemExit(1)
    if not service_id:
        log("ERROR: service_id is required")
        raise SystemExit(1)
    if urgency not in ("high", "low"):
        log(f"ERROR: urgency must be 'high' or 'low', got {urgency!r}")
        raise SystemExit(1)

    payload: Dict[str, Any] = {
        "incident": {
            "type": "incident",
            "title": title,
            "service": {"id": service_id, "type": "service_reference"},
            "urgency": urgency,
        }
    }
    if body:
        payload["incident"]["body"] = {"type": "incident_body", "details": body}

    log(f"create_incident: {title!r} service={service_id} urgency={urgency}")
    data = _pd_request("POST", "/incidents", api_key, from_email=from_email, body=payload)
    inc = data.get("incident", {})

    result = {
        "id": inc.get("id"),
        "incident_number": inc.get("incident_number"),
        "title": inc.get("title"),
        "status": inc.get("status"),
        "urgency": inc.get("urgency"),
        "html_url": inc.get("html_url"),
        "created_at": inc.get("created_at"),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_incident: #{inc.get('incident_number')} '{title}' id={inc.get('id')}",
        "create_incident", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Created incident #{inc.get('incident_number')}: {inc.get('id')}")
    return result


def acknowledge_incident(incident_id: str, from_email: Optional[str] = None) -> Dict[str, Any]:
    """
    Acknowledge an open incident.

    incident_id: PagerDuty incident ID
    from_email:  Override for From header (uses env var if not provided)
    """
    ctx, decision = _gate_and_emit("acknowledge_incident")
    api_key = _get_api_key()
    email = from_email or _get_from_email()

    if not incident_id:
        log("ERROR: incident_id is required")
        raise SystemExit(1)

    payload = {
        "incident": {
            "type": "incident_reference",
            "status": "acknowledged",
        }
    }

    log(f"acknowledge_incident: {incident_id}")
    data = _pd_request("PUT", f"/incidents/{incident_id}", api_key, from_email=email, body=payload)
    inc = data.get("incident", {})

    result = {
        "id": inc.get("id"),
        "incident_number": inc.get("incident_number"),
        "status": inc.get("status"),
        "last_status_change_at": inc.get("last_status_change_at"),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"acknowledge_incident: {incident_id} -> acknowledged",
        "acknowledge_incident", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Acknowledged incident #{inc.get('incident_number')}")
    return result


def resolve_incident(incident_id: str, from_email: Optional[str] = None) -> Dict[str, Any]:
    """
    Resolve an incident.

    incident_id: PagerDuty incident ID
    from_email:  Override for From header (uses env var if not provided)
    """
    ctx, decision = _gate_and_emit("resolve_incident")
    api_key = _get_api_key()
    email = from_email or _get_from_email()

    if not incident_id:
        log("ERROR: incident_id is required")
        raise SystemExit(1)

    payload = {
        "incident": {
            "type": "incident_reference",
            "status": "resolved",
        }
    }

    log(f"resolve_incident: {incident_id}")
    data = _pd_request("PUT", f"/incidents/{incident_id}", api_key, from_email=email, body=payload)
    inc = data.get("incident", {})

    result = {
        "id": inc.get("id"),
        "incident_number": inc.get("incident_number"),
        "status": inc.get("status"),
        "resolved_at": inc.get("resolved_at"),
        "last_status_change_at": inc.get("last_status_change_at"),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"resolve_incident: {incident_id} -> resolved",
        "resolve_incident", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Resolved incident #{inc.get('incident_number')}")
    return result


def add_note(incident_id: str, content: str) -> Dict[str, Any]:
    """
    Add a note to an incident.

    incident_id: PagerDuty incident ID
    content:     Note text (required)
    """
    ctx, decision = _gate_and_emit("add_note")
    api_key = _get_api_key()
    from_email = _get_from_email()

    if not incident_id:
        log("ERROR: incident_id is required")
        raise SystemExit(1)
    if not content:
        log("ERROR: content is required")
        raise SystemExit(1)

    payload = {"note": {"content": content}}

    log(f"add_note: incident={incident_id}")
    data = _pd_request(
        "POST", f"/incidents/{incident_id}/notes",
        api_key, from_email=from_email, body=payload,
    )
    note = data.get("note", {})

    result = {
        "id": note.get("id"),
        "content": note.get("content"),
        "created_at": note.get("created_at"),
        "user": note.get("user", {}).get("summary"),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"add_note: incident={incident_id} note_id={note.get('id')}",
        "add_note", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Note added: {note.get('id')}")
    return result


# --- Service Operations ---

def list_services(limit: int = 25) -> Dict[str, Any]:
    """List PagerDuty services."""
    ctx, decision = _gate_and_emit("list_services")
    api_key = _get_api_key()

    log(f"list_services: limit={limit}")
    data = _pd_request("GET", "/services", api_key, params={"limit": limit})

    services = data.get("services", [])
    result = {
        "count": len(services),
        "services": [
            {
                "id": svc.get("id"),
                "name": svc.get("name"),
                "status": svc.get("status"),
                "description": svc.get("description", ""),
                "escalation_policy": svc.get("escalation_policy", {}).get("summary"),
            }
            for svc in services
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_services: {len(services)} returned",
        "list_services", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(services)} service(s) returned")
    return result


def get_service(service_id: str) -> Dict[str, Any]:
    """Fetch a single service by ID."""
    ctx, decision = _gate_and_emit("get_service")
    api_key = _get_api_key()

    if not service_id:
        log("ERROR: service_id is required")
        raise SystemExit(1)

    log(f"get_service: {service_id}")
    data = _pd_request("GET", f"/services/{service_id}", api_key)
    svc = data.get("service", {})

    result = {
        "id": svc.get("id"),
        "name": svc.get("name"),
        "status": svc.get("status"),
        "description": svc.get("description", ""),
        "created_at": svc.get("created_at"),
        "escalation_policy": {
            "id": svc.get("escalation_policy", {}).get("id"),
            "name": svc.get("escalation_policy", {}).get("summary"),
        },
        "teams": [t.get("summary") for t in svc.get("teams", [])],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_service: {service_id} name={svc.get('name')}",
        "get_service", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


# --- User / On-Call Operations ---

def list_users(limit: int = 25) -> Dict[str, Any]:
    """List PagerDuty users."""
    ctx, decision = _gate_and_emit("list_users")
    api_key = _get_api_key()

    log(f"list_users: limit={limit}")
    data = _pd_request("GET", "/users", api_key, params={"limit": limit})

    users = data.get("users", [])
    result = {
        "count": len(users),
        "users": [
            {
                "id": u.get("id"),
                "name": u.get("name"),
                "email": u.get("email"),
                "role": u.get("role"),
                "time_zone": u.get("time_zone"),
            }
            for u in users
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_users: {len(users)} returned",
        "list_users", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(users)} user(s) returned")
    return result


def get_on_call(escalation_policy_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Return currently on-call users.

    escalation_policy_id: Optional — filter by escalation policy.
                          Returns all on-calls if not provided.
    """
    ctx, decision = _gate_and_emit("get_on_call")
    api_key = _get_api_key()

    params: Dict[str, Any] = {}
    if escalation_policy_id:
        params["escalation_policy_ids[]"] = escalation_policy_id

    log(f"get_on_call: escalation_policy_id={escalation_policy_id or 'all'}")
    data = _pd_request("GET", "/oncalls", api_key, params=params)

    oncalls = data.get("oncalls", [])
    result = {
        "count": len(oncalls),
        "oncalls": [
            {
                "user": {
                    "id": oc.get("user", {}).get("id"),
                    "name": oc.get("user", {}).get("summary"),
                },
                "schedule": oc.get("schedule", {}).get("summary"),
                "escalation_policy": oc.get("escalation_policy", {}).get("summary"),
                "escalation_level": oc.get("escalation_level"),
                "start": oc.get("start"),
                "end": oc.get("end"),
            }
            for oc in oncalls
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_on_call: {len(oncalls)} on-call entries returned",
        "get_on_call", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(oncalls)} on-call entry/entries returned")
    return result


# --- Escalation Policies ---

def list_escalation_policies() -> Dict[str, Any]:
    """List all escalation policies."""
    ctx, decision = _gate_and_emit("list_escalation_policies")
    api_key = _get_api_key()

    log("list_escalation_policies")
    data = _pd_request("GET", "/escalation_policies", api_key)

    policies = data.get("escalation_policies", [])
    result = {
        "count": len(policies),
        "escalation_policies": [
            {
                "id": ep.get("id"),
                "name": ep.get("name"),
                "description": ep.get("description", ""),
                "num_loops": ep.get("num_loops", 0),
                "teams": [t.get("summary") for t in ep.get("teams", [])],
            }
            for ep in policies
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_escalation_policies: {len(policies)} returned",
        "list_escalation_policies", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(policies)} escalation policy/policies returned")
    return result


# --- Events API v2 ---

def trigger_alert(
    routing_key: Optional[str] = None,
    summary: str = "",
    severity: str = "critical",
    source: Optional[str] = None,
    custom_details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Trigger an alert via PagerDuty Events API v2.

    Uses PAGERDUTY_ROUTING_KEY env var (service integration key) — NOT the REST API key.

    routing_key:    Override routing key (uses env var if not provided)
    summary:        Event summary / description (required)
    severity:       'critical' | 'error' | 'warning' | 'info' (default: 'critical')
    source:         Machine/service that originated the event (optional)
    custom_details: Additional key/value details (optional dict)
    """
    ctx, decision = _gate_and_emit("trigger_alert")

    rkey = routing_key or _get_routing_key()

    if not summary:
        log("ERROR: summary is required for trigger_alert")
        raise SystemExit(1)
    if severity not in ("critical", "error", "warning", "info"):
        log(f"ERROR: severity must be critical/error/warning/info, got {severity!r}")
        raise SystemExit(1)

    try:
        import requests
    except ImportError:
        log("ERROR: 'requests' package not installed. Run: pip install requests")
        raise SystemExit(1)

    payload: Dict[str, Any] = {
        "routing_key": rkey,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": source or "pyhall-pagerduty-worker",
            "timestamp": utc_now_iso(),
        },
    }
    if custom_details:
        payload["payload"]["custom_details"] = custom_details

    log(f"trigger_alert: severity={severity} summary={summary!r}")

    try:
        resp = requests.post(
            _PD_EVENTS_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
    except requests.exceptions.ConnectionError as exc:
        log(f"ERROR: Connection failed to PagerDuty Events API: {exc}")
        raise SystemExit(1)
    except requests.exceptions.Timeout:
        log("ERROR: Request to PagerDuty Events API timed out (30s)")
        raise SystemExit(1)

    if resp.status_code not in (200, 201, 202):
        try:
            err = resp.json()
            msg = err.get("message", resp.text[:200])
            errors = err.get("errors", [])
        except Exception:
            msg = resp.text[:200]
            errors = []
        detail = f"{msg}"
        if errors:
            detail += f" — {'; '.join(str(e) for e in errors)}"
        log(f"ERROR: Events API {resp.status_code}: {detail}")
        raise SystemExit(1)

    data = resp.json()
    result = {
        "status": data.get("status"),
        "message": data.get("message"),
        "dedup_key": data.get("dedup_key"),
        "severity": severity,
        "summary": summary,
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"trigger_alert: severity={severity} dedup_key={data.get('dedup_key')}",
        "trigger_alert", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Alert triggered: dedup_key={data.get('dedup_key')}")
    return result


# --- Output helpers ---

def _print_result(result: Dict[str, Any]) -> None:
    """Print result as formatted JSON."""
    print(json.dumps(result, indent=2, default=str))


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        epilog=(
            "Examples:\n"
            "  python3 worker_logic.py list_incidents\n"
            "  python3 worker_logic.py list_incidents --status triggered\n"
            "  python3 worker_logic.py get_incident --incident-id P123ABC\n"
            "  python3 worker_logic.py create_incident --title 'DB down' --service-id SVCID123\n"
            "  python3 worker_logic.py acknowledge_incident --incident-id P123ABC\n"
            "  python3 worker_logic.py resolve_incident --incident-id P123ABC\n"
            "  python3 worker_logic.py add_note --incident-id P123ABC --content 'Looking into it'\n"
            "  python3 worker_logic.py list_services\n"
            "  python3 worker_logic.py get_service --service-id SVCID123\n"
            "  python3 worker_logic.py list_users\n"
            "  python3 worker_logic.py get_on_call\n"
            "  python3 worker_logic.py get_on_call --escalation-policy-id EPID123\n"
            "  python3 worker_logic.py list_escalation_policies\n"
            "  python3 worker_logic.py trigger_alert --summary 'CPU spike 99%' --severity critical\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # Incident args
    p.add_argument("--incident-id", dest="incident_id", metavar="ID",
                   help="PagerDuty incident ID")
    p.add_argument("--title", dest="title", metavar="TEXT",
                   help="Incident title (create_incident)")
    p.add_argument("--service-id", dest="service_id", metavar="ID",
                   help="PagerDuty service ID (create_incident, get_service)")
    p.add_argument("--urgency", dest="urgency", choices=["high", "low"], default="high",
                   help="Incident urgency (default: high)")
    p.add_argument("--body", dest="body", metavar="TEXT",
                   help="Incident body/details (create_incident)")
    p.add_argument("--status", dest="status",
                   choices=["triggered", "acknowledged", "resolved"],
                   help="Filter incidents by status (list_incidents)")
    p.add_argument("--limit", dest="limit", type=int, default=25,
                   help="Max results to return (default: 25)")
    p.add_argument("--from-email", dest="from_email", metavar="EMAIL",
                   help="Override From email for write operations")
    p.add_argument("--content", dest="content", metavar="TEXT",
                   help="Note content (add_note)")

    # On-call args
    p.add_argument("--escalation-policy-id", dest="escalation_policy_id", metavar="ID",
                   help="Filter on-calls by escalation policy ID (get_on_call)")

    # Events API args
    p.add_argument("--routing-key", dest="routing_key", metavar="KEY",
                   help="Override routing key for trigger_alert")
    p.add_argument("--summary", dest="summary", metavar="TEXT",
                   help="Alert summary (trigger_alert)")
    p.add_argument("--severity", dest="severity",
                   choices=["critical", "error", "warning", "info"], default="critical",
                   help="Alert severity (trigger_alert, default: critical)")
    p.add_argument("--source", dest="source", metavar="TEXT",
                   help="Alert source (trigger_alert)")
    p.add_argument("--custom-details", dest="custom_details", metavar="JSON",
                   help="JSON string of custom details (trigger_alert)")

    return p


def run() -> None:
    """WCP worker entry point."""
    global _attest_meta

    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    args = build_arg_parser().parse_args()
    op = args.op

    # Dispatch
    if op == "list_incidents":
        result = list_incidents(status=args.status, limit=args.limit)
        _print_result(result)

    elif op == "get_incident":
        if not args.incident_id:
            log("ERROR: --incident-id required for get_incident")
            raise SystemExit(1)
        result = get_incident(args.incident_id)
        _print_result(result)

    elif op == "create_incident":
        if not args.title:
            log("ERROR: --title required for create_incident")
            raise SystemExit(1)
        if not args.service_id:
            log("ERROR: --service-id required for create_incident")
            raise SystemExit(1)
        result = create_incident(
            title=args.title,
            service_id=args.service_id,
            urgency=args.urgency,
            body=args.body,
        )
        _print_result(result)

    elif op == "acknowledge_incident":
        if not args.incident_id:
            log("ERROR: --incident-id required for acknowledge_incident")
            raise SystemExit(1)
        result = acknowledge_incident(args.incident_id, from_email=args.from_email)
        _print_result(result)

    elif op == "resolve_incident":
        if not args.incident_id:
            log("ERROR: --incident-id required for resolve_incident")
            raise SystemExit(1)
        result = resolve_incident(args.incident_id, from_email=args.from_email)
        _print_result(result)

    elif op == "add_note":
        if not args.incident_id:
            log("ERROR: --incident-id required for add_note")
            raise SystemExit(1)
        if not args.content:
            log("ERROR: --content required for add_note")
            raise SystemExit(1)
        result = add_note(args.incident_id, args.content)
        _print_result(result)

    elif op == "list_services":
        result = list_services(limit=args.limit)
        _print_result(result)

    elif op == "get_service":
        if not args.service_id:
            log("ERROR: --service-id required for get_service")
            raise SystemExit(1)
        result = get_service(args.service_id)
        _print_result(result)

    elif op == "list_users":
        result = list_users(limit=args.limit)
        _print_result(result)

    elif op == "get_on_call":
        result = get_on_call(escalation_policy_id=args.escalation_policy_id)
        _print_result(result)

    elif op == "list_escalation_policies":
        result = list_escalation_policies()
        _print_result(result)

    elif op == "trigger_alert":
        if not args.summary:
            log("ERROR: --summary required for trigger_alert")
            raise SystemExit(1)
        custom_details: Optional[Dict[str, Any]] = None
        if args.custom_details:
            try:
                custom_details = json.loads(args.custom_details)
            except json.JSONDecodeError as exc:
                log(f"ERROR: --custom-details is not valid JSON: {exc}")
                raise SystemExit(1)
        result = trigger_alert(
            routing_key=args.routing_key,
            summary=args.summary,
            severity=args.severity,
            source=args.source,
            custom_details=custom_details,
        )
        _print_result(result)

    else:
        log(f"ERROR: unhandled op {op!r}")
        raise SystemExit(1)


if __name__ == "__main__":
    run()
