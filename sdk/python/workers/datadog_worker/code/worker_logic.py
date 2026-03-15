#!/usr/bin/env python3
"""
worker_logic.py — Datadog Monitoring Worker (WCP v0.3.0)

Monitor management, dashboard queries, incident tracking, metric submission,
and event management via the Datadog REST API v1/v2.

Key capability: submit_worker_metrics — governance-as-observability. Posts WCP
worker telemetry (dispatch count, attestation status, policy decisions, evidence
chain length) as custom Datadog metrics, enabling SREs to build Datadog monitors
on AI worker trust levels.

Full WCP-compliant worker package: attested, fail-closed policy gate,
append-only evidence log, deterministic traceability via correlation IDs.

Setup:
    1. Set DATADOG_API_KEY in environment (Datadog API key)
    2. Set DATADOG_APP_KEY in environment (Datadog Application key)
    3. Optionally set DATADOG_SITE to override API host (e.g. datadoghq.eu)
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
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.datadog.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.datadog"
WORKER_NAME        = "Datadog Monitoring Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.datadog.read",
    "cap.pyhall.datadog.write",
    "cap.pyhall.datadog.manage",
]

ALLOWED_OPS = {
    "list_monitors",
    "get_monitor",
    "create_monitor",
    "mute_monitor",
    "list_dashboards",
    "get_dashboard",
    "list_incidents",
    "get_incident",
    "submit_metric",
    "submit_worker_metrics",
    "list_events",
    "create_event",
    "query_metrics",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# Datadog API v1 base URL (host overridable via DATADOG_SITE env var)
_DD_DEFAULT_SITE = "datadoghq.com"
_DD_V1_BASE      = "https://api.{site}/api/v1"
_DD_V2_BASE      = "https://api.{site}/api/v2"


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
class DatadogMonitor:
    monitor_id: int
    name: str
    monitor_type: str
    status: str
    query: str
    tags: List[str] = field(default_factory=list)
    created: Optional[str] = None
    modified: Optional[str] = None
    message: Optional[str] = None


@dataclass
class DatadogDashboard:
    dashboard_id: str
    title: str
    url: str
    layout_type: Optional[str] = None
    created_at: Optional[str] = None
    modified_at: Optional[str] = None
    author_name: Optional[str] = None


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


def unix_ts_now() -> int:
    """Return current Unix timestamp as integer."""
    return int(datetime.now(timezone.utc).timestamp())


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
#   code/worker_logic.py → package root is two levels up (datadog_worker/)
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent       # .../datadog_worker/
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

        rule_id = f"rr_datadog_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = (
    Path(os.path.expanduser("~"))
    / ".local" / "share" / "pyhall" / "evidence"
    / "wrk_pyhall_datadog_chain.log"
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

    def count_entries(self) -> int:
        """Return the number of entries in the evidence log."""
        try:
            if not self.log_path.exists() or self.log_path.stat().st_size == 0:
                return 0
            return sum(1 for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip())
        except Exception:
            return 0


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
    read_ops = {
        "list_monitors", "get_monitor", "list_dashboards", "get_dashboard",
        "list_incidents", "get_incident", "list_events", "query_metrics",
    }
    write_ops = {
        "submit_metric", "submit_worker_metrics", "create_event",
    }
    manage_ops = {
        "create_monitor", "mute_monitor",
    }
    if op in read_ops:
        return "cap.pyhall.datadog.read"
    if op in write_ops:
        return "cap.pyhall.datadog.write"
    if op in manage_ops:
        return "cap.pyhall.datadog.manage"
    return "cap.pyhall.datadog.read"


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
# SECTION 7: DOMAIN LOGIC — DATADOG REST API v1/v2
# ============================================================================

# --- Datadog API Client ---

def _get_dd_site() -> str:
    """Return the Datadog API hostname, using DATADOG_SITE env var or default."""
    site = os.environ.get("DATADOG_SITE", "").strip()
    return site if site else _DD_DEFAULT_SITE


def _get_api_key() -> str:
    """Retrieve Datadog API key from environment. Fails loudly if missing."""
    key_env = os.environ.get("DATADOG_API_KEY_ENV", "DATADOG_API_KEY")
    key = os.environ.get(key_env, "").strip()
    if not key:
        log(f"ERROR: {key_env} not set — Datadog API key required")
        raise SystemExit(1)
    return key


def _get_app_key() -> str:
    """Retrieve Datadog Application key from environment. Fails loudly if missing."""
    key_env = os.environ.get("DATADOG_APP_KEY_ENV", "DATADOG_APP_KEY")
    key = os.environ.get(key_env, "").strip()
    if not key:
        log(f"ERROR: {key_env} not set — Datadog Application key required")
        raise SystemExit(1)
    return key


def _dd_headers(api_key: str, app_key: str) -> Dict[str, str]:
    """Build standard Datadog API request headers."""
    return {
        "DD-API-KEY": api_key,
        "DD-APPLICATION-KEY": app_key,
        "Content-Type": "application/json",
    }


def _dd_request(
    method: str,
    path: str,
    api_key: str,
    app_key: str,
    params: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    api_version: str = "v1",
) -> Dict[str, Any]:
    """
    Execute a Datadog REST API request.

    api_version: 'v1' (default) or 'v2' — determines base URL.
    Raises SystemExit(1) on 4xx/5xx errors or network failures.
    Returns parsed JSON response dict.
    """
    try:
        import requests
    except ImportError:
        log("ERROR: 'requests' package not installed. Run: pip install requests")
        raise SystemExit(1)

    site = _get_dd_site()
    if api_version == "v2":
        base = _DD_V2_BASE.format(site=site)
    else:
        base = _DD_V1_BASE.format(site=site)

    url = f"{base}{path}"
    headers = _dd_headers(api_key, app_key)

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
        log(f"ERROR: Connection failed to Datadog API ({site}): {exc}")
        raise SystemExit(1)
    except requests.exceptions.Timeout:
        log("ERROR: Request to Datadog API timed out (30s)")
        raise SystemExit(1)

    if resp.status_code >= 400:
        try:
            err_data = resp.json()
            errors = err_data.get("errors", [])
            message = err_data.get("message", "")
            if not message and errors:
                message = "; ".join(str(e) for e in errors)
            if not message:
                message = resp.text[:300]
        except Exception:
            message = resp.text[:300]
        log(f"ERROR: Datadog API {resp.status_code}: {message}")
        raise SystemExit(1)

    if resp.status_code == 204:
        return {}

    try:
        return resp.json()
    except Exception:
        return {}


# --- Monitor Operations ---

def list_monitors(
    tags: Optional[List[str]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    List monitors from Datadog.

    tags:  Optional list of tag strings to filter by (e.g. ['env:prod', 'team:sre'])
    limit: Max results to return (default 100)
    """
    ctx, decision = _gate_and_emit("list_monitors")
    api_key = _get_api_key()
    app_key = _get_app_key()

    params: Dict[str, Any] = {"count": limit, "start": 0}
    if tags:
        params["monitor_tags"] = ",".join(tags)

    log(f"list_monitors: tags={tags} limit={limit}")
    data = _dd_request("GET", "/monitor", api_key, app_key, params=params)

    # Datadog returns a list for /monitor, not a dict
    monitors_raw: List[Dict[str, Any]] = data if isinstance(data, list) else []
    result: Dict[str, Any] = {
        "count": len(monitors_raw),
        "monitors": [
            {
                "id": m.get("id"),
                "name": m.get("name"),
                "type": m.get("type"),
                "status": m.get("overall_state"),
                "query": m.get("query"),
                "tags": m.get("tags", []),
                "created": m.get("created"),
                "modified": m.get("modified"),
            }
            for m in monitors_raw
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_monitors: {len(monitors_raw)} returned (tags={tags})",
        "list_monitors", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(monitors_raw)} monitor(s) returned")
    return result


def get_monitor(monitor_id: int) -> Dict[str, Any]:
    """Fetch a single monitor by ID."""
    ctx, decision = _gate_and_emit("get_monitor")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not monitor_id:
        log("ERROR: monitor_id is required")
        raise SystemExit(1)

    log(f"get_monitor: {monitor_id}")
    m = _dd_request("GET", f"/monitor/{monitor_id}", api_key, app_key)

    result = {
        "id": m.get("id"),
        "name": m.get("name"),
        "type": m.get("type"),
        "status": m.get("overall_state"),
        "query": m.get("query"),
        "message": m.get("message", ""),
        "tags": m.get("tags", []),
        "priority": m.get("priority"),
        "created": m.get("created"),
        "modified": m.get("modified"),
        "creator": m.get("creator", {}).get("name"),
        "options": m.get("options", {}),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_monitor: id={monitor_id} status={m.get('overall_state')}",
        "get_monitor", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


def create_monitor(
    name: str,
    monitor_type: str,
    query: str,
    message: Optional[str] = None,
    tags: Optional[List[str]] = None,
    priority: int = 3,
) -> Dict[str, Any]:
    """
    Create a new Datadog monitor.

    name:         Monitor name (required)
    monitor_type: 'metric alert' | 'service check' | 'event alert' | 'query alert' etc.
    query:        Monitor query string (required)
    message:      Notification message (optional)
    tags:         List of tag strings to apply to the monitor
    priority:     Monitor priority 1-5 (default 3)
    """
    ctx, decision = _gate_and_emit("create_monitor")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not name:
        log("ERROR: name is required for create_monitor")
        raise SystemExit(1)
    if not monitor_type:
        log("ERROR: type is required for create_monitor")
        raise SystemExit(1)
    if not query:
        log("ERROR: query is required for create_monitor")
        raise SystemExit(1)
    if priority not in range(1, 6):
        log(f"ERROR: priority must be 1-5, got {priority!r}")
        raise SystemExit(1)

    body: Dict[str, Any] = {
        "name": name,
        "type": monitor_type,
        "query": query,
        "priority": priority,
    }
    if message:
        body["message"] = message
    if tags:
        body["tags"] = tags

    log(f"create_monitor: name={name!r} type={monitor_type!r}")
    m = _dd_request("POST", "/monitor", api_key, app_key, body=body)

    result = {
        "id": m.get("id"),
        "name": m.get("name"),
        "type": m.get("type"),
        "status": m.get("overall_state"),
        "query": m.get("query"),
        "tags": m.get("tags", []),
        "created": m.get("created"),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_monitor: id={m.get('id')} name={name!r} type={monitor_type!r}",
        "create_monitor", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Monitor created: id={m.get('id')}")
    return result


def mute_monitor(
    monitor_id: int,
    end_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Mute a Datadog monitor.

    monitor_id: Datadog monitor ID (required)
    end_ts:     Unix timestamp when mute ends (optional, mutes indefinitely if omitted)
    """
    ctx, decision = _gate_and_emit("mute_monitor")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not monitor_id:
        log("ERROR: monitor_id is required for mute_monitor")
        raise SystemExit(1)

    body: Dict[str, Any] = {}
    if end_ts is not None:
        body["end"] = end_ts

    log(f"mute_monitor: id={monitor_id} end_ts={end_ts}")
    m = _dd_request("POST", f"/monitor/{monitor_id}/mute", api_key, app_key, body=body)

    result = {
        "id": m.get("id"),
        "name": m.get("name"),
        "status": m.get("overall_state"),
        "muted": True,
        "end_ts": end_ts,
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"mute_monitor: id={monitor_id} end_ts={end_ts}",
        "mute_monitor", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Monitor {monitor_id} muted")
    return result


# --- Dashboard Operations ---

def list_dashboards(limit: int = 50) -> Dict[str, Any]:
    """
    List dashboards from Datadog.

    limit: Max results to return (default 50)
    """
    ctx, decision = _gate_and_emit("list_dashboards")
    api_key = _get_api_key()
    app_key = _get_app_key()

    log(f"list_dashboards: limit={limit}")
    # Datadog returns {"dashboards": [...]}
    data = _dd_request("GET", "/dashboard", api_key, app_key)

    dashboards_raw = data.get("dashboards", [])[:limit]
    result: Dict[str, Any] = {
        "count": len(dashboards_raw),
        "dashboards": [
            {
                "id": d.get("id"),
                "title": d.get("title"),
                "url": d.get("url"),
                "layout_type": d.get("layout_type"),
                "created_at": d.get("created_at"),
                "modified_at": d.get("modified_at"),
                "author_name": d.get("author_name"),
            }
            for d in dashboards_raw
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_dashboards: {len(dashboards_raw)} returned",
        "list_dashboards", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(dashboards_raw)} dashboard(s) returned")
    return result


def get_dashboard(dashboard_id: str) -> Dict[str, Any]:
    """Fetch a single dashboard by ID."""
    ctx, decision = _gate_and_emit("get_dashboard")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not dashboard_id:
        log("ERROR: dashboard_id is required")
        raise SystemExit(1)

    log(f"get_dashboard: {dashboard_id}")
    d = _dd_request("GET", f"/dashboard/{dashboard_id}", api_key, app_key)

    result = {
        "id": d.get("id"),
        "title": d.get("title"),
        "description": d.get("description", ""),
        "url": d.get("url"),
        "layout_type": d.get("layout_type"),
        "created_at": d.get("created_at"),
        "modified_at": d.get("modified_at"),
        "author_handle": d.get("author_handle"),
        "author_name": d.get("author_name"),
        "tags": d.get("tags", []),
        "widget_count": len(d.get("widgets", [])),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_dashboard: id={dashboard_id} title={d.get('title')!r}",
        "get_dashboard", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


# --- Incident Operations (v2 API) ---

def list_incidents(limit: int = 25) -> Dict[str, Any]:
    """
    List incidents from Datadog (Incident Management v2 API).

    limit: Max results to return (default 25)
    """
    ctx, decision = _gate_and_emit("list_incidents")
    api_key = _get_api_key()
    app_key = _get_app_key()

    params: Dict[str, Any] = {"page[size]": limit}

    log(f"list_incidents: limit={limit}")
    # Incidents use the v2 API
    data = _dd_request("GET", "/incidents", api_key, app_key, params=params, api_version="v2")

    incidents_raw = data.get("data", [])
    result: Dict[str, Any] = {
        "count": len(incidents_raw),
        "incidents": [
            {
                "id": inc.get("id"),
                "title": inc.get("attributes", {}).get("title"),
                "status": inc.get("attributes", {}).get("status"),
                "severity": inc.get("attributes", {}).get("severity"),
                "created": inc.get("attributes", {}).get("created"),
                "modified": inc.get("attributes", {}).get("modified"),
                "resolved": inc.get("attributes", {}).get("resolved"),
                "customer_impact_scope": inc.get("attributes", {}).get("customer_impact_scope"),
            }
            for inc in incidents_raw
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_incidents: {len(incidents_raw)} returned",
        "list_incidents", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(incidents_raw)} incident(s) returned")
    return result


def get_incident(incident_id: str) -> Dict[str, Any]:
    """
    Fetch a single incident by ID (Datadog Incident Management v2 API).

    incident_id: Datadog incident ID (e.g. 'b35b3b99-...')
    """
    ctx, decision = _gate_and_emit("get_incident")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not incident_id:
        log("ERROR: incident_id is required")
        raise SystemExit(1)

    log(f"get_incident: {incident_id}")
    data = _dd_request("GET", f"/incidents/{incident_id}", api_key, app_key, api_version="v2")

    inc = data.get("data", {})
    attrs = inc.get("attributes", {})

    result = {
        "id": inc.get("id"),
        "title": attrs.get("title"),
        "status": attrs.get("status"),
        "severity": attrs.get("severity"),
        "created": attrs.get("created"),
        "modified": attrs.get("modified"),
        "resolved": attrs.get("resolved"),
        "detected": attrs.get("detected"),
        "customer_impact_scope": attrs.get("customer_impact_scope"),
        "customer_impact_duration": attrs.get("customer_impact_duration"),
        "customer_impacted": attrs.get("customer_impacted"),
        "notification_handle": attrs.get("notification_handle"),
        "postmortem_id": attrs.get("postmortem_id"),
        "time_to_resolve_duration": attrs.get("time_to_resolve_duration"),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_incident: id={incident_id} status={attrs.get('status')} severity={attrs.get('severity')}",
        "get_incident", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return result


# --- Metric Submission ---

def submit_metric(
    metric_name: str,
    value: float,
    tags: Optional[List[str]] = None,
    metric_type: str = "gauge",
    host: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Submit a single metric datapoint to Datadog.

    metric_name: Metric name (e.g. 'myapp.request.count')
    value:       Numeric metric value
    tags:        Optional list of tag strings (e.g. ['env:prod', 'service:api'])
    metric_type: 'gauge' (default) | 'count' | 'rate'
    host:        Hostname to associate with the metric (optional)
    """
    ctx, decision = _gate_and_emit("submit_metric")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not metric_name:
        log("ERROR: metric_name is required")
        raise SystemExit(1)
    if metric_type not in ("gauge", "count", "rate"):
        log(f"ERROR: metric_type must be gauge/count/rate, got {metric_type!r}")
        raise SystemExit(1)

    ts = unix_ts_now()
    series_entry: Dict[str, Any] = {
        "metric": metric_name,
        "type": metric_type,
        "points": [[ts, value]],
    }
    if tags:
        series_entry["tags"] = tags
    if host:
        series_entry["host"] = host

    body = {"series": [series_entry]}

    log(f"submit_metric: {metric_name}={value} type={metric_type} tags={tags}")
    _dd_request("POST", "/series", api_key, app_key, body=body)

    result = {
        "metric": metric_name,
        "value": value,
        "type": metric_type,
        "tags": tags or [],
        "host": host,
        "submitted_at_utc": utc_now_iso(),
        "status": "submitted",
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"submit_metric: metric={metric_name} value={value} type={metric_type} tags={tags}",
        "submit_metric", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Metric submitted: {metric_name}={value}")
    return result


def submit_worker_metrics(
    worker_species_id: str,
    op: str,
    allowed: bool,
    attestation_ok: bool,
    evidence_count: int,
) -> Dict[str, Any]:
    """
    Governance-as-observability: submit WCP worker telemetry as Datadog custom metrics.

    This is the key differentiating capability of this worker. It allows SREs to build
    Datadog monitors directly on AI worker trust levels, policy compliance, and activity.

    Metrics submitted (all as gauge or count):
      pyhall.worker.dispatch_count       — tagged: worker_species, env, op
      pyhall.worker.attestation_status   — 1=verified, 0=failed/skipped; tagged: worker_species
      pyhall.worker.policy_decision      — 1=allowed, 0=denied; tagged: worker_species, op
      pyhall.worker.evidence_chain_length — count of receipts in evidence log; tagged: worker_species

    worker_species_id: WCP species ID (e.g. 'wrk.pyhall.github')
    op:               Operation name that was dispatched
    allowed:          Whether the policy gate allowed the operation
    attestation_ok:   Whether package attestation passed
    evidence_count:   Number of entries currently in the evidence chain log
    """
    ctx, decision = _gate_and_emit("submit_worker_metrics")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not worker_species_id:
        log("ERROR: worker_species_id is required")
        raise SystemExit(1)
    if not op:
        log("ERROR: op is required")
        raise SystemExit(1)

    env = os.environ.get("PYHALL_ENV", "dev")
    ts = unix_ts_now()

    base_tags_species = [f"worker_species:{worker_species_id}"]
    base_tags_op      = [f"worker_species:{worker_species_id}", f"op:{op}"]
    env_tags          = [f"worker_species:{worker_species_id}", f"env:{env}", f"op:{op}"]

    series = [
        # 1. Dispatch count — count type: increment by 1 per dispatch
        {
            "metric": "pyhall.worker.dispatch_count",
            "type": "count",
            "points": [[ts, 1]],
            "tags": env_tags,
        },
        # 2. Attestation status — gauge: 1=verified, 0=failed/skipped
        {
            "metric": "pyhall.worker.attestation_status",
            "type": "gauge",
            "points": [[ts, 1 if attestation_ok else 0]],
            "tags": base_tags_species,
        },
        # 3. Policy decision — gauge: 1=allowed, 0=denied
        {
            "metric": "pyhall.worker.policy_decision",
            "type": "gauge",
            "points": [[ts, 1 if allowed else 0]],
            "tags": base_tags_op,
        },
        # 4. Evidence chain length — gauge: total entries in chain log
        {
            "metric": "pyhall.worker.evidence_chain_length",
            "type": "gauge",
            "points": [[ts, float(evidence_count)]],
            "tags": base_tags_species,
        },
    ]

    body = {"series": series}

    log(
        f"submit_worker_metrics: species={worker_species_id} op={op} "
        f"allowed={allowed} attested={attestation_ok} chain_len={evidence_count}"
    )
    _dd_request("POST", "/series", api_key, app_key, body=body)

    metric_names = [s["metric"] for s in series]
    result = {
        "worker_species_id": worker_species_id,
        "op": op,
        "env": env,
        "allowed": allowed,
        "attestation_ok": attestation_ok,
        "evidence_count": evidence_count,
        "metrics_submitted": metric_names,
        "submitted_at_utc": utc_now_iso(),
        "status": "submitted",
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        (
            f"submit_worker_metrics: species={worker_species_id} op={op} "
            f"metrics={metric_names} allowed={allowed} attested={attestation_ok} "
            f"evidence_count={evidence_count}"
        ),
        "submit_worker_metrics", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Worker governance metrics submitted: {metric_names}")
    return result


# --- Event Operations ---

def list_events(
    start_ts: int,
    end_ts: int,
    tags: Optional[List[str]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    List events from the Datadog event stream.

    start_ts: Unix timestamp — start of query window (required)
    end_ts:   Unix timestamp — end of query window (required)
    tags:     Optional list of tag filter strings
    limit:    Max results (default 100)
    """
    ctx, decision = _gate_and_emit("list_events")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not start_ts or not end_ts:
        log("ERROR: start_ts and end_ts are required for list_events")
        raise SystemExit(1)
    if end_ts <= start_ts:
        log("ERROR: end_ts must be greater than start_ts")
        raise SystemExit(1)

    params: Dict[str, Any] = {
        "start": start_ts,
        "end": end_ts,
        "count": limit,
    }
    if tags:
        params["tags"] = ",".join(tags)

    log(f"list_events: start={start_ts} end={end_ts} tags={tags} limit={limit}")
    data = _dd_request("GET", "/events", api_key, app_key, params=params)

    events_raw = data.get("events", [])
    result: Dict[str, Any] = {
        "count": len(events_raw),
        "events": [
            {
                "id": e.get("id"),
                "title": e.get("title"),
                "text": e.get("text", ""),
                "date_happened": e.get("date_happened"),
                "alert_type": e.get("alert_type"),
                "priority": e.get("priority"),
                "tags": e.get("tags", []),
                "host": e.get("host"),
                "source": e.get("source"),
                "url": e.get("url"),
            }
            for e in events_raw
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_events: {len(events_raw)} returned (start={start_ts} end={end_ts} tags={tags})",
        "list_events", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(events_raw)} event(s) returned")
    return result


def create_event(
    title: str,
    text: str,
    tags: Optional[List[str]] = None,
    alert_type: str = "info",
    priority: str = "normal",
) -> Dict[str, Any]:
    """
    Post an event to the Datadog event stream.

    title:      Event title (required)
    text:       Event body text (required)
    tags:       Optional list of tag strings
    alert_type: 'error' | 'warning' | 'info' | 'success' (default 'info')
    priority:   'normal' | 'low' (default 'normal')
    """
    ctx, decision = _gate_and_emit("create_event")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not title:
        log("ERROR: title is required for create_event")
        raise SystemExit(1)
    if not text:
        log("ERROR: text is required for create_event")
        raise SystemExit(1)
    if alert_type not in ("error", "warning", "info", "success"):
        log(f"ERROR: alert_type must be error/warning/info/success, got {alert_type!r}")
        raise SystemExit(1)
    if priority not in ("normal", "low"):
        log(f"ERROR: priority must be normal/low, got {priority!r}")
        raise SystemExit(1)

    body: Dict[str, Any] = {
        "title": title,
        "text": text,
        "alert_type": alert_type,
        "priority": priority,
    }
    if tags:
        body["tags"] = tags

    log(f"create_event: title={title!r} alert_type={alert_type} priority={priority}")
    data = _dd_request("POST", "/events", api_key, app_key, body=body)

    event = data.get("event", data)
    result = {
        "id": event.get("id"),
        "title": event.get("title"),
        "text": event.get("text"),
        "alert_type": event.get("alert_type"),
        "date_happened": event.get("date_happened"),
        "tags": event.get("tags", []),
        "url": event.get("url"),
        "status": data.get("status", "ok"),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_event: id={event.get('id')} title={title!r} alert_type={alert_type}",
        "create_event", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  Event created: id={event.get('id')}")
    return result


# --- Metrics Query ---

def query_metrics(
    query: str,
    start_ts: int,
    end_ts: int,
) -> Dict[str, Any]:
    """
    Query metric time series data from Datadog.

    query:    Datadog metrics query string (e.g. 'avg:system.cpu.user{*}')
    start_ts: Unix timestamp — start of query window (required)
    end_ts:   Unix timestamp — end of query window (required)
    """
    ctx, decision = _gate_and_emit("query_metrics")
    api_key = _get_api_key()
    app_key = _get_app_key()

    if not query:
        log("ERROR: query is required for query_metrics")
        raise SystemExit(1)
    if not start_ts or not end_ts:
        log("ERROR: start_ts and end_ts are required for query_metrics")
        raise SystemExit(1)
    if end_ts <= start_ts:
        log("ERROR: end_ts must be greater than start_ts")
        raise SystemExit(1)

    params = {
        "query": query,
        "from": start_ts,
        "to": end_ts,
    }

    log(f"query_metrics: query={query!r} start={start_ts} end={end_ts}")
    data = _dd_request("GET", "/query", api_key, app_key, params=params)

    series_list = data.get("series", [])
    result: Dict[str, Any] = {
        "query": query,
        "from_date": data.get("from_date"),
        "to_date": data.get("to_date"),
        "status": data.get("status"),
        "res_type": data.get("res_type"),
        "series_count": len(series_list),
        "series": [
            {
                "metric": s.get("metric"),
                "display_name": s.get("display_name"),
                "unit": s.get("unit"),
                "pointlist_count": len(s.get("pointlist", [])),
                "start": s.get("start"),
                "end": s.get("end"),
                "interval": s.get("interval"),
                "scope": s.get("scope"),
                "expression": s.get("expression"),
                # Include first and last datapoints for quick inspection
                "first_point": s.get("pointlist", [[None, None]])[0] if s.get("pointlist") else None,
                "last_point": s.get("pointlist", [[None, None]])[-1] if s.get("pointlist") else None,
            }
            for s in series_list
        ],
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"query_metrics: query={query!r} series_count={len(series_list)}",
        "query_metrics", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)

    log(f"  {len(series_list)} series returned for query")
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
            "  python3 worker_logic.py list_monitors\n"
            "  python3 worker_logic.py list_monitors --tags env:prod --limit 50\n"
            "  python3 worker_logic.py get_monitor --monitor-id 12345\n"
            "  python3 worker_logic.py create_monitor --name 'CPU Alert' --type 'metric alert'"
            " --query 'avg:system.cpu.user{*} > 90'\n"
            "  python3 worker_logic.py mute_monitor --monitor-id 12345\n"
            "  python3 worker_logic.py mute_monitor --monitor-id 12345 --end-ts 1799999999\n"
            "  python3 worker_logic.py list_dashboards\n"
            "  python3 worker_logic.py get_dashboard --dashboard-id abc-123-xyz\n"
            "  python3 worker_logic.py list_incidents --limit 10\n"
            "  python3 worker_logic.py get_incident --incident-id b35b3b99-1234\n"
            "  python3 worker_logic.py submit_metric --metric pyhall.test.value --value 42.0\n"
            "  python3 worker_logic.py submit_metric --metric myapp.errors --value 5 --type count"
            " --tags env:prod service:api\n"
            "  python3 worker_logic.py submit_worker_metrics --worker-species wrk.pyhall.github"
            " --op list_repos --allowed --attested --evidence-count 17\n"
            "  python3 worker_logic.py list_events --start-ts 1700000000 --end-ts 1700003600\n"
            "  python3 worker_logic.py create_event --title 'Deploy complete' --text 'v0.3.0 shipped'"
            " --alert-type success\n"
            "  python3 worker_logic.py query_metrics --query 'avg:system.cpu.user{*}'"
            " --start-ts 1700000000 --end-ts 1700003600\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # Monitor args
    p.add_argument("--monitor-id", dest="monitor_id", type=int, metavar="ID",
                   help="Datadog monitor ID (integer)")
    p.add_argument("--name", dest="name", metavar="TEXT",
                   help="Monitor/event name or title")
    p.add_argument("--type", dest="monitor_type", metavar="TYPE",
                   help="Monitor type (create_monitor): 'metric alert', 'service check', etc.")
    p.add_argument("--query", dest="query", metavar="QUERY",
                   help="Monitor query or metrics query string")
    p.add_argument("--message", dest="message", metavar="TEXT",
                   help="Monitor notification message (create_monitor)")
    p.add_argument("--priority", dest="priority", type=int, default=3, metavar="1-5",
                   help="Monitor priority 1-5 (default 3)")
    p.add_argument("--end-ts", dest="end_ts", type=int, metavar="UNIX_TS",
                   help="Unix timestamp: mute end (mute_monitor) or query window end")

    # Dashboard args
    p.add_argument("--dashboard-id", dest="dashboard_id", metavar="ID",
                   help="Datadog dashboard ID")

    # Incident args
    p.add_argument("--incident-id", dest="incident_id", metavar="ID",
                   help="Datadog incident ID")

    # Metric args
    p.add_argument("--metric", dest="metric_name", metavar="NAME",
                   help="Metric name (submit_metric)")
    p.add_argument("--value", dest="value", type=float, metavar="FLOAT",
                   help="Metric value (submit_metric)")
    p.add_argument("--metric-type", dest="metric_type", metavar="TYPE",
                   choices=["gauge", "count", "rate"], default="gauge",
                   help="Metric type: gauge|count|rate (default: gauge)")
    p.add_argument("--host", dest="host", metavar="HOSTNAME",
                   help="Hostname to associate with metric (submit_metric)")

    # submit_worker_metrics args
    p.add_argument("--worker-species", dest="worker_species", metavar="SPECIES_ID",
                   help="WCP worker species ID (submit_worker_metrics)")
    p.add_argument("--allowed", dest="allowed", action="store_true", default=False,
                   help="Policy gate allowed the operation (submit_worker_metrics)")
    p.add_argument("--denied", dest="denied", action="store_true", default=False,
                   help="Policy gate denied the operation (submit_worker_metrics)")
    p.add_argument("--attested", dest="attested", action="store_true", default=False,
                   help="Package attestation passed (submit_worker_metrics)")
    p.add_argument("--not-attested", dest="not_attested", action="store_true", default=False,
                   help="Package attestation failed/skipped (submit_worker_metrics)")
    p.add_argument("--evidence-count", dest="evidence_count", type=int, default=0,
                   metavar="N",
                   help="Evidence chain entry count (submit_worker_metrics)")

    # Event args
    p.add_argument("--title", dest="title", metavar="TEXT",
                   help="Event title (create_event)")
    p.add_argument("--text", dest="text", metavar="TEXT",
                   help="Event body text (create_event)")
    p.add_argument("--alert-type", dest="alert_type",
                   choices=["error", "warning", "info", "success"], default="info",
                   help="Event alert type (default: info)")
    p.add_argument("--event-priority", dest="event_priority",
                   choices=["normal", "low"], default="normal",
                   help="Event priority (default: normal)")

    # Shared / filter args
    p.add_argument("--tags", dest="tags", nargs="+", metavar="TAG",
                   help="Tag filter(s) e.g. --tags env:prod team:sre")
    p.add_argument("--limit", dest="limit", type=int, default=50,
                   help="Max results to return (default 50)")
    p.add_argument("--start-ts", dest="start_ts", type=int, metavar="UNIX_TS",
                   help="Unix timestamp — query window start (list_events, query_metrics)")

    return p


def run() -> None:
    """WCP worker entry point."""
    global _attest_meta

    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    args = build_arg_parser().parse_args()
    op = args.op

    # Dispatch
    if op == "list_monitors":
        result = list_monitors(tags=args.tags, limit=args.limit)
        _print_result(result)

    elif op == "get_monitor":
        if not args.monitor_id:
            log("ERROR: --monitor-id required for get_monitor")
            raise SystemExit(1)
        result = get_monitor(args.monitor_id)
        _print_result(result)

    elif op == "create_monitor":
        if not args.name:
            log("ERROR: --name required for create_monitor")
            raise SystemExit(1)
        if not args.monitor_type:
            log("ERROR: --type required for create_monitor")
            raise SystemExit(1)
        if not args.query:
            log("ERROR: --query required for create_monitor")
            raise SystemExit(1)
        result = create_monitor(
            name=args.name,
            monitor_type=args.monitor_type,
            query=args.query,
            message=args.message,
            tags=args.tags,
            priority=args.priority,
        )
        _print_result(result)

    elif op == "mute_monitor":
        if not args.monitor_id:
            log("ERROR: --monitor-id required for mute_monitor")
            raise SystemExit(1)
        result = mute_monitor(args.monitor_id, end_ts=args.end_ts)
        _print_result(result)

    elif op == "list_dashboards":
        result = list_dashboards(limit=args.limit)
        _print_result(result)

    elif op == "get_dashboard":
        if not args.dashboard_id:
            log("ERROR: --dashboard-id required for get_dashboard")
            raise SystemExit(1)
        result = get_dashboard(args.dashboard_id)
        _print_result(result)

    elif op == "list_incidents":
        result = list_incidents(limit=args.limit)
        _print_result(result)

    elif op == "get_incident":
        if not args.incident_id:
            log("ERROR: --incident-id required for get_incident")
            raise SystemExit(1)
        result = get_incident(args.incident_id)
        _print_result(result)

    elif op == "submit_metric":
        if not args.metric_name:
            log("ERROR: --metric required for submit_metric")
            raise SystemExit(1)
        if args.value is None:
            log("ERROR: --value required for submit_metric")
            raise SystemExit(1)
        result = submit_metric(
            metric_name=args.metric_name,
            value=args.value,
            tags=args.tags,
            metric_type=args.metric_type,
            host=args.host,
        )
        _print_result(result)

    elif op == "submit_worker_metrics":
        if not args.worker_species:
            log("ERROR: --worker-species required for submit_worker_metrics")
            raise SystemExit(1)
        if not args.op:
            log("ERROR: op is required for submit_worker_metrics")
            raise SystemExit(1)
        # --allowed / --denied flags; default to allowed=True if neither set
        policy_allowed = not args.denied
        attest_ok = args.attested and not args.not_attested
        result = submit_worker_metrics(
            worker_species_id=args.worker_species,
            op=op,
            allowed=policy_allowed,
            attestation_ok=attest_ok,
            evidence_count=args.evidence_count,
        )
        _print_result(result)

    elif op == "list_events":
        if not args.start_ts:
            log("ERROR: --start-ts required for list_events")
            raise SystemExit(1)
        if not args.end_ts:
            log("ERROR: --end-ts required for list_events")
            raise SystemExit(1)
        result = list_events(
            start_ts=args.start_ts,
            end_ts=args.end_ts,
            tags=args.tags,
            limit=args.limit,
        )
        _print_result(result)

    elif op == "create_event":
        if not args.title:
            log("ERROR: --title required for create_event")
            raise SystemExit(1)
        if not args.text:
            log("ERROR: --text required for create_event")
            raise SystemExit(1)
        result = create_event(
            title=args.title,
            text=args.text,
            tags=args.tags,
            alert_type=args.alert_type,
            priority=args.event_priority,
        )
        _print_result(result)

    elif op == "query_metrics":
        if not args.query:
            log("ERROR: --query required for query_metrics")
            raise SystemExit(1)
        if not args.start_ts:
            log("ERROR: --start-ts required for query_metrics")
            raise SystemExit(1)
        if not args.end_ts:
            log("ERROR: --end-ts required for query_metrics")
            raise SystemExit(1)
        result = query_metrics(
            query=args.query,
            start_ts=args.start_ts,
            end_ts=args.end_ts,
        )
        _print_result(result)

    else:
        log(f"ERROR: unhandled op {op!r}")
        raise SystemExit(1)


if __name__ == "__main__":
    run()
