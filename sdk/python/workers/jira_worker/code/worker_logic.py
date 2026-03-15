#!/usr/bin/env python3
"""
worker_logic.py — Jira Issues Worker (WCP v0.3.0)

Full WCP-compliant worker package for the Jira Cloud REST API v3.
Supports issue management, project queries, board listing, transitions,
labels, and comments via Jira Cloud's REST API.

Auth: Basic auth using Atlassian account email + API token.
Endpoint: {JIRA_URL}/rest/api/3/

All timestamps stored as UTC ISO 8601. Human-facing log output uses Central Time.

Setup:
    1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
    2. Create an API token
    3. Set environment variables:
         export JIRA_URL=https://yourorg.atlassian.net
         export JIRA_EMAIL=you@example.com
         export JIRA_API_TOKEN=your_token_here
    4. Run: python3 worker_logic.py list_projects  # verify connectivity
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

WORKER_ID          = "org.pyhall.jira.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.jira"
WORKER_NAME        = "Jira Issues Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.jira.read",
    "cap.pyhall.jira.write",
    "cap.pyhall.jira.manage",
]

ALLOWED_OPS = {
    "list_issues", "get_issue", "create_issue", "update_issue",
    "close_issue", "assign_issue", "add_comment", "list_comments",
    "list_projects", "get_project", "list_transitions",
    "transition_issue", "add_label", "list_boards",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]


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
class JiraIssue:
    key: str
    summary: str
    status: str
    assignee: Optional[str]
    priority: Optional[str]
    created: str
    updated: str
    description: Optional[str] = None
    labels: List[str] = field(default_factory=list)
    issue_type: Optional[str] = None


@dataclass
class JiraProject:
    key: str
    name: str
    project_type_key: str
    lead: Optional[str]


@dataclass
class JiraTransition:
    id: str
    name: str
    to_status: str


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


def _get_jira_creds() -> Tuple[str, str, str]:
    """
    Retrieve JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN from environment.
    Exits with code 1 if any are missing.
    """
    url = os.environ.get("JIRA_URL", "").strip().rstrip("/")
    email = os.environ.get("JIRA_EMAIL", "").strip()
    token = os.environ.get("JIRA_API_TOKEN", "").strip()

    missing = []
    if not url:
        missing.append("JIRA_URL")
    if not email:
        missing.append("JIRA_EMAIL")
    if not token:
        missing.append("JIRA_API_TOKEN")

    if missing:
        log(f"ERROR: Missing required environment variables: {', '.join(missing)}")
        log("  JIRA_URL    — e.g. https://yourorg.atlassian.net")
        log("  JIRA_EMAIL  — Atlassian account email")
        log("  JIRA_API_TOKEN — from https://id.atlassian.com/manage-profile/security/api-tokens")
        raise SystemExit(1)

    return url, email, token


def _adf_paragraph(text: str) -> Dict[str, Any]:
    """
    Build a minimal Atlassian Document Format (ADF) document from plain text.

    ADF is required for Jira Cloud description and comment body fields.
    Returns a top-level 'doc' node containing a single paragraph.
    """
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": text,
                    }
                ],
            }
        ],
    }


def _extract_text_from_adf(adf: Optional[Dict[str, Any]]) -> str:
    """
    Recursively extract plain text from an ADF content structure.

    Walks the 'content' tree and collects all 'text' node values,
    separated by spaces. Returns empty string if adf is None or malformed.
    """
    if not adf or not isinstance(adf, dict):
        return ""

    parts: List[str] = []

    def _walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("type") == "text":
            text_val = node.get("text", "")
            if text_val:
                parts.append(text_val)
        for child in node.get("content", []):
            _walk(child)

    _walk(adf)
    return " ".join(parts)


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
        log(f"WARNING: {msg} — continuing in dev")
        return {"dev_skip": True, "deny_code": deny_code, "meta": attest_meta}

    log(f"Attestation OK — {attest_meta.get('trust_statement', '')}")
    return attest_meta


# Derive paths from this file's location:
#   code/worker_logic.py → package root is two levels up (jira_worker/)
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../jira_worker/
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

        rule_id = f"rr_jira_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = Path(
    os.path.expanduser("~/.local/share/pyhall/evidence/")
) / f"{WORKER_SPECIES_ID.replace('.', '_')}_chain.log"


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
    """Select the appropriate capability ID for an operation."""
    read_ops = {
        "list_issues", "get_issue", "list_comments",
        "list_projects", "get_project", "list_transitions",
        "list_boards",
    }
    manage_ops = {
        "create_issue", "update_issue", "close_issue",
        "assign_issue", "add_comment", "transition_issue",
        "add_label",
    }
    if op in read_ops:
        return "cap.pyhall.jira.read"
    if op in manage_ops:
        return "cap.pyhall.jira.manage"
    return "cap.pyhall.jira.write"


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
# SECTION 7: DOMAIN LOGIC — JIRA CLOUD REST API v3
# ============================================================================

# --- HTTP transport helper ---

def _jira_request(
    method: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    base_path: str = "/rest/api/3",
) -> Optional[Dict[str, Any]]:
    """
    Execute a Jira Cloud REST API request using Basic Auth.

    method   — HTTP verb: GET, POST, PUT, DELETE
    path     — path relative to base_path, e.g. "/issue/PROJ-1"
    params   — optional URL query parameters
    body     — optional JSON request body (dict)
    base_path — API base path (default /rest/api/3; use /rest/agile/1.0 for agile)

    Returns parsed JSON dict, or None for 204 No Content responses.
    Raises RuntimeError on HTTP errors. Parses Jira 400 errorMessages.
    """
    try:
        import requests
        import requests.auth
    except ImportError:
        log("ERROR: 'requests' library not installed. Run: pip install requests")
        raise SystemExit(1)

    jira_url, email, token = _get_jira_creds()
    url = f"{jira_url}{base_path}{path}"
    auth = requests.auth.HTTPBasicAuth(email, token)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    try:
        resp = requests.request(
            method.upper(),
            url,
            auth=auth,
            headers=headers,
            params=params,
            json=body,
            timeout=30,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Jira API request failed [{method} {path}]: {exc}") from exc

    # 204 No Content — success with empty body
    if resp.status_code == 204:
        return None

    # Parse error details for 4xx/5xx
    if not resp.ok:
        try:
            err_body = resp.json()
            error_messages = err_body.get("errorMessages", [])
            errors_dict = err_body.get("errors", {})
            detail_parts: List[str] = []
            if error_messages:
                detail_parts.extend(error_messages)
            if errors_dict:
                detail_parts.extend(f"{k}: {v}" for k, v in errors_dict.items())
            detail = "; ".join(detail_parts) if detail_parts else resp.text[:500]
        except Exception:
            detail = resp.text[:500]
        raise RuntimeError(
            f"Jira API HTTP {resp.status_code} [{method} {path}]: {detail}"
        )

    # Empty body on 201/200
    if not resp.content:
        return {}

    return resp.json()


# --- ADF helpers (already defined in Section 3) ---
# _adf_paragraph(text) and _extract_text_from_adf(adf) are in Section 3.


# --- Read operations ---

def list_issues(
    project_key: Optional[str] = None,
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    List Jira issues using JQL search.

    Builds JQL from optional filters: project, status, assignee.
    Returns list of dicts with key, summary, status, assignee, priority,
    created, updated.
    """
    ctx, decision = _gate_and_emit("list_issues")

    jql_parts: List[str] = []
    if project_key:
        jql_parts.append(f"project = {project_key}")
    if status:
        jql_parts.append(f'status = "{status}"')
    if assignee:
        jql_parts.append(f'assignee = "{assignee}"')
    jql_parts.append("ORDER BY created DESC")
    jql = " AND ".join(jql_parts[:-1]) + (" ORDER BY created DESC" if jql_parts[:-1] else "ORDER BY created DESC")

    # Rebuild properly: join filters then append ORDER BY
    filter_parts: List[str] = []
    if project_key:
        filter_parts.append(f"project = {project_key}")
    if status:
        filter_parts.append(f'status = "{status}"')
    if assignee:
        filter_parts.append(f'assignee = "{assignee}"')

    if filter_parts:
        jql = " AND ".join(filter_parts) + " ORDER BY created DESC"
    else:
        jql = "ORDER BY created DESC"

    params = {
        "jql": jql,
        "maxResults": limit,
        "fields": "summary,status,assignee,priority,created,updated",
    }

    try:
        data = _jira_request("GET", "/search", params=params)
        raw_issues = (data or {}).get("issues", [])
        results = []
        for issue in raw_issues:
            f = issue.get("fields", {})
            results.append({
                "key": issue.get("key"),
                "summary": f.get("summary"),
                "status": (f.get("status") or {}).get("name"),
                "assignee": ((f.get("assignee") or {}).get("displayName")),
                "priority": (f.get("priority") or {}).get("name"),
                "created": f.get("created"),
                "updated": f.get("updated"),
            })
        log(
            f"list_issues: found {len(results)} issues"
            + (f" [project={project_key}]" if project_key else "")
            + (f" [status={status}]" if status else "")
            + (f" [assignee={assignee}]" if assignee else "")
        )
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_issues: {len(results)} results jql={jql!r}",
            "list_issues", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return results
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_issues", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def get_issue(issue_key: str) -> Dict[str, Any]:
    """
    Fetch a single Jira issue by key (e.g. PROJ-123) with full fields.

    Extracts plain text from ADF description for the 'description_text' field.
    Returns the full issue dict from Jira with an added 'description_text' key.
    """
    ctx, decision = _gate_and_emit("get_issue")

    try:
        data = _jira_request("GET", f"/issue/{issue_key}")
        if not data:
            raise RuntimeError(f"Issue not found: {issue_key}")

        fields = data.get("fields", {})
        desc_adf = fields.get("description")
        data["description_text"] = _extract_text_from_adf(desc_adf)

        log(f"get_issue: {data.get('key')} — {fields.get('summary', '?')}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"get_issue: {issue_key} retrieved",
            "get_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return data
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "get_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def list_comments(issue_key: str) -> List[Dict[str, Any]]:
    """
    List comments on a Jira issue.

    Returns list of dicts with author (displayName), body_text (plain text
    extracted from ADF), and created timestamp.
    """
    ctx, decision = _gate_and_emit("list_comments")

    try:
        data = _jira_request("GET", f"/issue/{issue_key}/comment")
        raw_comments = (data or {}).get("comments", [])
        results = []
        for c in raw_comments:
            body_adf = c.get("body")
            results.append({
                "id": c.get("id"),
                "author": (c.get("author") or {}).get("displayName"),
                "body_text": _extract_text_from_adf(body_adf),
                "created": c.get("created"),
                "updated": c.get("updated"),
            })
        log(f"list_comments: {len(results)} comments on {issue_key}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_comments: {issue_key} — {len(results)} comments",
            "list_comments", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return results
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_comments", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def list_projects(limit: int = 50) -> List[Dict[str, Any]]:
    """
    List Jira projects accessible to the authenticated user.

    Returns list of dicts with key, name, projectTypeKey, lead displayName.
    """
    ctx, decision = _gate_and_emit("list_projects")

    params = {"maxResults": limit}
    try:
        data = _jira_request("GET", "/project/search", params=params)
        raw_projects = (data or {}).get("values", [])
        results = []
        for p in raw_projects:
            results.append({
                "key": p.get("key"),
                "name": p.get("name"),
                "projectTypeKey": p.get("projectTypeKey"),
                "lead": (p.get("lead") or {}).get("displayName"),
                "id": p.get("id"),
            })
        log(f"list_projects: found {len(results)} projects")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_projects: {len(results)} results",
            "list_projects", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return results
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_projects", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def get_project(project_key: str) -> Dict[str, Any]:
    """Fetch full details of a Jira project by key."""
    ctx, decision = _gate_and_emit("get_project")

    try:
        data = _jira_request("GET", f"/project/{project_key}")
        if not data:
            raise RuntimeError(f"Project not found: {project_key}")
        log(f"get_project: {data.get('key')} — {data.get('name')}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"get_project: {project_key} retrieved",
            "get_project", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return data
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "get_project", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def list_transitions(issue_key: str) -> List[Dict[str, Any]]:
    """
    List available workflow transitions for a Jira issue.

    Returns list of dicts with id, name, to_status (the destination status name).
    """
    ctx, decision = _gate_and_emit("list_transitions")

    try:
        data = _jira_request("GET", f"/issue/{issue_key}/transitions")
        raw = (data or {}).get("transitions", [])
        results = []
        for t in raw:
            results.append({
                "id": t.get("id"),
                "name": t.get("name"),
                "to_status": (t.get("to") or {}).get("name"),
            })
        log(f"list_transitions: {len(results)} transitions for {issue_key}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_transitions: {issue_key} — {len(results)} transitions",
            "list_transitions", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return results
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_transitions", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def list_boards(project_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List Jira agile boards. Optionally filter by project key.

    Uses the Agile REST API (/rest/agile/1.0/board).
    Returns list of dicts with id, name, type, location.projectKey.
    """
    ctx, decision = _gate_and_emit("list_boards")

    params: Dict[str, Any] = {}
    if project_key:
        params["projectKeyOrId"] = project_key

    try:
        data = _jira_request(
            "GET", "/board",
            params=params,
            base_path="/rest/agile/1.0",
        )
        raw = (data or {}).get("values", [])
        results = []
        for b in raw:
            results.append({
                "id": b.get("id"),
                "name": b.get("name"),
                "type": b.get("type"),
                "project_key": (b.get("location") or {}).get("projectKey"),
            })
        log(f"list_boards: found {len(results)} boards"
            + (f" [project={project_key}]" if project_key else ""))
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_boards: {len(results)} results",
            "list_boards", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return results
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_boards", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


# --- Write/manage operations ---

def create_issue(
    project_key: str,
    summary: str,
    issue_type: str = "Task",
    description: Optional[str] = None,
    priority: Optional[str] = None,
    assignee_account_id: Optional[str] = None,
    labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Create a new Jira issue.

    description is plain text — converted to ADF paragraph automatically.
    priority is a name string e.g. "High", "Medium", "Low".
    assignee_account_id is the Atlassian account ID (not username/email).
    Returns the created issue dict with id, key, self URL.
    """
    ctx, decision = _gate_and_emit("create_issue")

    issue_body: Dict[str, Any] = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "issuetype": {"name": issue_type},
        }
    }

    if description:
        issue_body["fields"]["description"] = _adf_paragraph(description)
    if priority:
        issue_body["fields"]["priority"] = {"name": priority}
    if assignee_account_id:
        issue_body["fields"]["assignee"] = {"accountId": assignee_account_id}
    if labels:
        issue_body["fields"]["labels"] = labels

    try:
        data = _jira_request("POST", "/issue", body=issue_body)
        issue_key = (data or {}).get("key", "?")
        issue_id = (data or {}).get("id", "?")
        log(f"create_issue: created {issue_key} — {summary!r} [{issue_type}]")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"create_issue: {issue_key} id={issue_id} project={project_key}",
            "create_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return data or {}
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "create_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def update_issue(
    issue_key: str,
    summary: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[str] = None,
    labels: Optional[List[str]] = None,
) -> None:
    """
    Update fields on an existing Jira issue.

    Only provided (non-None) fields are sent in the update.
    description is plain text — converted to ADF automatically.
    priority is a name string e.g. "High".
    Returns None (Jira PUT /issue returns 204 No Content on success).
    """
    ctx, decision = _gate_and_emit("update_issue")

    fields: Dict[str, Any] = {}
    if summary is not None:
        fields["summary"] = summary
    if description is not None:
        fields["description"] = _adf_paragraph(description)
    if priority is not None:
        fields["priority"] = {"name": priority}
    if labels is not None:
        fields["labels"] = labels

    if not fields:
        raise ValueError("update_issue: at least one field must be provided to update")

    changed_fields = list(fields.keys())
    try:
        _jira_request("PUT", f"/issue/{issue_key}", body={"fields": fields})
        log(f"update_issue: {issue_key} updated fields={changed_fields}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"update_issue: {issue_key} fields={changed_fields}",
            "update_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "update_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def transition_issue(issue_key: str, transition_id: str) -> None:
    """
    Transition a Jira issue to a new workflow state.

    transition_id must be a valid transition ID from list_transitions().
    Returns None (Jira POST /transitions returns 204 No Content on success).
    """
    ctx, decision = _gate_and_emit("transition_issue")

    body = {"transition": {"id": transition_id}}
    try:
        _jira_request("POST", f"/issue/{issue_key}/transitions", body=body)
        log(f"transition_issue: {issue_key} transitioned via id={transition_id}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"transition_issue: {issue_key} transition_id={transition_id}",
            "transition_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "transition_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def close_issue(issue_key: str) -> None:
    """
    Close a Jira issue by transitioning it to the Done/Closed state.

    Automatically fetches available transitions and picks the first one
    whose name matches 'Done', 'Closed', or 'Resolve Issue' (case-insensitive).
    Raises RuntimeError if no suitable terminal transition is found.
    """
    ctx, decision = _gate_and_emit("close_issue")

    # We call list_transitions directly (bypasses gate — close_issue already gated)
    # Use _jira_request directly to avoid double-gating.
    try:
        trans_data = _jira_request("GET", f"/issue/{issue_key}/transitions")
        transitions = (trans_data or {}).get("transitions", [])

        terminal_names = {"done", "closed", "resolve issue", "resolved", "complete", "completed"}
        chosen: Optional[Dict[str, Any]] = None
        for t in transitions:
            if t.get("name", "").lower() in terminal_names:
                chosen = t
                break

        if chosen is None:
            available = [t.get("name") for t in transitions]
            raise RuntimeError(
                f"close_issue: no terminal transition found for {issue_key}. "
                f"Available transitions: {available}. "
                f"Use transition_issue with a specific transition_id."
            )

        transition_id = chosen["id"]
        _jira_request("POST", f"/issue/{issue_key}/transitions",
                      body={"transition": {"id": transition_id}})
        log(f"close_issue: {issue_key} transitioned via '{chosen['name']}' (id={transition_id})")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"close_issue: {issue_key} via transition '{chosen['name']}' id={transition_id}",
            "close_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "close_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def assign_issue(issue_key: str, account_id: str) -> None:
    """
    Assign a Jira issue to a user by Atlassian account ID.

    Uses PUT /issue/{issueKey}/assignee. Returns None on success.
    To unassign, pass account_id="-1" (Jira convention for unassigned).
    """
    ctx, decision = _gate_and_emit("assign_issue")

    body = {"accountId": account_id}
    try:
        _jira_request("PUT", f"/issue/{issue_key}/assignee", body=body)
        log(f"assign_issue: {issue_key} assigned to account={account_id}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"assign_issue: {issue_key} account_id={account_id}",
            "assign_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "assign_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def add_comment(issue_key: str, body_text: str) -> Dict[str, Any]:
    """
    Add a comment to a Jira issue.

    body_text is plain text — converted to ADF paragraph automatically.
    Returns the created comment dict with id and created timestamp.
    """
    ctx, decision = _gate_and_emit("add_comment")

    body = {"body": _adf_paragraph(body_text)}
    try:
        data = _jira_request("POST", f"/issue/{issue_key}/comment", body=body)
        comment_id = (data or {}).get("id", "?")
        log(f"add_comment: added comment {comment_id} to {issue_key}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"add_comment: {issue_key} comment_id={comment_id}",
            "add_comment", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return data or {}
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "add_comment", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def add_label(issue_key: str, label: str) -> None:
    """
    Add a single label to an existing Jira issue.

    Fetches the current labels first to avoid overwriting them,
    then appends the new label and performs a PUT update.
    Returns None on success (204 No Content).
    """
    ctx, decision = _gate_and_emit("add_label")

    try:
        # Fetch current labels to preserve them
        issue_data = _jira_request("GET", f"/issue/{issue_key}", params={"fields": "labels"})
        current_labels: List[str] = [
            lbl.get("name", "") for lbl in
            ((issue_data or {}).get("fields", {}).get("labels") or [])
        ]

        if label in current_labels:
            log(f"add_label: {issue_key} already has label={label!r} — no-op")
            receipt = build_evidence_receipt(
                ctx, decision, "ok",
                f"add_label: {issue_key} label={label!r} already present (no-op)",
                "add_label", _attest_meta,
            )
            _evidence_log.emit_evidence(receipt)
            return

        new_labels = current_labels + [label]
        _jira_request("PUT", f"/issue/{issue_key}", body={"fields": {"labels": new_labels}})
        log(f"add_label: {issue_key} label={label!r} added (total labels: {len(new_labels)})")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"add_label: {issue_key} label={label!r} labels_total={len(new_labels)}",
            "add_label", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "add_label", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


# --- Output helpers ---

def _print_issues(issues: List[Dict[str, Any]]) -> None:
    """Format and print a list of issue summary dicts to stdout."""
    if not issues:
        print("No issues found.")
        return
    for issue in issues:
        assignee = issue.get("assignee") or "unassigned"
        priority = issue.get("priority") or "?"
        print(f"  [{issue.get('key', '?')}] {issue.get('summary', '?')}")
        print(f"    status={issue.get('status', '?')}  priority={priority}  assignee={assignee}")
        print(f"    updated={issue.get('updated', '?')}")
    print(f"\n  ({len(issues)} issues)")


def _print_projects(projects: List[Dict[str, Any]]) -> None:
    """Format and print a list of project summary dicts to stdout."""
    if not projects:
        print("No projects found.")
        return
    for p in projects:
        lead = p.get("lead") or "no lead"
        print(f"  [{p.get('key')}] {p.get('name')}  type={p.get('projectTypeKey', '?')}  lead={lead}")
    print(f"\n  ({len(projects)} projects)")


def _print_transitions(transitions: List[Dict[str, Any]]) -> None:
    """Format and print a list of transition dicts to stdout."""
    if not transitions:
        print("No transitions available.")
        return
    for t in transitions:
        print(f"  id={t.get('id')}  name={t.get('name')!r}  to_status={t.get('to_status', '?')!r}")
    print(f"\n  ({len(transitions)} transitions)")


def _print_boards(boards: List[Dict[str, Any]]) -> None:
    """Format and print a list of board dicts to stdout."""
    if not boards:
        print("No boards found.")
        return
    for b in boards:
        project = b.get("project_key") or "?"
        print(f"  id={b.get('id')}  name={b.get('name')!r}  type={b.get('type', '?')}  project={project}")
    print(f"\n  ({len(boards)} boards)")


# ============================================================================
# SECTION 8: ENTRY POINT + ARGPARSE DISPATCH
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 worker_logic.py list_projects\n"
            "  python3 worker_logic.py list_issues --project-key PROJ\n"
            "  python3 worker_logic.py list_issues --project-key PROJ --status 'In Progress'\n"
            "  python3 worker_logic.py get_issue --issue-key PROJ-123\n"
            "  python3 worker_logic.py create_issue --project-key PROJ --summary 'Fix login bug'\n"
            "  python3 worker_logic.py create_issue --project-key PROJ --summary 'Task' --issue-type Story --priority High\n"
            "  python3 worker_logic.py update_issue --issue-key PROJ-123 --summary 'New title'\n"
            "  python3 worker_logic.py update_issue --issue-key PROJ-123 --priority Medium\n"
            "  python3 worker_logic.py close_issue --issue-key PROJ-123\n"
            "  python3 worker_logic.py assign_issue --issue-key PROJ-123 --account-id ACCT_ID\n"
            "  python3 worker_logic.py add_comment --issue-key PROJ-123 --body 'LGTM'\n"
            "  python3 worker_logic.py list_comments --issue-key PROJ-123\n"
            "  python3 worker_logic.py list_transitions --issue-key PROJ-123\n"
            "  python3 worker_logic.py transition_issue --issue-key PROJ-123 --transition-id 31\n"
            "  python3 worker_logic.py add_label --issue-key PROJ-123 --label bug\n"
            "  python3 worker_logic.py list_boards\n"
            "  python3 worker_logic.py list_boards --project-key PROJ\n"
            "  python3 worker_logic.py get_project --project-key PROJ\n"
        ),
    )
    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # Shared identifiers
    p.add_argument("--issue-key",      dest="issue_key",      help="Jira issue key e.g. PROJ-123")
    p.add_argument("--project-key",    dest="project_key",    help="Jira project key e.g. PROJ")
    p.add_argument("--account-id",     dest="account_id",     help="Atlassian account ID for assignee")
    p.add_argument("--transition-id",  dest="transition_id",  help="Workflow transition ID (transition_issue)")

    # Issue fields
    p.add_argument("--summary",         help="Issue summary/title (create_issue / update_issue)")
    p.add_argument("--description",     help="Issue description as plain text (ADF auto-built)")
    p.add_argument("--issue-type",  dest="issue_type", default="Task",
                   help="Issue type name e.g. Task, Story, Bug (create_issue, default: Task)")
    p.add_argument("--priority",        help="Priority name e.g. High, Medium, Low (create/update_issue)")
    p.add_argument("--labels",          nargs="+", help="Labels to set on issue (create/update_issue)")
    p.add_argument("--label",           help="Single label to add (add_label)")
    p.add_argument("--status",          help="Filter issues by status name (list_issues)")
    p.add_argument("--assignee",        help="Filter issues by assignee name or account ID (list_issues)")
    p.add_argument("--limit",   type=int, default=50, help="Max results for list ops (default: 50)")

    # Comment
    p.add_argument("--body",            help="Comment body as plain text (add_comment)")

    return p


def _dispatch(op: str, args: argparse.Namespace) -> Any:
    """Route the parsed op + args to the correct domain function."""

    if op == "list_issues":
        issues = list_issues(
            project_key=args.project_key,
            status=args.status,
            assignee=args.assignee,
            limit=args.limit,
        )
        _print_issues(issues)
        return issues

    elif op == "get_issue":
        if not args.issue_key:
            log("ERROR: --issue-key required for get_issue")
            raise SystemExit(1)
        issue = get_issue(args.issue_key)
        print(json.dumps(issue, indent=2, default=str))
        return issue

    elif op == "create_issue":
        if not args.project_key:
            log("ERROR: --project-key required for create_issue")
            raise SystemExit(1)
        if not args.summary:
            log("ERROR: --summary required for create_issue")
            raise SystemExit(1)
        issue = create_issue(
            project_key=args.project_key,
            summary=args.summary,
            issue_type=args.issue_type,
            description=args.description,
            priority=args.priority,
            labels=args.labels,
        )
        print(json.dumps(issue, indent=2, default=str))
        return issue

    elif op == "update_issue":
        if not args.issue_key:
            log("ERROR: --issue-key required for update_issue")
            raise SystemExit(1)
        update_issue(
            issue_key=args.issue_key,
            summary=args.summary,
            description=args.description,
            priority=args.priority,
            labels=args.labels,
        )
        log(f"update_issue: {args.issue_key} — update applied")
        return None

    elif op == "close_issue":
        if not args.issue_key:
            log("ERROR: --issue-key required for close_issue")
            raise SystemExit(1)
        close_issue(args.issue_key)
        return None

    elif op == "assign_issue":
        if not args.issue_key:
            log("ERROR: --issue-key required for assign_issue")
            raise SystemExit(1)
        if not args.account_id:
            log("ERROR: --account-id required for assign_issue")
            raise SystemExit(1)
        assign_issue(args.issue_key, args.account_id)
        return None

    elif op == "add_comment":
        if not args.issue_key:
            log("ERROR: --issue-key required for add_comment")
            raise SystemExit(1)
        if not args.body:
            log("ERROR: --body required for add_comment")
            raise SystemExit(1)
        comment = add_comment(args.issue_key, args.body)
        print(json.dumps(comment, indent=2, default=str))
        return comment

    elif op == "list_comments":
        if not args.issue_key:
            log("ERROR: --issue-key required for list_comments")
            raise SystemExit(1)
        comments = list_comments(args.issue_key)
        if not comments:
            print("No comments found.")
        else:
            for c in comments:
                print(f"  [{c.get('id')}] {c.get('author', '?')} @ {c.get('created', '?')[:10]}")
                print(f"    {c.get('body_text', '')[:120]}")
            print(f"\n  ({len(comments)} comments)")
        return comments

    elif op == "list_projects":
        projects = list_projects(limit=args.limit)
        _print_projects(projects)
        return projects

    elif op == "get_project":
        if not args.project_key:
            log("ERROR: --project-key required for get_project")
            raise SystemExit(1)
        project = get_project(args.project_key)
        print(json.dumps(project, indent=2, default=str))
        return project

    elif op == "list_transitions":
        if not args.issue_key:
            log("ERROR: --issue-key required for list_transitions")
            raise SystemExit(1)
        transitions = list_transitions(args.issue_key)
        _print_transitions(transitions)
        return transitions

    elif op == "transition_issue":
        if not args.issue_key:
            log("ERROR: --issue-key required for transition_issue")
            raise SystemExit(1)
        if not args.transition_id:
            log("ERROR: --transition-id required for transition_issue")
            raise SystemExit(1)
        transition_issue(args.issue_key, args.transition_id)
        return None

    elif op == "add_label":
        if not args.issue_key:
            log("ERROR: --issue-key required for add_label")
            raise SystemExit(1)
        if not args.label:
            log("ERROR: --label required for add_label")
            raise SystemExit(1)
        add_label(args.issue_key, args.label)
        return None

    elif op == "list_boards":
        boards = list_boards(project_key=args.project_key)
        _print_boards(boards)
        return boards

    else:
        log(f"ERROR: unknown op {op!r}")
        raise SystemExit(1)


def run() -> None:
    """WCP worker entry point."""
    global _attest_meta

    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = _build_parser()
    args = parser.parse_args()
    op = args.op

    # Policy gate is called inside each domain function via _gate_and_emit.
    # Dispatch to domain logic — domain functions handle their own gate + receipt.
    _dispatch(op, args)


if __name__ == "__main__":
    run()
