#!/usr/bin/env python3
"""
worker_logic.py — Linear Full Stack Worker (WCP v0.3.0)

Full WCP-compliant worker package for the Linear project management API.
Supports issue management, project queries, team ops, cycles, labels,
and comments via Linear's GraphQL API.

Auth: LINEAR_API_KEY environment variable (Personal API key from Linear settings).
Endpoint: https://api.linear.app/graphql

All timestamps stored as UTC ISO 8601. Human-facing log output uses Central Time.

Setup:
    1. Go to https://linear.app/settings/api
    2. Create a Personal API key
    3. Set environment variable: export LINEAR_API_KEY=lin_api_xxxx
    4. Optionally set default team: export LINEAR_DEFAULT_TEAM_ID=<team_id>
    5. Run: python3 worker_logic.py list_teams  # verify connectivity
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

WORKER_ID          = "org.pyhall.linear.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.linear"
WORKER_NAME        = "Linear Full Stack Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.linear.write",
    "cap.pyhall.linear.read",
    "cap.pyhall.linear.manage",
]

ALLOWED_OPS = {
    "list_issues", "get_issue", "create_issue", "update_issue", "close_issue",
    "list_projects", "get_project",
    "create_comment", "list_teams",
    "assign_issue", "set_priority",
    "list_cycles", "list_labels",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# Linear priority constants
PRIORITY_NO     = 0
PRIORITY_URGENT = 1
PRIORITY_HIGH   = 2
PRIORITY_MEDIUM = 3
PRIORITY_LOW    = 4

PRIORITY_LABELS = {
    PRIORITY_NO:     "No priority",
    PRIORITY_URGENT: "Urgent",
    PRIORITY_HIGH:   "High",
    PRIORITY_MEDIUM: "Medium",
    PRIORITY_LOW:    "Low",
}

LINEAR_GRAPHQL_ENDPOINT = "https://api.linear.app/graphql"


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
class LinearIssue:
    id: str
    identifier: str
    title: str
    state_name: str
    priority: int
    assignee_name: Optional[str]
    created_at: str
    updated_at: str
    description: Optional[str] = None
    label_names: List[str] = field(default_factory=list)


@dataclass
class LinearProject:
    id: str
    name: str
    state: str
    progress: float


@dataclass
class LinearTeam:
    id: str
    name: str
    key: str
    description: Optional[str]


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


def _get_api_key() -> str:
    """Retrieve LINEAR_API_KEY from environment. Exits if not set."""
    key = os.environ.get("LINEAR_API_KEY", "").strip()
    if not key:
        log("ERROR: LINEAR_API_KEY environment variable is not set.")
        log("  Set it with: export LINEAR_API_KEY=lin_api_xxxx")
        raise SystemExit(1)
    return key


def priority_label(priority: int) -> str:
    """Return human-readable priority label."""
    return PRIORITY_LABELS.get(priority, f"Unknown({priority})")


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
#   code/worker_logic.py → package root is two levels up (linear_worker/)
_THIS_FILE    = Path(__file__).resolve()
_PACKAGE_ROOT = _THIS_FILE.parent.parent   # .../linear_worker/
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

        rule_id = f"rr_linear_{op}_allow_v1"
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
    read_ops = {"list_issues", "get_issue", "list_projects", "get_project",
                "list_teams", "list_cycles", "list_labels"}
    manage_ops = {"create_issue", "update_issue", "close_issue",
                  "create_comment", "assign_issue", "set_priority"}
    if op in read_ops:
        return "cap.pyhall.linear.read"
    if op in manage_ops:
        return "cap.pyhall.linear.manage"
    return "cap.pyhall.linear.write"


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
# SECTION 7: DOMAIN LOGIC — LINEAR GRAPHQL API
# ============================================================================

# --- GraphQL transport helper ---

def _graphql(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    POST a GraphQL query/mutation to the Linear API.

    Returns the parsed JSON response dict. Raises RuntimeError on HTTP errors
    or if the response contains top-level GraphQL errors.

    Auth: reads LINEAR_API_KEY from environment each call (allows key rotation
    without restart).
    """
    try:
        import requests
    except ImportError:
        log("ERROR: 'requests' library not installed. Run: pip install requests")
        raise SystemExit(1)

    api_key = _get_api_key()
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json",
    }
    payload: Dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables

    try:
        resp = requests.post(
            LINEAR_GRAPHQL_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=30,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Linear API request failed: {exc}") from exc

    if resp.status_code != 200:
        raise RuntimeError(
            f"Linear API returned HTTP {resp.status_code}: {resp.text[:500]}"
        )

    data = resp.json()

    # GraphQL errors are returned as 200 with an `errors` key
    errors = data.get("errors")
    if errors:
        messages = "; ".join(e.get("message", str(e)) for e in errors)
        raise RuntimeError(f"Linear GraphQL errors: {messages}")

    return data


# --- Read operations ---

def list_issues(
    team_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    List issues from Linear. Optionally filter by team_id and/or status name.

    Returns a list of issue dicts with fields: id, identifier, title, state,
    priority, assignee, createdAt, updatedAt.
    """
    ctx, decision = _gate_and_emit("list_issues")

    filter_parts: List[str] = []
    variables: Dict[str, Any] = {"first": limit}

    if team_id:
        filter_parts.append("team: { id: { eq: $teamId } }")
        variables["teamId"] = team_id
    if status:
        filter_parts.append("state: { name: { eq: $statusName } }")
        variables["statusName"] = status

    filter_clause = ""
    if filter_parts:
        filter_clause = f"filter: {{ {' '.join(filter_parts)} }}"

    # Build variable declarations dynamically
    var_decls_parts: List[str] = ["$first: Int!"]
    if team_id:
        var_decls_parts.append("$teamId: ID!")
    if status:
        var_decls_parts.append("$statusName: String!")
    var_decls = ", ".join(var_decls_parts)

    query = f"""
    query ListIssues({var_decls}) {{
      issues(first: $first {filter_clause}) {{
        nodes {{
          id
          identifier
          title
          state {{
            name
          }}
          priority
          assignee {{
            name
          }}
          createdAt
          updatedAt
        }}
      }}
    }}
    """

    try:
        data = _graphql(query, variables)
        issues = data.get("data", {}).get("issues", {}).get("nodes", [])
        log(f"list_issues: found {len(issues)} issues"
            + (f" [team={team_id}]" if team_id else "")
            + (f" [status={status}]" if status else ""))
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_issues: {len(issues)} results",
            "list_issues", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return issues
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_issues", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def get_issue(issue_id: str) -> Dict[str, Any]:
    """
    Fetch a single Linear issue by ID with full fields including
    description, comments, and labels.
    """
    ctx, decision = _gate_and_emit("get_issue")

    query = """
    query GetIssue($id: String!) {
      issue(id: $id) {
        id
        identifier
        title
        description
        state {
          id
          name
          type
        }
        priority
        assignee {
          id
          name
          email
        }
        team {
          id
          name
          key
        }
        labels {
          nodes {
            id
            name
            color
          }
        }
        comments {
          nodes {
            id
            body
            createdAt
            user {
              name
            }
          }
        }
        createdAt
        updatedAt
        completedAt
        canceledAt
        url
      }
    }
    """

    try:
        data = _graphql(query, {"id": issue_id})
        issue = data.get("data", {}).get("issue")
        if issue is None:
            raise RuntimeError(f"Issue not found: {issue_id}")
        log(f"get_issue: {issue.get('identifier')} — {issue.get('title')}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"get_issue: {issue_id} retrieved",
            "get_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return issue
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "get_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def list_projects(team_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List Linear projects. Optionally filter by team."""
    ctx, decision = _gate_and_emit("list_projects")

    filter_clause = ""
    variables: Dict[str, Any] = {}
    var_decls = ""

    if team_id:
        filter_clause = "filter: { members: { some: { id: { eq: $teamId } } } }"
        variables["teamId"] = team_id
        var_decls = "($teamId: ID!)"

    query = f"""
    query ListProjects{var_decls} {{
      projects({filter_clause}) {{
        nodes {{
          id
          name
          state
          progress
          startedAt
          targetDate
          completedAt
        }}
      }}
    }}
    """

    try:
        data = _graphql(query, variables if variables else None)
        projects = data.get("data", {}).get("projects", {}).get("nodes", [])
        log(f"list_projects: found {len(projects)} projects")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_projects: {len(projects)} results",
            "list_projects", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return projects
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_projects", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def get_project(project_id: str) -> Dict[str, Any]:
    """Fetch a Linear project by ID with full details."""
    ctx, decision = _gate_and_emit("get_project")

    query = """
    query GetProject($id: String!) {
      project(id: $id) {
        id
        name
        description
        state
        progress
        startedAt
        targetDate
        completedAt
        lead {
          id
          name
        }
        members {
          nodes {
            id
            name
          }
        }
        teams {
          nodes {
            id
            name
            key
          }
        }
        url
      }
    }
    """

    try:
        data = _graphql(query, {"id": project_id})
        project = data.get("data", {}).get("project")
        if project is None:
            raise RuntimeError(f"Project not found: {project_id}")
        log(f"get_project: {project.get('name')}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"get_project: {project_id} retrieved",
            "get_project", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return project
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "get_project", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def list_teams() -> List[Dict[str, Any]]:
    """List all Linear teams accessible with the current API key."""
    ctx, decision = _gate_and_emit("list_teams")

    query = """
    query ListTeams {
      teams {
        nodes {
          id
          name
          key
          description
          issueCount
          timezone
        }
      }
    }
    """

    try:
        data = _graphql(query)
        teams = data.get("data", {}).get("teams", {}).get("nodes", [])
        log(f"list_teams: found {len(teams)} teams")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_teams: {len(teams)} results",
            "list_teams", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return teams
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_teams", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def list_cycles(team_id: str) -> List[Dict[str, Any]]:
    """List all cycles for a given team."""
    ctx, decision = _gate_and_emit("list_cycles")

    query = """
    query ListCycles($teamId: String!) {
      cycles(filter: { team: { id: { eq: $teamId } } }) {
        nodes {
          id
          number
          name
          startsAt
          endsAt
          completedAt
          issueCountHistory
          completedIssueCountHistory
          progress
        }
      }
    }
    """

    try:
        data = _graphql(query, {"teamId": team_id})
        cycles = data.get("data", {}).get("cycles", {}).get("nodes", [])
        log(f"list_cycles: found {len(cycles)} cycles for team {team_id}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_cycles: {len(cycles)} results for team {team_id}",
            "list_cycles", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return cycles
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_cycles", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def list_labels(team_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List issue labels. Optionally filter by team."""
    ctx, decision = _gate_and_emit("list_labels")

    filter_clause = ""
    variables: Dict[str, Any] = {}
    var_decls = ""

    if team_id:
        filter_clause = "filter: { team: { id: { eq: $teamId } } }"
        variables["teamId"] = team_id
        var_decls = "($teamId: ID!)"

    query = f"""
    query ListLabels{var_decls} {{
      issueLabels({filter_clause}) {{
        nodes {{
          id
          name
          color
          description
        }}
      }}
    }}
    """

    try:
        data = _graphql(query, variables if variables else None)
        labels = data.get("data", {}).get("issueLabels", {}).get("nodes", [])
        log(f"list_labels: found {len(labels)} labels")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"list_labels: {len(labels)} results",
            "list_labels", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return labels
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "list_labels", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


# --- Mutation operations ---

def create_issue(
    title: str,
    team_id: str,
    description: Optional[str] = None,
    priority: int = PRIORITY_NO,
    label_ids: Optional[List[str]] = None,
    assignee_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new Linear issue.

    priority: 0=No priority, 1=Urgent, 2=High, 3=Medium, 4=Low
    Returns the created issue dict.
    """
    ctx, decision = _gate_and_emit("create_issue")

    mutation = """
    mutation CreateIssue($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue {
          id
          identifier
          title
          state {
            name
          }
          priority
          url
          createdAt
        }
      }
    }
    """

    issue_input: Dict[str, Any] = {
        "title": title,
        "teamId": team_id,
        "priority": priority,
    }
    if description:
        issue_input["description"] = description
    if label_ids:
        issue_input["labelIds"] = label_ids
    if assignee_id:
        issue_input["assigneeId"] = assignee_id

    try:
        data = _graphql(mutation, {"input": issue_input})
        result = data.get("data", {}).get("issueCreate", {})
        if not result.get("success"):
            raise RuntimeError(f"IssueCreate returned success=false")
        issue = result.get("issue", {})
        log(f"create_issue: created {issue.get('identifier')} — {title!r} [{priority_label(priority)}]")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"create_issue: {issue.get('id')} title={title!r} priority={priority}",
            "create_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return issue
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "create_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def update_issue(
    issue_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    priority: Optional[int] = None,
    state_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Update fields on an existing Linear issue.
    Only provided (non-None) fields will be changed.
    """
    ctx, decision = _gate_and_emit("update_issue")

    mutation = """
    mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
      issueUpdate(id: $id, input: $input) {
        success
        issue {
          id
          identifier
          title
          state {
            name
          }
          priority
          updatedAt
        }
      }
    }
    """

    issue_input: Dict[str, Any] = {}
    if title is not None:
        issue_input["title"] = title
    if description is not None:
        issue_input["description"] = description
    if priority is not None:
        issue_input["priority"] = priority
    if state_id is not None:
        issue_input["stateId"] = state_id

    if not issue_input:
        raise ValueError("update_issue: at least one field must be provided to update")

    try:
        data = _graphql(mutation, {"id": issue_id, "input": issue_input})
        result = data.get("data", {}).get("issueUpdate", {})
        if not result.get("success"):
            raise RuntimeError(f"IssueUpdate returned success=false for {issue_id}")
        issue = result.get("issue", {})
        changed_fields = list(issue_input.keys())
        log(f"update_issue: {issue.get('identifier')} updated fields={changed_fields}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"update_issue: {issue_id} fields={changed_fields}",
            "update_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return issue
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "update_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def close_issue(issue_id: str, canceled: bool = False) -> Dict[str, Any]:
    """
    Close a Linear issue by moving it to a Completed (or Canceled) workflow state.

    This first fetches the team's workflow states to find a suitable terminal state,
    then applies it via IssueUpdate.

    canceled=True uses a Canceled state instead of Completed.
    """
    ctx, decision = _gate_and_emit("close_issue")

    # Step 1: Fetch the issue to get its team
    fetch_query = """
    query GetIssueTeam($id: String!) {
      issue(id: $id) {
        id
        identifier
        team {
          id
          states {
            nodes {
              id
              name
              type
            }
          }
        }
      }
    }
    """

    mutation = """
    mutation CloseIssue($id: String!, $input: IssueUpdateInput!) {
      issueUpdate(id: $id, input: $input) {
        success
        issue {
          id
          identifier
          state {
            name
            type
          }
          updatedAt
        }
      }
    }
    """

    try:
        fetch_data = _graphql(fetch_query, {"id": issue_id})
        issue_data = fetch_data.get("data", {}).get("issue")
        if not issue_data:
            raise RuntimeError(f"Issue not found: {issue_id}")

        states = issue_data.get("team", {}).get("states", {}).get("nodes", [])
        target_type = "cancelled" if canceled else "completed"
        # Linear state types: triage, backlog, started, unstarted, completed, cancelled
        state_id = next(
            (s["id"] for s in states if s.get("type", "").lower() == target_type),
            None,
        )

        if state_id is None:
            # Fallback: search by common name patterns
            name_patterns = (
                ["canceled", "cancelled", "won't fix", "wontfix"] if canceled
                else ["done", "completed", "closed", "finished"]
            )
            state_id = next(
                (s["id"] for s in states if s.get("name", "").lower() in name_patterns),
                None,
            )

        if state_id is None:
            available = [f"{s['name']}({s['type']})" for s in states]
            raise RuntimeError(
                f"Could not find a {'canceled' if canceled else 'completed'} state "
                f"for issue {issue_id}. Available: {available}"
            )

        data = _graphql(mutation, {"id": issue_id, "input": {"stateId": state_id}})
        result = data.get("data", {}).get("issueUpdate", {})
        if not result.get("success"):
            raise RuntimeError(f"IssueUpdate (close) returned success=false for {issue_id}")
        issue = result.get("issue", {})
        state_name = issue.get("state", {}).get("name", "?")
        identifier = issue_data.get("identifier", issue_id)
        log(f"close_issue: {identifier} → state={state_name!r}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"close_issue: {issue_id} state_id={state_id} canceled={canceled}",
            "close_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return issue
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "close_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def create_comment(issue_id: str, body: str) -> Dict[str, Any]:
    """Add a comment to a Linear issue."""
    ctx, decision = _gate_and_emit("create_comment")

    mutation = """
    mutation CreateComment($input: CommentCreateInput!) {
      commentCreate(input: $input) {
        success
        comment {
          id
          body
          createdAt
          user {
            name
          }
          issue {
            identifier
          }
        }
      }
    }
    """

    try:
        data = _graphql(mutation, {"input": {"issueId": issue_id, "body": body}})
        result = data.get("data", {}).get("commentCreate", {})
        if not result.get("success"):
            raise RuntimeError(f"CommentCreate returned success=false for issue {issue_id}")
        comment = result.get("comment", {})
        identifier = comment.get("issue", {}).get("identifier", issue_id)
        log(f"create_comment: added comment to {identifier} ({len(body)} chars)")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"create_comment: issue={issue_id} comment_id={comment.get('id')}",
            "create_comment", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return comment
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "create_comment", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def assign_issue(issue_id: str, assignee_id: str) -> Dict[str, Any]:
    """Assign a Linear issue to a user by user ID."""
    ctx, decision = _gate_and_emit("assign_issue")

    mutation = """
    mutation AssignIssue($id: String!, $input: IssueUpdateInput!) {
      issueUpdate(id: $id, input: $input) {
        success
        issue {
          id
          identifier
          assignee {
            id
            name
          }
          updatedAt
        }
      }
    }
    """

    try:
        data = _graphql(mutation, {"id": issue_id, "input": {"assigneeId": assignee_id}})
        result = data.get("data", {}).get("issueUpdate", {})
        if not result.get("success"):
            raise RuntimeError(f"IssueUpdate (assign) returned success=false for {issue_id}")
        issue = result.get("issue", {})
        assignee_name = (issue.get("assignee") or {}).get("name", assignee_id)
        log(f"assign_issue: {issue.get('identifier')} assigned to {assignee_name!r}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"assign_issue: {issue_id} assignee={assignee_id}",
            "assign_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return issue
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "assign_issue", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


def set_priority(issue_id: str, priority: int) -> Dict[str, Any]:
    """
    Set the priority of a Linear issue.

    priority: PRIORITY_NO(0) | PRIORITY_URGENT(1) | PRIORITY_HIGH(2)
              | PRIORITY_MEDIUM(3) | PRIORITY_LOW(4)
    """
    ctx, decision = _gate_and_emit("set_priority")

    if priority not in PRIORITY_LABELS:
        raise ValueError(
            f"Invalid priority {priority!r}. Valid values: {list(PRIORITY_LABELS.keys())}"
        )

    mutation = """
    mutation SetPriority($id: String!, $input: IssueUpdateInput!) {
      issueUpdate(id: $id, input: $input) {
        success
        issue {
          id
          identifier
          priority
          updatedAt
        }
      }
    }
    """

    try:
        data = _graphql(mutation, {"id": issue_id, "input": {"priority": priority}})
        result = data.get("data", {}).get("issueUpdate", {})
        if not result.get("success"):
            raise RuntimeError(f"IssueUpdate (set_priority) returned success=false for {issue_id}")
        issue = result.get("issue", {})
        log(f"set_priority: {issue.get('identifier')} priority={priority_label(priority)}")
        receipt = build_evidence_receipt(
            ctx, decision, "ok",
            f"set_priority: {issue_id} priority={priority} ({priority_label(priority)})",
            "set_priority", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return issue
    except RuntimeError as exc:
        receipt = build_evidence_receipt(
            ctx, decision, "error", str(exc), "set_priority", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        raise


# --- Output helpers ---

def _print_issues(issues: List[Dict[str, Any]]) -> None:
    """Format and print a list of issue dicts to stdout."""
    if not issues:
        print("No issues found.")
        return
    for issue in issues:
        state = (issue.get("state") or {}).get("name", "?")
        assignee = (issue.get("assignee") or {}).get("name", "unassigned")
        pri = priority_label(issue.get("priority", 0))
        print(f"  [{issue.get('identifier', '?')}] {issue.get('title', '?')}")
        print(f"    state={state}  priority={pri}  assignee={assignee}")
        print(f"    updated={issue.get('updatedAt', '?')}")
    print(f"\n  ({len(issues)} issues)")


def _print_teams(teams: List[Dict[str, Any]]) -> None:
    if not teams:
        print("No teams found.")
        return
    for t in teams:
        desc = t.get("description") or ""
        print(f"  [{t.get('key')}] {t.get('name')}  id={t.get('id')}")
        if desc:
            print(f"    {desc[:80]}")
    print(f"\n  ({len(teams)} teams)")


# ============================================================================
# SECTION 8: ENTRY POINT + ARGPARSE DISPATCH
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 worker_logic.py list_teams\n"
            "  python3 worker_logic.py list_issues --limit 20\n"
            "  python3 worker_logic.py list_issues --team-id TEAM_ID --status 'In Progress'\n"
            "  python3 worker_logic.py get_issue --issue-id ISSUE_ID\n"
            "  python3 worker_logic.py create_issue --title 'Fix bug' --team-id TEAM_ID --priority 2\n"
            "  python3 worker_logic.py update_issue --issue-id ISSUE_ID --title 'New title'\n"
            "  python3 worker_logic.py close_issue --issue-id ISSUE_ID\n"
            "  python3 worker_logic.py close_issue --issue-id ISSUE_ID --canceled\n"
            "  python3 worker_logic.py create_comment --issue-id ISSUE_ID --body 'LGTM'\n"
            "  python3 worker_logic.py assign_issue --issue-id ISSUE_ID --assignee-id USER_ID\n"
            "  python3 worker_logic.py set_priority --issue-id ISSUE_ID --priority 1\n"
            "  python3 worker_logic.py list_projects\n"
            "  python3 worker_logic.py get_project --project-id PROJECT_ID\n"
            "  python3 worker_logic.py list_cycles --team-id TEAM_ID\n"
            "  python3 worker_logic.py list_labels\n"
        ),
    )
    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # Shared identifiers
    p.add_argument("--issue-id",    dest="issue_id",    help="Linear issue ID (UUID)")
    p.add_argument("--team-id",     dest="team_id",     help="Linear team ID")
    p.add_argument("--project-id",  dest="project_id",  help="Linear project ID")
    p.add_argument("--assignee-id", dest="assignee_id", help="Linear user ID for assignee")

    # Issue fields
    p.add_argument("--title",       help="Issue title (create_issue / update_issue)")
    p.add_argument("--description", help="Issue description (markdown)")
    p.add_argument("--state-id",    dest="state_id",    help="Workflow state ID (update_issue)")
    p.add_argument(
        "--priority", type=int,
        choices=[PRIORITY_NO, PRIORITY_URGENT, PRIORITY_HIGH, PRIORITY_MEDIUM, PRIORITY_LOW],
        default=PRIORITY_NO,
        help="Priority: 0=None 1=Urgent 2=High 3=Medium 4=Low (default: 0)",
    )
    p.add_argument(
        "--label-ids", dest="label_ids", nargs="+",
        help="Label IDs to attach (create_issue)",
    )
    p.add_argument("--status",  help="Filter issues by status name (list_issues)")
    p.add_argument("--limit",   type=int, default=50, help="Max results for list ops (default: 50)")
    p.add_argument("--canceled", action="store_true", help="Close as canceled instead of completed")

    # Comment
    p.add_argument("--body", help="Comment body text (create_comment)")

    return p


def _dispatch(op: str, args: argparse.Namespace) -> Any:
    """Route the parsed op + args to the correct domain function."""
    if op == "list_issues":
        issues = list_issues(
            team_id=args.team_id or os.environ.get("LINEAR_DEFAULT_TEAM_ID"),
            status=args.status,
            limit=args.limit,
        )
        _print_issues(issues)
        return issues

    elif op == "get_issue":
        if not args.issue_id:
            log("ERROR: --issue-id required for get_issue")
            raise SystemExit(1)
        issue = get_issue(args.issue_id)
        print(json.dumps(issue, indent=2))
        return issue

    elif op == "create_issue":
        if not args.title:
            log("ERROR: --title required for create_issue")
            raise SystemExit(1)
        team = args.team_id or os.environ.get("LINEAR_DEFAULT_TEAM_ID")
        if not team:
            log("ERROR: --team-id or LINEAR_DEFAULT_TEAM_ID required for create_issue")
            raise SystemExit(1)
        issue = create_issue(
            title=args.title,
            team_id=team,
            description=args.description,
            priority=args.priority,
            label_ids=args.label_ids,
            assignee_id=args.assignee_id,
        )
        print(json.dumps(issue, indent=2))
        return issue

    elif op == "update_issue":
        if not args.issue_id:
            log("ERROR: --issue-id required for update_issue")
            raise SystemExit(1)
        issue = update_issue(
            issue_id=args.issue_id,
            title=args.title,
            description=args.description,
            priority=args.priority if args.priority != PRIORITY_NO else None,
            state_id=args.state_id,
        )
        print(json.dumps(issue, indent=2))
        return issue

    elif op == "close_issue":
        if not args.issue_id:
            log("ERROR: --issue-id required for close_issue")
            raise SystemExit(1)
        issue = close_issue(args.issue_id, canceled=args.canceled)
        print(json.dumps(issue, indent=2))
        return issue

    elif op == "create_comment":
        if not args.issue_id:
            log("ERROR: --issue-id required for create_comment")
            raise SystemExit(1)
        if not args.body:
            log("ERROR: --body required for create_comment")
            raise SystemExit(1)
        comment = create_comment(args.issue_id, args.body)
        print(json.dumps(comment, indent=2))
        return comment

    elif op == "assign_issue":
        if not args.issue_id:
            log("ERROR: --issue-id required for assign_issue")
            raise SystemExit(1)
        if not args.assignee_id:
            log("ERROR: --assignee-id required for assign_issue")
            raise SystemExit(1)
        issue = assign_issue(args.issue_id, args.assignee_id)
        print(json.dumps(issue, indent=2))
        return issue

    elif op == "set_priority":
        if not args.issue_id:
            log("ERROR: --issue-id required for set_priority")
            raise SystemExit(1)
        issue = set_priority(args.issue_id, args.priority)
        print(json.dumps(issue, indent=2))
        return issue

    elif op == "list_projects":
        projects = list_projects(team_id=args.team_id)
        if not projects:
            print("No projects found.")
        else:
            for p in projects:
                print(f"  {p.get('name')}  state={p.get('state')}  "
                      f"progress={p.get('progress', 0):.0%}  id={p.get('id')}")
            print(f"\n  ({len(projects)} projects)")
        return projects

    elif op == "get_project":
        if not args.project_id:
            log("ERROR: --project-id required for get_project")
            raise SystemExit(1)
        project = get_project(args.project_id)
        print(json.dumps(project, indent=2))
        return project

    elif op == "list_teams":
        teams = list_teams()
        _print_teams(teams)
        return teams

    elif op == "list_cycles":
        team = args.team_id or os.environ.get("LINEAR_DEFAULT_TEAM_ID")
        if not team:
            log("ERROR: --team-id or LINEAR_DEFAULT_TEAM_ID required for list_cycles")
            raise SystemExit(1)
        cycles = list_cycles(team)
        if not cycles:
            print("No cycles found.")
        else:
            for c in cycles:
                completed = c.get("completedAt") or ""
                print(f"  Cycle #{c.get('number')} {c.get('name') or ''}  "
                      f"starts={c.get('startsAt', '?')[:10]}  "
                      f"ends={c.get('endsAt', '?')[:10]}"
                      + (f"  completed={completed[:10]}" if completed else ""))
            print(f"\n  ({len(cycles)} cycles)")
        return cycles

    elif op == "list_labels":
        labels = list_labels(team_id=args.team_id)
        if not labels:
            print("No labels found.")
        else:
            for lbl in labels:
                print(f"  {lbl.get('name')}  color={lbl.get('color', '?')}  id={lbl.get('id')}")
            print(f"\n  ({len(labels)} labels)")
        return labels

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
