#!/usr/bin/env python3
"""
worker_logic.py — GitHub Full Stack Worker (WCP v0.3.0)

Full-stack GitHub REST API v3 worker. Manages repos, issues, pull requests,
comments, labels, assignees, commits, and file content via authenticated PAT.

Auth: GITHUB_TOKEN env var (PAT with repo scope).
All timestamps stored as UTC ISO 8601. Human-facing log output uses Central Time.

Setup:
    export GITHUB_TOKEN=ghp_yourtoken
    python3 bootstrap.py list_repos
    python3 bootstrap.py list_issues --owner myorg --repo myrepo
"""

from __future__ import annotations

# ============================================================================
# SECTION 1: HEADER + IDENTITY + WCP DECLARATIONS
# ============================================================================

import argparse
import base64
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

WORKER_ID          = "org.pyhall.github.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.github"
WORKER_NAME        = "GitHub Full Stack Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.github.write",
    "cap.pyhall.github.read",
]

ALLOWED_OPS = {
    "list_repos", "get_repo", "get_repo_stats",
    "list_issues", "get_issue", "create_issue", "update_issue", "close_issue",
    "add_comment", "list_comments",
    "create_label", "assign_issue",
    "list_prs", "get_pr", "create_pr", "merge_pr",
    "list_commits", "get_file_content",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# Read-only ops use cap.pyhall.github.read; write ops use specific capability
_READ_OPS = {
    "list_repos", "get_repo", "get_repo_stats",
    "list_issues", "get_issue", "list_comments",
    "list_prs", "get_pr",
    "list_commits", "get_file_content",
}

_WRITE_OPS = {
    "create_issue", "update_issue", "close_issue",
    "add_comment", "create_label", "assign_issue",
    "create_pr", "merge_pr",
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
class RepoSummary:
    name: str
    full_name: str
    description: Optional[str]
    private: bool
    html_url: str
    language: Optional[str]
    stargazers_count: int
    forks_count: int


@dataclass
class IssueSummary:
    number: int
    title: str
    state: str
    body: Optional[str]
    html_url: str
    labels: List[str]
    assignees: List[str]
    created_at: str
    updated_at: str


@dataclass
class PRSummary:
    number: int
    title: str
    state: str
    body: Optional[str]
    html_url: str
    head: str
    base: str
    draft: bool
    created_at: str
    updated_at: str


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


def _capability_for_op(op: str) -> str:
    """Select the most appropriate capability ID for a given op."""
    if op in _READ_OPS:
        return "cap.pyhall.github.read"
    if op in {"list_issues", "get_issue", "create_issue", "update_issue", "close_issue",
              "add_comment", "list_comments", "create_label", "assign_issue"}:
        return "cap.pyhall.github.write"
    if op in {"list_prs", "get_pr", "create_pr", "merge_pr"}:
        return "cap.pyhall.github.write"
    if op in {"list_repos", "get_repo", "get_repo_stats"}:
        return "cap.pyhall.github.read"
    return "cap.pyhall.github.write"


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
#   code/worker_logic.py → package root is two levels up (github_worker/)
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent          # .../github_worker/
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

        rule_id = f"rr_github_{op}_allow_v1"
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
_attest_meta: Dict[str, Any] = {}   # populated by run() at startup


def _make_ctx(op: str, capability_id: Optional[str] = None) -> WCPContext:
    """Build a WCPContext for the given operation."""
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=capability_id or _capability_for_op(op),
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
# SECTION 7: DOMAIN LOGIC — GITHUB REST API v3
# ============================================================================

_GH_BASE_URL = "https://api.github.com"
_RATE_WARN_THRESHOLD = 100


def _get_token() -> str:
    """Retrieve GitHub PAT from environment. Raises SystemExit if missing."""
    token_env = os.environ.get("GITHUB_WORKER_TOKEN_ENV", "GITHUB_TOKEN")
    token = os.environ.get(token_env, "").strip()
    if not token:
        log(f"ERROR: {token_env} not set. Export a GitHub PAT with repo scope.")
        raise SystemExit(1)
    return token


def _gh_headers(token: str) -> Dict[str, str]:
    """Build GitHub API request headers."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _gh(method: str, path: str, token: Optional[str] = None, **kwargs: Any) -> Any:
    """
    Make an authenticated GitHub REST API request.

    Handles:
    - Rate limit: emits warning if X-RateLimit-Remaining < _RATE_WARN_THRESHOLD.
      Waits if remaining == 0.
    - 404: returns None (caller decides how to handle not-found).
    - Other non-2xx: raises RuntimeError with status + body.

    Returns parsed JSON (dict/list) or None for 204/404.
    """
    try:
        import requests
    except ImportError:
        log("ERROR: 'requests' package not installed. Run: pip install requests")
        raise SystemExit(1)

    if token is None:
        token = _get_token()

    url = f"{_GH_BASE_URL}{path}" if path.startswith("/") else path
    headers = _gh_headers(token)

    resp = requests.request(method.upper(), url, headers=headers, **kwargs)

    # Rate limit check
    remaining = resp.headers.get("X-RateLimit-Remaining")
    if remaining is not None:
        remaining_int = int(remaining)
        if remaining_int == 0:
            reset_at = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait_secs = max(0, reset_at - int(time.time())) + 2
            log(f"WARNING: GitHub rate limit exhausted. Waiting {wait_secs}s for reset...")
            time.sleep(wait_secs)
            # Retry once after waiting
            resp = requests.request(method.upper(), url, headers=headers, **kwargs)
        elif remaining_int < _RATE_WARN_THRESHOLD:
            log(f"WARNING: GitHub rate limit low — {remaining_int} requests remaining")

    # 404 → caller handles
    if resp.status_code == 404:
        return None

    # 204 No Content (e.g. delete, merge success with no body)
    if resp.status_code == 204:
        return {}

    if not resp.ok:
        try:
            err_body = resp.json()
        except Exception:
            err_body = resp.text
        raise RuntimeError(
            f"GitHub API error {resp.status_code} {method.upper()} {path}: {err_body}"
        )

    return resp.json()


# ── Repos ─────────────────────────────────────────────────────────────────────

def list_repos(
    owner: Optional[str] = None,
    repo_type: str = "all",
    limit: int = 30,
) -> List[Dict[str, Any]]:
    """
    List repositories for the authenticated user, a GitHub user, or an org.

    owner=None  → GET /user/repos (authenticated user)
    owner set   → tries /orgs/{owner}/repos first, falls back to /users/{owner}/repos
    """
    ctx, decision = _gate_and_emit("list_repos")
    token = _get_token()

    results: List[Dict[str, Any]] = []
    page = 1
    per_page = min(limit, 100)

    while len(results) < limit:
        if owner is None:
            path = f"/user/repos?type={repo_type}&per_page={per_page}&page={page}&sort=updated"
        else:
            # Try org first; if 404 fall back to user
            org_path = f"/orgs/{owner}/repos?type={repo_type}&per_page={per_page}&page={page}&sort=updated"
            org_data = _gh("GET", org_path, token=token)
            if org_data is None:
                path = f"/users/{owner}/repos?type={repo_type}&per_page={per_page}&page={page}&sort=updated"
            else:
                page_data = org_data
                if not isinstance(page_data, list) or len(page_data) == 0:
                    break
                results.extend(page_data)
                page += 1
                continue

        page_data = _gh("GET", path, token=token)
        if not isinstance(page_data, list) or len(page_data) == 0:
            break
        results.extend(page_data)
        page += 1

    results = results[:limit]
    simplified = [
        {
            "name": r.get("name"),
            "full_name": r.get("full_name"),
            "description": r.get("description"),
            "private": r.get("private"),
            "html_url": r.get("html_url"),
            "language": r.get("language"),
            "stargazers_count": r.get("stargazers_count", 0),
            "forks_count": r.get("forks_count", 0),
        }
        for r in results
    ]

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_repos: owner={owner!r} returned {len(simplified)} repos",
        "list_repos", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"list_repos: {len(simplified)} repos" + (f" for {owner}" if owner else " (authenticated user)"))
    return simplified


def get_repo(owner: str, repo: str) -> Optional[Dict[str, Any]]:
    """GET /repos/{owner}/{repo}. Returns None if not found."""
    ctx, decision = _gate_and_emit("get_repo")
    token = _get_token()

    data = _gh("GET", f"/repos/{owner}/{repo}", token=token)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found", f"get_repo: {owner}/{repo} not found", "get_repo", _attest_meta
        )
        _evidence_log.emit_evidence(receipt)
        log(f"get_repo: {owner}/{repo} — not found (404)")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok", f"get_repo: {owner}/{repo}", "get_repo", _attest_meta
    )
    _evidence_log.emit_evidence(receipt)
    log(f"get_repo: {owner}/{repo} — stars={data.get('stargazers_count', 0)}, forks={data.get('forks_count', 0)}")
    return data


def get_repo_stats(owner: str, repo: str) -> Optional[Dict[str, Any]]:
    """
    GET /repos/{owner}/{repo} + /repos/{owner}/{repo}/stats/contributors.

    Returns combined dict with repo info and contributor count.
    """
    ctx, decision = _gate_and_emit("get_repo_stats")
    token = _get_token()

    repo_data = _gh("GET", f"/repos/{owner}/{repo}", token=token)
    if repo_data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found", f"get_repo_stats: {owner}/{repo} not found",
            "get_repo_stats", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"get_repo_stats: {owner}/{repo} — not found (404)")
        return None

    # Contributor stats (may return 202 while GitHub computes — retry once)
    contributors: List[Any] = []
    for attempt in range(2):
        contrib_data = _gh("GET", f"/repos/{owner}/{repo}/stats/contributors", token=token)
        if isinstance(contrib_data, list):
            contributors = contrib_data
            break
        if attempt == 0:
            log(f"get_repo_stats: contributor stats not ready, retrying in 3s...")
            time.sleep(3)

    # Commit count from default branch commits endpoint
    commits_data = _gh(
        "GET", f"/repos/{owner}/{repo}/commits?per_page=1",
        token=token,
    )
    commit_count: Optional[int] = None
    # GitHub returns total count in Link header when per_page=1
    # (not always present; leave as None if unavailable)

    stats = {
        "name": repo_data.get("name"),
        "full_name": repo_data.get("full_name"),
        "description": repo_data.get("description"),
        "private": repo_data.get("private"),
        "html_url": repo_data.get("html_url"),
        "language": repo_data.get("language"),
        "stargazers_count": repo_data.get("stargazers_count", 0),
        "forks_count": repo_data.get("forks_count", 0),
        "open_issues_count": repo_data.get("open_issues_count", 0),
        "watchers_count": repo_data.get("watchers_count", 0),
        "size_kb": repo_data.get("size", 0),
        "default_branch": repo_data.get("default_branch"),
        "created_at": repo_data.get("created_at"),
        "updated_at": repo_data.get("updated_at"),
        "pushed_at": repo_data.get("pushed_at"),
        "contributor_count": len(contributors),
        "commit_count": commit_count,
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_repo_stats: {owner}/{repo} contributors={len(contributors)}",
        "get_repo_stats", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"get_repo_stats: {owner}/{repo} — contributors={len(contributors)}, stars={stats['stargazers_count']}")
    return stats


# ── Issues ────────────────────────────────────────────────────────────────────

def list_issues(
    owner: str,
    repo: str,
    state: str = "open",
    labels: Optional[List[str]] = None,
    limit: int = 30,
) -> List[Dict[str, Any]]:
    """GET /repos/{owner}/{repo}/issues. Returns simplified issue list."""
    ctx, decision = _gate_and_emit("list_issues")
    token = _get_token()

    results: List[Dict[str, Any]] = []
    page = 1
    per_page = min(limit, 100)

    while len(results) < limit:
        params = f"state={state}&per_page={per_page}&page={page}"
        if labels:
            params += f"&labels={','.join(labels)}"
        path = f"/repos/{owner}/{repo}/issues?{params}"
        page_data = _gh("GET", path, token=token)

        if page_data is None:
            log(f"list_issues: {owner}/{repo} not found (404)")
            receipt = build_evidence_receipt(
                ctx, decision, "not_found", f"list_issues: {owner}/{repo} not found",
                "list_issues", _attest_meta,
            )
            _evidence_log.emit_evidence(receipt)
            return []

        if not isinstance(page_data, list) or len(page_data) == 0:
            break

        # /issues returns PRs too — filter them out
        page_data = [i for i in page_data if "pull_request" not in i]
        results.extend(page_data)
        page += 1

    results = results[:limit]
    simplified = [
        {
            "number": i.get("number"),
            "title": i.get("title"),
            "state": i.get("state"),
            "body": i.get("body"),
            "html_url": i.get("html_url"),
            "labels": [lb.get("name") for lb in i.get("labels", [])],
            "assignees": [a.get("login") for a in i.get("assignees", [])],
            "created_at": i.get("created_at"),
            "updated_at": i.get("updated_at"),
        }
        for i in results
    ]

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_issues: {owner}/{repo} state={state} returned {len(simplified)}",
        "list_issues", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"list_issues: {owner}/{repo} — {len(simplified)} issues (state={state})")
    return simplified


def get_issue(owner: str, repo: str, issue_number: int) -> Optional[Dict[str, Any]]:
    """GET /repos/{owner}/{repo}/issues/{number}. Returns None if not found."""
    ctx, decision = _gate_and_emit("get_issue")
    token = _get_token()

    data = _gh("GET", f"/repos/{owner}/{repo}/issues/{issue_number}", token=token)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"get_issue: {owner}/{repo}#{issue_number} not found",
            "get_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"get_issue: {owner}/{repo}#{issue_number} — not found (404)")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_issue: {owner}/{repo}#{issue_number} state={data.get('state')}",
        "get_issue", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"get_issue: {owner}/{repo}#{issue_number} — {data.get('title', '')!r}")
    return data


def create_issue(
    owner: str,
    repo: str,
    title: str,
    body: Optional[str] = None,
    labels: Optional[List[str]] = None,
    assignees: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """POST /repos/{owner}/{repo}/issues. Returns created issue dict."""
    ctx, decision = _gate_and_emit("create_issue")
    token = _get_token()

    payload: Dict[str, Any] = {"title": title}
    if body:
        payload["body"] = body
    if labels:
        payload["labels"] = labels
    if assignees:
        payload["assignees"] = assignees

    data = _gh("POST", f"/repos/{owner}/{repo}/issues", token=token, json=payload)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"create_issue: {owner}/{repo} not found",
            "create_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"create_issue: {owner}/{repo} — not found (404)")
        return None

    number = data.get("number")
    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_issue: {owner}/{repo}#{number} title={title!r}",
        "create_issue", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"create_issue: {owner}/{repo}#{number} created — {title!r}")
    return data


def update_issue(
    owner: str,
    repo: str,
    issue_number: int,
    title: Optional[str] = None,
    body: Optional[str] = None,
    state: Optional[str] = None,
    labels: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """PATCH /repos/{owner}/{repo}/issues/{number}. Returns updated issue dict."""
    ctx, decision = _gate_and_emit("update_issue")
    token = _get_token()

    payload: Dict[str, Any] = {}
    if title is not None:
        payload["title"] = title
    if body is not None:
        payload["body"] = body
    if state is not None:
        payload["state"] = state
    if labels is not None:
        payload["labels"] = labels

    if not payload:
        log(f"update_issue: no fields provided — nothing to update")
        receipt = build_evidence_receipt(
            ctx, decision, "noop",
            f"update_issue: {owner}/{repo}#{issue_number} no fields to update",
            "update_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return None

    data = _gh("PATCH", f"/repos/{owner}/{repo}/issues/{issue_number}", token=token, json=payload)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"update_issue: {owner}/{repo}#{issue_number} not found",
            "update_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"update_issue: {owner}/{repo}#{issue_number} — not found (404)")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"update_issue: {owner}/{repo}#{issue_number} updated fields={list(payload.keys())}",
        "update_issue", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"update_issue: {owner}/{repo}#{issue_number} — updated {list(payload.keys())}")
    return data


def close_issue(owner: str, repo: str, issue_number: int) -> Optional[Dict[str, Any]]:
    """Close an issue by setting state='closed'."""
    ctx, decision = _gate_and_emit("close_issue")
    token = _get_token()

    data = _gh(
        "PATCH", f"/repos/{owner}/{repo}/issues/{issue_number}",
        token=token, json={"state": "closed"},
    )

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"close_issue: {owner}/{repo}#{issue_number} not found",
            "close_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"close_issue: {owner}/{repo}#{issue_number} — not found (404)")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"close_issue: {owner}/{repo}#{issue_number} closed",
        "close_issue", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"close_issue: {owner}/{repo}#{issue_number} — closed")
    return data


# ── Comments ──────────────────────────────────────────────────────────────────

def add_comment(
    owner: str, repo: str, issue_number: int, body: str
) -> Optional[Dict[str, Any]]:
    """POST /repos/{owner}/{repo}/issues/{number}/comments."""
    ctx, decision = _gate_and_emit("add_comment")
    token = _get_token()

    data = _gh(
        "POST", f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
        token=token, json={"body": body},
    )

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"add_comment: {owner}/{repo}#{issue_number} not found",
            "add_comment", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"add_comment: {owner}/{repo}#{issue_number} — not found (404)")
        return None

    comment_id = data.get("id")
    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"add_comment: {owner}/{repo}#{issue_number} comment_id={comment_id}",
        "add_comment", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"add_comment: {owner}/{repo}#{issue_number} — comment {comment_id} added")
    return data


def list_comments(
    owner: str, repo: str, issue_number: int
) -> List[Dict[str, Any]]:
    """GET /repos/{owner}/{repo}/issues/{number}/comments."""
    ctx, decision = _gate_and_emit("list_comments")
    token = _get_token()

    data = _gh(
        "GET", f"/repos/{owner}/{repo}/issues/{issue_number}/comments?per_page=100",
        token=token,
    )

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"list_comments: {owner}/{repo}#{issue_number} not found",
            "list_comments", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"list_comments: {owner}/{repo}#{issue_number} — not found (404)")
        return []

    comments = data if isinstance(data, list) else []
    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_comments: {owner}/{repo}#{issue_number} returned {len(comments)}",
        "list_comments", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"list_comments: {owner}/{repo}#{issue_number} — {len(comments)} comments")
    return comments


# ── Labels & Assignees ────────────────────────────────────────────────────────

def create_label(
    owner: str,
    repo: str,
    name: str,
    color: str,
    description: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    POST /repos/{owner}/{repo}/labels.

    color: 6-char hex without '#' (e.g. 'e4e669').
    """
    ctx, decision = _gate_and_emit("create_label")
    token = _get_token()

    # Strip leading # if someone passes it anyway
    color = color.lstrip("#")

    payload: Dict[str, Any] = {"name": name, "color": color}
    if description is not None:
        payload["description"] = description

    data = _gh("POST", f"/repos/{owner}/{repo}/labels", token=token, json=payload)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"create_label: {owner}/{repo} not found",
            "create_label", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"create_label: {owner}/{repo} — not found (404)")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_label: {owner}/{repo} label={name!r} color=#{color}",
        "create_label", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"create_label: {owner}/{repo} — '{name}' (#{color}) created")
    return data


def assign_issue(
    owner: str,
    repo: str,
    issue_number: int,
    assignees: List[str],
) -> Optional[Dict[str, Any]]:
    """POST /repos/{owner}/{repo}/issues/{number}/assignees."""
    ctx, decision = _gate_and_emit("assign_issue")
    token = _get_token()

    data = _gh(
        "POST", f"/repos/{owner}/{repo}/issues/{issue_number}/assignees",
        token=token, json={"assignees": assignees},
    )

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"assign_issue: {owner}/{repo}#{issue_number} not found",
            "assign_issue", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"assign_issue: {owner}/{repo}#{issue_number} — not found (404)")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"assign_issue: {owner}/{repo}#{issue_number} assignees={assignees}",
        "assign_issue", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"assign_issue: {owner}/{repo}#{issue_number} — assigned to {assignees}")
    return data


# ── Pull Requests ─────────────────────────────────────────────────────────────

def list_prs(
    owner: str,
    repo: str,
    state: str = "open",
    limit: int = 30,
) -> List[Dict[str, Any]]:
    """GET /repos/{owner}/{repo}/pulls. Returns simplified PR list."""
    ctx, decision = _gate_and_emit("list_prs")
    token = _get_token()

    results: List[Dict[str, Any]] = []
    page = 1
    per_page = min(limit, 100)

    while len(results) < limit:
        path = f"/repos/{owner}/{repo}/pulls?state={state}&per_page={per_page}&page={page}"
        page_data = _gh("GET", path, token=token)

        if page_data is None:
            log(f"list_prs: {owner}/{repo} not found (404)")
            receipt = build_evidence_receipt(
                ctx, decision, "not_found",
                f"list_prs: {owner}/{repo} not found", "list_prs", _attest_meta,
            )
            _evidence_log.emit_evidence(receipt)
            return []

        if not isinstance(page_data, list) or len(page_data) == 0:
            break
        results.extend(page_data)
        page += 1

    results = results[:limit]
    simplified = [
        {
            "number": pr.get("number"),
            "title": pr.get("title"),
            "state": pr.get("state"),
            "body": pr.get("body"),
            "html_url": pr.get("html_url"),
            "head": pr.get("head", {}).get("ref"),
            "base": pr.get("base", {}).get("ref"),
            "draft": pr.get("draft", False),
            "created_at": pr.get("created_at"),
            "updated_at": pr.get("updated_at"),
        }
        for pr in results
    ]

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_prs: {owner}/{repo} state={state} returned {len(simplified)}",
        "list_prs", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"list_prs: {owner}/{repo} — {len(simplified)} PRs (state={state})")
    return simplified


def get_pr(owner: str, repo: str, pr_number: int) -> Optional[Dict[str, Any]]:
    """GET /repos/{owner}/{repo}/pulls/{number}. Returns None if not found."""
    ctx, decision = _gate_and_emit("get_pr")
    token = _get_token()

    data = _gh("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}", token=token)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"get_pr: {owner}/{repo}#{pr_number} not found",
            "get_pr", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"get_pr: {owner}/{repo}#{pr_number} — not found (404)")
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_pr: {owner}/{repo}#{pr_number} state={data.get('state')}",
        "get_pr", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"get_pr: {owner}/{repo}#{pr_number} — {data.get('title', '')!r}")
    return data


def create_pr(
    owner: str,
    repo: str,
    title: str,
    head: str,
    base: str,
    body: Optional[str] = None,
    draft: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    POST /repos/{owner}/{repo}/pulls.

    head: source branch name (e.g. 'feature/my-feature')
    base: target branch name (e.g. 'main')
    """
    ctx, decision = _gate_and_emit("create_pr")
    token = _get_token()

    payload: Dict[str, Any] = {
        "title": title,
        "head": head,
        "base": base,
        "draft": draft,
    }
    if body:
        payload["body"] = body

    data = _gh("POST", f"/repos/{owner}/{repo}/pulls", token=token, json=payload)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"create_pr: {owner}/{repo} not found",
            "create_pr", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"create_pr: {owner}/{repo} — not found (404)")
        return None

    number = data.get("number")
    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_pr: {owner}/{repo}#{number} head={head!r}→base={base!r}",
        "create_pr", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"create_pr: {owner}/{repo}#{number} created — {title!r} ({head} → {base})")
    return data


def merge_pr(
    owner: str,
    repo: str,
    pr_number: int,
    commit_title: Optional[str] = None,
    merge_method: str = "squash",
) -> Optional[Dict[str, Any]]:
    """
    PUT /repos/{owner}/{repo}/pulls/{number}/merge.

    merge_method: 'merge', 'squash', or 'rebase'
    """
    ctx, decision = _gate_and_emit("merge_pr")
    token = _get_token()

    payload: Dict[str, Any] = {"merge_method": merge_method}
    if commit_title:
        payload["commit_title"] = commit_title

    data = _gh(
        "PUT", f"/repos/{owner}/{repo}/pulls/{pr_number}/merge",
        token=token, json=payload,
    )

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"merge_pr: {owner}/{repo}#{pr_number} not found",
            "merge_pr", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"merge_pr: {owner}/{repo}#{pr_number} — not found (404)")
        return None

    sha = data.get("sha", "unknown")
    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"merge_pr: {owner}/{repo}#{pr_number} merged sha={sha} method={merge_method}",
        "merge_pr", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"merge_pr: {owner}/{repo}#{pr_number} — merged ({merge_method}) sha={sha}")
    return data


# ── Commits & Content ─────────────────────────────────────────────────────────

def list_commits(
    owner: str,
    repo: str,
    branch: Optional[str] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """GET /repos/{owner}/{repo}/commits. Returns simplified commit list."""
    ctx, decision = _gate_and_emit("list_commits")
    token = _get_token()

    path = f"/repos/{owner}/{repo}/commits?per_page={min(limit, 100)}"
    if branch:
        path += f"&sha={branch}"

    data = _gh("GET", path, token=token)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"list_commits: {owner}/{repo} not found",
            "list_commits", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"list_commits: {owner}/{repo} — not found (404)")
        return []

    commits = data if isinstance(data, list) else []
    commits = commits[:limit]

    simplified = [
        {
            "sha": c.get("sha"),
            "message": (c.get("commit", {}).get("message") or "").split("\n")[0],
            "author": c.get("commit", {}).get("author", {}).get("name"),
            "date": c.get("commit", {}).get("author", {}).get("date"),
            "html_url": c.get("html_url"),
        }
        for c in commits
    ]

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_commits: {owner}/{repo}" + (f" branch={branch}" if branch else "") + f" returned {len(simplified)}",
        "list_commits", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"list_commits: {owner}/{repo} — {len(simplified)} commits" + (f" (branch={branch})" if branch else ""))
    return simplified


def get_file_content(
    owner: str,
    repo: str,
    path: str,
    ref: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    GET /repos/{owner}/{repo}/contents/{path}.

    Decodes base64 content. Returns dict with name, path, content, sha, size, html_url.
    """
    ctx, decision = _gate_and_emit("get_file_content")
    token = _get_token()

    api_path = f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}"
    if ref:
        api_path += f"?ref={ref}"

    data = _gh("GET", api_path, token=token)

    if data is None:
        receipt = build_evidence_receipt(
            ctx, decision, "not_found",
            f"get_file_content: {owner}/{repo}/{path} not found",
            "get_file_content", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        log(f"get_file_content: {owner}/{repo}/{path} — not found (404)")
        return None

    # Decode base64 content if present
    raw_content = data.get("content", "")
    decoded_content = ""
    if raw_content:
        try:
            decoded_content = base64.b64decode(raw_content).decode("utf-8", errors="replace")
        except Exception as exc:
            decoded_content = f"[decode error: {exc}]"

    result = {
        "name": data.get("name"),
        "path": data.get("path"),
        "content": decoded_content,
        "sha": data.get("sha"),
        "size": data.get("size"),
        "html_url": data.get("html_url"),
    }

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_file_content: {owner}/{repo}/{path} size={data.get('size', 0)}B",
        "get_file_content", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"get_file_content: {owner}/{repo}/{path} — {data.get('size', 0)} bytes" + (f" ref={ref}" if ref else ""))
    return result


# ============================================================================
# SECTION 8: ENTRY POINT + ARGPARSE DISPATCH
# ============================================================================

def _print_json(data: Any) -> None:
    """Print data as pretty JSON."""
    print(json.dumps(data, indent=2, default=str))


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        epilog=(
            "Examples:\n"
            "  python3 bootstrap.py list_repos\n"
            "  python3 bootstrap.py list_repos --owner pyhall\n"
            "  python3 bootstrap.py get_repo --owner pyhall --repo pyhall\n"
            "  python3 bootstrap.py get_repo_stats --owner pyhall --repo pyhall\n"
            "  python3 bootstrap.py list_issues --owner pyhall --repo pyhall --state open\n"
            "  python3 bootstrap.py get_issue --owner pyhall --repo pyhall --number 42\n"
            "  python3 bootstrap.py create_issue --owner pyhall --repo pyhall --title 'Bug: ...' --body 'Details'\n"
            "  python3 bootstrap.py update_issue --owner pyhall --repo pyhall --number 42 --state closed\n"
            "  python3 bootstrap.py close_issue --owner pyhall --repo pyhall --number 42\n"
            "  python3 bootstrap.py add_comment --owner pyhall --repo pyhall --number 42 --body 'Comment text'\n"
            "  python3 bootstrap.py list_comments --owner pyhall --repo pyhall --number 42\n"
            "  python3 bootstrap.py create_label --owner pyhall --repo pyhall --name 'bug' --color 'cc0000'\n"
            "  python3 bootstrap.py assign_issue --owner pyhall --repo pyhall --number 42 --assignees itsr0b\n"
            "  python3 bootstrap.py list_prs --owner pyhall --repo pyhall --state open\n"
            "  python3 bootstrap.py get_pr --owner pyhall --repo pyhall --number 7\n"
            "  python3 bootstrap.py create_pr --owner pyhall --repo pyhall --title 'feat: ...' --head my-branch --base main\n"
            "  python3 bootstrap.py merge_pr --owner pyhall --repo pyhall --number 7 --merge-method squash\n"
            "  python3 bootstrap.py list_commits --owner pyhall --repo pyhall --branch main --limit 10\n"
            "  python3 bootstrap.py get_file_content --owner pyhall --repo pyhall --path README.md\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("op", choices=sorted(ALLOWED_OPS), help="Operation to perform")

    # Common repo args
    p.add_argument("--owner", default=None, help="GitHub owner (user or org)")
    p.add_argument("--repo", default=None, help="Repository name")
    p.add_argument("--number", type=int, default=None, help="Issue or PR number")

    # list_repos
    p.add_argument("--type", dest="repo_type", default="all",
                   choices=["all", "owner", "public", "private", "member"],
                   help="Repo type filter (default: all)")
    p.add_argument("--limit", type=int, default=30, help="Max results to return (default: 30)")

    # Issues
    p.add_argument("--state", default="open", choices=["open", "closed", "all"],
                   help="Issue/PR state filter")
    p.add_argument("--title", default=None, help="Issue or PR title")
    p.add_argument("--body", default=None, help="Issue, PR, or comment body")
    p.add_argument("--labels", nargs="+", default=None, help="Labels (space-separated)")
    p.add_argument("--assignees", nargs="+", default=None, help="Assignee logins (space-separated)")

    # Labels
    p.add_argument("--name", default=None, help="Label name")
    p.add_argument("--color", default=None, help="Label color (6-char hex, no #)")
    p.add_argument("--description", default=None, help="Label description")

    # PRs
    p.add_argument("--head", default=None, help="PR source branch")
    p.add_argument("--base", default=None, help="PR target branch")
    p.add_argument("--draft", action="store_true", help="Create PR as draft")
    p.add_argument("--merge-method", dest="merge_method", default="squash",
                   choices=["merge", "squash", "rebase"],
                   help="PR merge method (default: squash)")
    p.add_argument("--commit-title", dest="commit_title", default=None,
                   help="Commit title for merge_pr")

    # Commits / file content
    p.add_argument("--branch", default=None, help="Branch name for list_commits")
    p.add_argument("--path", default=None, help="File path for get_file_content")
    p.add_argument("--ref", default=None, help="Git ref for get_file_content")

    return p


def _dispatch(op: str, args: argparse.Namespace) -> Any:
    """Dispatch parsed args to the correct domain function."""

    def require(attr: str, flag: str) -> Any:
        val = getattr(args, attr, None)
        if val is None:
            log(f"ERROR: {flag} is required for op={op}")
            raise SystemExit(1)
        return val

    if op == "list_repos":
        return list_repos(owner=args.owner, repo_type=args.repo_type, limit=args.limit)

    if op == "get_repo":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        return get_repo(owner, repo)

    if op == "get_repo_stats":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        return get_repo_stats(owner, repo)

    if op == "list_issues":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        return list_issues(owner, repo, state=args.state, labels=args.labels, limit=args.limit)

    if op == "get_issue":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        number = require("number", "--number")
        return get_issue(owner, repo, number)

    if op == "create_issue":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        title = require("title", "--title")
        return create_issue(owner, repo, title, body=args.body, labels=args.labels, assignees=args.assignees)

    if op == "update_issue":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        number = require("number", "--number")
        return update_issue(owner, repo, number,
                            title=args.title, body=args.body, state=args.state, labels=args.labels)

    if op == "close_issue":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        number = require("number", "--number")
        return close_issue(owner, repo, number)

    if op == "add_comment":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        number = require("number", "--number")
        body = require("body", "--body")
        return add_comment(owner, repo, number, body)

    if op == "list_comments":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        number = require("number", "--number")
        return list_comments(owner, repo, number)

    if op == "create_label":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        name = require("name", "--name")
        color = require("color", "--color")
        return create_label(owner, repo, name, color, description=args.description)

    if op == "assign_issue":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        number = require("number", "--number")
        assignees = require("assignees", "--assignees")
        return assign_issue(owner, repo, number, assignees)

    if op == "list_prs":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        return list_prs(owner, repo, state=args.state, limit=args.limit)

    if op == "get_pr":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        number = require("number", "--number")
        return get_pr(owner, repo, number)

    if op == "create_pr":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        title = require("title", "--title")
        head = require("head", "--head")
        base = require("base", "--base")
        return create_pr(owner, repo, title, head, base, body=args.body, draft=args.draft)

    if op == "merge_pr":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        number = require("number", "--number")
        return merge_pr(owner, repo, number,
                        commit_title=args.commit_title, merge_method=args.merge_method)

    if op == "list_commits":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        return list_commits(owner, repo, branch=args.branch, limit=args.limit)

    if op == "get_file_content":
        owner = require("owner", "--owner")
        repo = require("repo", "--repo")
        path = require("path", "--path")
        return get_file_content(owner, repo, path, ref=args.ref)

    log(f"ERROR: op={op!r} not handled in dispatch (should not happen)")
    raise SystemExit(1)


def run() -> None:
    """WCP worker entry point. Called from bootstrap.py."""
    global _attest_meta

    # Run startup attestation — may warn in dev, hard-fail in prod
    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = _build_arg_parser()
    args = parser.parse_args()
    op = args.op

    result = _dispatch(op, args)

    if result is not None:
        _print_json(result)


if __name__ == "__main__":
    run()
