#!/usr/bin/env python3
"""
worker_logic.py — HackerNews Monitor Worker (WCP v0.3.0)

Fetches, monitors, and searches HackerNews stories using the HN Firebase API
and the Algolia HN Search API. No authentication required for either API.

Full WCP-compliant worker package: attested, fail-closed policy gate,
append-only evidence log, deterministic traceability via correlation IDs.

All timestamps stored as UTC ISO 8601. Human-facing log output uses Central Time.
Seen-item tracking persisted to SQLite at ~/.local/share/pyhall/hackernews_worker.db.

Usage:
    python3 bootstrap.py get_top_stories --limit 30
    python3 bootstrap.py get_new_stories --limit 20
    python3 bootstrap.py get_best_stories --limit 20
    python3 bootstrap.py get_ask_hn --limit 10
    python3 bootstrap.py get_show_hn --limit 10
    python3 bootstrap.py get_jobs --limit 10
    python3 bootstrap.py get_item --item-id 12345
    python3 bootstrap.py get_user --username pg
    python3 bootstrap.py search --query "python asyncio" --limit 20
    python3 bootstrap.py filter_by_keyword --keywords python asyncio
    python3 bootstrap.py get_latest_since --hours 24 --min-score 50 --limit 50
    python3 bootstrap.py monitor_keywords --keywords rust webassembly --hours 6 --min-score 10
"""

from __future__ import annotations

# ============================================================================
# SECTION 1: HEADER + IDENTITY + WCP DECLARATIONS
# ============================================================================

import argparse
import concurrent.futures
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.hackernews.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.hackernews"
WORKER_NAME        = "HackerNews Monitor Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.hackernews.read",
    "cap.pyhall.hackernews.monitor",
]

ALLOWED_OPS = {
    "get_top_stories", "get_new_stories", "get_best_stories",
    "get_ask_hn", "get_show_hn", "get_jobs",
    "get_item", "get_user",
    "search", "filter_by_keyword",
    "get_latest_since", "monitor_keywords",
}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

ALLOWED_ENVS = {"dev", "stage", "prod"}

# Read-only ops — use cap.pyhall.hackernews.read
_READ_OPS = {
    "get_top_stories", "get_new_stories", "get_best_stories",
    "get_ask_hn", "get_show_hn", "get_jobs",
    "get_item", "get_user",
    "search", "filter_by_keyword",
    "get_latest_since",
}
# Monitor ops — use cap.pyhall.hackernews.monitor (writes to local SQLite)
_MONITOR_OPS = {"monitor_keywords"}

# HN API constants
_HN_BASE     = "https://hacker-news.firebaseio.com/v0"
_ALGOLIA_BASE = "https://hn.algolia.com/api/v1"
_HN_UA       = f"pyhall-hackernews-worker/{WORKER_VERSION}"


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
class HNStory:
    id: int
    title: Optional[str]
    url: Optional[str]
    score: Optional[int]
    by: Optional[str]
    time: Optional[int]
    descendants: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "url": self.url,
            "score": self.score,
            "by": self.by,
            "time": self.time,
            "descendants": self.descendants,
        }


@dataclass
class SeenItemRecord:
    id: int
    title: Optional[str]
    url: Optional[str]
    score: Optional[int]
    by: Optional[str]
    hn_time: Optional[int]
    fetched_at: str


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
    """Print a timestamped message using Central Time."""
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


def _resolve_db_path() -> Path:
    """Resolve the SQLite DB path. Env var HN_WORKER_DB_PATH overrides default."""
    override = os.environ.get("HN_WORKER_DB_PATH", "").strip()
    if override:
        return Path(override)
    return Path.home() / ".local" / "share" / "pyhall" / "hackernews_worker.db"


# ============================================================================
# SECTION 4: PACKAGE ATTESTATION + SIGNATURE VERIFICATION
# ============================================================================
# required for PyHall APP.
# not strictly required in-file for API-only usage.
# if this worker file changes, a new attestation is required.


def _run_startup_attestation(package_root: Path, manifest_path: Path) -> Dict[str, Any]:
    """
    Run full package attestation using the pyhall PackageAttestationVerifier.

    In dev (PYHALL_ENV != 'prod') with no WCP_ATTEST_HMAC_KEY:
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
#   code/worker_logic.py → package root is two levels up (hackernews_worker/)
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../hackernews_worker/
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

        rule_id = f"rr_hackernews_{op}_allow_v1"
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

    Each entry: prev_hash, entry_hash (sha256(prev_hash_bytes + payload_bytes)), receipt.
    Writes are best-effort — will not crash the worker if the directory is absent.
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
    """Build a WCP execution evidence receipt dict."""
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


def _make_ctx(op: str, capability_id: Optional[str] = None) -> WCPContext:
    """Build a WCPContext for the given operation, auto-selecting capability."""
    if capability_id is None:
        capability_id = (
            "cap.pyhall.hackernews.monitor" if op in _MONITOR_OPS
            else "cap.pyhall.hackernews.read"
        )
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=capability_id,
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
# SECTION 7: DOMAIN LOGIC — HACKERNEWS INTELLIGENCE
# ============================================================================

# ---------------------------------------------------------------------------
# Database bootstrap
# ---------------------------------------------------------------------------

def _get_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """
    Return a sqlite3 Connection with row_factory set.
    Creates the DB file and tables if they do not yet exist.
    """
    path = db_path or _resolve_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS seen_items (
            id          INTEGER PRIMARY KEY,
            title       TEXT,
            url         TEXT,
            score       INTEGER,
            by          TEXT,
            hn_time     INTEGER,
            fetched_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_seen_hn_time  ON seen_items(hn_time DESC);
        CREATE INDEX IF NOT EXISTS idx_seen_fetched  ON seen_items(fetched_at DESC);
        CREATE INDEX IF NOT EXISTS idx_seen_score    ON seen_items(score DESC);
    """)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Internal HN API helpers
# ---------------------------------------------------------------------------

def _hn_get(session: Any, url: str) -> Optional[Dict[str, Any]]:
    """
    Perform a GET request to the HN Firebase API.
    Returns parsed JSON or None on error. session is a requests.Session.
    """
    try:
        resp = session.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def _fetch_item_raw(session: Any, item_id: int) -> Optional[Dict[str, Any]]:
    """Fetch a single HN item by ID from the Firebase API."""
    return _hn_get(session, f"{_HN_BASE}/item/{item_id}.json")


def _fetch_story_list(session: Any, list_name: str) -> List[int]:
    """
    Fetch a HN story list (topstories, newstories, etc.).
    Returns list of integer IDs (up to 500).
    """
    data = _hn_get(session, f"{_HN_BASE}/{list_name}.json")
    if isinstance(data, list):
        return data
    return []


def _batch_fetch_items(
    session: Any,
    ids: List[int],
    limit: int,
    max_workers: int = 10,
) -> List[Dict[str, Any]]:
    """
    Fetch up to `limit` HN items concurrently using ThreadPoolExecutor.
    Returns list of item dicts (None results are silently dropped).
    """
    ids_to_fetch = ids[:limit]
    results: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_fetch_item_raw, session, item_id): item_id
            for item_id in ids_to_fetch
        }
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            if item is not None:
                results.append(item)

    # Preserve original list order
    id_order = {item_id: idx for idx, item_id in enumerate(ids_to_fetch)}
    results.sort(key=lambda x: id_order.get(x.get("id", 0), 999999))
    return results


def _normalize_story(item: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and normalize story fields for external output."""
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "url": item.get("url"),
        "score": item.get("score"),
        "by": item.get("by"),
        "time": item.get("time"),
        "descendants": item.get("descendants"),
        "type": item.get("type"),
    }


def _get_requests_session() -> Any:
    """Return a requests.Session with default headers."""
    try:
        import requests
    except ImportError as exc:
        raise ImportError(f"requests is required: {exc}") from exc
    session = requests.Session()
    session.headers.update({"User-Agent": _HN_UA})
    return session


# ---------------------------------------------------------------------------
# Tool: _get_story_list (internal reusable helper)
# ---------------------------------------------------------------------------

def _get_story_list(
    op: str,
    list_name: str,
    limit: int,
) -> Dict[str, Any]:
    """
    Internal helper used by get_top_stories, get_new_stories, etc.
    Fetches story IDs from `list_name`, batch-fetches items concurrently.
    """
    ctx, decision = _gate_and_emit(op)

    try:
        session = _get_requests_session()
    except ImportError as exc:
        detail = f"{op}: missing dependency: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, op, _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    try:
        ids = _fetch_story_list(session, list_name)
    except Exception as exc:
        detail = f"{op}: failed to fetch story list {list_name!r}: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, op, _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    if not ids:
        detail = f"{op}: story list {list_name!r} returned 0 IDs"
        receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
        _evidence_log.emit_evidence(receipt)
        return {"status": "ok", "stories": [], "story_count": 0, "list": list_name}

    try:
        raw_items = _batch_fetch_items(session, ids, limit=limit, max_workers=10)
    except Exception as exc:
        detail = f"{op}: batch fetch error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, op, _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    stories = [_normalize_story(item) for item in raw_items]
    detail = f"{op}: list={list_name!r} limit={limit} story_count={len(stories)}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, op, _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"{op}: fetched {len(stories)} stories from {list_name!r}")
    return {
        "status": "ok",
        "stories": stories,
        "story_count": len(stories),
        "list": list_name,
    }


# ---------------------------------------------------------------------------
# Tool: get_top_stories
# ---------------------------------------------------------------------------

def get_top_stories(limit: int = 30) -> Dict[str, Any]:
    """
    Fetch the current HN top stories.
    Returns up to `limit` stories sorted by HN rank.
    """
    return _get_story_list("get_top_stories", "topstories", limit)


# ---------------------------------------------------------------------------
# Tool: get_new_stories
# ---------------------------------------------------------------------------

def get_new_stories(limit: int = 30) -> Dict[str, Any]:
    """
    Fetch the most recently submitted HN stories.
    Returns up to `limit` stories in reverse-chronological order.
    """
    return _get_story_list("get_new_stories", "newstories", limit)


# ---------------------------------------------------------------------------
# Tool: get_best_stories
# ---------------------------------------------------------------------------

def get_best_stories(limit: int = 30) -> Dict[str, Any]:
    """
    Fetch the current HN best stories (high score + recent activity).
    Returns up to `limit` stories.
    """
    return _get_story_list("get_best_stories", "beststories", limit)


# ---------------------------------------------------------------------------
# Tool: get_ask_hn
# ---------------------------------------------------------------------------

def get_ask_hn(limit: int = 20) -> Dict[str, Any]:
    """
    Fetch Ask HN posts.
    Returns up to `limit` stories.
    """
    return _get_story_list("get_ask_hn", "askstories", limit)


# ---------------------------------------------------------------------------
# Tool: get_show_hn
# ---------------------------------------------------------------------------

def get_show_hn(limit: int = 20) -> Dict[str, Any]:
    """
    Fetch Show HN posts.
    Returns up to `limit` stories.
    """
    return _get_story_list("get_show_hn", "showstories", limit)


# ---------------------------------------------------------------------------
# Tool: get_jobs
# ---------------------------------------------------------------------------

def get_jobs(limit: int = 20) -> Dict[str, Any]:
    """
    Fetch HN job postings (Who is Hiring + job type posts).
    Returns up to `limit` job items.
    """
    return _get_story_list("get_jobs", "jobstories", limit)


# ---------------------------------------------------------------------------
# Tool: get_item
# ---------------------------------------------------------------------------

def get_item(item_id: int) -> Dict[str, Any]:
    """
    Fetch a single HN item by ID.
    Returns the full item including kids (comment IDs) list.
    """
    ctx, decision = _gate_and_emit("get_item")

    try:
        session = _get_requests_session()
    except ImportError as exc:
        detail = f"get_item: missing dependency: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_item", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    try:
        item = _fetch_item_raw(session, item_id)
    except Exception as exc:
        detail = f"get_item: fetch error for id={item_id}: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_item", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    if item is None:
        detail = f"get_item: item_id={item_id} not found or API returned null"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_item", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    detail = f"get_item: id={item_id} type={item.get('type', 'unknown')} story_count=1"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_item", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"get_item: fetched id={item_id} ({item.get('type', 'unknown')})")
    return {"status": "ok", "item": item}


# ---------------------------------------------------------------------------
# Tool: get_user
# ---------------------------------------------------------------------------

def get_user(username: str) -> Dict[str, Any]:
    """
    Fetch a HN user profile by username.
    Returns id, karma, about, and submitted count.
    """
    ctx, decision = _gate_and_emit("get_user")

    if not username or not username.strip():
        detail = "get_user: username is required"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_user", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    username = username.strip()

    try:
        session = _get_requests_session()
    except ImportError as exc:
        detail = f"get_user: missing dependency: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_user", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    try:
        data = _hn_get(session, f"{_HN_BASE}/user/{username}.json")
    except Exception as exc:
        detail = f"get_user: fetch error for username={username!r}: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_user", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    if data is None:
        detail = f"get_user: user {username!r} not found"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_user", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    user = {
        "id": data.get("id"),
        "karma": data.get("karma"),
        "about": data.get("about"),
        "submitted_count": len(data.get("submitted", [])),
        "created": data.get("created"),
    }
    detail = f"get_user: username={username!r} karma={user['karma']} story_count=1"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_user", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"get_user: {username!r} karma={user['karma']} submitted={user['submitted_count']}")
    return {"status": "ok", "user": user}


# ---------------------------------------------------------------------------
# Tool: search
# ---------------------------------------------------------------------------

def search(
    query: str,
    limit: int = 20,
    story_type: str = "story",
) -> Dict[str, Any]:
    """
    Search HN stories via the Algolia HN Search API.
    story_type: "story" | "comment" | "poll" | "job" (passed as Algolia tags filter).
    Returns list with objectID, title, url, author, points, created_at, num_comments.
    """
    ctx, decision = _gate_and_emit("search")

    if not query or not query.strip():
        detail = "search: query is required and must be non-empty"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "search", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    query = query.strip()

    try:
        import requests as req_lib
    except ImportError as exc:
        detail = f"search: missing dependency: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "search", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    try:
        resp = req_lib.get(
            f"{_ALGOLIA_BASE}/search",
            params={
                "query": query,
                "tags": story_type,
                "hitsPerPage": limit,
            },
            headers={"User-Agent": _HN_UA},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        detail = f"search: Algolia API error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "search", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    hits = data.get("hits", [])
    stories = [
        {
            "objectID": h.get("objectID"),
            "title": h.get("title"),
            "url": h.get("url"),
            "author": h.get("author"),
            "points": h.get("points"),
            "created_at": h.get("created_at"),
            "num_comments": h.get("num_comments"),
        }
        for h in hits
    ]

    detail = f"search: query={query!r} story_type={story_type!r} story_count={len(stories)}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "search", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"search: query={query!r} — {len(stories)} results")
    return {
        "status": "ok",
        "query": query,
        "story_type": story_type,
        "stories": stories,
        "story_count": len(stories),
    }


# ---------------------------------------------------------------------------
# Tool: filter_by_keyword
# ---------------------------------------------------------------------------

def filter_by_keyword(
    keywords: List[str],
    stories: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Filter a list of story dicts by keywords (AND logic, case-insensitive).
    Checks title and url fields.

    This is a standalone local filter — no API call is made.
    If `stories` is None or empty, returns an empty result with a warning.

    Designed to be composed with get_top_stories / get_new_stories output.
    """
    ctx, decision = _gate_and_emit("filter_by_keyword")

    if not keywords:
        detail = "filter_by_keyword: keywords list is required and must be non-empty"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "filter_by_keyword", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    if not stories:
        detail = "filter_by_keyword: stories list is empty — no items to filter"
        receipt = build_evidence_receipt(ctx, decision, "ok", detail, "filter_by_keyword", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"WARNING: {detail}")
        return {"status": "ok", "keywords": keywords, "stories": [], "story_count": 0}

    kws_lower = [kw.lower() for kw in keywords]

    def _matches(story: Dict[str, Any]) -> bool:
        text = " ".join([
            (story.get("title") or ""),
            (story.get("url") or ""),
        ]).lower()
        return all(kw in text for kw in kws_lower)

    matched = [s for s in stories if _matches(s)]

    detail = (
        f"filter_by_keyword: keywords={keywords!r} "
        f"input={len(stories)} story_count={len(matched)}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "filter_by_keyword", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"filter_by_keyword: {keywords!r} — {len(matched)}/{len(stories)} matched")
    return {
        "status": "ok",
        "keywords": keywords,
        "stories": matched,
        "story_count": len(matched),
    }


# ---------------------------------------------------------------------------
# Tool: get_latest_since
# ---------------------------------------------------------------------------

def get_latest_since(
    hours: int = 24,
    min_score: int = 10,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Fetch stories from the last N hours above a score threshold using Algolia.
    Uses numericFilters to push timestamp and score filtering to the API.
    Returns stories sorted by points DESC.
    """
    ctx, decision = _gate_and_emit("get_latest_since")

    try:
        import requests as req_lib
        import time as time_lib
    except ImportError as exc:
        detail = f"get_latest_since: missing dependency: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_latest_since", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    cutoff_ts = int(time_lib.time()) - (hours * 3600)

    try:
        resp = req_lib.get(
            f"{_ALGOLIA_BASE}/search",
            params={
                "tags": "story",
                "numericFilters": f"created_at_i>={cutoff_ts},points>={min_score}",
                "hitsPerPage": limit,
            },
            headers={"User-Agent": _HN_UA},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        detail = f"get_latest_since: Algolia API error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_latest_since", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    hits = data.get("hits", [])
    stories = [
        {
            "objectID": h.get("objectID"),
            "title": h.get("title"),
            "url": h.get("url"),
            "author": h.get("author"),
            "points": h.get("points"),
            "created_at": h.get("created_at"),
            "num_comments": h.get("num_comments"),
        }
        for h in hits
    ]

    detail = (
        f"get_latest_since: hours={hours} min_score={min_score} "
        f"limit={limit} story_count={len(stories)}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_latest_since", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"get_latest_since: {len(stories)} stories in last {hours}h with score>={min_score}")
    return {
        "status": "ok",
        "hours": hours,
        "min_score": min_score,
        "stories": stories,
        "story_count": len(stories),
        "cutoff_utc": datetime.fromtimestamp(cutoff_ts, tz=timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


# ---------------------------------------------------------------------------
# Tool: monitor_keywords
# ---------------------------------------------------------------------------

def monitor_keywords(
    keywords: List[str],
    hours: int = 6,
    min_score: int = 5,
) -> Dict[str, Any]:
    """
    Monitor HN for stories matching keywords over the last N hours.
    Combines get_latest_since + filter_by_keyword.
    Deduplicates against locally tracked seen_items SQLite table.
    Returns only new stories that have not been seen before.

    Use case: competitor monitoring, topic tracking, alert detection.
    """
    ctx, decision = _gate_and_emit("monitor_keywords")

    if not keywords:
        detail = "monitor_keywords: keywords list is required and must be non-empty"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "monitor_keywords", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    # --- Step 1: get_latest_since (calls its own policy gate internally) ---
    # We call the domain function directly (bypasses second gate — that's correct:
    # monitor_keywords is the authoritative gate here; the sub-call is internal).
    try:
        import requests as req_lib
        import time as time_lib
    except ImportError as exc:
        detail = f"monitor_keywords: missing dependency: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "monitor_keywords", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    cutoff_ts = int(time_lib.time()) - (hours * 3600)

    try:
        resp = req_lib.get(
            f"{_ALGOLIA_BASE}/search",
            params={
                "tags": "story",
                "numericFilters": f"created_at_i>={cutoff_ts},points>={min_score}",
                "hitsPerPage": 200,
            },
            headers={"User-Agent": _HN_UA},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        detail = f"monitor_keywords: Algolia API error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "monitor_keywords", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    hits = data.get("hits", [])
    all_stories = [
        {
            "objectID": h.get("objectID"),
            "id": int(h.get("objectID", 0)) if h.get("objectID", "").isdigit() else 0,
            "title": h.get("title"),
            "url": h.get("url"),
            "author": h.get("author"),
            "points": h.get("points"),
            "created_at": h.get("created_at"),
            "num_comments": h.get("num_comments"),
            "created_at_i": h.get("created_at_i"),
        }
        for h in hits
    ]

    # --- Step 2: Filter by keywords (AND logic, case-insensitive) ---
    kws_lower = [kw.lower() for kw in keywords]

    def _matches(story: Dict[str, Any]) -> bool:
        text = " ".join([
            (story.get("title") or ""),
            (story.get("url") or ""),
        ]).lower()
        return all(kw in text for kw in kws_lower)

    keyword_matched = [s for s in all_stories if _matches(s)]

    # --- Step 3: Deduplicate against seen_items SQLite table ---
    now_utc = utc_now_iso()
    new_stories: List[Dict[str, Any]] = []

    try:
        conn = _get_db()
        try:
            for story in keyword_matched:
                hn_id = story.get("id", 0) or 0
                if hn_id <= 0:
                    # No valid ID — include without dedup
                    new_stories.append(story)
                    continue

                row = conn.execute(
                    "SELECT id FROM seen_items WHERE id = ?", (hn_id,)
                ).fetchone()

                if row is None:
                    # New story — record it and include in results
                    new_stories.append(story)
                    try:
                        conn.execute(
                            """
                            INSERT INTO seen_items (id, title, url, score, by, hn_time, fetched_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                hn_id,
                                story.get("title"),
                                story.get("url"),
                                story.get("points"),
                                story.get("author"),
                                story.get("created_at_i"),
                                now_utc,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        # Race condition — already inserted, skip
                        pass
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        # DB error is non-fatal for monitoring — return results without dedup
        log(f"WARNING: monitor_keywords: DB dedup error (returning without dedup): {exc}")
        new_stories = keyword_matched

    detail = (
        f"monitor_keywords: keywords={keywords!r} hours={hours} min_score={min_score} "
        f"total_fetched={len(all_stories)} keyword_matched={len(keyword_matched)} "
        f"story_count={len(new_stories)}"
    )
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "monitor_keywords", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(
        f"monitor_keywords: {keywords!r} — "
        f"{len(all_stories)} fetched, {len(keyword_matched)} matched, "
        f"{len(new_stories)} new"
    )
    return {
        "status": "ok",
        "keywords": keywords,
        "hours": hours,
        "min_score": min_score,
        "stories": new_stories,
        "story_count": len(new_stories),
        "total_fetched": len(all_stories),
        "keyword_matched": len(keyword_matched),
    }


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

def _dispatch(op: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Route parsed args to the correct domain function."""
    if op == "get_top_stories":
        return get_top_stories(limit=getattr(args, "limit", 30))

    if op == "get_new_stories":
        return get_new_stories(limit=getattr(args, "limit", 30))

    if op == "get_best_stories":
        return get_best_stories(limit=getattr(args, "limit", 30))

    if op == "get_ask_hn":
        return get_ask_hn(limit=getattr(args, "limit", 20))

    if op == "get_show_hn":
        return get_show_hn(limit=getattr(args, "limit", 20))

    if op == "get_jobs":
        return get_jobs(limit=getattr(args, "limit", 20))

    if op == "get_item":
        return get_item(item_id=args.item_id)

    if op == "get_user":
        return get_user(username=args.username)

    if op == "search":
        return search(
            query=args.query,
            limit=getattr(args, "limit", 20),
            story_type=getattr(args, "story_type", "story"),
        )

    if op == "filter_by_keyword":
        # filter_by_keyword is a pure local filter — stories come from stdin JSON or empty
        raw = getattr(args, "stories_json", None)
        stories: List[Dict[str, Any]] = []
        if raw:
            try:
                stories = json.loads(raw)
            except json.JSONDecodeError as exc:
                return {"status": "error", "detail": f"filter_by_keyword: invalid --stories-json: {exc}"}
        return filter_by_keyword(
            keywords=args.keywords,
            stories=stories,
        )

    if op == "get_latest_since":
        return get_latest_since(
            hours=getattr(args, "hours", 24),
            min_score=getattr(args, "min_score", 10),
            limit=getattr(args, "limit", 100),
        )

    if op == "monitor_keywords":
        return monitor_keywords(
            keywords=args.keywords,
            hours=getattr(args, "hours", 6),
            min_score=getattr(args, "min_score", 5),
        )

    return {"status": "error", "detail": f"unknown op: {op!r}"}


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        epilog=(
            "Examples:\n"
            "  python3 bootstrap.py get_top_stories --limit 30\n"
            "  python3 bootstrap.py get_new_stories --limit 20\n"
            "  python3 bootstrap.py get_best_stories --limit 20\n"
            "  python3 bootstrap.py get_ask_hn --limit 10\n"
            "  python3 bootstrap.py get_show_hn --limit 10\n"
            "  python3 bootstrap.py get_jobs --limit 10\n"
            "  python3 bootstrap.py get_item --item-id 12345\n"
            "  python3 bootstrap.py get_user --username pg\n"
            "  python3 bootstrap.py search --query 'python asyncio' --limit 20\n"
            "  python3 bootstrap.py search --query 'rust' --story-type story\n"
            "  python3 bootstrap.py filter_by_keyword --keywords python asyncio\n"
            "  python3 bootstrap.py filter_by_keyword --keywords rust --stories-json '[{...}]'\n"
            "  python3 bootstrap.py get_latest_since --hours 24 --min-score 50 --limit 50\n"
            "  python3 bootstrap.py monitor_keywords --keywords rust webassembly --hours 6\n"
            "  python3 bootstrap.py monitor_keywords --keywords openai --min-score 20 --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # Story list pagination
    p.add_argument("--limit", dest="limit", type=int, default=None,
                   help="Max stories to return (default varies by op)")

    # Item / user targeting
    p.add_argument("--item-id", dest="item_id", type=int, default=None,
                   help="HN item ID (get_item)")
    p.add_argument("--username", dest="username", default=None,
                   help="HN username (get_user)")

    # Search
    p.add_argument("--query", dest="query", default=None,
                   help="Search query string (search)")
    p.add_argument("--story-type", dest="story_type", default="story",
                   choices=["story", "comment", "poll", "job"],
                   help="Algolia story type filter for search (default: story)")

    # Keyword filtering
    p.add_argument("--keywords", dest="keywords", nargs="+", default=None,
                   help="One or more keywords (filter_by_keyword, monitor_keywords)")
    p.add_argument("--stories-json", dest="stories_json", default=None,
                   help="JSON array of story dicts to filter (filter_by_keyword)")

    # Time/score filters
    p.add_argument("--hours", dest="hours", type=int, default=None,
                   help="Look-back window in hours (get_latest_since, monitor_keywords; default varies)")
    p.add_argument("--min-score", dest="min_score", type=int, default=None,
                   help="Minimum HN score/points threshold (default varies by op)")

    # Output
    p.add_argument("--json", dest="output_json", action="store_true",
                   help="Print result as JSON to stdout")

    return p


def run() -> None:
    """WCP worker entry point. Called from bootstrap.py."""
    global _attest_meta

    # Run startup attestation — warns in dev, hard-fails in prod
    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = _build_arg_parser()
    args = parser.parse_args()
    op = args.op

    # Apply defaults that vary per op
    if args.limit is None:
        args.limit = {
            "get_top_stories": 30, "get_new_stories": 30, "get_best_stories": 30,
            "get_ask_hn": 20, "get_show_hn": 20, "get_jobs": 20,
            "search": 20, "get_latest_since": 100,
        }.get(op, 30)
    if args.hours is None:
        args.hours = 6 if op == "monitor_keywords" else 24
    if args.min_score is None:
        args.min_score = 5 if op == "monitor_keywords" else 10

    result = _dispatch(op, args)

    if getattr(args, "output_json", False):
        print(json.dumps(result, indent=2, default=str))
    else:
        status = result.get("status", "unknown")
        if status == "error":
            log(f"RESULT [{op}]: ERROR — {result.get('detail', '')}")
            sys.exit(1)
        else:
            # Concise human-readable output
            story_count = result.get("story_count", 0)
            if op in ("get_top_stories", "get_new_stories", "get_best_stories",
                      "get_ask_hn", "get_show_hn", "get_jobs"):
                stories = result.get("stories", [])
                if not stories:
                    print("  (no stories)")
                for s in stories:
                    score = s.get("score") or 0
                    by = s.get("by") or "?"
                    print(f"  [{s['id']}] ({score}pts, {by}) {s.get('title', '(no title)')}")
                    if s.get("url"):
                        print(f"        {s['url']}")
                print(f"\n  {story_count} stories returned")

            elif op == "get_item":
                item = result.get("item", {})
                print(f"  ID:    {item.get('id')}")
                print(f"  Type:  {item.get('type')}")
                print(f"  Title: {item.get('title', '(no title)')}")
                print(f"  By:    {item.get('by')}")
                print(f"  Score: {item.get('score')}")
                if item.get("url"):
                    print(f"  URL:   {item.get('url')}")
                kids = item.get("kids", [])
                if kids:
                    print(f"  Comments ({len(kids)}): {kids[:5]}{'...' if len(kids) > 5 else ''}")

            elif op == "get_user":
                user = result.get("user", {})
                print(f"  User:      {user.get('id')}")
                print(f"  Karma:     {user.get('karma')}")
                print(f"  Submitted: {user.get('submitted_count')}")
                if user.get("about"):
                    about = (user["about"] or "")[:200]
                    print(f"  About:     {about}")

            elif op in ("search", "get_latest_since"):
                stories = result.get("stories", [])
                if not stories:
                    print("  (no results)")
                for s in stories:
                    pts = s.get("points") or 0
                    author = s.get("author") or "?"
                    print(f"  [{s.get('objectID')}] ({pts}pts, {author}) {s.get('title', '(no title)')}")
                    if s.get("url"):
                        print(f"        {s['url']}")
                print(f"\n  {story_count} stories returned")

            elif op == "filter_by_keyword":
                stories = result.get("stories", [])
                print(f"  {story_count} match(es) for {result.get('keywords', [])!r}")
                for s in stories:
                    score = s.get("score") or s.get("points") or 0
                    print(f"  {s.get('title', '(no title)')}  ({score}pts)")

            elif op == "monitor_keywords":
                stories = result.get("stories", [])
                kws = result.get("keywords", [])
                print(f"  Keywords: {kws!r}")
                print(f"  Window:   {result.get('hours')}h, min_score={result.get('min_score')}")
                print(f"  Fetched:  {result.get('total_fetched', 0)} | "
                      f"Matched: {result.get('keyword_matched', 0)} | "
                      f"New: {story_count}")
                if not stories:
                    print("  (no new matching stories)")
                for s in stories:
                    pts = s.get("points") or 0
                    author = s.get("author") or "?"
                    print(f"  [{s.get('objectID')}] ({pts}pts, {author}) {s.get('title', '(no title)')}")
                    if s.get("url"):
                        print(f"        {s['url']}")

            else:
                log(f"RESULT [{op}]: {result}")


if __name__ == "__main__":
    run()
