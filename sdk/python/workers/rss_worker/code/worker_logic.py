#!/usr/bin/env python3
"""
worker_logic.py — RSS Intelligence Worker (WCP v0.3.0)

Fetches, stores, and searches RSS/Atom feeds using feedparser + requests.
Full WCP-compliant worker package: attested, fail-closed policy gate,
append-only evidence log, deterministic traceability via correlation IDs.

All timestamps stored as UTC ISO 8601. Human-facing log output uses Central Time.
Feed/item data persisted to local SQLite at ~/.local/share/pyhall/rss_worker.db.

Usage:
    python3 bootstrap.py add_feed --url https://example.com/feed.xml --name "My Feed"
    python3 bootstrap.py list_feeds
    python3 bootstrap.py fetch_feed --feed-id 1
    python3 bootstrap.py list_items --feed-id 1 --limit 20
    python3 bootstrap.py get_latest --count 10
    python3 bootstrap.py search_items --query "python release"
    python3 bootstrap.py filter_by_keyword --keywords python release --feed-id 1
    python3 bootstrap.py get_item --item-id 42
    python3 bootstrap.py get_summary --item-id 42
    python3 bootstrap.py remove_feed --feed-id 1
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.rss.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.rss"
WORKER_NAME        = "RSS Intelligence Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.rss.read",
    "cap.pyhall.rss.manage",
]

ALLOWED_OPS = {
    "add_feed", "remove_feed", "list_feeds",
    "fetch_feed", "list_items", "get_item",
    "search_items", "get_latest", "filter_by_keyword",
    "get_summary",
}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

ALLOWED_ENVS = {"dev", "stage", "prod"}

# Read ops use cap.pyhall.rss.read; mutating ops use cap.pyhall.rss.manage
_READ_OPS = {"list_feeds", "fetch_feed", "list_items", "get_item",
             "search_items", "get_latest", "filter_by_keyword", "get_summary"}
_MANAGE_OPS = {"add_feed", "remove_feed"}


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
class FeedRecord:
    id: Optional[int]
    url: str
    name: Optional[str]
    added_at: str
    last_fetched_at: Optional[str]


@dataclass
class ItemRecord:
    id: Optional[int]
    feed_id: int
    guid: Optional[str]
    title: Optional[str]
    link: Optional[str]
    description: Optional[str]
    published_at: Optional[str]
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
    """Resolve the SQLite DB path. Env var RSS_WORKER_DB_PATH overrides default."""
    override = os.environ.get("RSS_WORKER_DB_PATH", "").strip()
    if override:
        return Path(override)
    return Path(os.path.expanduser("~")) / ".local" / "share" / "pyhall" / "rss_worker.db"


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
#   code/worker_logic.py → package root is two levels up (rss_worker/)
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../rss_worker/
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

        rule_id = f"rr_rss_{op}_allow_v1"
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
            "cap.pyhall.rss.manage" if op in _MANAGE_OPS else "cap.pyhall.rss.read"
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
# SECTION 7: DOMAIN LOGIC — RSS INTELLIGENCE
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
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS feeds (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            url            TEXT    NOT NULL UNIQUE,
            name           TEXT,
            added_at       TEXT    NOT NULL,
            last_fetched_at TEXT
        );

        CREATE TABLE IF NOT EXISTS items (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_id        INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
            guid           TEXT,
            title          TEXT,
            link           TEXT,
            description    TEXT,
            published_at   TEXT,
            fetched_at     TEXT    NOT NULL,
            UNIQUE(feed_id, guid)
        );

        CREATE INDEX IF NOT EXISTS idx_items_feed_id    ON items(feed_id);
        CREATE INDEX IF NOT EXISTS idx_items_fetched_at ON items(fetched_at DESC);
        CREATE INDEX IF NOT EXISTS idx_items_published  ON items(published_at DESC);
    """)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Tool: add_feed
# ---------------------------------------------------------------------------

def add_feed(url: str, name: Optional[str] = None) -> Dict[str, Any]:
    """
    Add an RSS/Atom feed URL to the local SQLite store.

    Returns a result dict with feed_id on success or error detail on failure.
    """
    ctx, decision = _gate_and_emit("add_feed")

    if not url or not url.strip():
        receipt = build_evidence_receipt(ctx, decision, "error", "add_feed: url is required", "add_feed", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log("ERROR: url is required")
        return {"status": "error", "detail": "url is required"}

    url = url.strip()
    now = utc_now_iso()

    try:
        conn = _get_db()
        try:
            cursor = conn.execute(
                "INSERT INTO feeds (url, name, added_at) VALUES (?, ?, ?)",
                (url, name, now),
            )
            conn.commit()
            feed_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            # Already exists — return existing row
            row = conn.execute("SELECT id, url, name, added_at FROM feeds WHERE url = ?", (url,)).fetchone()
            conn.close()
            detail = f"add_feed: feed already exists with id={row['id']}"
            receipt = build_evidence_receipt(ctx, decision, "exists", detail, "add_feed", _attest_meta)
            _evidence_log.emit_evidence(receipt)
            log(f"Feed already tracked: id={row['id']} url={url}")
            return {"status": "exists", "feed_id": row["id"], "url": url, "name": row["name"]}
        finally:
            conn.close()
    except Exception as exc:
        detail = f"add_feed: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "add_feed", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    display_name = name or url
    detail = f"add_feed: added feed id={feed_id} url={url} name={name!r}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "add_feed", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"Feed added: id={feed_id} name={display_name!r} url={url}")
    return {"status": "ok", "feed_id": feed_id, "url": url, "name": name, "added_at": now}


# ---------------------------------------------------------------------------
# Tool: remove_feed
# ---------------------------------------------------------------------------

def remove_feed(feed_id: int) -> Dict[str, Any]:
    """
    Remove a feed and all its items by feed ID.

    Cascades to items via ON DELETE CASCADE.
    """
    ctx, decision = _gate_and_emit("remove_feed")

    try:
        conn = _get_db()
        try:
            row = conn.execute("SELECT id, url, name FROM feeds WHERE id = ?", (feed_id,)).fetchone()
            if not row:
                detail = f"remove_feed: feed_id={feed_id} not found"
                receipt = build_evidence_receipt(ctx, decision, "error", detail, "remove_feed", _attest_meta)
                _evidence_log.emit_evidence(receipt)
                log(f"ERROR: {detail}")
                return {"status": "error", "detail": detail}

            url = row["url"]
            name = row["name"]
            conn.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"remove_feed: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "remove_feed", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    detail = f"remove_feed: removed feed_id={feed_id} url={url}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "remove_feed", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"Feed removed: id={feed_id} name={name!r} url={url}")
    return {"status": "ok", "feed_id": feed_id, "url": url, "name": name}


# ---------------------------------------------------------------------------
# Tool: list_feeds
# ---------------------------------------------------------------------------

def list_feeds() -> Dict[str, Any]:
    """Return all tracked feeds from the local store."""
    ctx, decision = _gate_and_emit("list_feeds")

    try:
        conn = _get_db()
        try:
            rows = conn.execute(
                "SELECT id, url, name, added_at, last_fetched_at FROM feeds ORDER BY id"
            ).fetchall()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"list_feeds: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "list_feeds", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    feeds = [
        {
            "id": r["id"],
            "url": r["url"],
            "name": r["name"],
            "added_at": r["added_at"],
            "last_fetched_at": r["last_fetched_at"],
        }
        for r in rows
    ]

    detail = f"list_feeds: {len(feeds)} feeds"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "list_feeds", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"Feeds: {len(feeds)} tracked")
    return {"status": "ok", "feeds": feeds, "count": len(feeds)}


# ---------------------------------------------------------------------------
# Tool: fetch_feed
# ---------------------------------------------------------------------------

def fetch_feed(feed_id_or_url: str) -> Dict[str, Any]:
    """
    Fetch and parse a feed (by ID or URL), store new items in SQLite.

    Resolves feed_id_or_url:
    - If it looks like an integer, treat as feed_id.
    - Otherwise treat as a URL.
    If the URL is not yet tracked, it is added automatically.
    """
    ctx, decision = _gate_and_emit("fetch_feed")

    try:
        import feedparser
        import requests
    except ImportError as exc:
        detail = f"fetch_feed: missing dependency: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "fetch_feed", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    # Resolve to (feed_id, url)
    feed_id: Optional[int] = None
    url: Optional[str] = None

    try:
        feed_id = int(feed_id_or_url)
    except (ValueError, TypeError):
        url = str(feed_id_or_url).strip()

    try:
        conn = _get_db()
        try:
            if feed_id is not None:
                row = conn.execute("SELECT id, url, name FROM feeds WHERE id = ?", (feed_id,)).fetchone()
                if not row:
                    detail = f"fetch_feed: feed_id={feed_id} not found"
                    receipt = build_evidence_receipt(ctx, decision, "error", detail, "fetch_feed", _attest_meta)
                    _evidence_log.emit_evidence(receipt)
                    log(f"ERROR: {detail}")
                    return {"status": "error", "detail": detail}
                url = row["url"]
            else:
                # URL path — auto-add if not tracked
                row = conn.execute("SELECT id, url FROM feeds WHERE url = ?", (url,)).fetchone()
                if row:
                    feed_id = row["id"]
                else:
                    now = utc_now_iso()
                    cursor = conn.execute(
                        "INSERT INTO feeds (url, name, added_at) VALUES (?, NULL, ?)", (url, now)
                    )
                    conn.commit()
                    feed_id = cursor.lastrowid
                    log(f"Auto-added new feed: id={feed_id} url={url}")
        finally:
            conn.close()
    except Exception as exc:
        detail = f"fetch_feed: db error resolving feed: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "fetch_feed", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    # Fetch the feed
    log(f"Fetching feed id={feed_id} url={url}")
    try:
        headers = {"User-Agent": f"pyhall-rss-worker/{WORKER_VERSION}"}
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
    except Exception as exc:
        detail = f"fetch_feed: http/parse error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "fetch_feed", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    entries = parsed.get("entries", [])
    now_utc = utc_now_iso()
    inserted = 0
    skipped = 0

    try:
        conn = _get_db()
        try:
            for entry in entries:
                guid = entry.get("id") or entry.get("link") or entry.get("title") or str(uuid.uuid4())
                title = entry.get("title", "")
                link = entry.get("link", "")

                # Description: prefer content, fall back to summary
                description = ""
                content_list = entry.get("content", [])
                if content_list:
                    description = content_list[0].get("value", "")
                if not description:
                    description = entry.get("summary", "")

                # Published timestamp — normalize to UTC ISO string
                published_at: Optional[str] = None
                if entry.get("published_parsed"):
                    try:
                        from calendar import timegm
                        ts = timegm(entry["published_parsed"])
                        published_at = datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                    except Exception:
                        published_at = entry.get("published")
                elif entry.get("updated_parsed"):
                    try:
                        from calendar import timegm
                        ts = timegm(entry["updated_parsed"])
                        published_at = datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                    except Exception:
                        published_at = entry.get("updated")

                try:
                    conn.execute(
                        """
                        INSERT INTO items (feed_id, guid, title, link, description, published_at, fetched_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (feed_id, guid, title, link, description, published_at, now_utc),
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    # Duplicate guid — already have this item
                    skipped += 1

            conn.execute(
                "UPDATE feeds SET last_fetched_at = ? WHERE id = ?", (now_utc, feed_id)
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"fetch_feed: db error storing items: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "fetch_feed", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    feed_title = parsed.feed.get("title", url)
    detail = f"fetch_feed: feed_id={feed_id} title={feed_title!r} new={inserted} skipped={skipped}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "fetch_feed", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"Fetched: {feed_title!r} — {inserted} new items, {skipped} already known")
    return {
        "status": "ok",
        "feed_id": feed_id,
        "feed_title": feed_title,
        "new_items": inserted,
        "skipped_items": skipped,
        "fetched_at": now_utc,
    }


# ---------------------------------------------------------------------------
# Tool: list_items
# ---------------------------------------------------------------------------

def list_items(feed_id: Optional[int] = None, limit: int = 50) -> Dict[str, Any]:
    """
    List recent items from the local store.

    feed_id=None returns items across all feeds.
    Items sorted by fetched_at DESC, limited to `limit` rows.
    """
    ctx, decision = _gate_and_emit("list_items")

    try:
        conn = _get_db()
        try:
            if feed_id is not None:
                rows = conn.execute(
                    """
                    SELECT i.id, i.feed_id, f.name AS feed_name, i.title, i.link,
                           i.published_at, i.fetched_at
                    FROM items i JOIN feeds f ON f.id = i.feed_id
                    WHERE i.feed_id = ?
                    ORDER BY i.fetched_at DESC
                    LIMIT ?
                    """,
                    (feed_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT i.id, i.feed_id, f.name AS feed_name, i.title, i.link,
                           i.published_at, i.fetched_at
                    FROM items i JOIN feeds f ON f.id = i.feed_id
                    ORDER BY i.fetched_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"list_items: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "list_items", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    items = [
        {
            "id": r["id"],
            "feed_id": r["feed_id"],
            "feed_name": r["feed_name"],
            "title": r["title"],
            "link": r["link"],
            "published_at": r["published_at"],
            "fetched_at": r["fetched_at"],
        }
        for r in rows
    ]

    detail = f"list_items: feed_id={feed_id} limit={limit} returned={len(items)}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "list_items", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"Items: {len(items)} returned (feed_id={feed_id}, limit={limit})")
    return {"status": "ok", "items": items, "count": len(items)}


# ---------------------------------------------------------------------------
# Tool: get_item
# ---------------------------------------------------------------------------

def get_item(item_id: int) -> Dict[str, Any]:
    """Return a single item by ID including full description."""
    ctx, decision = _gate_and_emit("get_item")

    try:
        conn = _get_db()
        try:
            row = conn.execute(
                """
                SELECT i.id, i.feed_id, f.url AS feed_url, f.name AS feed_name,
                       i.guid, i.title, i.link, i.description, i.published_at, i.fetched_at
                FROM items i JOIN feeds f ON f.id = i.feed_id
                WHERE i.id = ?
                """,
                (item_id,),
            ).fetchone()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"get_item: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_item", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    if not row:
        detail = f"get_item: item_id={item_id} not found"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_item", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    item = {
        "id": row["id"],
        "feed_id": row["feed_id"],
        "feed_url": row["feed_url"],
        "feed_name": row["feed_name"],
        "guid": row["guid"],
        "title": row["title"],
        "link": row["link"],
        "description": row["description"],
        "published_at": row["published_at"],
        "fetched_at": row["fetched_at"],
    }
    receipt = build_evidence_receipt(ctx, decision, "ok", f"get_item: id={item_id}", "get_item", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {"status": "ok", "item": item}


# ---------------------------------------------------------------------------
# Tool: search_items
# ---------------------------------------------------------------------------

def search_items(query: str, feed_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Full-text search items by title and description (case-insensitive LIKE).

    feed_id=None searches across all feeds.
    """
    ctx, decision = _gate_and_emit("search_items")

    if not query or not query.strip():
        detail = "search_items: query is required"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "search_items", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    pattern = f"%{query.strip()}%"

    try:
        conn = _get_db()
        try:
            if feed_id is not None:
                rows = conn.execute(
                    """
                    SELECT i.id, i.feed_id, f.name AS feed_name, i.title, i.link,
                           i.published_at, i.fetched_at
                    FROM items i JOIN feeds f ON f.id = i.feed_id
                    WHERE i.feed_id = ?
                      AND (i.title LIKE ? OR i.description LIKE ?)
                    ORDER BY i.published_at DESC
                    LIMIT 200
                    """,
                    (feed_id, pattern, pattern),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT i.id, i.feed_id, f.name AS feed_name, i.title, i.link,
                           i.published_at, i.fetched_at
                    FROM items i JOIN feeds f ON f.id = i.feed_id
                    WHERE i.title LIKE ? OR i.description LIKE ?
                    ORDER BY i.published_at DESC
                    LIMIT 200
                    """,
                    (pattern, pattern),
                ).fetchall()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"search_items: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "search_items", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    items = [
        {
            "id": r["id"],
            "feed_id": r["feed_id"],
            "feed_name": r["feed_name"],
            "title": r["title"],
            "link": r["link"],
            "published_at": r["published_at"],
            "fetched_at": r["fetched_at"],
        }
        for r in rows
    ]

    detail = f"search_items: query={query!r} feed_id={feed_id} matches={len(items)}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "search_items", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"Search {query!r}: {len(items)} matches")
    return {"status": "ok", "query": query, "items": items, "count": len(items)}


# ---------------------------------------------------------------------------
# Tool: get_latest
# ---------------------------------------------------------------------------

def get_latest(count: int = 10) -> Dict[str, Any]:
    """Return the latest N items across all feeds, sorted by published_at DESC."""
    ctx, decision = _gate_and_emit("get_latest")

    try:
        conn = _get_db()
        try:
            rows = conn.execute(
                """
                SELECT i.id, i.feed_id, f.name AS feed_name, i.title, i.link,
                       i.published_at, i.fetched_at
                FROM items i JOIN feeds f ON f.id = i.feed_id
                ORDER BY COALESCE(i.published_at, i.fetched_at) DESC
                LIMIT ?
                """,
                (count,),
            ).fetchall()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"get_latest: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_latest", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    items = [
        {
            "id": r["id"],
            "feed_id": r["feed_id"],
            "feed_name": r["feed_name"],
            "title": r["title"],
            "link": r["link"],
            "published_at": r["published_at"],
            "fetched_at": r["fetched_at"],
        }
        for r in rows
    ]

    detail = f"get_latest: count={count} returned={len(items)}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_latest", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"Latest: {len(items)} items")
    return {"status": "ok", "items": items, "count": len(items)}


# ---------------------------------------------------------------------------
# Tool: filter_by_keyword
# ---------------------------------------------------------------------------

def filter_by_keyword(keywords: List[str], feed_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Filter items where ALL keywords appear in title OR description (case-insensitive).

    keywords: list of strings — item must match every keyword (AND logic).
    feed_id=None searches all feeds.
    """
    ctx, decision = _gate_and_emit("filter_by_keyword")

    if not keywords:
        detail = "filter_by_keyword: keywords list is required and must be non-empty"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "filter_by_keyword", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    # Build SQL: one LIKE clause per keyword on (title OR description)
    kw_clauses = " AND ".join(
        "(i.title LIKE ? OR i.description LIKE ?)" for _ in keywords
    )
    params: List[Any] = []
    for kw in keywords:
        pattern = f"%{kw}%"
        params.extend([pattern, pattern])

    base_sql = f"""
        SELECT i.id, i.feed_id, f.name AS feed_name, i.title, i.link,
               i.published_at, i.fetched_at
        FROM items i JOIN feeds f ON f.id = i.feed_id
        WHERE {kw_clauses}
    """

    if feed_id is not None:
        base_sql += " AND i.feed_id = ?"
        params.append(feed_id)

    base_sql += " ORDER BY COALESCE(i.published_at, i.fetched_at) DESC LIMIT 200"

    try:
        conn = _get_db()
        try:
            rows = conn.execute(base_sql, params).fetchall()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"filter_by_keyword: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "filter_by_keyword", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    items = [
        {
            "id": r["id"],
            "feed_id": r["feed_id"],
            "feed_name": r["feed_name"],
            "title": r["title"],
            "link": r["link"],
            "published_at": r["published_at"],
            "fetched_at": r["fetched_at"],
        }
        for r in rows
    ]

    detail = f"filter_by_keyword: keywords={keywords!r} feed_id={feed_id} matches={len(items)}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "filter_by_keyword", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"Filter {keywords!r}: {len(items)} matches")
    return {"status": "ok", "keywords": keywords, "items": items, "count": len(items)}


# ---------------------------------------------------------------------------
# Tool: get_summary
# ---------------------------------------------------------------------------

def get_summary(item_id: int) -> Dict[str, Any]:
    """Return title, description, link, and published_at for a single item."""
    ctx, decision = _gate_and_emit("get_summary")

    try:
        conn = _get_db()
        try:
            row = conn.execute(
                """
                SELECT i.id, i.title, i.link, i.description, i.published_at,
                       f.name AS feed_name, f.url AS feed_url
                FROM items i JOIN feeds f ON f.id = i.feed_id
                WHERE i.id = ?
                """,
                (item_id,),
            ).fetchone()
        finally:
            conn.close()
    except Exception as exc:
        detail = f"get_summary: db error: {exc}"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_summary", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    if not row:
        detail = f"get_summary: item_id={item_id} not found"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "get_summary", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"ERROR: {detail}")
        return {"status": "error", "detail": detail}

    summary = {
        "id": row["id"],
        "title": row["title"],
        "link": row["link"],
        "description": row["description"],
        "published_at": row["published_at"],
        "feed_name": row["feed_name"],
        "feed_url": row["feed_url"],
    }
    receipt = build_evidence_receipt(ctx, decision, "ok", f"get_summary: id={item_id}", "get_summary", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return {"status": "ok", "summary": summary}


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

def _dispatch(op: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Route parsed args to the correct domain function."""
    if op == "add_feed":
        return add_feed(url=args.url, name=getattr(args, "name", None))

    if op == "remove_feed":
        return remove_feed(feed_id=args.feed_id)

    if op == "list_feeds":
        return list_feeds()

    if op == "fetch_feed":
        val = getattr(args, "feed_id", None) or getattr(args, "url", None)
        return fetch_feed(feed_id_or_url=str(val))

    if op == "list_items":
        return list_items(
            feed_id=getattr(args, "feed_id", None),
            limit=getattr(args, "limit", 50),
        )

    if op == "get_item":
        return get_item(item_id=args.item_id)

    if op == "search_items":
        return search_items(
            query=args.query,
            feed_id=getattr(args, "feed_id", None),
        )

    if op == "get_latest":
        return get_latest(count=getattr(args, "count", 10))

    if op == "filter_by_keyword":
        return filter_by_keyword(
            keywords=args.keywords,
            feed_id=getattr(args, "feed_id", None),
        )

    if op == "get_summary":
        return get_summary(item_id=args.item_id)

    return {"status": "error", "detail": f"unknown op: {op!r}"}


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        epilog=(
            "Examples:\n"
            "  python3 bootstrap.py add_feed --url https://example.com/feed.xml --name 'My Feed'\n"
            "  python3 bootstrap.py remove_feed --feed-id 1\n"
            "  python3 bootstrap.py list_feeds\n"
            "  python3 bootstrap.py fetch_feed --feed-id 1\n"
            "  python3 bootstrap.py fetch_feed --url https://example.com/feed.xml\n"
            "  python3 bootstrap.py list_items --feed-id 1 --limit 20\n"
            "  python3 bootstrap.py get_item --item-id 42\n"
            "  python3 bootstrap.py search_items --query 'python release'\n"
            "  python3 bootstrap.py search_items --query 'python' --feed-id 1\n"
            "  python3 bootstrap.py get_latest --count 5\n"
            "  python3 bootstrap.py filter_by_keyword --keywords python release\n"
            "  python3 bootstrap.py filter_by_keyword --keywords python --feed-id 2\n"
            "  python3 bootstrap.py get_summary --item-id 42\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # Feed targeting
    p.add_argument("--feed-id", dest="feed_id", type=int, default=None,
                   help="Feed ID (integer)")
    p.add_argument("--url", dest="url", default=None,
                   help="Feed URL (for add_feed or fetch_feed by URL)")
    p.add_argument("--name", dest="name", default=None,
                   help="Human name for the feed (optional, add_feed)")

    # Item targeting
    p.add_argument("--item-id", dest="item_id", type=int, default=None,
                   help="Item ID (get_item, get_summary)")

    # Pagination
    p.add_argument("--limit", dest="limit", type=int, default=50,
                   help="Max items to return (list_items, default 50)")
    p.add_argument("--count", dest="count", type=int, default=10,
                   help="Number of items to return (get_latest, default 10)")

    # Search
    p.add_argument("--query", dest="query", default=None,
                   help="Search query string (search_items)")
    p.add_argument("--keywords", dest="keywords", nargs="+", default=None,
                   help="One or more keywords (filter_by_keyword)")

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

    result = _dispatch(op, args)

    if getattr(args, "output_json", False):
        print(json.dumps(result, indent=2, default=str))
    else:
        status = result.get("status", "unknown")
        if status == "error":
            log(f"RESULT [{op}]: ERROR — {result.get('detail', '')}")
            sys.exit(1)
        else:
            # Print a concise human summary for common ops
            if op == "list_feeds":
                feeds = result.get("feeds", [])
                if not feeds:
                    print("  (no feeds tracked)")
                for f in feeds:
                    fetched = f["last_fetched_at"] or "never"
                    print(f"  [{f['id']}] {f['name'] or f['url']}  (last fetched: {fetched})")
            elif op in ("list_items", "get_latest"):
                items = result.get("items", [])
                if not items:
                    print("  (no items)")
                for it in items:
                    pub = it["published_at"] or it["fetched_at"] or ""
                    print(f"  [{it['id']}] {it['title'] or '(no title)'}  ({pub})")
                    if it.get("link"):
                        print(f"        {it['link']}")
            elif op in ("search_items", "filter_by_keyword"):
                items = result.get("items", [])
                print(f"  {result.get('count', 0)} match(es)")
                for it in items:
                    pub = it["published_at"] or it["fetched_at"] or ""
                    print(f"  [{it['id']}] {it['title'] or '(no title)'}  ({pub})")
            elif op == "get_summary":
                s = result.get("summary", {})
                print(f"  Title:     {s.get('title', '')}")
                print(f"  Link:      {s.get('link', '')}")
                print(f"  Published: {s.get('published_at', '')}")
                desc = (s.get("description") or "")[:300]
                if desc:
                    print(f"  Summary:   {desc}")
            elif op == "get_item":
                item = result.get("item", {})
                print(f"  [{item.get('id')}] {item.get('title', '')}")
                print(f"  Feed:      {item.get('feed_name', '')} ({item.get('feed_url', '')})")
                print(f"  Link:      {item.get('link', '')}")
                print(f"  Published: {item.get('published_at', '')}")
            else:
                log(f"Done: op={op} status={status}")


if __name__ == "__main__":
    run()
