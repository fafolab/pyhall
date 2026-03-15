#!/usr/bin/env python3
"""
worker_logic.py — Notion Full Stack Worker (WCP v0.3.0)

Full read/write access to Notion pages, databases, and blocks via the
Notion Internal Integration API.

Authentication: Internal Integration Token (Bearer token). Set NOTION_TOKEN
environment variable to the token value.

IMPORTANT — Notion integration sharing requirement:
    A Notion Internal Integration can only access pages and databases that have
    been explicitly shared with it. To share a page or database:
        1. Open the page/database in Notion
        2. Click "..." (three-dot menu) → "Add connections"
        3. Find your integration by name and click to share
    Without this sharing step, all API calls for that content will return 404.

Capabilities:
    cap.pyhall.notion.write     — create/update pages and database entries
    cap.pyhall.notion.query     — list and query databases
    cap.pyhall.notion.read      — read-only operations (get_page, list_blocks, get_block)

All operations:
    search_pages, get_page, create_page, update_page,
    append_block, list_blocks, get_block,
    list_databases, query_database, create_database_entry

Cross-platform: uses pathlib.Path throughout. No hardcoded POSIX separators.
All timestamps stored UTC ISO 8601, logged Central Time.

Setup:
    1. Go to https://www.notion.so/my-integrations
    2. Create a new internal integration
    3. Copy the "Internal Integration Token" (starts with ntn_ or secret_)
    4. export NOTION_TOKEN=<your_token>
    5. Share target pages/databases with your integration (see note above)
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

WORKER_ID          = "org.pyhall.notion.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.notion"
WORKER_NAME        = "Notion Full Stack Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.notion.write",
    "cap.pyhall.notion.query",
    "cap.pyhall.notion.read",
]

ALLOWED_OPS = {
    "search_pages",
    "get_page",
    "create_page",
    "update_page",
    "append_block",
    "list_blocks",
    "get_block",
    "list_databases",
    "query_database",
    "create_database_entry",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# Capability routing: map ops to their primary capability
_OP_CAPABILITY: Dict[str, str] = {
    "search_pages":          "cap.pyhall.notion.read",
    "get_page":              "cap.pyhall.notion.read",
    "create_page":           "cap.pyhall.notion.write",
    "update_page":           "cap.pyhall.notion.write",
    "append_block":          "cap.pyhall.notion.write",
    "list_blocks":           "cap.pyhall.notion.read",
    "get_block":             "cap.pyhall.notion.read",
    "list_databases":        "cap.pyhall.notion.query",
    "query_database":        "cap.pyhall.notion.query",
    "create_database_entry": "cap.pyhall.notion.write",
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
class NotionPageSummary:
    """Lightweight summary of a Notion page returned from search/list ops."""
    page_id: str
    title: str
    url: str
    last_edited_time: str
    object_type: str  # "page" or "database"


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
    """Print a timestamped log line using Central Time."""
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

    Dev (PYHALL_ENV != 'prod') with no WCP_ATTEST_HMAC_KEY set:
      - logs WARNING, does not block.
    Prod: any attestation failure raises SystemExit(2).

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
#   code/worker_logic.py → package root is two levels up (notion_worker/)
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../notion_worker/
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

        rule_id = f"rr_notion_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = Path(
    os.path.expanduser("~")
) / ".local" / "share" / "pyhall" / "evidence" / "wrk_pyhall_notion_chain.log"


class AppendOnlyEvidenceLog:
    """
    Hash-chained append-only local evidence log.

    Each entry: prev_hash, entry_hash (sha256(prev_hash_bytes + payload_bytes)), receipt.
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
# SECTION 7: DOMAIN LOGIC — NOTION API
# ============================================================================

# ---------------------------------------------------------------------------
# Notion client bootstrap
# ---------------------------------------------------------------------------

def _get_notion_client():
    """
    Return an authenticated notion_client.Client.

    Reads NOTION_TOKEN from environment. Raises SystemExit(1) if not set
    or if notion-client is not installed.
    """
    try:
        from notion_client import Client
    except ImportError:
        log("ERROR: notion-client not installed.")
        log("  pip install notion-client>=2.2.0")
        raise SystemExit(1)

    token = os.environ.get("NOTION_TOKEN", "").strip()
    if not token:
        log("ERROR: NOTION_TOKEN environment variable not set.")
        log("  Get your token at: https://www.notion.so/my-integrations")
        raise SystemExit(1)

    return Client(auth=token)


def _check_notion_deps() -> bool:
    """Return True if notion-client is importable."""
    try:
        import notion_client  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Notion helpers
# ---------------------------------------------------------------------------

def _build_rich_text(text: str) -> List[Dict[str, Any]]:
    """
    Build a Notion rich_text array from a plain string.

    Returns a list with a single text object — the standard Notion format
    expected by most write operations.
    """
    return [
        {
            "type": "text",
            "text": {"content": text, "link": None},
        }
    ]


def _extract_title(page: Dict[str, Any]) -> str:
    """
    Extract the plain text title from a Notion page or database object.

    Handles both page objects (title in properties["title"] or properties["Name"])
    and database objects (title at top level).
    """
    # Top-level title array (databases and search results)
    if "title" in page and isinstance(page["title"], list):
        parts = [t.get("plain_text", "") for t in page["title"]]
        title = "".join(parts).strip()
        if title:
            return title

    # Page properties — try "title" property type first
    props = page.get("properties", {})
    for _key, prop in props.items():
        if prop.get("type") == "title":
            title_arr = prop.get("title", [])
            parts = [t.get("plain_text", "") for t in title_arr]
            title = "".join(parts).strip()
            if title:
                return title

    return "(Untitled)"


def _summarize_page(page: Dict[str, Any]) -> Dict[str, Any]:
    """Return a lightweight summary dict from a raw Notion page/db object."""
    return {
        "id": page.get("id", ""),
        "title": _extract_title(page),
        "url": page.get("url", ""),
        "last_edited_time": page.get("last_edited_time", ""),
        "object": page.get("object", "page"),
    }


def _handle_notion_error(exc: Exception, op: str) -> None:
    """Log a Notion API error with relevant details. Does not re-raise."""
    try:
        from notion_client.errors import APIResponseError
        if isinstance(exc, APIResponseError):
            log(f"ERROR [{op}]: Notion API error {exc.status} — {exc.code}: {exc.message}")
            if exc.status == 404:
                log(f"  Hint: Is the page/database shared with your integration?")
            elif exc.status == 401:
                log(f"  Hint: Check that NOTION_TOKEN is valid and not expired.")
            elif exc.status == 403:
                log(f"  Hint: Integration lacks access. Share the page/database with your integration.")
            return
    except ImportError:
        pass
    log(f"ERROR [{op}]: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Op: search_pages
# ---------------------------------------------------------------------------

def search_pages(
    query: str,
    filter_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search Notion pages (and optionally databases) by query string.

    Args:
        query:       Search string. Empty string returns all accessible objects.
        filter_type: "page" or "database". If None, defaults to "page".

    Returns:
        List of page summary dicts: id, title, url, last_edited_time, object.

    Evidence receipt includes result count and query string.
    """
    op = "search_pages"
    ctx, decision = _gate_and_emit(op)

    obj_type = filter_type or "page"
    results: List[Dict[str, Any]] = []

    try:
        client = _get_notion_client()
        response = client.search(
            query=query,
            filter={"property": "object", "value": obj_type},
        )
        raw_results = response.get("results", [])
        results = [_summarize_page(p) for p in raw_results]
        log(f"search_pages: query={query!r} type={obj_type} → {len(results)} results")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"search_pages failed: query={query!r} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"search_pages: query={query!r} type={obj_type} count={len(results)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return results


# ---------------------------------------------------------------------------
# Op: get_page
# ---------------------------------------------------------------------------

def get_page(page_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve full page metadata and properties for a Notion page.

    Args:
        page_id: Notion page UUID (with or without hyphens).

    Returns:
        Full Notion page object dict, or None on error.

    Evidence receipt includes page_id.
    """
    op = "get_page"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_notion_client()
        page = client.pages.retrieve(page_id=page_id)
        title = _extract_title(page)
        log(f"get_page: page_id={page_id} title={title!r}")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"get_page failed: page_id={page_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_page: page_id={page_id} title={_extract_title(page)!r}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return page


# ---------------------------------------------------------------------------
# Op: create_page
# ---------------------------------------------------------------------------

def create_page(
    parent_id: str,
    title: str,
    properties: Optional[Dict[str, Any]] = None,
    is_database_page: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Create a new Notion page under a parent page or database.

    Args:
        parent_id:        UUID of the parent page or database.
        title:            Plain text title for the new page.
        properties:       Optional dict of Notion property objects. If provided,
                          merged with the title property.
        is_database_page: If True, parent is {"database_id": parent_id}.
                          If False, parent is {"page_id": parent_id}.

    Returns:
        The created Notion page object, or None on error.

    Evidence receipt includes new page_id and title.
    """
    op = "create_page"
    ctx, decision = _gate_and_emit(op)

    parent: Dict[str, Any]
    if is_database_page:
        parent = {"database_id": parent_id}
    else:
        parent = {"page_id": parent_id}

    # Build the title property — always required
    title_prop: Dict[str, Any] = {"title": _build_rich_text(title)}
    merged_props: Dict[str, Any] = {"title": title_prop}
    if properties:
        # Caller-supplied properties take precedence except for title
        for k, v in properties.items():
            if k != "title":
                merged_props[k] = v

    try:
        client = _get_notion_client()
        page = client.pages.create(parent=parent, properties=merged_props)
        new_id = page.get("id", "unknown")
        log(f"create_page: created page_id={new_id} title={title!r} parent_id={parent_id}")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"create_page failed: parent_id={parent_id} title={title!r} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_page: page_id={page.get('id')} title={title!r} parent_id={parent_id}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return page


# ---------------------------------------------------------------------------
# Op: update_page
# ---------------------------------------------------------------------------

def update_page(
    page_id: str,
    properties: Optional[Dict[str, Any]] = None,
    archived: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Update properties or archive status of a Notion page.

    Args:
        page_id:    UUID of the page to update.
        properties: Dict of Notion property objects to update. Pass None to
                    only change archived status.
        archived:   If True, moves page to Notion trash.

    Returns:
        The updated Notion page object, or None on error.

    Evidence receipt includes page_id and what was updated.
    """
    op = "update_page"
    ctx, decision = _gate_and_emit(op)

    update_kwargs: Dict[str, Any] = {"archived": archived}
    if properties:
        update_kwargs["properties"] = properties

    try:
        client = _get_notion_client()
        page = client.pages.update(page_id=page_id, **update_kwargs)
        log(f"update_page: page_id={page_id} archived={archived} props_updated={bool(properties)}")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"update_page failed: page_id={page_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"update_page: page_id={page_id} archived={archived} props_updated={bool(properties)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return page


# ---------------------------------------------------------------------------
# Op: append_block
# ---------------------------------------------------------------------------

# Supported block type strings for reference
SUPPORTED_BLOCK_TYPES = {
    "paragraph",
    "heading_1",
    "heading_2",
    "heading_3",
    "bulleted_list_item",
    "numbered_list_item",
    "to_do",
    "code",
    "divider",
}


def _build_block(block_type: str, text: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Build a Notion block object dict for a given type and text.

    Args:
        block_type: One of SUPPORTED_BLOCK_TYPES.
        text:       Plain text content.
        extra:      Optional extra fields merged into the block type dict
                    (e.g., {"language": "python"} for code blocks,
                     {"checked": True} for to_do blocks).

    Returns:
        Notion block object dict.
    """
    if block_type == "divider":
        return {"object": "block", "type": "divider", "divider": {}}

    rich = _build_rich_text(text)

    if block_type == "code":
        inner: Dict[str, Any] = {"rich_text": rich, "language": "plain text"}
        if extra:
            inner.update(extra)
        return {"object": "block", "type": "code", "code": inner}

    if block_type == "to_do":
        inner = {"rich_text": rich, "checked": False}
        if extra:
            inner.update(extra)
        return {"object": "block", "type": "to_do", "to_do": inner}

    # paragraph, heading_1/2/3, bulleted_list_item, numbered_list_item
    inner = {"rich_text": rich}
    if extra:
        inner.update(extra)
    return {"object": "block", "type": block_type, block_type: inner}


def append_block(
    block_id: str,
    children: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Append block children to a page or block.

    Args:
        block_id: UUID of the parent page or block to append to.
        children: List of Notion block objects. Use _build_block() helper
                  to construct blocks, or pass raw Notion block dicts.

    Returns:
        Notion append response dict, or None on error.

    Evidence receipt includes block_id and child count.
    """
    op = "append_block"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_notion_client()
        response = client.blocks.children.append(block_id=block_id, children=children)
        appended = len(response.get("results", []))
        log(f"append_block: block_id={block_id} children_appended={appended}")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"append_block failed: block_id={block_id} children={len(children)} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"append_block: block_id={block_id} children_requested={len(children)} appended={appended}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return response


# ---------------------------------------------------------------------------
# Op: list_blocks
# ---------------------------------------------------------------------------

def list_blocks(block_id: str) -> List[Dict[str, Any]]:
    """
    List all block children of a page or block.

    Args:
        block_id: UUID of the parent page or block.

    Returns:
        List of Notion block objects, or empty list on error.

    Evidence receipt includes block_id and result count.
    """
    op = "list_blocks"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_notion_client()
        response = client.blocks.children.list(block_id=block_id)
        blocks = response.get("results", [])
        log(f"list_blocks: block_id={block_id} count={len(blocks)}")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"list_blocks failed: block_id={block_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_blocks: block_id={block_id} count={len(blocks)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return blocks


# ---------------------------------------------------------------------------
# Op: get_block
# ---------------------------------------------------------------------------

def get_block(block_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single Notion block by ID.

    Args:
        block_id: UUID of the block to retrieve.

    Returns:
        Notion block object dict, or None on error.

    Evidence receipt includes block_id.
    """
    op = "get_block"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_notion_client()
        block = client.blocks.retrieve(block_id=block_id)
        log(f"get_block: block_id={block_id} type={block.get('type', 'unknown')}")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"get_block failed: block_id={block_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_block: block_id={block_id} type={block.get('type', 'unknown')}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return block


# ---------------------------------------------------------------------------
# Op: list_databases
# ---------------------------------------------------------------------------

def list_databases() -> List[Dict[str, Any]]:
    """
    List all Notion databases accessible to this integration.

    Returns:
        List of database summary dicts: id, title, url, last_edited_time, object.

    Evidence receipt includes database count.
    """
    op = "list_databases"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_notion_client()
        response = client.search(filter={"property": "object", "value": "database"})
        raw_results = response.get("results", [])
        databases = [_summarize_page(db) for db in raw_results]
        log(f"list_databases: {len(databases)} databases accessible")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"list_databases failed: error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_databases: count={len(databases)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return databases


# ---------------------------------------------------------------------------
# Op: query_database
# ---------------------------------------------------------------------------

def query_database(
    database_id: str,
    filter: Optional[Dict[str, Any]] = None,
    sorts: Optional[List[Dict[str, Any]]] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    Query a Notion database and return matching page rows.

    Args:
        database_id: UUID of the Notion database.
        filter:      Notion filter object (see Notion API docs for schema).
                     Example: {"property": "Status", "select": {"equals": "Done"}}
        sorts:       List of Notion sort objects.
                     Example: [{"property": "Created", "direction": "descending"}]
        limit:       Max rows to return (1–100, capped at 100 by Notion API).

    Returns:
        List of Notion page objects (database rows), or empty list on error.

    Evidence receipt includes database_id and result count.
    """
    op = "query_database"
    ctx, decision = _gate_and_emit(op)

    page_size = min(max(1, limit), 100)
    query_kwargs: Dict[str, Any] = {"database_id": database_id, "page_size": page_size}
    if filter:
        query_kwargs["filter"] = filter
    if sorts:
        query_kwargs["sorts"] = sorts

    try:
        client = _get_notion_client()
        response = client.databases.query(**query_kwargs)
        rows = response.get("results", [])
        log(f"query_database: database_id={database_id} rows={len(rows)} limit={page_size}")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"query_database failed: database_id={database_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return []

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"query_database: database_id={database_id} rows={len(rows)}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return rows


# ---------------------------------------------------------------------------
# Op: create_database_entry
# ---------------------------------------------------------------------------

def create_database_entry(
    database_id: str,
    properties: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Create a new row (page) in a Notion database.

    Args:
        database_id: UUID of the target database.
        properties:  Notion properties dict matching the database schema.
                     Title property must be included. Example:
                     {
                       "Name": {"title": [{"text": {"content": "My entry"}}]},
                       "Status": {"select": {"name": "In Progress"}},
                     }

    Returns:
        The created Notion page object (the new database row), or None on error.

    Evidence receipt includes database_id and new page_id.
    """
    op = "create_database_entry"
    ctx, decision = _gate_and_emit(op)

    try:
        client = _get_notion_client()
        page = client.pages.create(
            parent={"database_id": database_id},
            properties=properties,
        )
        new_id = page.get("id", "unknown")
        log(f"create_database_entry: database_id={database_id} new_page_id={new_id}")
    except Exception as exc:
        _handle_notion_error(exc, op)
        receipt = build_evidence_receipt(
            ctx, decision, "error",
            f"create_database_entry failed: database_id={database_id} error={exc}",
            op, _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        return None

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_database_entry: database_id={database_id} page_id={page.get('id')}",
        op, _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    return page


# ============================================================================
# SECTION 8: ENTRY POINT + ARGPARSE DISPATCH
# ============================================================================

def _print_result(result: Any, op: str) -> None:
    """Pretty-print a result object to stdout as JSON."""
    if result is None:
        print(f"[{op}] No result (see log for errors).")
        return
    try:
        print(json.dumps(result, indent=2, default=str))
    except (TypeError, ValueError):
        print(repr(result))


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"{WORKER_NAME}",
        epilog=(
            "Examples:\n"
            "  python3 worker_logic.py search_pages --query 'Project'\n"
            "  python3 worker_logic.py get_page --page-id <uuid>\n"
            "  python3 worker_logic.py create_page --parent-id <uuid> --title 'New Page'\n"
            "  python3 worker_logic.py update_page --page-id <uuid> --archive\n"
            "  python3 worker_logic.py append_block --block-id <uuid> --type paragraph --text 'Hello'\n"
            "  python3 worker_logic.py list_blocks --block-id <uuid>\n"
            "  python3 worker_logic.py get_block --block-id <uuid>\n"
            "  python3 worker_logic.py list_databases\n"
            "  python3 worker_logic.py query_database --database-id <uuid> --limit 50\n"
            "  python3 worker_logic.py create_database_entry --database-id <uuid> "
            "--properties '{\"Name\":{\"title\":[{\"text\":{\"content\":\"Row\"}}]}}'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "op",
        choices=sorted(ALLOWED_OPS),
        help="Operation to perform",
    )

    # --- search_pages ---
    p.add_argument("--query", default="", help="Search query string (search_pages)")
    p.add_argument(
        "--filter-type", default=None, dest="filter_type",
        choices=["page", "database"],
        help="Object type filter for search_pages (default: page)",
    )

    # --- page ops ---
    p.add_argument("--page-id", dest="page_id", help="Notion page UUID (get_page, update_page)")
    p.add_argument("--parent-id", dest="parent_id", help="Parent page/database UUID (create_page)")
    p.add_argument("--title", help="Page title (create_page)")
    p.add_argument(
        "--db-page", action="store_true", dest="db_page",
        help="Parent is a database (create_page with --db-page → database_id)",
    )
    p.add_argument(
        "--properties", default=None,
        help="JSON string of Notion properties dict (create_page, update_page, create_database_entry)",
    )
    p.add_argument(
        "--archive", action="store_true",
        help="Archive the page (update_page --archive)",
    )

    # --- block ops ---
    p.add_argument("--block-id", dest="block_id", help="Notion block/page UUID (block ops)")
    p.add_argument(
        "--type", dest="block_type", default="paragraph",
        choices=sorted(SUPPORTED_BLOCK_TYPES),
        help="Block type for append_block (default: paragraph)",
    )
    p.add_argument("--text", default="", help="Text content for append_block")
    p.add_argument(
        "--block-extra", dest="block_extra", default=None,
        help="JSON string of extra fields for the block (e.g. language for code blocks)",
    )

    # --- database ops ---
    p.add_argument("--database-id", dest="database_id", help="Notion database UUID")
    p.add_argument(
        "--filter-json", dest="filter_json", default=None,
        help="JSON string of Notion filter for query_database",
    )
    p.add_argument(
        "--sorts-json", dest="sorts_json", default=None,
        help="JSON string of Notion sorts list for query_database",
    )
    p.add_argument(
        "--limit", type=int, default=100,
        help="Max rows for query_database (1-100, default: 100)",
    )

    return p


def run() -> None:
    """WCP worker entry point."""
    global _attest_meta

    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    if not _check_notion_deps():
        log("ERROR: notion-client not installed. Run: pip install notion-client>=2.2.0")
        raise SystemExit(1)

    args = build_arg_parser().parse_args()
    op = args.op

    # --- Parse optional JSON args ---
    props: Optional[Dict[str, Any]] = None
    if args.properties:
        try:
            props = json.loads(args.properties)
        except json.JSONDecodeError as e:
            log(f"ERROR: --properties is not valid JSON: {e}")
            raise SystemExit(1)

    filter_obj: Optional[Dict[str, Any]] = None
    if hasattr(args, "filter_json") and args.filter_json:
        try:
            filter_obj = json.loads(args.filter_json)
        except json.JSONDecodeError as e:
            log(f"ERROR: --filter-json is not valid JSON: {e}")
            raise SystemExit(1)

    sorts_list: Optional[List[Dict[str, Any]]] = None
    if hasattr(args, "sorts_json") and args.sorts_json:
        try:
            sorts_list = json.loads(args.sorts_json)
        except json.JSONDecodeError as e:
            log(f"ERROR: --sorts-json is not valid JSON: {e}")
            raise SystemExit(1)

    block_extra: Optional[Dict[str, Any]] = None
    if hasattr(args, "block_extra") and args.block_extra:
        try:
            block_extra = json.loads(args.block_extra)
        except json.JSONDecodeError as e:
            log(f"ERROR: --block-extra is not valid JSON: {e}")
            raise SystemExit(1)

    # --- Dispatch ---

    if op == "search_pages":
        result = search_pages(query=args.query, filter_type=args.filter_type)
        _print_result(result, op)

    elif op == "get_page":
        if not args.page_id:
            log("ERROR: --page-id required for get_page")
            raise SystemExit(1)
        result = get_page(page_id=args.page_id)
        _print_result(result, op)

    elif op == "create_page":
        if not args.parent_id:
            log("ERROR: --parent-id required for create_page")
            raise SystemExit(1)
        if not args.title:
            log("ERROR: --title required for create_page")
            raise SystemExit(1)
        result = create_page(
            parent_id=args.parent_id,
            title=args.title,
            properties=props,
            is_database_page=args.db_page,
        )
        _print_result(result, op)

    elif op == "update_page":
        if not args.page_id:
            log("ERROR: --page-id required for update_page")
            raise SystemExit(1)
        result = update_page(
            page_id=args.page_id,
            properties=props,
            archived=args.archive,
        )
        _print_result(result, op)

    elif op == "append_block":
        if not args.block_id:
            log("ERROR: --block-id required for append_block")
            raise SystemExit(1)
        block = _build_block(args.block_type, args.text, extra=block_extra)
        result = append_block(block_id=args.block_id, children=[block])
        _print_result(result, op)

    elif op == "list_blocks":
        if not args.block_id:
            log("ERROR: --block-id required for list_blocks")
            raise SystemExit(1)
        result = list_blocks(block_id=args.block_id)
        _print_result(result, op)

    elif op == "get_block":
        if not args.block_id:
            log("ERROR: --block-id required for get_block")
            raise SystemExit(1)
        result = get_block(block_id=args.block_id)
        _print_result(result, op)

    elif op == "list_databases":
        result = list_databases()
        _print_result(result, op)

    elif op == "query_database":
        if not args.database_id:
            log("ERROR: --database-id required for query_database")
            raise SystemExit(1)
        result = query_database(
            database_id=args.database_id,
            filter=filter_obj,
            sorts=sorts_list,
            limit=args.limit,
        )
        _print_result(result, op)

    elif op == "create_database_entry":
        if not args.database_id:
            log("ERROR: --database-id required for create_database_entry")
            raise SystemExit(1)
        if not props:
            log("ERROR: --properties (JSON) required for create_database_entry")
            raise SystemExit(1)
        result = create_database_entry(database_id=args.database_id, properties=props)
        _print_result(result, op)

    else:
        log(f"ERROR: Unknown op={op!r}")
        raise SystemExit(1)


if __name__ == "__main__":
    run()
