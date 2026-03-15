#!/usr/bin/env python3
"""
worker_logic.py — Telegram Notifications Worker (WCP v0.3.0)

Sends messages, photos, documents, and inline keyboards via the Telegram Bot API.
Also provides read and management operations: get updates, chat info, pin/delete
messages, answer callback queries, and fetch bot info.

Authentication via TELEGRAM_BOT_TOKEN environment variable (from BotFather).
All timestamps stored as UTC ISO 8601. Human-facing log output uses Central Time.

Setup:
    1. Create a bot via @BotFather on Telegram and copy the token.
    2. Set TELEGRAM_BOT_TOKEN=<your-bot-token> in the environment.
    3. Add the bot to any group/channel you want to send to, or use a user chat_id.
    4. Optionally set TELEGRAM_DEFAULT_CHAT_ID for a default send target.
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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.telegram.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.telegram"
WORKER_NAME        = "Telegram Notifications Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.telegram.send",
    "cap.pyhall.telegram.read",
    "cap.pyhall.telegram.manage",
]

ALLOWED_OPS = {
    "send_message",
    "send_photo",
    "send_document",
    "send_markdown",
    "send_html",
    "get_updates",
    "get_chat_info",
    "pin_message",
    "delete_message",
    "answer_callback_query",
    "send_inline_keyboard",
    "get_bot_info",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# Telegram Bot API base URL — token is interpolated per-call
_TG_API_BASE = "https://api.telegram.org/bot{token}/{method}"


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
class TelegramMessage:
    """Lightweight representation of a Telegram message for send operations."""
    chat_id: str
    text: str
    parse_mode: Optional[str] = None
    disable_notification: bool = False
    reply_to_message_id: Optional[int] = None


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


def _escape_markdownv2(text: str) -> str:
    """
    Escape all special characters required by Telegram's MarkdownV2 parse mode.

    The following characters must be preceded by a backslash:
    _ * [ ] ( ) ~ ` > # + - = | { } . !

    See: https://core.telegram.org/bots/api#markdownv2-style
    """
    # Order matters — escape backslash first to avoid double-escaping
    special = r"\_*[]()~`>#+-=|{}.!"
    result = []
    for ch in text:
        if ch in special:
            result.append(f"\\{ch}")
        else:
            result.append(ch)
    return "".join(result)


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
#   code/worker_logic.py → package root is two levels up (telegram_worker/)
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../telegram_worker/
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

        rule_id = f"rr_telegram_{op}_allow_v1"
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

    Each entry records: prev_hash, entry_hash (sha256 of prev_hash + payload), receipt dict.
    Writes are best-effort — will not crash if the directory is absent or write fails.
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


def _capability_for_op(op: str) -> str:
    """Map an operation name to the appropriate capability ID."""
    send_ops = {
        "send_message", "send_photo", "send_document",
        "send_markdown", "send_html", "send_inline_keyboard",
    }
    read_ops = {"get_updates", "get_chat_info", "get_bot_info"}
    manage_ops = {"pin_message", "delete_message", "answer_callback_query"}
    if op in send_ops:
        return "cap.pyhall.telegram.send"
    if op in read_ops:
        return "cap.pyhall.telegram.read"
    if op in manage_ops:
        return "cap.pyhall.telegram.manage"
    return CAPABILITIES[0]


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
# SECTION 7: DOMAIN LOGIC — TELEGRAM BOT API
# ============================================================================

# --- Auth + HTTP helpers ---

def _get_token() -> str:
    """
    Return the Telegram bot token from the environment.

    Reads TELEGRAM_BOT_TOKEN. Raises SystemExit(1) with a clear message if not set.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        log("ERROR: TELEGRAM_BOT_TOKEN environment variable is not set.")
        log("  Obtain a token from @BotFather and set: export TELEGRAM_BOT_TOKEN=<token>")
        raise SystemExit(1)
    return token


def _tg(method: str, **params: Any) -> Any:
    """
    POST to the Telegram Bot API.

    Constructs the URL as:
        https://api.telegram.org/bot{token}/{method}

    Sends params as JSON. Checks response["ok"] == True.
    Raises RuntimeError with the Telegram error description if ok is False.
    Raises SystemExit(1) if the requests package is not installed.

    Returns response["result"] on success.
    """
    try:
        import requests as _requests
    except ImportError:
        log("ERROR: 'requests' package is not installed.")
        log("  Install with: pip install requests")
        raise SystemExit(1)

    token = _get_token()
    url = _TG_API_BASE.format(token=token, method=method)

    # Strip None values — Telegram ignores unknown params but this keeps payloads clean
    clean_params = {k: v for k, v in params.items() if v is not None}

    resp = _requests.post(
        url,
        json=clean_params,
        timeout=30,
        headers={"User-Agent": f"pyhall-telegram-worker/{WORKER_VERSION}"},
    )
    resp.raise_for_status()

    data = resp.json()
    if not data.get("ok"):
        err_code = data.get("error_code", "unknown")
        description = data.get("description", "No description from Telegram API")
        raise RuntimeError(
            f"Telegram API error {err_code} calling {method!r}: {description}"
        )

    return data.get("result")


def _tg_multipart(method: str, files: Dict[str, Any], **params: Any) -> Any:
    """
    POST to the Telegram Bot API using multipart/form-data for file uploads.

    Used by send_photo (local path) and send_document.
    Non-file params are sent as form fields (stringified).
    Returns response["result"] on success.
    """
    try:
        import requests as _requests
    except ImportError:
        log("ERROR: 'requests' package is not installed.")
        raise SystemExit(1)

    token = _get_token()
    url = _TG_API_BASE.format(token=token, method=method)

    # Non-file fields must be sent as strings in multipart
    data_fields = {k: str(v) for k, v in params.items() if v is not None}

    resp = _requests.post(
        url,
        data=data_fields,
        files=files,
        timeout=60,
        headers={"User-Agent": f"pyhall-telegram-worker/{WORKER_VERSION}"},
    )
    resp.raise_for_status()

    data = resp.json()
    if not data.get("ok"):
        err_code = data.get("error_code", "unknown")
        description = data.get("description", "No description from Telegram API")
        raise RuntimeError(
            f"Telegram API error {err_code} calling {method!r}: {description}"
        )

    return data.get("result")


# --- Telegram domain operations ---

def get_bot_info() -> Dict[str, Any]:
    """
    Retrieve information about the authenticated bot.

    Calls Telegram getMe. Returns a summary dict with:
        "id", "username", "first_name", "can_join_groups",
        "can_read_all_group_messages", "supports_inline_queries".

    Policy gate: cap.pyhall.telegram.read
    """
    ctx, decision = _gate_and_emit("get_bot_info")
    log("get_bot_info")

    result = _tg("getMe")

    summary = {
        "id": result.get("id"),
        "username": result.get("username"),
        "first_name": result.get("first_name"),
        "can_join_groups": result.get("can_join_groups"),
        "can_read_all_group_messages": result.get("can_read_all_group_messages"),
        "supports_inline_queries": result.get("supports_inline_queries"),
    }

    detail = f"get_bot_info: bot_id={summary['id']} username=@{summary['username']}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_bot_info", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Bot: @{summary['username']} (id={summary['id']})")
    return summary


def send_message(
    chat_id: str,
    text: str,
    parse_mode: Optional[str] = None,
    disable_notification: bool = False,
    reply_to_message_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Send a text message to a Telegram chat.

    Calls Telegram sendMessage. chat_id can be a numeric ID (int as str) or
    a public @username string.

    Args:
        chat_id:              Target chat ID or @username.
        text:                 Message text (up to 4096 characters).
        parse_mode:           Optional: "MarkdownV2", "HTML", or None (plain text).
        disable_notification: If True, send silently (no notification sound).
        reply_to_message_id:  Optional message_id to reply to.

    Returns the sent Message object from Telegram.

    Policy gate: cap.pyhall.telegram.send
    """
    ctx, decision = _gate_and_emit("send_message")
    log(f"send_message: chat_id={chat_id!r} parse_mode={parse_mode!r}")

    result = _tg(
        "sendMessage",
        chat_id=chat_id,
        text=text,
        parse_mode=parse_mode,
        disable_notification=disable_notification or None,
        reply_to_message_id=reply_to_message_id,
    )

    msg_id = result.get("message_id", "unknown")
    detail = f"send_message: chat_id={chat_id} message_id={msg_id}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_message", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent message {msg_id} to chat {chat_id}")
    return result


def send_markdown(chat_id: str, text: str) -> Dict[str, Any]:
    """
    Send a MarkdownV2-formatted message to a Telegram chat.

    Escapes all MarkdownV2 special characters in the provided text before sending,
    so callers can pass plain text containing periods, dashes, parentheses, etc.
    without triggering Telegram parse errors.

    If you need raw MarkdownV2 control (bold, italic, code blocks), escape the
    text yourself and call send_message(..., parse_mode="MarkdownV2") directly.

    Args:
        chat_id: Target chat ID or @username.
        text:    Plain text to escape and send as MarkdownV2.

    Returns the sent Message object from Telegram.

    Policy gate: cap.pyhall.telegram.send
    """
    ctx, decision = _gate_and_emit("send_markdown")
    log(f"send_markdown: chat_id={chat_id!r}")

    escaped = _escape_markdownv2(text)
    result = _tg(
        "sendMessage",
        chat_id=chat_id,
        text=escaped,
        parse_mode="MarkdownV2",
    )

    msg_id = result.get("message_id", "unknown")
    detail = f"send_markdown: chat_id={chat_id} message_id={msg_id}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_markdown", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent MarkdownV2 message {msg_id} to chat {chat_id}")
    return result


def send_html(chat_id: str, text: str) -> Dict[str, Any]:
    """
    Send an HTML-formatted message to a Telegram chat.

    Telegram HTML supports: <b>, <i>, <u>, <s>, <code>, <pre>, <a href="">.
    Other HTML tags are stripped or cause errors.

    Args:
        chat_id: Target chat ID or @username.
        text:    HTML-formatted message text.

    Returns the sent Message object from Telegram.

    Policy gate: cap.pyhall.telegram.send
    """
    ctx, decision = _gate_and_emit("send_html")
    log(f"send_html: chat_id={chat_id!r}")

    result = _tg(
        "sendMessage",
        chat_id=chat_id,
        text=text,
        parse_mode="HTML",
    )

    msg_id = result.get("message_id", "unknown")
    detail = f"send_html: chat_id={chat_id} message_id={msg_id}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_html", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent HTML message {msg_id} to chat {chat_id}")
    return result


def send_photo(
    chat_id: str,
    photo_url_or_path: str,
    caption: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send a photo to a Telegram chat.

    If photo_url_or_path looks like a URL (starts with http:// or https://),
    it is passed as a string to Telegram's sendPhoto API (Telegram fetches it).
    Otherwise, it is treated as a local file path and uploaded via multipart/form-data.

    Args:
        chat_id:           Target chat ID or @username.
        photo_url_or_path: HTTP/HTTPS URL string, or local file path (str or Path-like).
        caption:           Optional caption text (plain text, max 1024 chars).

    Returns the sent Message object from Telegram.

    Policy gate: cap.pyhall.telegram.send
    """
    ctx, decision = _gate_and_emit("send_photo")
    log(f"send_photo: chat_id={chat_id!r} source={photo_url_or_path!r}")

    is_url = str(photo_url_or_path).startswith(("http://", "https://"))

    if is_url:
        result = _tg(
            "sendPhoto",
            chat_id=chat_id,
            photo=photo_url_or_path,
            caption=caption,
        )
    else:
        photo_path = Path(photo_url_or_path)
        if not photo_path.exists():
            msg = f"send_photo: local file not found: {photo_path}"
            log(f"ERROR: {msg}")
            receipt = build_evidence_receipt(ctx, decision, "error", msg, "send_photo", _attest_meta)
            _evidence_log.emit_evidence(receipt)
            raise FileNotFoundError(msg)
        with photo_path.open("rb") as fh:
            result = _tg_multipart(
                "sendPhoto",
                files={"photo": (photo_path.name, fh, "application/octet-stream")},
                chat_id=chat_id,
                caption=caption,
            )

    msg_id = result.get("message_id", "unknown")
    detail = f"send_photo: chat_id={chat_id} message_id={msg_id} source={'url' if is_url else 'file'}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_photo", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent photo message {msg_id} to chat {chat_id}")
    return result


def send_document(
    chat_id: str,
    document_path: str,
    caption: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send a document (file) to a Telegram chat via multipart upload.

    Always uses multipart/form-data. document_path must be a local file path.
    Telegram accepts up to 50 MB via Bot API.

    Args:
        chat_id:       Target chat ID or @username.
        document_path: Local path to the file to upload (str or Path-like).
        caption:       Optional caption text (plain text, max 1024 chars).

    Returns the sent Message object from Telegram.

    Policy gate: cap.pyhall.telegram.send
    """
    ctx, decision = _gate_and_emit("send_document")
    doc_path = Path(document_path)
    log(f"send_document: chat_id={chat_id!r} file={doc_path.name!r}")

    if not doc_path.exists():
        msg = f"send_document: local file not found: {doc_path}"
        log(f"ERROR: {msg}")
        receipt = build_evidence_receipt(ctx, decision, "error", msg, "send_document", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        raise FileNotFoundError(msg)

    with doc_path.open("rb") as fh:
        result = _tg_multipart(
            "sendDocument",
            files={"document": (doc_path.name, fh, "application/octet-stream")},
            chat_id=chat_id,
            caption=caption,
        )

    msg_id = result.get("message_id", "unknown")
    detail = f"send_document: chat_id={chat_id} message_id={msg_id} file={doc_path.name}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_document", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent document {doc_path.name!r} as message {msg_id} to chat {chat_id}")
    return result


def get_updates(
    offset: Optional[int] = None,
    limit: int = 10,
    timeout: int = 0,
) -> List[Dict[str, Any]]:
    """
    Retrieve pending updates from the Telegram Bot API.

    Calls Telegram getUpdates. Use offset = last_update_id + 1 to mark
    previously received updates as read (they will not be returned again).

    Args:
        offset:  Update ID offset. All updates with update_id < offset are dismissed.
        limit:   Maximum updates to return (1–100, default 10).
        timeout: Long-polling timeout in seconds. 0 = short-poll (default).

    Returns a list of Update objects from Telegram.

    Policy gate: cap.pyhall.telegram.read
    """
    ctx, decision = _gate_and_emit("get_updates")
    limit = max(1, min(100, limit))
    log(f"get_updates: offset={offset!r} limit={limit} timeout={timeout}")

    result = _tg(
        "getUpdates",
        offset=offset,
        limit=limit,
        timeout=timeout,
    )
    updates: List[Dict[str, Any]] = result if isinstance(result, list) else []

    detail = f"get_updates: retrieved {len(updates)} updates"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_updates", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Retrieved {len(updates)} updates")
    return updates


def get_chat_info(chat_id: str) -> Dict[str, Any]:
    """
    Retrieve information about a Telegram chat.

    Calls Telegram getChat. Works for private chats, groups, supergroups,
    and channels where the bot is a member.

    Returns a summary dict with keys:
        "id", "type", "title", "username", "description",
        "member_count" (if available).

    Args:
        chat_id: Target chat ID or @username.

    Policy gate: cap.pyhall.telegram.read
    """
    ctx, decision = _gate_and_emit("get_chat_info")
    log(f"get_chat_info: chat_id={chat_id!r}")

    result = _tg("getChat", chat_id=chat_id)

    # getMemberCount is a separate call — make it best-effort
    member_count: Optional[int] = None
    try:
        member_count = _tg("getChatMemberCount", chat_id=chat_id)
    except Exception:
        pass  # Not all chat types support member count

    summary = {
        "id": result.get("id"),
        "type": result.get("type"),
        "title": result.get("title"),
        "username": result.get("username"),
        "description": result.get("description"),
        "member_count": member_count,
    }

    detail = f"get_chat_info: chat_id={chat_id} type={summary['type']} title={summary.get('title') or summary.get('username')!r}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_chat_info", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Chat: {summary.get('title') or summary.get('username')} (id={summary['id']}, type={summary['type']})")
    if member_count is not None:
        log(f"    Members: {member_count}")
    return summary


def pin_message(
    chat_id: str,
    message_id: int,
    disable_notification: bool = False,
) -> bool:
    """
    Pin a message in a Telegram chat.

    Calls Telegram pinChatMessage. The bot must be an administrator with the
    can_pin_messages permission.

    Args:
        chat_id:              Target chat ID or @username.
        message_id:           ID of the message to pin.
        disable_notification: If True, pin silently (no notification).

    Returns True on success.

    Policy gate: cap.pyhall.telegram.manage
    """
    ctx, decision = _gate_and_emit("pin_message")
    log(f"pin_message: chat_id={chat_id!r} message_id={message_id}")

    _tg(
        "pinChatMessage",
        chat_id=chat_id,
        message_id=message_id,
        disable_notification=disable_notification or None,
    )

    detail = f"pin_message: chat_id={chat_id} message_id={message_id}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "pin_message", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Pinned message {message_id} in chat {chat_id}")
    return True


def delete_message(chat_id: str, message_id: int) -> bool:
    """
    Delete a message from a Telegram chat.

    Calls Telegram deleteMessage. The bot must have appropriate permissions
    (admin in groups/channels, or the message must be from the bot in private chats).
    Messages older than 48 hours cannot be deleted in groups.

    Args:
        chat_id:    Target chat ID or @username.
        message_id: ID of the message to delete.

    Returns True on success.

    Policy gate: cap.pyhall.telegram.manage
    """
    ctx, decision = _gate_and_emit("delete_message")
    log(f"delete_message: chat_id={chat_id!r} message_id={message_id}")

    _tg(
        "deleteMessage",
        chat_id=chat_id,
        message_id=message_id,
    )

    detail = f"delete_message: chat_id={chat_id} message_id={message_id}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "delete_message", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Deleted message {message_id} from chat {chat_id}")
    return True


def answer_callback_query(
    callback_query_id: str,
    text: Optional[str] = None,
    show_alert: bool = False,
) -> bool:
    """
    Answer an inline keyboard callback query.

    Calls Telegram answerCallbackQuery. Must be called within 10 seconds of
    receiving the callback_query or the button will show a loading state.

    Args:
        callback_query_id: ID from the CallbackQuery object (Update.callback_query.id).
        text:              Optional notification text shown to the user (0–200 chars).
                           If show_alert=False, shown as a toast at the top of the screen.
        show_alert:        If True, show text as a popup alert requiring user dismissal.

    Returns True on success.

    Policy gate: cap.pyhall.telegram.manage
    """
    ctx, decision = _gate_and_emit("answer_callback_query")
    log(f"answer_callback_query: callback_query_id={callback_query_id!r} show_alert={show_alert}")

    _tg(
        "answerCallbackQuery",
        callback_query_id=callback_query_id,
        text=text,
        show_alert=show_alert or None,
    )

    detail = f"answer_callback_query: callback_query_id={callback_query_id}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "answer_callback_query", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Answered callback query {callback_query_id}")
    return True


def send_inline_keyboard(
    chat_id: str,
    text: str,
    buttons: List[List[Dict[str, str]]],
) -> Dict[str, Any]:
    """
    Send a message with an inline keyboard to a Telegram chat.

    Calls Telegram sendMessage with reply_markup=InlineKeyboardMarkup.

    buttons is a 2D list (rows x columns) of button dicts, each with:
        "text"          — label displayed on the button
        "callback_data" — string payload sent back in the callback query (max 64 bytes)

    Example:
        buttons = [
            [{"text": "Yes", "callback_data": "confirm_yes"},
             {"text": "No",  "callback_data": "confirm_no"}],
            [{"text": "Cancel", "callback_data": "confirm_cancel"}],
        ]

    Args:
        chat_id:  Target chat ID or @username.
        text:     Message text to display above the keyboard.
        buttons:  2D list of button dicts.

    Returns the sent Message object from Telegram.

    Policy gate: cap.pyhall.telegram.send
    """
    ctx, decision = _gate_and_emit("send_inline_keyboard")
    log(f"send_inline_keyboard: chat_id={chat_id!r} rows={len(buttons)}")

    # Build the InlineKeyboardMarkup structure
    keyboard_rows: List[List[Dict[str, str]]] = []
    for row in buttons:
        keyboard_rows.append(
            [{"text": btn["text"], "callback_data": btn["callback_data"]} for btn in row]
        )

    reply_markup = {"inline_keyboard": keyboard_rows}

    result = _tg(
        "sendMessage",
        chat_id=chat_id,
        text=text,
        reply_markup=reply_markup,
    )

    msg_id = result.get("message_id", "unknown")
    detail = f"send_inline_keyboard: chat_id={chat_id} message_id={msg_id} rows={len(buttons)}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_inline_keyboard", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent inline keyboard message {msg_id} to chat {chat_id}")
    return result


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        epilog=(
            "Examples:\n"
            "  python3 worker_logic.py send_message --chat-id @mychannel --text 'Hello'\n"
            "  python3 worker_logic.py send_markdown --chat-id 123456789 --text 'Build *done*'\n"
            "  python3 worker_logic.py send_html --chat-id 123456789 --text '<b>Alert</b>: deploy done'\n"
            "  python3 worker_logic.py send_photo --chat-id 123456789 --photo /tmp/screen.png\n"
            "  python3 worker_logic.py send_photo --chat-id 123456789 --photo https://example.com/img.jpg\n"
            "  python3 worker_logic.py send_document --chat-id 123456789 --document /tmp/report.pdf\n"
            "  python3 worker_logic.py get_updates --limit 5\n"
            "  python3 worker_logic.py get_chat_info --chat-id @mychannel\n"
            "  python3 worker_logic.py pin_message --chat-id 123456789 --message-id 42\n"
            "  python3 worker_logic.py delete_message --chat-id 123456789 --message-id 42\n"
            "  python3 worker_logic.py answer_callback_query --callback-query-id abc123 --text 'Done'\n"
            "  python3 worker_logic.py send_inline_keyboard --chat-id 123456789 --text 'Choose:' --buttons-json '[[{\"text\":\"Yes\",\"callback_data\":\"yes\"}]]'\n"
            "  python3 worker_logic.py get_bot_info\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("op", choices=sorted(ALLOWED_OPS), help="Operation to perform")

    # Shared / per-operation arguments
    p.add_argument(
        "--chat-id", dest="chat_id",
        default=os.environ.get("TELEGRAM_DEFAULT_CHAT_ID", ""),
        help="Telegram chat ID (numeric) or @username (or set TELEGRAM_DEFAULT_CHAT_ID)",
    )
    p.add_argument("--text", default=None, help="Message text (send_message, send_markdown, send_html, send_inline_keyboard)")
    p.add_argument("--caption", default=None, help="Photo/document caption (send_photo, send_document)")
    p.add_argument(
        "--parse-mode", dest="parse_mode", default=None,
        choices=["MarkdownV2", "HTML"],
        help="Parse mode for send_message (MarkdownV2 or HTML)",
    )
    p.add_argument(
        "--disable-notification", dest="disable_notification",
        action="store_true",
        help="Send silently (send_message, pin_message)",
    )
    p.add_argument(
        "--reply-to", dest="reply_to_message_id", type=int, default=None,
        help="Message ID to reply to (send_message)",
    )
    p.add_argument("--photo", default=None, help="Photo URL or local path (send_photo)")
    p.add_argument("--document", default=None, help="Local file path to upload (send_document)")
    p.add_argument(
        "--offset", type=int, default=None,
        help="Update ID offset for get_updates (marks prior updates read)",
    )
    p.add_argument("--limit", type=int, default=10, help="Max updates to retrieve (get_updates, 1-100)")
    p.add_argument("--timeout", type=int, default=0, help="Long-poll timeout in seconds (get_updates)")
    p.add_argument(
        "--message-id", dest="message_id", type=int, default=None,
        help="Message ID (pin_message, delete_message)",
    )
    p.add_argument(
        "--callback-query-id", dest="callback_query_id", default=None,
        help="Callback query ID (answer_callback_query)",
    )
    p.add_argument(
        "--show-alert", dest="show_alert", action="store_true",
        help="Show popup alert instead of toast (answer_callback_query)",
    )
    p.add_argument(
        "--buttons-json", dest="buttons_json", default=None,
        help=(
            "JSON 2D array of button dicts for send_inline_keyboard. "
            'Each button: {"text": "Label", "callback_data": "value"}'
        ),
    )
    return p


def _dispatch(op: str, args: argparse.Namespace) -> Any:
    """Route the parsed operation to the appropriate domain function."""

    if op == "get_bot_info":
        return get_bot_info()

    if op == "send_message":
        if not args.chat_id:
            log("ERROR: --chat-id is required for send_message")
            raise SystemExit(1)
        if not args.text:
            log("ERROR: --text is required for send_message")
            raise SystemExit(1)
        return send_message(
            args.chat_id,
            args.text,
            parse_mode=args.parse_mode,
            disable_notification=args.disable_notification,
            reply_to_message_id=args.reply_to_message_id,
        )

    if op == "send_markdown":
        if not args.chat_id:
            log("ERROR: --chat-id is required for send_markdown")
            raise SystemExit(1)
        if not args.text:
            log("ERROR: --text is required for send_markdown")
            raise SystemExit(1)
        return send_markdown(args.chat_id, args.text)

    if op == "send_html":
        if not args.chat_id:
            log("ERROR: --chat-id is required for send_html")
            raise SystemExit(1)
        if not args.text:
            log("ERROR: --text is required for send_html")
            raise SystemExit(1)
        return send_html(args.chat_id, args.text)

    if op == "send_photo":
        if not args.chat_id:
            log("ERROR: --chat-id is required for send_photo")
            raise SystemExit(1)
        if not args.photo:
            log("ERROR: --photo is required for send_photo")
            raise SystemExit(1)
        return send_photo(args.chat_id, args.photo, caption=args.caption)

    if op == "send_document":
        if not args.chat_id:
            log("ERROR: --chat-id is required for send_document")
            raise SystemExit(1)
        if not args.document:
            log("ERROR: --document is required for send_document")
            raise SystemExit(1)
        return send_document(args.chat_id, args.document, caption=args.caption)

    if op == "get_updates":
        updates = get_updates(
            offset=args.offset,
            limit=args.limit,
            timeout=args.timeout,
        )
        for u in updates:
            uid = u.get("update_id")
            msg = u.get("message") or u.get("channel_post") or {}
            sender = msg.get("from", {}).get("username") or msg.get("chat", {}).get("title") or "?"
            text_preview = (msg.get("text") or "")[:80]
            print(f"  update_id={uid} from={sender!r}: {text_preview}")
        return updates

    if op == "get_chat_info":
        if not args.chat_id:
            log("ERROR: --chat-id is required for get_chat_info")
            raise SystemExit(1)
        return get_chat_info(args.chat_id)

    if op == "pin_message":
        if not args.chat_id:
            log("ERROR: --chat-id is required for pin_message")
            raise SystemExit(1)
        if args.message_id is None:
            log("ERROR: --message-id is required for pin_message")
            raise SystemExit(1)
        return pin_message(args.chat_id, args.message_id, disable_notification=args.disable_notification)

    if op == "delete_message":
        if not args.chat_id:
            log("ERROR: --chat-id is required for delete_message")
            raise SystemExit(1)
        if args.message_id is None:
            log("ERROR: --message-id is required for delete_message")
            raise SystemExit(1)
        return delete_message(args.chat_id, args.message_id)

    if op == "answer_callback_query":
        if not args.callback_query_id:
            log("ERROR: --callback-query-id is required for answer_callback_query")
            raise SystemExit(1)
        return answer_callback_query(
            args.callback_query_id,
            text=args.text,
            show_alert=args.show_alert,
        )

    if op == "send_inline_keyboard":
        if not args.chat_id:
            log("ERROR: --chat-id is required for send_inline_keyboard")
            raise SystemExit(1)
        if not args.text:
            log("ERROR: --text is required for send_inline_keyboard")
            raise SystemExit(1)
        if not args.buttons_json:
            log("ERROR: --buttons-json is required for send_inline_keyboard")
            raise SystemExit(1)
        try:
            buttons = json.loads(args.buttons_json)
        except json.JSONDecodeError as exc:
            log(f"ERROR: --buttons-json is not valid JSON: {exc}")
            raise SystemExit(1)
        return send_inline_keyboard(args.chat_id, args.text, buttons)

    log(f"ERROR: Unknown op {op!r} — this should not happen (argparse should catch it)")
    raise SystemExit(1)


def run() -> None:
    """WCP worker entry point. Called from bootstrap.py and directly."""
    global _attest_meta

    # Run startup attestation — warns in dev, hard-fails in prod
    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = build_arg_parser()
    args = parser.parse_args()
    op = args.op

    log(f"Starting {WORKER_NAME} op={op!r}")

    result = _dispatch(op, args)

    if result is not None and isinstance(result, (dict, list)):
        print(json.dumps(result, indent=2, default=str))

    log(f"Done: op={op!r}")


if __name__ == "__main__":
    run()
