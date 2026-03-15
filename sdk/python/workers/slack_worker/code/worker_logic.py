#!/usr/bin/env python3
"""
worker_logic.py — Slack Full Stack Worker (WCP v0.3.0)

Full-coverage Slack integration: messaging, DMs, Block Kit, channel management,
reactions, file uploads, user info, status, and incoming webhooks.

Uses slack-sdk WebClient (Bot Token / xoxb-). Auth via SLACK_BOT_TOKEN env var.

Setup (one-time):
    1. Go to api.slack.com/apps → Create New App
    2. Add Bot Token Scopes listed in Section 7
    3. Install to workspace → copy Bot User OAuth Token (xoxb-)
    4. export SLACK_BOT_TOKEN="xoxb-..."
    5. Optional: export SLACK_WEBHOOK_URL="https://hooks.slack.com/..." for post_webhook
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

WORKER_ID          = "org.pyhall.slack.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.slack"
WORKER_NAME        = "Slack Full Stack Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.slack.send",
    "cap.pyhall.slack.read",
    "cap.pyhall.slack.manage",
]

ALLOWED_OPS = {
    "send_message", "send_dm", "send_blocks",
    "list_channels", "get_channel_history",
    "create_channel", "invite_to_channel",
    "add_reaction", "upload_file",
    "get_user_info", "list_users",
    "set_status", "post_webhook",
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
class SlackMessage:
    channel: str
    text: str
    ts: Optional[str] = None
    thread_ts: Optional[str] = None


@dataclass
class SlackChannel:
    id: str
    name: str
    is_private: bool
    is_archived: bool
    num_members: int


@dataclass
class SlackUser:
    id: str
    name: str
    real_name: Optional[str]
    email: Optional[str]
    title: Optional[str]
    status_text: Optional[str]
    is_bot: bool
    deleted: bool


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
#   code/worker_logic.py → package root is two levels up (slack_worker/)
_THIS_FILE    = Path(__file__).resolve()
_PACKAGE_ROOT = _THIS_FILE.parent.parent   # .../slack_worker/
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

        rule_id = f"rr_slack_{op}_allow_v1"
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


# Module-level singletons (instantiated at import time)
_policy_gate  = PolicyGate()
_evidence_log = AppendOnlyEvidenceLog(_EVIDENCE_LOG_PATH)
_attest_meta: Dict[str, Any] = {}   # populated by run() at startup


def _cap_for_op(op: str) -> str:
    """Map an operation to its primary capability ID."""
    _read_ops = {"list_channels", "get_channel_history", "get_user_info", "list_users"}
    _manage_ops = {"create_channel", "invite_to_channel", "set_status"}
    _channel_ops = {"list_channels", "get_channel_history", "create_channel", "invite_to_channel"}
    if op in _read_ops:
        return "cap.pyhall.slack.read"
    if op in _manage_ops:
        return "cap.pyhall.slack.manage"
    if op in _channel_ops:
        return "cap.pyhall.slack.manage"
    return "cap.pyhall.slack.send"


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
    """Run the policy gate for an operation. Emit deny receipt and exit if blocked."""
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
# SECTION 7: DOMAIN LOGIC (SLACK FULL STACK)
# ============================================================================

# Required Bot Token Scopes:
# chat:write, chat:write.public, im:write, channels:read, channels:history
# groups:read, groups:history, mpim:read, mpim:history, im:read, im:history
# reactions:write, files:write, users:read, users:read.email, users.profile:write
# channels:manage, groups:write

# --- Slack client factory ---

def _get_client():
    """Return an authenticated slack_sdk WebClient."""
    try:
        from slack_sdk import WebClient
    except ImportError as exc:
        log(f"FATAL: slack-sdk not installed: {exc}")
        log("  pip install slack-sdk")
        raise SystemExit(1)

    token = os.environ.get("SLACK_BOT_TOKEN", "").strip()
    if not token:
        log("FATAL: SLACK_BOT_TOKEN env var is not set.")
        log("  export SLACK_BOT_TOKEN='xoxb-...'")
        raise SystemExit(1)
    if not token.startswith("xoxb-"):
        log("WARNING: SLACK_BOT_TOKEN does not start with 'xoxb-' — expected a Bot User token.")

    from slack_sdk import WebClient
    return WebClient(token=token)


# --- Error helper ---

def _handle_slack_error(error) -> Dict[str, Any]:
    """
    Extract error code and message from a SlackApiError.

    Returns a dict with keys: error_code, error_message, response_body.
    """
    try:
        error_code = error.response.get("error", "unknown_error")
        error_message = str(error)
        response_body = dict(error.response) if error.response else {}
    except Exception:
        error_code = "unknown_error"
        error_message = str(error)
        response_body = {}
    return {
        "error_code": error_code,
        "error_message": error_message,
        "response_body": response_body,
    }


def _handle_rate_limit(error) -> int:
    """
    Extract Retry-After seconds from a SlackApiError 429 response.

    Returns the number of seconds to wait, defaulting to 30 if not present.
    """
    try:
        retry_after = int(error.response.headers.get("Retry-After", 30))
    except Exception:
        retry_after = 30
    return retry_after


# --- Tool: send_message ---

def send_message(
    channel: str,
    text: str,
    thread_ts: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Post a plain-text message to a channel or DM.

    channel can be: channel ID (C...), name (#general), or @username for DM lookup.
    thread_ts: if set, posts as a reply in the given thread.
    """
    ctx, decision = _gate_and_emit("send_message", "cap.pyhall.slack.send")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()
        kwargs: Dict[str, Any] = {"channel": channel, "text": text}
        if thread_ts:
            kwargs["thread_ts"] = thread_ts

        response = client.chat_postMessage(**kwargs)
        result = {
            "ok": True,
            "channel": response["channel"],
            "ts": response["ts"],
            "thread_ts": response.get("message", {}).get("thread_ts"),
        }
        log(f"send_message: posted to channel={channel!r} ts={response['ts']}")
        detail = f"send_message: channel={channel!r} ts={response['ts']}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    log(f"send_message: rate limited — Retry-After {wait}s")
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"send_message error: {err['error_code']} channel={channel!r}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"send_message error: {exc}"
        status = "error"
        log(f"send_message FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "send_message", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: send_dm ---

def send_dm(user_id: str, text: str) -> Dict[str, Any]:
    """
    Send a direct message to a user by Slack user ID (U...).

    Opens a DM conversation channel if one does not exist, then posts.
    """
    ctx, decision = _gate_and_emit("send_dm", "cap.pyhall.slack.send")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()

        # Open (or retrieve) DM channel
        open_resp = client.conversations_open(users=user_id)
        dm_channel = open_resp["channel"]["id"]

        response = client.chat_postMessage(channel=dm_channel, text=text)
        result = {
            "ok": True,
            "dm_channel": dm_channel,
            "user_id": user_id,
            "ts": response["ts"],
        }
        log(f"send_dm: DM sent to user={user_id!r} via channel={dm_channel!r} ts={response['ts']}")
        detail = f"send_dm: user={user_id!r} channel={dm_channel!r} ts={response['ts']}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"send_dm error: {err['error_code']} user={user_id!r}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"send_dm error: {exc}"
        status = "error"
        log(f"send_dm FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "send_dm", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: send_blocks ---

def send_blocks(
    channel: str,
    blocks: List[Dict[str, Any]],
    text: str = "",
) -> Dict[str, Any]:
    """
    Post a Block Kit message to a channel.

    blocks: list of Block Kit block dicts (e.g. section, divider, image, actions).
    text: fallback plain-text summary shown in notifications and accessibility contexts.
    """
    ctx, decision = _gate_and_emit("send_blocks", "cap.pyhall.slack.send")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()
        response = client.chat_postMessage(channel=channel, blocks=blocks, text=text)
        result = {
            "ok": True,
            "channel": response["channel"],
            "ts": response["ts"],
            "block_count": len(blocks),
        }
        log(f"send_blocks: posted {len(blocks)} block(s) to channel={channel!r} ts={response['ts']}")
        detail = f"send_blocks: channel={channel!r} blocks={len(blocks)} ts={response['ts']}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"send_blocks error: {err['error_code']} channel={channel!r}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"send_blocks error: {exc}"
        status = "error"
        log(f"send_blocks FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "send_blocks", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: list_channels ---

def list_channels(
    types: str = "public_channel,private_channel",
    limit: int = 100,
) -> Dict[str, Any]:
    """
    List workspace channels (public and/or private).

    types: comma-separated list of channel types.
         Valid values: public_channel, private_channel, mpim, im
    limit: max channels to return per page (Slack max 200; we paginate automatically).
    """
    ctx, decision = _gate_and_emit("list_channels", "cap.pyhall.slack.manage")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()

        channels: List[Dict[str, Any]] = []
        cursor = None
        while True:
            kwargs: Dict[str, Any] = {"types": types, "limit": min(limit, 200)}
            if cursor:
                kwargs["cursor"] = cursor
            response = client.conversations_list(**kwargs)
            for ch in response.get("channels", []):
                channels.append({
                    "id": ch["id"],
                    "name": ch.get("name", ""),
                    "is_private": ch.get("is_private", False),
                    "is_archived": ch.get("is_archived", False),
                    "num_members": ch.get("num_members", 0),
                })
                if len(channels) >= limit:
                    break
            meta = response.get("response_metadata", {})
            cursor = meta.get("next_cursor", "")
            if not cursor or len(channels) >= limit:
                break

        result = {"ok": True, "channels": channels, "count": len(channels)}
        log(f"list_channels: retrieved {len(channels)} channel(s) (types={types!r})")
        detail = f"list_channels: count={len(channels)} types={types!r}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"list_channels error: {err['error_code']}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"list_channels error: {exc}"
        status = "error"
        log(f"list_channels FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "list_channels", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: get_channel_history ---

def get_channel_history(
    channel_id: str,
    limit: int = 50,
    oldest: Optional[str] = None,
    latest: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fetch message history for a channel.

    channel_id: Slack channel ID (C...).
    limit: number of messages to return (max 999).
    oldest: start of time range as Unix timestamp string (exclusive).
    latest: end of time range as Unix timestamp string (inclusive).
    """
    ctx, decision = _gate_and_emit("get_channel_history", "cap.pyhall.slack.read")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()

        kwargs: Dict[str, Any] = {"channel": channel_id, "limit": min(limit, 999)}
        if oldest:
            kwargs["oldest"] = oldest
        if latest:
            kwargs["latest"] = latest

        response = client.conversations_history(**kwargs)
        messages = response.get("messages", [])
        result = {
            "ok": True,
            "channel_id": channel_id,
            "messages": messages,
            "count": len(messages),
            "has_more": response.get("has_more", False),
        }
        log(f"get_channel_history: fetched {len(messages)} message(s) from channel={channel_id!r}")
        detail = f"get_channel_history: channel={channel_id!r} count={len(messages)}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"get_channel_history error: {err['error_code']} channel={channel_id!r}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"get_channel_history error: {exc}"
        status = "error"
        log(f"get_channel_history FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "get_channel_history", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: create_channel ---

def create_channel(name: str, is_private: bool = False) -> Dict[str, Any]:
    """
    Create a new Slack channel.

    name: channel name (lowercase, no spaces, max 80 chars).
    is_private: True to create a private channel.
    """
    ctx, decision = _gate_and_emit("create_channel", "cap.pyhall.slack.manage")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()
        response = client.conversations_create(name=name, is_private=is_private)
        ch = response["channel"]
        result = {
            "ok": True,
            "channel_id": ch["id"],
            "channel_name": ch.get("name", name),
            "is_private": ch.get("is_private", is_private),
        }
        log(f"create_channel: created #{ch.get('name', name)!r} id={ch['id']!r} private={is_private}")
        detail = f"create_channel: name={ch.get('name', name)!r} id={ch['id']!r} private={is_private}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"create_channel error: {err['error_code']} name={name!r}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"create_channel error: {exc}"
        status = "error"
        log(f"create_channel FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "create_channel", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: invite_to_channel ---

def invite_to_channel(channel_id: str, user_ids: List[str]) -> Dict[str, Any]:
    """
    Invite one or more users to a channel.

    channel_id: Slack channel ID (C...).
    user_ids: list of Slack user IDs (U...) to invite.
    """
    ctx, decision = _gate_and_emit("invite_to_channel", "cap.pyhall.slack.manage")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()
        response = client.conversations_invite(
            channel=channel_id,
            users=",".join(user_ids),
        )
        ch = response.get("channel", {})
        result = {
            "ok": True,
            "channel_id": ch.get("id", channel_id),
            "invited_users": user_ids,
            "member_count": ch.get("num_members", None),
        }
        log(f"invite_to_channel: invited {user_ids} to channel={channel_id!r}")
        detail = f"invite_to_channel: channel={channel_id!r} users={user_ids}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"invite_to_channel error: {err['error_code']} channel={channel_id!r}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"invite_to_channel error: {exc}"
        status = "error"
        log(f"invite_to_channel FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "invite_to_channel", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: add_reaction ---

def add_reaction(
    channel_id: str,
    timestamp: str,
    emoji_name: str,
) -> Dict[str, Any]:
    """
    Add an emoji reaction to a message.

    channel_id: Slack channel ID (C...).
    timestamp: message timestamp string (ts field from a message).
    emoji_name: emoji name WITHOUT colons (e.g. "thumbsup", "rocket", "+1").
    """
    ctx, decision = _gate_and_emit("add_reaction", "cap.pyhall.slack.send")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()
        client.reactions_add(
            channel=channel_id,
            timestamp=timestamp,
            name=emoji_name,
        )
        result = {
            "ok": True,
            "channel_id": channel_id,
            "timestamp": timestamp,
            "emoji": emoji_name,
        }
        log(f"add_reaction: :{emoji_name}: added to channel={channel_id!r} ts={timestamp!r}")
        detail = f"add_reaction: emoji={emoji_name!r} channel={channel_id!r} ts={timestamp!r}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                # already_reacted is not really an error — surface it gracefully
                if err.get("error_code") == "already_reacted":
                    result = {"ok": True, "already_reacted": True, "emoji": emoji_name}
                    detail = f"add_reaction: already_reacted emoji={emoji_name!r}"
                    status = "ok"
                    log(f"add_reaction: already_reacted :{emoji_name}: on ts={timestamp!r}")
                else:
                    result = {"ok": False, **err}
                    detail = f"add_reaction error: {err['error_code']} emoji={emoji_name!r}"
                    status = "error"
                    log(f"add_reaction FAILED: {detail}")
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"add_reaction error: {exc}"
            status = "error"
            log(f"add_reaction FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "add_reaction", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: upload_file ---

def upload_file(
    channel_id: str,
    file_path: Optional[str] = None,
    content: Optional[str] = None,
    filename: Optional[str] = None,
    title: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Upload a file or string content to a channel.

    channel_id: Slack channel ID (C...) to share the file into.
    file_path: path to a local file (cross-platform via pathlib).
    content: string content to upload as a snippet (alternative to file_path).
    filename: display filename (required if using content; optional for file_path).
    title: optional file title shown in Slack.

    Exactly one of file_path or content must be provided.
    """
    ctx, decision = _gate_and_emit("upload_file", "cap.pyhall.slack.send")

    if not file_path and not content:
        result = {"ok": False, "error_message": "Either file_path or content must be provided."}
        detail = "upload_file error: no file_path or content"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "upload_file", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"upload_file FAILED: {detail}")
        return result

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()

        kwargs: Dict[str, Any] = {"channel": channel_id}
        if title:
            kwargs["title"] = title

        if file_path:
            resolved = Path(file_path).resolve()
            fname = filename or resolved.name
            response = client.files_upload_v2(
                file=str(resolved),
                filename=fname,
                **kwargs,
            )
        else:
            fname = filename or "snippet.txt"
            response = client.files_upload_v2(
                content=content,
                filename=fname,
                **kwargs,
            )

        # files_upload_v2 returns a 'file' key in the response
        file_info = response.get("file", {})
        result = {
            "ok": True,
            "file_id": file_info.get("id"),
            "filename": file_info.get("name", fname),
            "channel_id": channel_id,
            "permalink": file_info.get("permalink"),
        }
        log(f"upload_file: uploaded filename={fname!r} to channel={channel_id!r} id={file_info.get('id')!r}")
        detail = f"upload_file: filename={fname!r} channel={channel_id!r} id={file_info.get('id')!r}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"upload_file error: {err['error_code']} channel={channel_id!r}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"upload_file error: {exc}"
        status = "error"
        log(f"upload_file FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "upload_file", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: get_user_info ---

def get_user_info(user_id: str) -> Dict[str, Any]:
    """
    Fetch profile info for a Slack user.

    user_id: Slack user ID (U...).
    Returns: name, real_name, email, title, status_text.
    """
    ctx, decision = _gate_and_emit("get_user_info", "cap.pyhall.slack.read")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()
        response = client.users_info(user=user_id)
        user = response.get("user", {})
        profile = user.get("profile", {})
        result = {
            "ok": True,
            "user_id": user_id,
            "name": user.get("name"),
            "real_name": user.get("real_name"),
            "email": profile.get("email"),
            "title": profile.get("title"),
            "status_text": profile.get("status_text"),
            "status_emoji": profile.get("status_emoji"),
            "is_bot": user.get("is_bot", False),
            "deleted": user.get("deleted", False),
        }
        log(f"get_user_info: fetched user={user_id!r} name={user.get('name')!r}")
        detail = f"get_user_info: user={user_id!r} name={user.get('name')!r}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"get_user_info error: {err['error_code']} user={user_id!r}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"get_user_info error: {exc}"
        status = "error"
        log(f"get_user_info FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "get_user_info", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: list_users ---

def list_users(limit: int = 200) -> Dict[str, Any]:
    """
    List active (non-deleted) workspace members.

    limit: maximum users to return (paginated automatically).
    Returns: list of active users with id, name, real_name, email, is_bot.
    """
    ctx, decision = _gate_and_emit("list_users", "cap.pyhall.slack.read")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()

        users: List[Dict[str, Any]] = []
        cursor = None
        while True:
            kwargs: Dict[str, Any] = {"limit": min(200, limit)}
            if cursor:
                kwargs["cursor"] = cursor
            response = client.users_list(**kwargs)
            for u in response.get("members", []):
                if u.get("deleted"):
                    continue
                profile = u.get("profile", {})
                users.append({
                    "id": u["id"],
                    "name": u.get("name"),
                    "real_name": u.get("real_name"),
                    "email": profile.get("email"),
                    "is_bot": u.get("is_bot", False),
                    "is_app_user": u.get("is_app_user", False),
                })
                if len(users) >= limit:
                    break
            meta = response.get("response_metadata", {})
            cursor = meta.get("next_cursor", "")
            if not cursor or len(users) >= limit:
                break

        result = {"ok": True, "users": users, "count": len(users)}
        log(f"list_users: retrieved {len(users)} active member(s)")
        detail = f"list_users: count={len(users)}"
        status = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"list_users error: {err['error_code']}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"list_users error: {exc}"
        status = "error"
        log(f"list_users FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "list_users", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: set_status ---

def set_status(
    status_text: str,
    status_emoji: str = "",
    expiration: int = 0,
) -> Dict[str, Any]:
    """
    Set the authenticated bot/user's Slack status.

    status_text: visible status message.
    status_emoji: emoji name WITH colons (e.g. ":rocket:") or empty string to clear.
    expiration: Unix timestamp when status expires; 0 = never expires.
    """
    ctx, decision = _gate_and_emit("set_status", "cap.pyhall.slack.manage")

    try:
        from slack_sdk.errors import SlackApiError
        client = _get_client()
        profile = {
            "status_text": status_text,
            "status_emoji": status_emoji,
            "status_expiration": expiration,
        }
        client.users_profile_set(profile=profile)
        result = {
            "ok": True,
            "status_text": status_text,
            "status_emoji": status_emoji,
            "expiration": expiration,
        }
        log(f"set_status: status_text={status_text!r} emoji={status_emoji!r} expiration={expiration}")
        detail = f"set_status: text={status_text!r} emoji={status_emoji!r}"
        status_str = "ok"
    except Exception as exc:
        try:
            from slack_sdk.errors import SlackApiError
            if isinstance(exc, SlackApiError):
                err = _handle_slack_error(exc)
                if exc.response.status_code == 429:
                    wait = _handle_rate_limit(exc)
                    err["retry_after_seconds"] = wait
                result = {"ok": False, **err}
                detail = f"set_status error: {err['error_code']}"
            else:
                raise
        except ImportError:
            result = {"ok": False, "error_message": str(exc)}
            detail = f"set_status error: {exc}"
        status_str = "error"
        log(f"set_status FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status_str, detail, "set_status", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# --- Tool: post_webhook ---

def post_webhook(
    webhook_url: str,
    text: Optional[str] = None,
    blocks: Optional[List[Dict[str, Any]]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    POST a message to a Slack incoming webhook URL.

    webhook_url: full Slack incoming webhook URL (https://hooks.slack.com/...).
    text: plain-text message body.
    blocks: optional Block Kit blocks list.
    attachments: optional legacy attachments list.

    At least one of text, blocks, or attachments must be provided.
    Does not use the Slack SDK — uses requests directly.
    """
    ctx, decision = _gate_and_emit("post_webhook", "cap.pyhall.slack.send")

    if not text and not blocks and not attachments:
        result = {"ok": False, "error_message": "At least one of text, blocks, or attachments is required."}
        detail = "post_webhook error: empty payload"
        receipt = build_evidence_receipt(ctx, decision, "error", detail, "post_webhook", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        log(f"post_webhook FAILED: {detail}")
        return result

    try:
        import requests
        payload: Dict[str, Any] = {}
        if text:
            payload["text"] = text
        if blocks:
            payload["blocks"] = blocks
        if attachments:
            payload["attachments"] = attachments

        resp = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 30))
            result = {
                "ok": False,
                "error_code": "rate_limited",
                "http_status": 429,
                "retry_after_seconds": retry_after,
            }
            detail = f"post_webhook: rate limited, retry after {retry_after}s"
            status = "error"
            log(f"post_webhook RATE LIMITED — Retry-After {retry_after}s")
        elif resp.status_code != 200:
            result = {
                "ok": False,
                "http_status": resp.status_code,
                "response_text": resp.text,
            }
            detail = f"post_webhook error: HTTP {resp.status_code} body={resp.text!r}"
            status = "error"
            log(f"post_webhook FAILED: HTTP {resp.status_code}")
        else:
            result = {"ok": True, "http_status": 200, "response_text": resp.text}
            detail = f"post_webhook: delivered to webhook ok"
            status = "ok"
            log(f"post_webhook: delivered to webhook (text={str(text)[:60]!r})")
    except ImportError:
        result = {"ok": False, "error_message": "requests library not installed — pip install requests"}
        detail = "post_webhook error: requests not installed"
        status = "error"
        log(f"post_webhook FAILED: {detail}")
    except Exception as exc:
        result = {"ok": False, "error_message": str(exc)}
        detail = f"post_webhook error: {exc}"
        status = "error"
        log(f"post_webhook FAILED: {detail}")

    receipt = build_evidence_receipt(ctx, decision, status, detail, "post_webhook", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    return result


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def _print_result(result: Dict[str, Any]) -> None:
    """Pretty-print a result dict to stdout as JSON."""
    print(json.dumps(result, indent=2, default=str))


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"{WORKER_NAME}",
        epilog=(
            "Examples:\n"
            "  python3 bootstrap.py send_message --channel '#general' --text 'Hello'\n"
            "  python3 bootstrap.py send_dm --user-id U012AB3CD --text 'Hey there'\n"
            "  python3 bootstrap.py send_blocks --channel C012AB3CD --blocks '[{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"Hi\"}}]'\n"
            "  python3 bootstrap.py list_channels\n"
            "  python3 bootstrap.py get_channel_history --channel-id C012AB3CD --limit 20\n"
            "  python3 bootstrap.py create_channel --name my-new-channel --private\n"
            "  python3 bootstrap.py invite_to_channel --channel-id C012AB3CD --user-ids U012AB3CD U012AB3CE\n"
            "  python3 bootstrap.py add_reaction --channel-id C012AB3CD --ts 1234567890.123456 --emoji rocket\n"
            "  python3 bootstrap.py upload_file --channel-id C012AB3CD --file /tmp/report.txt --title 'Report'\n"
            "  python3 bootstrap.py upload_file --channel-id C012AB3CD --content 'hello world' --filename snippet.txt\n"
            "  python3 bootstrap.py get_user_info --user-id U012AB3CD\n"
            "  python3 bootstrap.py list_users\n"
            "  python3 bootstrap.py set_status --status-text 'In a meeting' --status-emoji ':calendar:'\n"
            "  python3 bootstrap.py post_webhook --webhook-url https://hooks.slack.com/... --text 'Deploy done'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = p.add_subparsers(dest="op", required=True)

    # send_message
    sp = subparsers.add_parser("send_message", help="Post a message to a channel")
    sp.add_argument("--channel", required=True, help="Channel ID, #name, or @username")
    sp.add_argument("--text", required=True, help="Message text")
    sp.add_argument("--thread-ts", default=None, dest="thread_ts", help="Thread timestamp to reply to")

    # send_dm
    sp = subparsers.add_parser("send_dm", help="Send a direct message to a user")
    sp.add_argument("--user-id", required=True, dest="user_id", help="Slack user ID (U...)")
    sp.add_argument("--text", required=True, help="Message text")

    # send_blocks
    sp = subparsers.add_parser("send_blocks", help="Post a Block Kit message")
    sp.add_argument("--channel", required=True, help="Channel ID or name")
    sp.add_argument("--blocks", required=True, help="JSON array of Block Kit blocks")
    sp.add_argument("--text", default="", help="Fallback plain text")

    # list_channels
    sp = subparsers.add_parser("list_channels", help="List workspace channels")
    sp.add_argument("--types", default="public_channel,private_channel",
                    help="Channel types (default: public_channel,private_channel)")
    sp.add_argument("--limit", type=int, default=100, help="Max channels to return")

    # get_channel_history
    sp = subparsers.add_parser("get_channel_history", help="Fetch message history for a channel")
    sp.add_argument("--channel-id", required=True, dest="channel_id", help="Channel ID (C...)")
    sp.add_argument("--limit", type=int, default=50, help="Max messages to return")
    sp.add_argument("--oldest", default=None, help="Oldest timestamp (Unix ts)")
    sp.add_argument("--latest", default=None, help="Latest timestamp (Unix ts)")

    # create_channel
    sp = subparsers.add_parser("create_channel", help="Create a new channel")
    sp.add_argument("--name", required=True, help="Channel name (lowercase, no spaces)")
    sp.add_argument("--private", action="store_true", help="Create as private channel")

    # invite_to_channel
    sp = subparsers.add_parser("invite_to_channel", help="Invite users to a channel")
    sp.add_argument("--channel-id", required=True, dest="channel_id", help="Channel ID (C...)")
    sp.add_argument("--user-ids", required=True, nargs="+", dest="user_ids", help="User IDs to invite")

    # add_reaction
    sp = subparsers.add_parser("add_reaction", help="Add an emoji reaction to a message")
    sp.add_argument("--channel-id", required=True, dest="channel_id", help="Channel ID (C...)")
    sp.add_argument("--ts", required=True, dest="timestamp", help="Message timestamp")
    sp.add_argument("--emoji", required=True, dest="emoji_name", help="Emoji name without colons")

    # upload_file
    sp = subparsers.add_parser("upload_file", help="Upload a file or snippet to a channel")
    sp.add_argument("--channel-id", required=True, dest="channel_id", help="Channel ID (C...)")
    sp.add_argument("--file", default=None, dest="file_path", help="Path to local file")
    sp.add_argument("--content", default=None, help="String content to upload as snippet")
    sp.add_argument("--filename", default=None, help="Display filename")
    sp.add_argument("--title", default=None, help="File title shown in Slack")

    # get_user_info
    sp = subparsers.add_parser("get_user_info", help="Fetch profile info for a user")
    sp.add_argument("--user-id", required=True, dest="user_id", help="Slack user ID (U...)")

    # list_users
    sp = subparsers.add_parser("list_users", help="List active workspace members")
    sp.add_argument("--limit", type=int, default=200, help="Max users to return")

    # set_status
    sp = subparsers.add_parser("set_status", help="Set the bot/user Slack status")
    sp.add_argument("--status-text", required=True, dest="status_text", help="Status message")
    sp.add_argument("--status-emoji", default="", dest="status_emoji", help="Status emoji (with colons)")
    sp.add_argument("--expiration", type=int, default=0, help="Unix timestamp expiration (0=never)")

    # post_webhook
    sp = subparsers.add_parser("post_webhook", help="POST to a Slack incoming webhook URL")
    sp.add_argument("--webhook-url", required=True, dest="webhook_url", help="Incoming webhook URL")
    sp.add_argument("--text", default=None, help="Message text")
    sp.add_argument("--blocks", default=None, help="JSON array of Block Kit blocks")
    sp.add_argument("--attachments", default=None, help="JSON array of legacy attachments")

    return p


def run() -> None:
    """WCP worker entry point. Called from bootstrap.py."""
    global _attest_meta

    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = build_arg_parser()
    args = parser.parse_args()
    op = args.op

    result: Dict[str, Any] = {}

    if op == "send_message":
        result = send_message(
            channel=args.channel,
            text=args.text,
            thread_ts=getattr(args, "thread_ts", None),
        )

    elif op == "send_dm":
        result = send_dm(user_id=args.user_id, text=args.text)

    elif op == "send_blocks":
        try:
            blocks = json.loads(args.blocks)
        except json.JSONDecodeError as exc:
            log(f"ERROR: --blocks is not valid JSON: {exc}")
            raise SystemExit(1)
        result = send_blocks(channel=args.channel, blocks=blocks, text=args.text)

    elif op == "list_channels":
        result = list_channels(types=args.types, limit=args.limit)

    elif op == "get_channel_history":
        result = get_channel_history(
            channel_id=args.channel_id,
            limit=args.limit,
            oldest=args.oldest,
            latest=args.latest,
        )

    elif op == "create_channel":
        result = create_channel(name=args.name, is_private=args.private)

    elif op == "invite_to_channel":
        result = invite_to_channel(channel_id=args.channel_id, user_ids=args.user_ids)

    elif op == "add_reaction":
        result = add_reaction(
            channel_id=args.channel_id,
            timestamp=args.timestamp,
            emoji_name=args.emoji_name,
        )

    elif op == "upload_file":
        result = upload_file(
            channel_id=args.channel_id,
            file_path=args.file_path,
            content=args.content,
            filename=args.filename,
            title=args.title,
        )

    elif op == "get_user_info":
        result = get_user_info(user_id=args.user_id)

    elif op == "list_users":
        result = list_users(limit=args.limit)

    elif op == "set_status":
        result = set_status(
            status_text=args.status_text,
            status_emoji=args.status_emoji,
            expiration=args.expiration,
        )

    elif op == "post_webhook":
        blocks = None
        attachments = None
        if args.blocks:
            try:
                blocks = json.loads(args.blocks)
            except json.JSONDecodeError as exc:
                log(f"ERROR: --blocks is not valid JSON: {exc}")
                raise SystemExit(1)
        if args.attachments:
            try:
                attachments = json.loads(args.attachments)
            except json.JSONDecodeError as exc:
                log(f"ERROR: --attachments is not valid JSON: {exc}")
                raise SystemExit(1)
        result = post_webhook(
            webhook_url=args.webhook_url,
            text=args.text,
            blocks=blocks,
            attachments=attachments,
        )

    _print_result(result)

    if not result.get("ok", False):
        raise SystemExit(1)


if __name__ == "__main__":
    run()
