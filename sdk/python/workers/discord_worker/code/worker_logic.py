#!/usr/bin/env python3
"""
worker_logic.py — Discord Notifications & Bot Worker (WCP v0.3.0)

Sends messages, embeds, DMs, and webhook payloads via the Discord REST API.
Also provides read and management operations: list guilds/channels, get messages,
add reactions, create webhooks, and fetch guild info.

Authentication via DISCORD_BOT_TOKEN environment variable.
All timestamps stored as UTC ISO 8601. Human-facing log output uses Central Time.

Setup:
    1. Create a Discord application at https://discord.com/developers/applications
    2. Create a Bot under the application and copy the token
    3. Set DISCORD_BOT_TOKEN=<your-bot-token> in the environment
    4. Invite the bot to your server with appropriate permissions
    5. Optionally set DISCORD_DEFAULT_CHANNEL_ID for a default send target
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

WORKER_ID          = "org.pyhall.discord.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.discord"
WORKER_NAME        = "Discord Notifications & Bot Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.discord.send",
    "cap.pyhall.discord.read",
    "cap.pyhall.discord.manage",
]

ALLOWED_OPS = {
    "send_message",
    "send_embed",
    "send_dm",
    "list_guilds",
    "list_channels",
    "get_messages",
    "add_reaction",
    "create_webhook",
    "send_webhook",
    "get_guild_info",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# Discord REST API base URL
DISCORD_API_BASE = "https://discord.com/api/v10"


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
class DiscordMessage:
    """Represents a Discord message for send operations."""
    channel_id: str
    content: Optional[str]
    tts: bool = False
    embeds: Optional[List[Dict[str, Any]]] = None


@dataclass
class EmbedField:
    """A single field in a Discord embed."""
    name: str
    value: str
    inline: bool = False


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
        log(f"WARNING: {msg} — continuing in dev")
        return {"dev_skip": True, "deny_code": deny_code, "meta": attest_meta}

    log(f"Attestation OK — {attest_meta.get('trust_statement', '')}")
    return attest_meta


# Derive paths from this file's location:
#   code/worker_logic.py → package root is two levels up (discord_worker/)
_THIS_FILE    = Path(__file__).resolve()
_PACKAGE_ROOT = _THIS_FILE.parent.parent   # .../discord_worker/
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

        rule_id = f"rr_discord_{op}_allow_v1"
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
    Writes are best-effort — will not crash if the directory is absent.
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
    send_ops = {"send_message", "send_embed", "send_dm", "send_webhook"}
    read_ops = {"list_guilds", "list_channels", "get_messages", "get_guild_info"}
    manage_ops = {"add_reaction", "create_webhook"}
    if op in send_ops:
        return "cap.pyhall.discord.send"
    if op in read_ops:
        return "cap.pyhall.discord.read"
    if op in manage_ops:
        return "cap.pyhall.discord.manage"
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
# SECTION 7: DOMAIN LOGIC — DISCORD REST API
# ============================================================================

# --- HTTP client with rate-limit handling ---

def _get_token() -> str:
    """
    Return the Discord bot token from the environment.

    Reads DISCORD_BOT_TOKEN. Raises SystemExit(1) with a clear message if not set,
    so operators know exactly what is missing.
    """
    token = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
    if not token:
        log("ERROR: DISCORD_BOT_TOKEN environment variable is not set.")
        log("  Set it with: export DISCORD_BOT_TOKEN=<your-bot-token>")
        raise SystemExit(1)
    return token


def _discord_request(
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Make an authenticated request to the Discord REST API.

    Handles HTTP 429 rate-limiting: reads the Retry-After header and waits
    before retrying (up to MAX_RETRIES attempts). Raises on 4xx/5xx errors
    that are not rate-limits.

    Args:
        method:  HTTP method string (GET, POST, PUT, DELETE, PATCH).
        path:    API path, e.g. "/channels/123/messages". Must start with "/".
        payload: JSON body dict (for POST/PUT/PATCH).
        params:  URL query parameters dict.

    Returns the parsed JSON response body (dict or list), or None for 204.
    """
    try:
        import requests
    except ImportError:
        log("ERROR: 'requests' package is not installed.")
        log("  Install with: pip install requests")
        raise SystemExit(1)

    token = _get_token()
    url = f"{DISCORD_API_BASE}{path}"
    headers = {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
        "User-Agent": f"DiscordBot (pyhall, {WORKER_VERSION})",
    }

    MAX_RETRIES = 5
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.request(
            method,
            url,
            headers=headers,
            json=payload,
            params=params,
            timeout=30,
        )

        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", "1"))
            log(f"WARNING: Discord rate-limited (429). Waiting {retry_after}s before retry {attempt}/{MAX_RETRIES}.")
            time.sleep(retry_after)
            continue

        if resp.status_code == 204:
            return None

        resp.raise_for_status()

        if resp.content:
            return resp.json()
        return None

    log(f"ERROR: Discord API request failed after {MAX_RETRIES} rate-limit retries: {method} {path}")
    raise SystemExit(1)


# --- Discord domain operations ---

def send_message(channel_id: str, content: str, tts: bool = False) -> Dict[str, Any]:
    """
    Send a plain text message to a Discord channel.

    POST /channels/{channel_id}/messages

    Args:
        channel_id: Target channel snowflake ID.
        content:    Message text (max 2000 characters per Discord limits).
        tts:        If True, send as a text-to-speech message.

    Returns the created message object from the Discord API.
    """
    ctx, decision = _gate_and_emit("send_message")
    log(f"send_message: channel={channel_id!r} tts={tts}")

    payload: Dict[str, Any] = {"content": content, "tts": tts}
    result = _discord_request("POST", f"/channels/{channel_id}/messages", payload=payload)

    detail = f"send_message: channel={channel_id} message_id={result.get('id', 'unknown')}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_message", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent message {result.get('id')} to channel {channel_id}")
    return result


def send_embed(
    channel_id: str,
    title: str,
    description: str,
    color: int = 0x0050D4,
    fields: Optional[List[Dict[str, Any]]] = None,
    footer: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send a rich embed message to a Discord channel.

    POST /channels/{channel_id}/messages with an embeds array.

    Args:
        channel_id:  Target channel snowflake ID.
        title:       Embed title text.
        description: Embed body text.
        color:       Integer color value (default: 0x0050D4 — pyhall blue).
        fields:      Optional list of embed field dicts, each with keys:
                     "name" (str), "value" (str), "inline" (bool, optional).
        footer:      Optional footer text string.

    Returns the created message object from the Discord API.
    """
    ctx, decision = _gate_and_emit("send_embed")
    log(f"send_embed: channel={channel_id!r} title={title!r}")

    embed: Dict[str, Any] = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": utc_now_iso(),
    }
    if fields:
        embed["fields"] = fields
    if footer:
        embed["footer"] = {"text": footer}

    payload: Dict[str, Any] = {"embeds": [embed]}
    result = _discord_request("POST", f"/channels/{channel_id}/messages", payload=payload)

    detail = f"send_embed: channel={channel_id} message_id={result.get('id', 'unknown')} title={title!r}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_embed", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent embed {result.get('id')} to channel {channel_id}")
    return result


def send_dm(user_id: str, content: str) -> Dict[str, Any]:
    """
    Send a direct message to a Discord user.

    Opens a DM channel (POST /users/@me/channels) then sends the message.
    Discord deduplicates DM channels so this is safe to call repeatedly.

    Args:
        user_id: Target user snowflake ID.
        content: Message text.

    Returns the created message object from the Discord API.
    """
    ctx, decision = _gate_and_emit("send_dm")
    log(f"send_dm: user={user_id!r}")

    # Step 1: Open or retrieve the DM channel
    dm_payload = {"recipient_id": user_id}
    dm_channel = _discord_request("POST", "/users/@me/channels", payload=dm_payload)
    dm_channel_id = dm_channel["id"]
    log(f"  DM channel opened: {dm_channel_id}")

    # Step 2: Send the message into the DM channel
    msg_payload: Dict[str, Any] = {"content": content}
    result = _discord_request("POST", f"/channels/{dm_channel_id}/messages", payload=msg_payload)

    detail = f"send_dm: user={user_id} dm_channel={dm_channel_id} message_id={result.get('id', 'unknown')}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_dm", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Sent DM {result.get('id')} to user {user_id}")
    return result


def list_guilds() -> List[Dict[str, Any]]:
    """
    List all guilds (servers) the bot is a member of.

    GET /users/@me/guilds

    Returns a list of partial guild objects. Each contains at minimum:
    "id" (snowflake), "name" (str), "icon" (str or None), "owner" (bool).
    """
    ctx, decision = _gate_and_emit("list_guilds")
    log("list_guilds")

    result = _discord_request("GET", "/users/@me/guilds")
    guilds: List[Dict[str, Any]] = result if isinstance(result, list) else []

    detail = f"list_guilds: found {len(guilds)} guilds"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "list_guilds", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Found {len(guilds)} guilds")
    for g in guilds:
        log(f"    [{g.get('id')}] {g.get('name')}")
    return guilds


def list_channels(guild_id: str) -> List[Dict[str, Any]]:
    """
    List all channels in a guild.

    GET /guilds/{guild_id}/channels

    Returns a list of channel objects. Each contains "id", "name", "type"
    (0=text, 2=voice, 4=category, etc.), and "position".

    Args:
        guild_id: Guild snowflake ID.
    """
    ctx, decision = _gate_and_emit("list_channels")
    log(f"list_channels: guild={guild_id!r}")

    result = _discord_request("GET", f"/guilds/{guild_id}/channels")
    channels: List[Dict[str, Any]] = result if isinstance(result, list) else []

    detail = f"list_channels: guild={guild_id} found {len(channels)} channels"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "list_channels", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Found {len(channels)} channels in guild {guild_id}")
    for c in sorted(channels, key=lambda x: x.get("position", 0)):
        ctype = c.get("type", "?")
        log(f"    [{c.get('id')}] #{c.get('name')} (type={ctype})")
    return channels


def get_messages(channel_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieve recent messages from a channel.

    GET /channels/{channel_id}/messages

    Args:
        channel_id: Target channel snowflake ID.
        limit:      Number of messages to retrieve (1–100, default 50).

    Returns a list of message objects, newest first. Each contains "id",
    "content", "author" (dict with "id" and "username"), and "timestamp".
    """
    ctx, decision = _gate_and_emit("get_messages")
    limit = max(1, min(100, limit))  # clamp to Discord's valid range
    log(f"get_messages: channel={channel_id!r} limit={limit}")

    result = _discord_request("GET", f"/channels/{channel_id}/messages", params={"limit": limit})
    messages: List[Dict[str, Any]] = result if isinstance(result, list) else []

    detail = f"get_messages: channel={channel_id} retrieved {len(messages)} messages"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_messages", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Retrieved {len(messages)} messages from channel {channel_id}")
    return messages


def add_reaction(channel_id: str, message_id: str, emoji: str) -> None:
    """
    Add a reaction emoji to a message.

    PUT /channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me

    Args:
        channel_id: Channel snowflake ID containing the message.
        message_id: Message snowflake ID to react to.
        emoji:      Unicode emoji character or custom emoji in "name:id" format.
                    For standard emoji, pass the literal character (e.g. "👍").
                    For custom emoji, pass "name:snowflake_id".

    The API returns 204 No Content on success.
    """
    ctx, decision = _gate_and_emit("add_reaction")
    log(f"add_reaction: channel={channel_id!r} message={message_id!r} emoji={emoji!r}")

    # URL-encode the emoji for the path segment
    from urllib.parse import quote
    emoji_encoded = quote(emoji, safe="")

    _discord_request(
        "PUT",
        f"/channels/{channel_id}/messages/{message_id}/reactions/{emoji_encoded}/@me",
    )

    detail = f"add_reaction: channel={channel_id} message={message_id} emoji={emoji!r}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "add_reaction", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Added reaction {emoji!r} to message {message_id}")


def create_webhook(channel_id: str, name: str) -> Dict[str, Any]:
    """
    Create a webhook for a channel.

    POST /channels/{channel_id}/webhooks

    Args:
        channel_id: Target channel snowflake ID. The bot must have MANAGE_WEBHOOKS
                    permission in this channel.
        name:       Display name for the webhook (1–80 characters).

    Returns a webhook object containing "id", "token", and "url"
    (constructed as https://discord.com/api/webhooks/{id}/{token}).
    """
    ctx, decision = _gate_and_emit("create_webhook")
    log(f"create_webhook: channel={channel_id!r} name={name!r}")

    payload = {"name": name}
    result = _discord_request("POST", f"/channels/{channel_id}/webhooks", payload=payload)

    # Build the webhook URL from id + token
    webhook_id = result.get("id", "")
    webhook_token = result.get("token", "")
    webhook_url = f"https://discord.com/api/webhooks/{webhook_id}/{webhook_token}"
    result["url"] = webhook_url

    detail = f"create_webhook: channel={channel_id} webhook_id={webhook_id} name={name!r}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "create_webhook", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Created webhook {webhook_id} ({name!r}) in channel {channel_id}")
    log(f"  Webhook URL: {webhook_url}")
    return result


def send_webhook(
    webhook_url: str,
    content: Optional[str] = None,
    embeds: Optional[List[Dict[str, Any]]] = None,
    username: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Send a message via a webhook URL (no bot token required for this call).

    POST to the webhook URL directly.

    At least one of content or embeds must be provided.

    Args:
        webhook_url: Full webhook URL (https://discord.com/api/webhooks/{id}/{token}).
        content:     Plain text message content.
        embeds:      List of embed dicts following Discord's embed structure.
        username:    Override the webhook's display name for this message.

    Returns the message object if the webhook was created with "wait=true",
    otherwise returns None (Discord sends 204 by default).
    """
    ctx, decision = _gate_and_emit("send_webhook")
    log(f"send_webhook: url={webhook_url[:60]}...")

    if not content and not embeds:
        msg = "send_webhook requires at least one of: content, embeds"
        log(f"ERROR: {msg}")
        receipt = build_evidence_receipt(ctx, decision, "error", msg, "send_webhook", _attest_meta)
        _evidence_log.emit_evidence(receipt)
        raise ValueError(msg)

    try:
        import requests
    except ImportError:
        log("ERROR: 'requests' package is not installed.")
        raise SystemExit(1)

    payload: Dict[str, Any] = {}
    if content:
        payload["content"] = content
    if embeds:
        payload["embeds"] = embeds
    if username:
        payload["username"] = username

    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"DiscordBot (pyhall, {WORKER_VERSION})",
    }

    MAX_RETRIES = 5
    result = None
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.post(
            webhook_url,
            headers=headers,
            json=payload,
            params={"wait": "true"},
            timeout=30,
        )
        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", "1"))
            log(f"WARNING: Webhook rate-limited (429). Waiting {retry_after}s (attempt {attempt}/{MAX_RETRIES}).")
            time.sleep(retry_after)
            continue
        if resp.status_code == 204:
            break
        resp.raise_for_status()
        if resp.content:
            result = resp.json()
        break

    detail = f"send_webhook: url={webhook_url[:60]}... message_id={result.get('id', 'none') if result else 'none'}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "send_webhook", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log("  Webhook message sent")
    return result


def get_guild_info(guild_id: str) -> Dict[str, Any]:
    """
    Retrieve detailed information about a guild.

    GET /guilds/{guild_id}

    Returns a summary dict with keys:
        "id", "name", "description", "member_count",
        "owner_id", "icon", "approximate_member_count".

    Note: member_count is only present if the bot has the SERVER_MEMBERS intent.
    The response also includes approximate_member_count from the API.

    Args:
        guild_id: Guild snowflake ID.
    """
    ctx, decision = _gate_and_emit("get_guild_info")
    log(f"get_guild_info: guild={guild_id!r}")

    result = _discord_request(
        "GET",
        f"/guilds/{guild_id}",
        params={"with_counts": "true"},
    )

    summary = {
        "id": result.get("id"),
        "name": result.get("name"),
        "description": result.get("description"),
        "member_count": result.get("member_count"),
        "approximate_member_count": result.get("approximate_member_count"),
        "owner_id": result.get("owner_id"),
        "icon": result.get("icon"),
        "verification_level": result.get("verification_level"),
    }

    detail = f"get_guild_info: guild={guild_id} name={summary.get('name')!r}"
    receipt = build_evidence_receipt(ctx, decision, "ok", detail, "get_guild_info", _attest_meta)
    _evidence_log.emit_evidence(receipt)
    log(f"  Guild: {summary.get('name')} (id={guild_id})")
    log(f"    Members: {summary.get('approximate_member_count', summary.get('member_count', 'N/A'))}")
    if summary.get("description"):
        log(f"    Description: {summary['description']}")
    return summary


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        epilog=(
            "Examples:\n"
            "  python3 worker_logic.py send_message --channel-id 123 --content 'Hello'\n"
            "  python3 worker_logic.py send_embed --channel-id 123 --title 'Alert' --description 'Server is down'\n"
            "  python3 worker_logic.py send_dm --user-id 456 --content 'Hey there'\n"
            "  python3 worker_logic.py list_guilds\n"
            "  python3 worker_logic.py list_channels --guild-id 789\n"
            "  python3 worker_logic.py get_messages --channel-id 123 --limit 20\n"
            "  python3 worker_logic.py add_reaction --channel-id 123 --message-id 999 --emoji '👍'\n"
            "  python3 worker_logic.py create_webhook --channel-id 123 --webhook-name 'MyHook'\n"
            "  python3 worker_logic.py send_webhook --webhook-url https://discord.com/api/webhooks/... --content 'Hi'\n"
            "  python3 worker_logic.py get_guild_info --guild-id 789\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("op", choices=sorted(ALLOWED_OPS), help="Operation to perform")

    # Shared / per-operation arguments
    p.add_argument("--channel-id", dest="channel_id",
                   default=os.environ.get("DISCORD_DEFAULT_CHANNEL_ID", ""),
                   help="Discord channel snowflake ID (or set DISCORD_DEFAULT_CHANNEL_ID)")
    p.add_argument("--content", default=None, help="Message text content")
    p.add_argument("--tts", action="store_true", help="Send message as TTS (send_message only)")
    p.add_argument("--title", default=None, help="Embed title (send_embed)")
    p.add_argument("--description", default=None, help="Embed description (send_embed)")
    p.add_argument("--color", type=lambda x: int(x, 0), default=0x0050D4,
                   help="Embed color as integer or hex (default: 0x0050D4)")
    p.add_argument("--footer", default=None, help="Embed footer text (send_embed)")
    p.add_argument("--user-id", dest="user_id", default=None, help="Discord user ID (send_dm)")
    p.add_argument("--guild-id", dest="guild_id",
                   default=os.environ.get("DISCORD_DEFAULT_GUILD_ID", ""),
                   help="Discord guild/server ID")
    p.add_argument("--limit", type=int, default=50, help="Message limit for get_messages (1-100)")
    p.add_argument("--message-id", dest="message_id", default=None, help="Message ID (add_reaction)")
    p.add_argument("--emoji", default=None, help="Emoji for add_reaction (e.g. '👍' or 'name:id')")
    p.add_argument("--webhook-name", dest="webhook_name", default=None,
                   help="Webhook display name (create_webhook)")
    p.add_argument("--webhook-url", dest="webhook_url", default=None,
                   help="Full webhook URL (send_webhook)")
    p.add_argument("--username", default=None, help="Override username for send_webhook")
    return p


def _dispatch(op: str, args: argparse.Namespace) -> Any:
    """Route the parsed operation to the appropriate domain function."""

    if op == "send_message":
        if not args.channel_id:
            log("ERROR: --channel-id is required for send_message")
            raise SystemExit(1)
        if not args.content:
            log("ERROR: --content is required for send_message")
            raise SystemExit(1)
        return send_message(args.channel_id, args.content, tts=args.tts)

    if op == "send_embed":
        if not args.channel_id:
            log("ERROR: --channel-id is required for send_embed")
            raise SystemExit(1)
        if not args.title:
            log("ERROR: --title is required for send_embed")
            raise SystemExit(1)
        if not args.description:
            log("ERROR: --description is required for send_embed")
            raise SystemExit(1)
        return send_embed(
            args.channel_id,
            args.title,
            args.description,
            color=args.color,
            footer=args.footer,
        )

    if op == "send_dm":
        if not args.user_id:
            log("ERROR: --user-id is required for send_dm")
            raise SystemExit(1)
        if not args.content:
            log("ERROR: --content is required for send_dm")
            raise SystemExit(1)
        return send_dm(args.user_id, args.content)

    if op == "list_guilds":
        return list_guilds()

    if op == "list_channels":
        if not args.guild_id:
            log("ERROR: --guild-id is required for list_channels")
            raise SystemExit(1)
        return list_channels(args.guild_id)

    if op == "get_messages":
        if not args.channel_id:
            log("ERROR: --channel-id is required for get_messages")
            raise SystemExit(1)
        msgs = get_messages(args.channel_id, limit=args.limit)
        for m in msgs:
            author = m.get("author", {}).get("username", "unknown")
            ts = m.get("timestamp", "")[:19]
            print(f"  [{ts}] {author}: {m.get('content', '')[:120]}")
        return msgs

    if op == "add_reaction":
        if not args.channel_id:
            log("ERROR: --channel-id is required for add_reaction")
            raise SystemExit(1)
        if not args.message_id:
            log("ERROR: --message-id is required for add_reaction")
            raise SystemExit(1)
        if not args.emoji:
            log("ERROR: --emoji is required for add_reaction")
            raise SystemExit(1)
        add_reaction(args.channel_id, args.message_id, args.emoji)
        return None

    if op == "create_webhook":
        if not args.channel_id:
            log("ERROR: --channel-id is required for create_webhook")
            raise SystemExit(1)
        if not args.webhook_name:
            log("ERROR: --webhook-name is required for create_webhook")
            raise SystemExit(1)
        return create_webhook(args.channel_id, args.webhook_name)

    if op == "send_webhook":
        if not args.webhook_url:
            log("ERROR: --webhook-url is required for send_webhook")
            raise SystemExit(1)
        if not args.content:
            log("ERROR: --content is required for send_webhook (embeds not supported via CLI)")
            raise SystemExit(1)
        return send_webhook(args.webhook_url, content=args.content, username=args.username)

    if op == "get_guild_info":
        if not args.guild_id:
            log("ERROR: --guild-id is required for get_guild_info")
            raise SystemExit(1)
        return get_guild_info(args.guild_id)

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
