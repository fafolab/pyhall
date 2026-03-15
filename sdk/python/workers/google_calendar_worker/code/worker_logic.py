#!/usr/bin/env python3
"""
worker_logic.py — Google Calendar Worker (WCP v0.3.0)

Full WCP-compliant worker for the Google Calendar API.
Supports read, write, and manage capabilities against any calendar in the
authenticated user's account.  All timestamps stored as UTC ISO 8601;
human-facing log output uses Central Time (America/Chicago).

OAuth pattern mirrors google_tasks_worker: token auto-refreshed, stored at
~/.local/share/pyhall/google_calendar_token.json.  Credentials JSON path
read from env var GOOGLE_CREDENTIALS_JSON (default:
~/.config/pyhall/google_credentials.json).

Setup (one-time):
    1. console.cloud.google.com → create / select project
    2. Enable Google Calendar API
    3. Create OAuth2 credentials (Desktop application) → download JSON
    4. export GOOGLE_CREDENTIALS_JSON=/path/to/credentials.json
    5. python3 bootstrap.py setup
       (opens browser for auth, saves token)
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

WORKER_ID          = "org.pyhall.google-calendar.instance-1"
WORKER_SPECIES_ID  = "wrk.pyhall.google-calendar"
WORKER_NAME        = "Google Calendar Worker (WCP v0.3.0)"
WORKER_VERSION     = "0.3.0"

CAPABILITIES = [
    "cap.pyhall.google_calendar.read",
    "cap.pyhall.google_calendar.write",
    "cap.pyhall.google_calendar.manage",
]

ALLOWED_OPS = {
    "list_calendars",
    "list_events",
    "get_event",
    "create_event",
    "update_event",
    "delete_event",
    "quick_add_event",
    "list_upcoming",
    "find_free_time",
    "setup",
}

ALLOWED_ENVS = {"dev", "stage", "prod"}

REQUIRED_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.integrity.package_attested",
    "ctrl.authz.fail_closed_policy_gate",
    "ctrl.trace.correlation_id_required",
]

# Map ops → minimum required capability
_OP_CAPABILITY: Dict[str, str] = {
    "list_calendars":  "cap.pyhall.google_calendar.read",
    "list_events":     "cap.pyhall.google_calendar.read",
    "get_event":       "cap.pyhall.google_calendar.read",
    "list_upcoming":   "cap.pyhall.google_calendar.read",
    "find_free_time":  "cap.pyhall.google_calendar.read",
    "create_event":    "cap.pyhall.google_calendar.write",
    "update_event":    "cap.pyhall.google_calendar.write",
    "delete_event":    "cap.pyhall.google_calendar.write",
    "quick_add_event": "cap.pyhall.google_calendar.write",
    "setup":           "cap.pyhall.google_calendar.manage",
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
class CalendarEntry:
    """Minimal representation of a Google Calendar list entry."""
    calendar_id: str
    summary: str
    primary: bool
    access_role: str


@dataclass
class CalendarEvent:
    """Minimal representation of a Google Calendar event."""
    event_id: str
    summary: str
    start: str          # RFC3339 dateTime or date string
    end: str
    calendar_id: str
    description: Optional[str] = None
    location: Optional[str] = None
    status: Optional[str] = None
    html_link: Optional[str] = None


@dataclass
class FreeWindow:
    """A contiguous free time window."""
    start_utc: str
    end_utc: str
    duration_minutes: int


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
    """Print a message prefixed with Central Time timestamp."""
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


def _to_rfc3339(dt_str: str, all_day: bool = False) -> str:
    """
    Normalise a datetime string to RFC 3339 / ISO 8601.

    - If all_day=True, return YYYY-MM-DD (date only).
    - If the string already has a timezone offset, return as-is (strip microseconds).
    - If naive (no offset), assume UTC and append Z.
    """
    if all_day:
        # Accept 'YYYY-MM-DD' or full datetime — extract date portion
        return dt_str[:10]

    # Strip microseconds for cleanliness
    if "." in dt_str:
        base, rest = dt_str.split(".", 1)
        # keep timezone suffix if present
        for suffix in ["+", "-", "Z"]:
            if suffix in rest:
                tz_part = rest[rest.index(suffix):]
                dt_str = base + tz_part
                break
        else:
            dt_str = base  # naive, no tz

    if dt_str.endswith("Z") or "+" in dt_str[10:] or (len(dt_str) > 19 and "-" in dt_str[19:]):
        return dt_str  # already has tz
    return dt_str + "Z"  # assume UTC


def _parse_dt(dt_str: str) -> datetime:
    """Parse an RFC3339 datetime string to a timezone-aware datetime (UTC)."""
    dt_str = dt_str.replace("Z", "+00:00")
    return datetime.fromisoformat(dt_str).astimezone(timezone.utc)


def _minutes_between(start: str, end: str) -> int:
    """Return integer minutes between two RFC3339 strings."""
    return int((_parse_dt(end) - _parse_dt(start)).total_seconds() / 60)


# ============================================================================
# SECTION 4: PACKAGE ATTESTATION + SIGNATURE VERIFICATION
# ============================================================================
# required for PyHall APP.
# not strictly required in-file for API-only usage.
# if this worker file changes, a new attestation is required.


def _run_startup_attestation(package_root: Path, manifest_path: Path) -> Dict[str, Any]:
    """
    Run full package attestation via pyhall PackageAttestationVerifier.

    Dev mode (PYHALL_ENV != 'prod' or WCP_ATTEST_HMAC_KEY not set):
      logs a WARNING and continues.
    Prod mode: any failure raises SystemExit(2).

    Returns attest_meta dict (may be empty/dev-skip dict).
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
#   code/worker_logic.py → parent = code/ → parent = google_calendar_worker/
_THIS_FILE     = Path(__file__).resolve()
_PACKAGE_ROOT  = _THIS_FILE.parent.parent   # .../google_calendar_worker/
_MANIFEST_PATH = _PACKAGE_ROOT / "manifest.json"


# ============================================================================
# SECTION 5: POLICY GATE (FAIL-CLOSED)
# ============================================================================

class PolicyGate:
    """
    Local fail-closed WCP policy gate.

    Default = deny.  Every check must pass to allow.
    Capability is resolved per-operation using _OP_CAPABILITY map.
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

        # Verify the capability supplied is sufficient for this op
        required_cap = _OP_CAPABILITY.get(op, CAPABILITIES[0])
        if ctx.capability_id not in CAPABILITIES or CAPABILITIES.index(ctx.capability_id) < CAPABILITIES.index(required_cap):
            return WCPDecision(
                False, "INSUFFICIENT_CAPABILITY",
                f"op={op!r} requires {required_cap!r}, got {ctx.capability_id!r}",
                self.policy_version, None, None,
            )

        rule_id = f"rr_google_calendar_{op}_allow_v1"
        return WCPDecision(True, None, None, self.policy_version, rule_id, WORKER_SPECIES_ID)


# ============================================================================
# SECTION 6: OBSERVABILITY — HASH-CHAINED EVIDENCE LOG
# ============================================================================

_EVIDENCE_LOG_PATH = Path(
    os.path.expanduser("~/.local/share/pyhall/evidence/")
) / "wrk_pyhall_google_calendar_chain.log"


class AppendOnlyEvidenceLog:
    """
    Hash-chained append-only local evidence log.

    Each entry: { prev_hash, entry_hash, receipt }
    entry_hash = SHA-256(prev_hash_bytes + payload_bytes)
    Writes are best-effort — will not crash if the directory is missing.
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
    """Build a WCP execution receipt dict."""
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


# Module-level singletons — instantiated once at import time
_policy_gate  = PolicyGate()
_evidence_log = AppendOnlyEvidenceLog(_EVIDENCE_LOG_PATH)
_attest_meta: Dict[str, Any] = {}   # populated by run() at startup


def _make_ctx(op: str) -> WCPContext:
    """Build a WCPContext for the given operation, selecting the correct capability."""
    cap = _OP_CAPABILITY.get(op, CAPABILITIES[0])
    return WCPContext(
        correlation_id=str(uuid.uuid4()),
        env=os.environ.get("PYHALL_ENV", "dev"),
        capability_id=cap,
        data_label="INTERNAL",
        tenant_risk="low",
        qos_class="P2",
        requested_at_utc=utc_now_iso(),
    )


def _gate_and_emit(op: str) -> Tuple[WCPContext, WCPDecision]:
    """Run the policy gate; emit deny receipt and exit if blocked."""
    ctx = _make_ctx(op)
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
# SECTION 7: DOMAIN LOGIC — GOOGLE CALENDAR
# ============================================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCOPES = ["https://www.googleapis.com/auth/calendar"]

_TOKEN_PATH_DEFAULT   = Path("~/.local/share/pyhall/google_calendar_token.json").expanduser()
_CREDS_PATH_DEFAULT   = Path("~/.config/pyhall/google_credentials.json").expanduser()
_DEFAULT_CALENDAR_ID  = os.environ.get("GOOGLE_CALENDAR_DEFAULT", "primary")


def _token_path() -> Path:
    """Return the token file path (respects config.schema.json token_path if set via env)."""
    env_token = os.environ.get("GOOGLE_CALENDAR_TOKEN_PATH", "")
    if env_token:
        return Path(env_token).expanduser()
    return _TOKEN_PATH_DEFAULT


def _creds_path() -> Path:
    """Return the credentials JSON path from GOOGLE_CREDENTIALS_JSON env var or default."""
    env_creds = os.environ.get("GOOGLE_CREDENTIALS_JSON", "")
    if env_creds:
        return Path(env_creds).expanduser()
    return _CREDS_PATH_DEFAULT


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------

def _check_deps() -> bool:
    """Return True if Google API client libraries are available."""
    try:
        from google.oauth2.credentials import Credentials      # noqa: F401
        from google_auth_oauthlib.flow import InstalledAppFlow  # noqa: F401
        from googleapiclient.discovery import build             # noqa: F401
        return True
    except ImportError:
        return False


def _require_deps() -> None:
    """Exit with instructions if Google API libs are missing."""
    if not _check_deps():
        log("ERROR: Google API client libraries not installed.")
        log("  pip install google-api-python-client google-auth-oauthlib google-auth-httplib2")
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# OAuth / service factory
# ---------------------------------------------------------------------------

def get_google_service():
    """
    Authenticate and return a Google Calendar API service object.

    Token file: _token_path()       (auto-refreshed if expired)
    Creds file: _creds_path()       (sourced from GOOGLE_CREDENTIALS_JSON env var)

    On first run (no token), opens a local browser OAuth flow and saves the token.
    Token file is stored chmod 600 (owner-read only).
    """
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    token_file = _token_path()
    creds_file = _creds_path()

    creds = None
    if token_file.exists():
        creds = Credentials.from_authorized_user_file(str(token_file), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                log("Token refreshed automatically.")
            except Exception as exc:
                log(f"Token refresh failed: {exc}")
                log("Deleting stale token. Run 'setup' again to re-authenticate.")
                token_file.unlink(missing_ok=True)
                raise SystemExit(1)
        else:
            if not creds_file.exists():
                log(f"ERROR: Credentials file not found: {creds_file}")
                log("  Download from Google Cloud Console → APIs & Services → Credentials")
                log(f"  Then set: export GOOGLE_CREDENTIALS_JSON={creds_file}")
                raise SystemExit(1)
            flow = InstalledAppFlow.from_client_secrets_file(str(creds_file), SCOPES)
            creds = flow.run_local_server(port=0)

        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(creds.to_json(), encoding="utf-8")
        try:
            token_file.chmod(0o600)
        except Exception:
            pass  # Windows does not support chmod; best-effort
        log(f"Token saved: {token_file}")

    return build("calendar", "v3", credentials=creds)


# ---------------------------------------------------------------------------
# Tool functions
# ---------------------------------------------------------------------------

def list_calendars() -> List[Dict[str, Any]]:
    """
    List all calendars in the authenticated user's account.

    Returns a list of dicts with keys: id, summary, primary, accessRole.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("list_calendars")

    service = get_google_service()
    result = service.calendarList().list().execute()
    items = result.get("items", [])

    calendars = [
        {
            "id":          cal.get("id", ""),
            "summary":     cal.get("summary", ""),
            "primary":     cal.get("primary", False),
            "accessRole":  cal.get("accessRole", ""),
        }
        for cal in items
    ]

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_calendars: returned {len(calendars)} calendars",
        "list_calendars", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"list_calendars: {len(calendars)} calendars found")
    return calendars


def list_events(
    calendar_id: str = "primary",
    max_results: int = 50,
    time_min: Optional[str] = None,
    time_max: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    List events on a calendar.

    calendar_id: Google Calendar ID or 'primary' (default).
    max_results:  Max events to return (1-2500, default 50).
    time_min:     Lower bound (RFC3339) — events starting at or after.
    time_max:     Upper bound (RFC3339) — events starting before.

    Returns list of event dicts with keys: id, summary, start, end,
    description, location, status, htmlLink.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("list_events")

    kwargs: Dict[str, Any] = {
        "calendarId":   calendar_id,
        "maxResults":   max_results,
        "singleEvents": True,
        "orderBy":      "startTime",
    }
    if time_min:
        kwargs["timeMin"] = _to_rfc3339(time_min)
    if time_max:
        kwargs["timeMax"] = _to_rfc3339(time_max)

    service = get_google_service()
    result = service.events().list(**kwargs).execute()
    items = result.get("items", [])

    events = [_format_event(e, calendar_id) for e in items]

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_events: cal={calendar_id!r} returned {len(events)} events",
        "list_events", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"list_events: {len(events)} events on {calendar_id!r}")
    return events


def get_event(event_id: str, calendar_id: str = "primary") -> Dict[str, Any]:
    """
    Retrieve a single event by ID.

    Returns full event dict as returned by Google Calendar API.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("get_event")

    service = get_google_service()
    event = service.events().get(calendarId=calendar_id, eventId=event_id).execute()

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"get_event: event_id={event_id!r} cal={calendar_id!r}",
        "get_event", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"get_event: {event_id!r} — {event.get('summary', '(no title)')}")
    return event


def create_event(
    summary: str,
    start_dt: str,
    end_dt: str,
    calendar_id: str = "primary",
    description: Optional[str] = None,
    location: Optional[str] = None,
    attendees: Optional[List[str]] = None,
    all_day: bool = False,
) -> Dict[str, Any]:
    """
    Create a new calendar event.

    summary:     Event title.
    start_dt:    ISO datetime string for start (or YYYY-MM-DD if all_day=True).
    end_dt:      ISO datetime string for end   (or YYYY-MM-DD if all_day=True).
    calendar_id: Target calendar (default 'primary').
    description: Optional event description.
    location:    Optional location string.
    attendees:   Optional list of email address strings.
    all_day:     If True, creates a date-only (all-day) event.

    Returns the created event resource dict from Google.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("create_event")

    if all_day:
        start_block: Dict[str, Any] = {"date": _to_rfc3339(start_dt, all_day=True)}
        end_block:   Dict[str, Any] = {"date": _to_rfc3339(end_dt,   all_day=True)}
    else:
        start_block = {"dateTime": _to_rfc3339(start_dt), "timeZone": "UTC"}
        end_block   = {"dateTime": _to_rfc3339(end_dt),   "timeZone": "UTC"}

    body: Dict[str, Any] = {
        "summary": summary,
        "start":   start_block,
        "end":     end_block,
    }
    if description:
        body["description"] = description
    if location:
        body["location"] = location
    if attendees:
        body["attendees"] = [{"email": addr} for addr in attendees]

    service = get_google_service()
    created = service.events().insert(calendarId=calendar_id, body=body).execute()

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"create_event: summary={summary!r} cal={calendar_id!r} id={created.get('id')}",
        "create_event", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"create_event: created {created.get('id')!r} — {summary!r}")
    return created


def update_event(
    event_id: str,
    calendar_id: str = "primary",
    summary: Optional[str] = None,
    start_dt: Optional[str] = None,
    end_dt: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Patch (partial update) an existing calendar event.

    Only the fields provided (non-None) are sent to the API.
    Returns the updated event resource dict.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("update_event")

    patch_body: Dict[str, Any] = {}
    if summary is not None:
        patch_body["summary"] = summary
    if description is not None:
        patch_body["description"] = description
    if start_dt is not None:
        patch_body["start"] = {"dateTime": _to_rfc3339(start_dt), "timeZone": "UTC"}
    if end_dt is not None:
        patch_body["end"]   = {"dateTime": _to_rfc3339(end_dt),   "timeZone": "UTC"}

    if not patch_body:
        log(f"update_event: no fields to update for event_id={event_id!r}")
        receipt = build_evidence_receipt(
            ctx, decision, "noop",
            f"update_event: no fields supplied for event_id={event_id!r}",
            "update_event", _attest_meta,
        )
        _evidence_log.emit_evidence(receipt)
        # Return existing event unchanged
        service = get_google_service()
        return service.events().get(calendarId=calendar_id, eventId=event_id).execute()

    service = get_google_service()
    updated = service.events().patch(
        calendarId=calendar_id, eventId=event_id, body=patch_body
    ).execute()

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"update_event: event_id={event_id!r} cal={calendar_id!r} fields={list(patch_body.keys())}",
        "update_event", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"update_event: patched {event_id!r} fields={list(patch_body.keys())}")
    return updated


def delete_event(event_id: str, calendar_id: str = "primary") -> Dict[str, Any]:
    """
    Delete an event permanently.

    Returns a status dict: {"deleted": True, "event_id": ..., "calendar_id": ...}
    """
    _require_deps()
    ctx, decision = _gate_and_emit("delete_event")

    service = get_google_service()
    service.events().delete(calendarId=calendar_id, eventId=event_id).execute()

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"delete_event: event_id={event_id!r} cal={calendar_id!r}",
        "delete_event", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"delete_event: deleted {event_id!r} from {calendar_id!r}")
    return {"deleted": True, "event_id": event_id, "calendar_id": calendar_id}


def quick_add_event(text: str, calendar_id: str = "primary") -> Dict[str, Any]:
    """
    Create an event from a natural-language string using Google's quickAdd endpoint.

    Example text: "Dentist appointment tomorrow at 3pm for 1 hour"

    Returns the created event resource dict.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("quick_add_event")

    service = get_google_service()
    created = service.events().quickAdd(calendarId=calendar_id, text=text).execute()

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"quick_add_event: text={text!r} cal={calendar_id!r} id={created.get('id')}",
        "quick_add_event", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"quick_add_event: created {created.get('id')!r} via text={text!r}")
    return created


def list_upcoming(days: int = 7, calendar_id: str = "primary") -> List[Dict[str, Any]]:
    """
    Return events starting from now through the next `days` calendar days.

    Convenience wrapper around list_events with computed time bounds.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("list_upcoming")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    time_min = now.isoformat().replace("+00:00", "Z")
    time_max = (now + timedelta(days=days)).isoformat().replace("+00:00", "Z")

    service = get_google_service()
    result = service.events().list(
        calendarId=calendar_id,
        timeMin=time_min,
        timeMax=time_max,
        maxResults=250,
        singleEvents=True,
        orderBy="startTime",
    ).execute()
    items  = result.get("items", [])
    events = [_format_event(e, calendar_id) for e in items]

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"list_upcoming: days={days} cal={calendar_id!r} returned {len(events)} events",
        "list_upcoming", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"list_upcoming: {len(events)} events in next {days} day(s) on {calendar_id!r}")
    return events


def find_free_time(
    start_dt: str,
    end_dt: str,
    calendars: Optional[List[str]] = None,
    duration_minutes: int = 60,
) -> List[Dict[str, Any]]:
    """
    Find free time windows within a datetime range across one or more calendars.

    Uses the Google Calendar freebusy().query() endpoint to retrieve busy
    intervals, then computes the complement (free) windows that are at least
    duration_minutes long.

    start_dt:          RFC3339 start of search window.
    end_dt:            RFC3339 end of search window.
    calendars:         List of calendar IDs to check (default: ['primary']).
    duration_minutes:  Minimum free window length in minutes (default: 60).

    Returns a list of dicts: {start_utc, end_utc, duration_minutes}.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("find_free_time")

    if calendars is None:
        calendars = ["primary"]

    time_min = _to_rfc3339(start_dt)
    time_max = _to_rfc3339(end_dt)

    query_body: Dict[str, Any] = {
        "timeMin":  time_min,
        "timeMax":  time_max,
        "items":    [{"id": cal_id} for cal_id in calendars],
    }

    service = get_google_service()
    fb_result = service.freebusy().query(body=query_body).execute()

    # Merge busy intervals across all requested calendars
    all_busy: List[Tuple[datetime, datetime]] = []
    calendars_data = fb_result.get("calendars", {})
    for cal_id in calendars:
        busy_list = calendars_data.get(cal_id, {}).get("busy", [])
        for b in busy_list:
            all_busy.append((_parse_dt(b["start"]), _parse_dt(b["end"])))

    # Sort and merge overlapping busy intervals
    all_busy.sort(key=lambda x: x[0])
    merged_busy: List[Tuple[datetime, datetime]] = []
    for start_b, end_b in all_busy:
        if merged_busy and start_b <= merged_busy[-1][1]:
            merged_busy[-1] = (merged_busy[-1][0], max(merged_busy[-1][1], end_b))
        else:
            merged_busy.append((start_b, end_b))

    # Build free windows as the complement of busy within [time_min, time_max]
    window_start = _parse_dt(time_min)
    window_end   = _parse_dt(time_max)
    free_windows: List[Dict[str, Any]] = []

    cursor = window_start
    for busy_start, busy_end in merged_busy:
        if cursor < busy_start:
            free_mins = int((busy_start - cursor).total_seconds() / 60)
            if free_mins >= duration_minutes:
                free_windows.append({
                    "start_utc":        cursor.isoformat().replace("+00:00", "Z"),
                    "end_utc":          busy_start.isoformat().replace("+00:00", "Z"),
                    "duration_minutes": free_mins,
                })
        cursor = max(cursor, busy_end)

    # Check remaining time after last busy interval
    if cursor < window_end:
        free_mins = int((window_end - cursor).total_seconds() / 60)
        if free_mins >= duration_minutes:
            free_windows.append({
                "start_utc":        cursor.isoformat().replace("+00:00", "Z"),
                "end_utc":          window_end.isoformat().replace("+00:00", "Z"),
                "duration_minutes": free_mins,
            })

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        (
            f"find_free_time: {len(free_windows)} windows >= {duration_minutes}min "
            f"in [{time_min}, {time_max}] across {calendars}"
        ),
        "find_free_time", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)
    log(f"find_free_time: {len(free_windows)} free window(s) found (>= {duration_minutes} min)")
    return free_windows


def setup_oauth() -> None:
    """
    Run the first-time OAuth2 browser flow and save the token.

    Policy-gated.  On success, verifies connectivity by listing calendars.
    """
    _require_deps()
    ctx, decision = _gate_and_emit("setup")

    log("Running OAuth2 setup for Google Calendar...")
    log(f"  Credentials file: {_creds_path()}")
    log(f"  Token will be saved to: {_token_path()}")

    service = get_google_service()   # triggers flow if no valid token

    # Verify by listing calendars
    result = service.calendarList().list().execute()
    cals   = result.get("items", [])
    primary = next((c for c in cals if c.get("primary")), None)
    log(f"Authenticated successfully. {len(cals)} calendar(s) accessible.")
    if primary:
        log(f"  Primary calendar: {primary.get('summary', 'unknown')}")

    receipt = build_evidence_receipt(
        ctx, decision, "ok",
        f"setup: OAuth complete, {len(cals)} calendars accessible",
        "setup", _attest_meta,
    )
    _evidence_log.emit_evidence(receipt)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _format_event(event: Dict[str, Any], calendar_id: str) -> Dict[str, Any]:
    """Normalize a Google Calendar event resource to a consistent output dict."""
    start_raw = event.get("start", {})
    end_raw   = event.get("end",   {})
    return {
        "id":          event.get("id", ""),
        "summary":     event.get("summary", "(no title)"),
        "start":       start_raw.get("dateTime") or start_raw.get("date", ""),
        "end":         end_raw.get("dateTime")   or end_raw.get("date", ""),
        "calendar_id": calendar_id,
        "description": event.get("description", ""),
        "location":    event.get("location", ""),
        "status":      event.get("status", ""),
        "htmlLink":    event.get("htmlLink", ""),
    }


# ============================================================================
# SECTION 8: ENTRY POINT
# ============================================================================

def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=WORKER_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Operations:\n"
            "  setup                        Run first-time OAuth flow\n"
            "  list_calendars               List all calendars\n"
            "  list_events                  List events (use --calendar-id, --time-min, --time-max)\n"
            "  get_event                    Get a single event (requires --event-id)\n"
            "  create_event                 Create event (requires --summary --start --end)\n"
            "  update_event                 Patch event (requires --event-id; any of --summary --start --end --description)\n"
            "  delete_event                 Delete event (requires --event-id)\n"
            "  quick_add_event              Natural-language event creation (requires --text)\n"
            "  list_upcoming                Events in next N days (use --days)\n"
            "  find_free_time               Free slots (requires --start --end; use --duration)\n"
        ),
    )

    p.add_argument("op", choices=sorted(ALLOWED_OPS), help="Operation to perform")

    # Calendar targeting
    p.add_argument(
        "--calendar-id", default=_DEFAULT_CALENDAR_ID, dest="calendar_id",
        metavar="CAL_ID",
        help="Calendar ID (default: 'primary' or GOOGLE_CALENDAR_DEFAULT env var)",
    )
    p.add_argument(
        "--calendars", nargs="+", dest="calendars", metavar="CAL_ID",
        help="Multiple calendar IDs for find_free_time",
    )

    # Event identification
    p.add_argument("--event-id", dest="event_id", metavar="EVENT_ID", help="Event ID")

    # Event content
    p.add_argument("--summary",     help="Event title (create_event / update_event)")
    p.add_argument("--start",       metavar="DATETIME", help="Start datetime (ISO 8601)")
    p.add_argument("--end",         metavar="DATETIME", help="End datetime (ISO 8601)")
    p.add_argument("--description", help="Event description")
    p.add_argument("--location",    help="Event location")
    p.add_argument(
        "--attendees", nargs="+", metavar="EMAIL",
        help="Attendee email addresses for create_event",
    )
    p.add_argument(
        "--all-day", action="store_true", dest="all_day",
        help="Create as all-day event (use date strings for --start / --end)",
    )

    # Filters / options
    p.add_argument("--time-min", dest="time_min", metavar="DATETIME", help="Lower time bound (RFC3339)")
    p.add_argument("--time-max", dest="time_max", metavar="DATETIME", help="Upper time bound (RFC3339)")
    p.add_argument("--max-results", dest="max_results", type=int, default=50, help="Max events to return")
    p.add_argument("--days", type=int, default=7, help="Days ahead for list_upcoming (default: 7)")
    p.add_argument(
        "--duration", dest="duration_minutes", type=int, default=60,
        help="Minimum free-time window in minutes for find_free_time (default: 60)",
    )

    # Natural language (quick_add)
    p.add_argument("--text", help="Natural-language event text for quick_add_event")

    return p


def run() -> None:
    """WCP worker entry point — called from bootstrap.py and directly."""
    global _attest_meta
    _attest_meta = _run_startup_attestation(_PACKAGE_ROOT, _MANIFEST_PATH)

    parser = _build_arg_parser()
    args   = parser.parse_args()
    op     = args.op

    # ── Dispatch ────────────────────────────────────────────────────────────

    if op == "setup":
        setup_oauth()

    elif op == "list_calendars":
        _print_json(list_calendars())

    elif op == "list_events":
        _print_json(list_events(
            calendar_id=args.calendar_id,
            max_results=args.max_results,
            time_min=args.time_min,
            time_max=args.time_max,
        ))

    elif op == "get_event":
        if not args.event_id:
            parser.error("get_event requires --event-id")
        _print_json(get_event(args.event_id, calendar_id=args.calendar_id))

    elif op == "create_event":
        if not args.summary or not args.start or not args.end:
            parser.error("create_event requires --summary --start --end")
        _print_json(create_event(
            summary=args.summary,
            start_dt=args.start,
            end_dt=args.end,
            calendar_id=args.calendar_id,
            description=args.description,
            location=args.location,
            attendees=args.attendees,
            all_day=args.all_day,
        ))

    elif op == "update_event":
        if not args.event_id:
            parser.error("update_event requires --event-id")
        _print_json(update_event(
            event_id=args.event_id,
            calendar_id=args.calendar_id,
            summary=args.summary,
            start_dt=args.start,
            end_dt=args.end,
            description=args.description,
        ))

    elif op == "delete_event":
        if not args.event_id:
            parser.error("delete_event requires --event-id")
        _print_json(delete_event(args.event_id, calendar_id=args.calendar_id))

    elif op == "quick_add_event":
        if not args.text:
            parser.error("quick_add_event requires --text")
        _print_json(quick_add_event(args.text, calendar_id=args.calendar_id))

    elif op == "list_upcoming":
        _print_json(list_upcoming(days=args.days, calendar_id=args.calendar_id))

    elif op == "find_free_time":
        if not args.start or not args.end:
            parser.error("find_free_time requires --start and --end")
        _print_json(find_free_time(
            start_dt=args.start,
            end_dt=args.end,
            calendars=args.calendars,
            duration_minutes=args.duration_minutes,
        ))

    else:
        parser.error(f"Unhandled op: {op!r}")


if __name__ == "__main__":
    run()
