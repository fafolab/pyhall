"""
pyhall/common.py — shared utilities for PyHall workers and router.

No lab-specific paths. No internal IP addresses. All server URLs
are configurable via environment variables or constructor parameters.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def now_utc() -> str:
    """Return current time as ISO 8601 UTC with Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def now_local_display(tz_name: str = "UTC") -> str:
    """
    Return a human-readable display timestamp in the given timezone.

    Falls back to UTC if the timezone is unavailable.

    Args:
        tz_name: IANA timezone name, e.g. "America/Chicago", "Europe/London".
    """
    try:
        from zoneinfo import ZoneInfo
        dt = datetime.now(ZoneInfo(tz_name))
        return dt.strftime("%Y-%m-%d %H:%M %Z")
    except Exception:
        return now_utc()


# ---------------------------------------------------------------------------
# Worker response envelopes
# ---------------------------------------------------------------------------

def ok(result: Any, *, source: str = "", metadata: dict | None = None) -> dict:
    """Standard success response envelope."""
    return {
        "status": "ok",
        "result": result,
        "source": source,
        "timestamp": now_utc(),
        "metadata": metadata or {},
    }


def err(message: str, *, code: str = "error", metadata: dict | None = None) -> dict:
    """Standard error response envelope."""
    return {
        "status": "error",
        "error": message,
        "code": code,
        "timestamp": now_utc(),
        "metadata": metadata or {},
    }


def partial(result: Any, *, message: str = "", source: str = "") -> dict:
    """
    Partial success — some backends failed but result is still usable.
    Use when a worker has multiple backends and some are unavailable.
    """
    return {
        "status": "partial",
        "result": result,
        "message": message,
        "source": source,
        "timestamp": now_utc(),
    }


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------

def sha256(data: str | bytes) -> str:
    """Return the hex-encoded SHA-256 digest of the input."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Correlation ID helpers
# ---------------------------------------------------------------------------

def new_correlation_id() -> str:
    """Generate a fresh UUID v4 correlation ID."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Configurable HTTP helper — no hardcoded server addresses
# ---------------------------------------------------------------------------

def post_json(
    url: str,
    payload: dict,
    *,
    timeout: int = 10,
    auth: tuple | None = None,
) -> dict:
    """
    POST JSON to url and return parsed response.

    Args:
        url:     Full URL including scheme and path.
        payload: Dict to send as JSON body.
        timeout: Request timeout in seconds.
        auth:    Optional (username, password) tuple for Basic auth.

    Raises:
        requests.HTTPError on non-2xx responses.
        requests.RequestException on network failure.
    """
    import requests  # lazy import — not all users need HTTP

    resp = requests.post(url, json=payload, auth=auth, timeout=timeout)
    resp.raise_for_status()
    return resp.json()
