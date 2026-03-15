#!/usr/bin/env python3
"""
bootstrap.py — PagerDuty Worker (WCP v0.3.0) entry point shim

This file is the canonical CLI entry point. It delegates all logic to
worker_logic.py so the worker package stays self-contained and testable.

Usage:
    python3 bootstrap.py <op> [options]
    python3 bootstrap.py --help

Environment variables required:
    PAGERDUTY_API_KEY      — PagerDuty REST API v2 key (required for most ops)
    PAGERDUTY_ROUTING_KEY  — Service integration key (required for trigger_alert)
    PAGERDUTY_FROM_EMAIL   — Email for write operations (required for state changes)

Optional:
    PYHALL_ENV             — dev (default) | stage | prod
    WCP_ATTEST_HMAC_KEY    — Required in prod for package attestation

Examples:
    python3 bootstrap.py list_incidents
    python3 bootstrap.py list_incidents --status triggered --limit 10
    python3 bootstrap.py get_incident --incident-id P123ABC
    python3 bootstrap.py create_incident --title "API down" --service-id SVCXYZ
    python3 bootstrap.py acknowledge_incident --incident-id P123ABC
    python3 bootstrap.py resolve_incident --incident-id P123ABC
    python3 bootstrap.py add_note --incident-id P123ABC --content "Mitigating now"
    python3 bootstrap.py list_services
    python3 bootstrap.py get_service --service-id SVCXYZ
    python3 bootstrap.py list_users
    python3 bootstrap.py get_on_call
    python3 bootstrap.py get_on_call --escalation-policy-id EPID123
    python3 bootstrap.py list_escalation_policies
    python3 bootstrap.py trigger_alert --summary "DB unreachable" --severity critical
    python3 bootstrap.py trigger_alert --summary "High CPU" --severity warning --source "host-01"
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the worker package root and SDK are importable regardless of CWD
_THIS_DIR = Path(__file__).resolve().parent
_PACKAGE_ROOT = _THIS_DIR.parent
_SDK_ROOT = _PACKAGE_ROOT.parent.parent  # sdk/python/

if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

# Delegate all logic to worker_logic
from worker_logic import run  # noqa: E402

if __name__ == "__main__":
    run()
