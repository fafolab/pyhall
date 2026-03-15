#!/usr/bin/env python3
"""
bootstrap.py — Datadog Monitoring Worker (WCP v0.3.0) entry point shim

This file is the canonical CLI entry point. It delegates all logic to
worker_logic.py so the worker package stays self-contained and testable.

Usage:
    python3 bootstrap.py <op> [options]
    python3 bootstrap.py --help

Environment variables required:
    DATADOG_API_KEY      — Datadog API key (DD-API-KEY header)
    DATADOG_APP_KEY      — Datadog Application key (DD-APPLICATION-KEY header)

Optional:
    DATADOG_SITE         — Datadog site host override (default: datadoghq.com)
                           Use e.g. 'datadoghq.eu' for EU region
    PYHALL_ENV           — dev (default) | stage | prod
    WCP_ATTEST_HMAC_KEY  — Required in prod for package attestation

Examples:
    python3 bootstrap.py list_monitors
    python3 bootstrap.py list_monitors --tags env:prod --limit 50
    python3 bootstrap.py get_monitor --monitor-id 12345
    python3 bootstrap.py create_monitor --name 'CPU Alert' --type 'metric alert' --query 'avg:system.cpu.user{*} > 90'
    python3 bootstrap.py mute_monitor --monitor-id 12345
    python3 bootstrap.py mute_monitor --monitor-id 12345 --end-ts 1799999999
    python3 bootstrap.py list_dashboards
    python3 bootstrap.py get_dashboard --dashboard-id abc-123-xyz
    python3 bootstrap.py list_incidents --limit 10
    python3 bootstrap.py get_incident --incident-id b35b3b99-1234-5678-abcd-ef0123456789
    python3 bootstrap.py submit_metric --metric pyhall.test.value --value 42.0
    python3 bootstrap.py submit_metric --metric myapp.errors --value 5 --metric-type count --tags env:prod service:api
    python3 bootstrap.py submit_worker_metrics --worker-species wrk.pyhall.github --op list_repos --allowed --attested --evidence-count 17
    python3 bootstrap.py list_events --start-ts 1700000000 --end-ts 1700003600
    python3 bootstrap.py list_events --start-ts 1700000000 --end-ts 1700003600 --tags env:prod
    python3 bootstrap.py create_event --title 'Deploy complete' --text 'v0.3.0 shipped to prod' --alert-type success
    python3 bootstrap.py query_metrics --query 'avg:system.cpu.user{*}' --start-ts 1700000000 --end-ts 1700003600
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the worker package root and SDK are importable regardless of CWD
_THIS_DIR    = Path(__file__).resolve().parent
_PACKAGE_ROOT = _THIS_DIR.parent
_SDK_ROOT    = _PACKAGE_ROOT.parent.parent  # sdk/python/

if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

# Delegate all logic to worker_logic
from worker_logic import run  # noqa: E402

if __name__ == "__main__":
    run()
