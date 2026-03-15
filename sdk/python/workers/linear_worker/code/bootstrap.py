#!/usr/bin/env python3
"""
bootstrap.py — Linear Full Stack Worker entry point

Thin shim that delegates to worker_logic.run().
Run this file directly or import worker_logic for programmatic use.

Usage:
    python3 bootstrap.py list_teams
    python3 bootstrap.py list_issues --limit 20
    python3 bootstrap.py create_issue --title "Fix login bug" --team-id TEAM_ID --priority 2
    python3 bootstrap.py get_issue --issue-id ISSUE_ID
    python3 bootstrap.py close_issue --issue-id ISSUE_ID

Environment variables:
    LINEAR_API_KEY            — required. Personal API key from linear.app/settings/api
    LINEAR_DEFAULT_TEAM_ID    — optional. Default team for list_issues, list_cycles, etc.
    PYHALL_ENV                — dev|stage|prod (default: dev)
    WCP_ATTEST_HMAC_KEY       — required in prod for package attestation
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure code/ is on the path when invoked directly
_CODE_DIR = Path(__file__).resolve().parent
if str(_CODE_DIR) not in sys.path:
    sys.path.insert(0, str(_CODE_DIR))

from worker_logic import run  # noqa: E402

if __name__ == "__main__":
    run()
