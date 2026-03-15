#!/usr/bin/env python3
"""
bootstrap.py — Jira Issues Worker entry point

Thin shim that delegates to worker_logic.run().
Run this file directly or import worker_logic for programmatic use.

Usage:
    python3 bootstrap.py list_projects
    python3 bootstrap.py list_issues --project-key PROJ
    python3 bootstrap.py list_issues --project-key PROJ --status 'In Progress' --limit 20
    python3 bootstrap.py get_issue --issue-key PROJ-123
    python3 bootstrap.py create_issue --project-key PROJ --summary 'Fix login bug'
    python3 bootstrap.py create_issue --project-key PROJ --summary 'Story' --issue-type Story --priority High
    python3 bootstrap.py update_issue --issue-key PROJ-123 --priority Medium
    python3 bootstrap.py close_issue --issue-key PROJ-123
    python3 bootstrap.py assign_issue --issue-key PROJ-123 --account-id ACCT_ID
    python3 bootstrap.py add_comment --issue-key PROJ-123 --body 'LGTM'
    python3 bootstrap.py list_comments --issue-key PROJ-123
    python3 bootstrap.py list_transitions --issue-key PROJ-123
    python3 bootstrap.py transition_issue --issue-key PROJ-123 --transition-id 31
    python3 bootstrap.py add_label --issue-key PROJ-123 --label bug
    python3 bootstrap.py list_boards
    python3 bootstrap.py list_boards --project-key PROJ
    python3 bootstrap.py get_project --project-key PROJ

Environment variables:
    JIRA_URL            — required. Jira Cloud base URL e.g. https://yourorg.atlassian.net
    JIRA_EMAIL          — required. Atlassian account email
    JIRA_API_TOKEN      — required. API token from https://id.atlassian.com/manage-profile/security/api-tokens
    PYHALL_ENV          — dev|stage|prod (default: dev)
    WCP_ATTEST_HMAC_KEY — required in prod for package attestation
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
