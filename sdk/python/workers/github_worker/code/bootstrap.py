#!/usr/bin/env python3
"""
bootstrap.py — GitHub Full Stack Worker (WCP v0.3.0)

Entry point shim. Delegates to worker_logic.run().

Usage:
    export GITHUB_TOKEN=ghp_yourtoken
    python3 bootstrap.py list_repos
    python3 bootstrap.py list_repos --owner pyhall
    python3 bootstrap.py get_repo --owner pyhall --repo pyhall
    python3 bootstrap.py list_issues --owner pyhall --repo pyhall --state open
    python3 bootstrap.py create_issue --owner pyhall --repo pyhall --title "Bug report" --body "Details"
    python3 bootstrap.py close_issue --owner pyhall --repo pyhall --number 42
    python3 bootstrap.py list_prs --owner pyhall --repo pyhall
    python3 bootstrap.py get_file_content --owner pyhall --repo pyhall --path README.md

Environment variables:
    GITHUB_TOKEN        GitHub PAT with repo scope (required)
    PYHALL_ENV          dev | stage | prod (default: dev)
    WCP_ATTEST_HMAC_KEY HMAC signing key (required in prod for hard attestation)

Auth setup:
    1. Go to github.com/settings/tokens/new
    2. Select 'repo' scope (and 'read:org' if listing org repos)
    3. Generate and copy the token
    4. export GITHUB_TOKEN=ghp_yourtoken
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure worker_logic is importable from this file's directory
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from worker_logic import run

if __name__ == "__main__":
    run()
