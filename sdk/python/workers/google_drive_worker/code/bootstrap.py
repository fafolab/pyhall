#!/usr/bin/env python3
"""
bootstrap.py — Google Drive Worker (WCP v0.3.0)

Entry point shim. All logic lives in worker_logic.py.

Usage:
    python3 bootstrap.py setup
    python3 bootstrap.py list_files [--folder-id ID] [--limit N] [--mime-type TYPE]
    python3 bootstrap.py get_file --file-id ID
    python3 bootstrap.py search_files --query "name contains 'report'"
    python3 bootstrap.py upload_file --local-path /path/to/file.pdf [--parent-folder-id ID]
    python3 bootstrap.py download_file --file-id ID [--local-path /dest/dir/]
    python3 bootstrap.py create_folder --name "Folder Name" [--parent-folder-id ID]
    python3 bootstrap.py move_file --file-id ID --new-parent-id ID
    python3 bootstrap.py share_file --file-id ID --email user@example.com [--role writer]
    python3 bootstrap.py delete_file --file-id ID
    python3 bootstrap.py get_file_metadata --file-id ID

Environment variables:
    GOOGLE_CREDENTIALS_JSON   — Path to OAuth2 credentials JSON file (required for auth)
    PYHALL_DRIVE_TOKEN_PATH   — Override default token path (~/.local/share/pyhall/google_drive_token.json)
    PYHALL_ENV                — dev (default) | stage | prod
    WCP_ATTEST_HMAC_KEY       — Required in prod for package attestation
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the code directory is on the path so worker_logic is importable
_CODE_DIR = Path(__file__).resolve().parent
if str(_CODE_DIR) not in sys.path:
    sys.path.insert(0, str(_CODE_DIR))

from worker_logic import run  # noqa: E402

if __name__ == "__main__":
    run()
