#!/usr/bin/env python3
"""
bootstrap.py — Notion Full Stack Worker entry point (WCP v0.3.0)

Thin shim that delegates to worker_logic.run().

Usage (from the notion_worker/ package root):
    python3 code/bootstrap.py <op> [args...]

Or invoke directly:
    python3 bootstrap.py <op> [args...]

Prerequisite:
    export NOTION_TOKEN=<your_integration_token>
    pip install notion-client>=2.2.0 pyhall-wcp>=0.2.2

Examples:
    python3 bootstrap.py search_pages --query 'Meeting Notes'
    python3 bootstrap.py list_databases
    python3 bootstrap.py get_page --page-id <uuid>
    python3 bootstrap.py create_page --parent-id <uuid> --title 'New Page'
    python3 bootstrap.py append_block --block-id <uuid> --type paragraph --text 'Hello, Notion!'
    python3 bootstrap.py query_database --database-id <uuid> --limit 25
    python3 bootstrap.py create_database_entry --database-id <uuid> \
        --properties '{"Name":{"title":[{"text":{"content":"My Row"}}]}}'
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure worker_logic is importable regardless of invocation path
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from worker_logic import run  # noqa: E402

if __name__ == "__main__":
    run()
