#!/usr/bin/env python3
"""
bootstrap.py — Airtable Database Worker entry point (WCP v0.3.0)

Thin shim that delegates to worker_logic.run().

Usage (from the airtable_worker/ package root):
    python3 code/bootstrap.py <op> [args...]

Or invoke directly:
    python3 bootstrap.py <op> [args...]

Prerequisite:
    export AIRTABLE_PAT=<your_personal_access_token>
    pip install requests>=2.28.0 pyhall-wcp>=0.2.2

PAT setup:
    1. Go to https://airtable.com/create/tokens
    2. Create a token with scopes:
         data.records:read, data.records:write,
         schema.bases:read, schema.bases:write
    3. Add the bases or workspaces you want to access
    4. export AIRTABLE_PAT=<token>

Examples:
    python3 bootstrap.py list_bases
    python3 bootstrap.py list_tables --base-id appXXXXXXXXXXXXXX
    python3 bootstrap.py list_fields --base-id appXXX --table-id tblXXX
    python3 bootstrap.py list_records --base-id appXXX --table-id tblXXX --max-records 50
    python3 bootstrap.py get_record --base-id appXXX --table-id tblXXX --record-id recXXX
    python3 bootstrap.py create_record --base-id appXXX --table-id tblXXX \\
        --fields '{"Name":"Alice","Status":"Active"}'
    python3 bootstrap.py update_record --base-id appXXX --table-id tblXXX \\
        --record-id recXXX --fields '{"Status":"Done"}'
    python3 bootstrap.py delete_record --base-id appXXX --table-id tblXXX --record-id recXXX
    python3 bootstrap.py search_records --base-id appXXX --table-id tblXXX \\
        --field-name Status --value Active
    python3 bootstrap.py create_field --base-id appXXX --table-id tblXXX \\
        --field-name Priority --field-type singleSelect \\
        --field-options '{"choices":[{"name":"High"},{"name":"Medium"},{"name":"Low"}]}'
    python3 bootstrap.py bulk_create_records --base-id appXXX --table-id tblXXX \\
        --records '[{"Name":"Row A"},{"Name":"Row B"}]'
    python3 bootstrap.py bulk_update_records --base-id appXXX --table-id tblXXX \\
        --records '[{"id":"recXXX","fields":{"Status":"Done"}}]'
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
