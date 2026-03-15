#!/usr/bin/env python3
"""
bootstrap.py — Batch for OpenAI Worker (WCP v0.3.0)

Thin entry-point that delegates to worker_logic.run().

Usage:
    python3 bootstrap.py <op> [args...]

    python3 bootstrap.py validate_requests --input-file requests.jsonl
    python3 bootstrap.py upload_file --input-file requests.jsonl
    python3 bootstrap.py create_batch --file-id file-abc123
    python3 bootstrap.py get_batch_status --batch-id batch-xyz
    python3 bootstrap.py list_batches --limit 10
    python3 bootstrap.py get_batch_results --batch-id batch-xyz
    python3 bootstrap.py cancel_batch --batch-id batch-xyz
    python3 bootstrap.py get_file_content --file-id file-abc123

Environment variables:
    OPENAI_API_KEY        — required for all API operations
    PYHALL_ENV            — dev (default) | stage | prod
    WCP_ATTEST_HMAC_KEY   — required for prod attestation
    PYHALL_BATCH_DB_PATH  — override default SQLite DB path
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure worker_logic is importable from this directory
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from worker_logic import run

if __name__ == "__main__":
    run()
