#!/usr/bin/env python3
"""
bootstrap.py — Batch for Claude Worker entry point

Delegates all execution to worker_logic.run().

Usage:
    python3 bootstrap.py <op> [options]

    python3 bootstrap.py validate_requests --requests '[...]'
    python3 bootstrap.py create_batch --requests-file my_requests.json
    python3 bootstrap.py get_batch_status --batch-id msgbatch_abc123
    python3 bootstrap.py get_batch_results --batch-id msgbatch_abc123
    python3 bootstrap.py list_batches --limit 10
    python3 bootstrap.py cancel_batch --batch-id msgbatch_abc123
    python3 bootstrap.py count_tokens_estimate --requests-file my_requests.json

Prerequisites:
    pip install anthropic>=0.50.0 pyhall-wcp>=0.2.2
    export ANTHROPIC_API_KEY=<your-api-key>
    export PYHALL_ENV=dev   # or stage / prod
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the code directory is on the path when run directly
_CODE_DIR = Path(__file__).resolve().parent
if str(_CODE_DIR) not in sys.path:
    sys.path.insert(0, str(_CODE_DIR))

from worker_logic import run

if __name__ == "__main__":
    run()
