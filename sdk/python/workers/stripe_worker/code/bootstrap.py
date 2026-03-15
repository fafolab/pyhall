#!/usr/bin/env python3
"""
bootstrap.py — Stripe Full Stack Worker entry point

Delegates to worker_logic.run(). This file is the canonical CLI entry point.

Usage:
    python3 bootstrap.py <op> [args...]
    python3 bootstrap.py --help

Auth:
    export STRIPE_SECRET_KEY=sk_test_...
    export PYHALL_ENV=dev          # dev (default) | stage | prod
    export WCP_ATTEST_HMAC_KEY=... # required only in prod for hard attestation

Examples:
    python3 bootstrap.py list_customers
    python3 bootstrap.py create_customer --email user@example.com
    python3 bootstrap.py create_payment_intent --amount-cents 1999
    python3 bootstrap.py list_products
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure this package's parent directory is on sys.path so worker_logic
# can import pyhall if it is installed as a local package.
_HERE = Path(__file__).resolve().parent
_WORKER_ROOT = _HERE.parent
if str(_WORKER_ROOT.parent.parent) not in sys.path:
    sys.path.insert(0, str(_WORKER_ROOT.parent.parent))

from worker_logic import run  # noqa: E402 (must come after path adjustment)

if __name__ == "__main__":
    run()
