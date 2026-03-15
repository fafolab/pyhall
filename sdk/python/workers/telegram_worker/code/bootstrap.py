#!/usr/bin/env python3
"""
bootstrap.py — Telegram Notifications Worker entry point

This is the canonical entrypoint for the telegram_worker package.
It delegates immediately to worker_logic.run() — all logic lives there.

Usage:
    python3 bootstrap.py <op> [options]
    python3 worker_logic.py <op> [options]   (same result)

Environment variables required:
    TELEGRAM_BOT_TOKEN          — Bot token from @BotFather (required)

Environment variables optional:
    TELEGRAM_DEFAULT_CHAT_ID    — Default chat ID or @username for notifications
    PYHALL_ENV                  — Runtime environment: dev (default) | stage | prod
    WCP_ATTEST_HMAC_KEY         — HMAC key for package attestation (required in prod)

Examples:
    python3 bootstrap.py send_message --chat-id @mychannel --text "Hello from pyhall"
    python3 bootstrap.py send_html --chat-id 123456789 --text "<b>Deploy</b> complete"
    python3 bootstrap.py send_photo --chat-id 123456789 --photo /tmp/screenshot.png
    python3 bootstrap.py send_document --chat-id 123456789 --document /tmp/report.pdf
    python3 bootstrap.py get_updates --limit 10
    python3 bootstrap.py get_chat_info --chat-id @mychannel
    python3 bootstrap.py get_bot_info
    python3 bootstrap.py pin_message --chat-id 123456789 --message-id 42
    python3 bootstrap.py delete_message --chat-id 123456789 --message-id 42
    python3 bootstrap.py answer_callback_query --callback-query-id abc123 --text "Got it"
    python3 bootstrap.py send_inline_keyboard --chat-id 123456789 --text "Choose:" \
        --buttons-json '[[{"text":"Yes","callback_data":"yes"},{"text":"No","callback_data":"no"}]]'
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the code/ directory is on the path so worker_logic imports cleanly
_CODE_DIR = Path(__file__).resolve().parent
if str(_CODE_DIR) not in sys.path:
    sys.path.insert(0, str(_CODE_DIR))

from worker_logic import run  # noqa: E402

if __name__ == "__main__":
    run()
