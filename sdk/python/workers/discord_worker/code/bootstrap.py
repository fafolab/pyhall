#!/usr/bin/env python3
"""
bootstrap.py — Discord Notifications & Bot Worker entry point

This is the canonical entrypoint for the discord_worker package.
It delegates immediately to worker_logic.run() — all logic lives there.

Usage:
    python3 bootstrap.py <op> [options]
    python3 worker_logic.py <op> [options]   (same result)

Environment variables required:
    DISCORD_BOT_TOKEN           — Bot token from Discord developer portal (required)

Environment variables optional:
    DISCORD_DEFAULT_CHANNEL_ID  — Default channel for send_message/send_embed
    DISCORD_DEFAULT_GUILD_ID    — Default guild for list_channels/get_guild_info
    PYHALL_ENV                  — Runtime environment: dev (default) | stage | prod
    WCP_ATTEST_HMAC_KEY         — HMAC key for package attestation (required in prod)

Examples:
    python3 bootstrap.py send_message --channel-id 123456789 --content "Hello from pyhall"
    python3 bootstrap.py send_embed --channel-id 123456789 --title "Alert" --description "Deploy done"
    python3 bootstrap.py list_guilds
    python3 bootstrap.py get_guild_info --guild-id 987654321
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
