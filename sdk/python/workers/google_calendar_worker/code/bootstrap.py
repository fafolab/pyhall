#!/usr/bin/env python3
"""WCP bootstrap entry point for google_calendar_worker.

All business logic lives in:
  workers/google_calendar_worker/code/worker_logic.py

Usage examples:
  python3 bootstrap.py setup
  python3 bootstrap.py list_calendars
  python3 bootstrap.py list_upcoming --days 14
  python3 bootstrap.py create_event --summary "Team Sync" --start "2026-03-15T14:00:00Z" --end "2026-03-15T15:00:00Z"
  python3 bootstrap.py find_free_time --start "2026-03-15T09:00:00Z" --end "2026-03-15T17:00:00Z" --duration 30
"""
from worker_logic import run

if __name__ == "__main__":
    run()
