#!/usr/bin/env python3
"""WCP bootstrap entry point for slack_worker.

All business logic lives in:
  workers/slack_worker/code/worker_logic.py
"""
from worker_logic import run

if __name__ == '__main__':
    run()
