# Copyright (c) 2026 pyhall.dev — https://pyhall.dev
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""
test_coord_logs.py — Coordination log file API tests.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from hall_api.server import create_app

_AUTH = {"Authorization": "Bearer test-token"}


@pytest.fixture
def client():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as f:
        db_path = f.name
    app = create_app(testing=True, db_path=db_path)
    with app.test_client() as c:
        yield c
    try:
        os.unlink(db_path)
    except FileNotFoundError:
        pass


def test_coord_log_files_requires_auth(client):
    r = client.get("/api/coord/logs/files")
    assert r.status_code == 401


def test_coord_log_files_catalog_contains_full_paths(client):
    r = client.get("/api/coord/logs/files", headers=_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] >= 3
    keys = {f["log_key"] for f in data["files"]}
    assert "agent_comms" in keys
    assert "agent_activity" in keys
    assert "command_trace" in keys
    for f in data["files"]:
        assert os.path.isabs(f["full_path"])
        assert f["full_path"].endswith(".log")


def test_append_and_read_coord_log(client):
    r = client.post(
        "/api/coord/logs/agent_comms/append",
        headers=_AUTH,
        json={"source": "rob", "entry": "@all test message"},
    )
    assert r.status_code == 200
    assert r.get_json()["ok"] is True

    r = client.get("/api/coord/logs/agent_comms?lines=20", headers=_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["log_key"] == "agent_comms"
    assert "@all test message" in data["content"]
    assert "rob" in data["content"]


def test_export_coord_log(client):
    r = client.get("/api/coord/logs/command_trace/export", headers=_AUTH)
    assert r.status_code == 200
    cd = r.headers.get("Content-Disposition", "")
    assert "attachment" in cd
    assert "command_trace.log" in cd
