# Copyright (c) 2026 pyhall.dev — https://pyhall.dev
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""
test_coordination.py — Orchestrator coordination API tests.

Covers: coord_agents, coord_tasks, coord_locks tables and routes.
Run: pytest tests/test_coordination.py -v
"""

import json
import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from hall_api.server import create_app

# Auth headers for all protected endpoints
_AUTH = {"Authorization": "Bearer test-token"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Auth enforcement — 401 without token
# ---------------------------------------------------------------------------

def test_coord_agents_requires_auth(client):
    r = client.get("/api/coord/agents")
    assert r.status_code == 401

def test_coord_heartbeat_requires_auth(client):
    r = client.post("/api/coord/agents/heartbeat", json={"id": "x"})
    assert r.status_code == 401

def test_coord_tasks_requires_auth(client):
    r = client.get("/api/coord/tasks")
    assert r.status_code == 401

def test_coord_locks_requires_auth(client):
    r = client.get("/api/coord/locks")
    assert r.status_code == 401

def test_coord_task_reassign_requires_auth(client):
    r = client.post("/api/coord/tasks/t1/reassign", json={"owner_id": "x"})
    assert r.status_code == 401

def test_coord_task_complete_requires_auth(client):
    r = client.post("/api/coord/tasks/t1/complete", json={})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/coord/agents
# ---------------------------------------------------------------------------

def test_coord_agents_empty(client):
    r = client.get("/api/coord/agents", headers=_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] == 0
    assert data["agents"] == []


# ---------------------------------------------------------------------------
# POST /api/coord/agents/heartbeat
# ---------------------------------------------------------------------------

def test_coord_agent_heartbeat(client):
    r = client.post("/api/coord/agents/heartbeat",
                    json={"id": "agent-1", "name": "Test Agent", "status": "idle"},
                    headers=_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert data["agent_id"] == "agent-1"
    assert "ts" in data


def test_coord_agent_appears_after_heartbeat(client):
    client.post("/api/coord/agents/heartbeat",
                json={"id": "agent-2", "status": "active"},
                headers=_AUTH)
    r = client.get("/api/coord/agents", headers=_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] == 1
    assert data["agents"][0]["id"] == "agent-2"


def test_coord_agent_heartbeat_missing_id(client):
    r = client.post("/api/coord/agents/heartbeat", json={"status": "idle"}, headers=_AUTH)
    assert r.status_code == 400
    assert "missing id" in r.get_json()["error"]


def test_coord_agent_heartbeat_upsert(client):
    """Second heartbeat from same agent updates, does not duplicate."""
    client.post("/api/coord/agents/heartbeat",
                json={"id": "agent-3", "status": "idle"}, headers=_AUTH)
    client.post("/api/coord/agents/heartbeat",
                json={"id": "agent-3", "status": "active"}, headers=_AUTH)
    r = client.get("/api/coord/agents", headers=_AUTH)
    data = r.get_json()
    assert data["count"] == 1
    assert data["agents"][0]["status"] == "active"


# ---------------------------------------------------------------------------
# GET /api/coord/tasks
# ---------------------------------------------------------------------------

def test_coord_tasks_empty(client):
    r = client.get("/api/coord/tasks", headers=_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["count"] == 0
    assert data["tasks"] == []


# ---------------------------------------------------------------------------
# GET /api/coord/locks
# ---------------------------------------------------------------------------

def test_coord_locks_empty(client):
    r = client.get("/api/coord/locks", headers=_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["locks"] == []
