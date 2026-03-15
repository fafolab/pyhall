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


# ---------------------------------------------------------------------------
# POST /api/coord/tasks — create task (SEP-1686)
# ---------------------------------------------------------------------------

def test_coord_task_create(client):
    r = client.post("/api/coord/tasks", headers=_AUTH, json={"capability_id": "cap.test.x", "priority": 5})
    assert r.status_code == 201
    data = r.get_json()
    assert data["ok"] is True
    assert "task_id" in data
    assert "receipt_id" in data


def test_coord_task_create_appears_in_list(client):
    r = client.post("/api/coord/tasks", headers=_AUTH, json={"capability_id": "cap.test.y"})
    assert r.status_code == 201
    task_id = r.get_json()["task_id"]
    r2 = client.get("/api/coord/tasks", headers=_AUTH)
    tasks = r2.get_json()["tasks"]
    ids = [t["id"] for t in tasks]
    assert task_id in ids


def test_coord_task_create_requires_auth(client):
    r = client.post("/api/coord/tasks", json={"capability_id": "cap.test.z"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/coord/tasks/<task_id>/start
# ---------------------------------------------------------------------------

def test_coord_task_start(client):
    r = client.post("/api/coord/tasks", headers=_AUTH, json={"capability_id": "cap.test.start"})
    task_id = r.get_json()["task_id"]
    r2 = client.post(f"/api/coord/tasks/{task_id}/start", headers=_AUTH, json={})
    assert r2.status_code == 200
    data = r2.get_json()
    assert data["ok"] is True
    assert data["task"]["status"] == "running"
    assert data["task"]["started_at"] is not None


def test_coord_task_start_not_found(client):
    r = client.post("/api/coord/tasks/nonexistent-id/start", headers=_AUTH, json={})
    assert r.status_code == 404


def test_coord_task_start_requires_auth(client):
    r = client.post("/api/coord/tasks/any/start", json={})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/coord/tasks/<task_id>/fail
# ---------------------------------------------------------------------------

def test_coord_task_fail(client):
    r = client.post("/api/coord/tasks", headers=_AUTH, json={"capability_id": "cap.test.fail"})
    task_id = r.get_json()["task_id"]
    r2 = client.post(f"/api/coord/tasks/{task_id}/fail", headers=_AUTH, json={"reason": "test error"})
    assert r2.status_code == 200
    data = r2.get_json()
    assert data["ok"] is True
    assert data["task"]["status"] == "failure"
    assert data["task"]["fail_reason"] == "test error"
    assert data["task"]["completed_at"] is not None


def test_coord_task_fail_requires_auth(client):
    r = client.post("/api/coord/tasks/any/fail", json={"reason": "x"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/coord/tasks/<task_id>/timeout
# ---------------------------------------------------------------------------

def test_coord_task_timeout(client):
    r = client.post("/api/coord/tasks", headers=_AUTH, json={"capability_id": "cap.test.timeout"})
    task_id = r.get_json()["task_id"]
    r2 = client.post(f"/api/coord/tasks/{task_id}/timeout", headers=_AUTH, json={})
    assert r2.status_code == 200
    data = r2.get_json()
    assert data["ok"] is True
    assert data["task"]["status"] == "timeout"


def test_coord_task_timeout_requires_auth(client):
    r = client.post("/api/coord/tasks/any/timeout", json={})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/coord/tasks/<task_id>/complete — updated to status='success'
# ---------------------------------------------------------------------------

def test_coord_task_complete_sets_success_status(client):
    r = client.post("/api/coord/tasks", headers=_AUTH, json={"capability_id": "cap.test.complete"})
    task_id = r.get_json()["task_id"]
    r2 = client.post(f"/api/coord/tasks/{task_id}/complete", headers=_AUTH, json={"result": {"x": 1}})
    assert r2.status_code == 200
    r3 = client.get("/api/coord/tasks", headers=_AUTH)
    tasks = r3.get_json()["tasks"]
    task = next((t for t in tasks if t["id"] == task_id), None)
    assert task is not None
    assert task["status"] == "success"
    assert task["completed_at"] is not None


# ---------------------------------------------------------------------------
# POST /api/coord/fanout + GET /api/coord/fanout/<fanout_id>
# ---------------------------------------------------------------------------

def test_coord_fanout_create(client):
    r = client.post("/api/coord/fanout", headers=_AUTH, json={
        "tasks": [{"capability_id": "cap.a.x"}, {"capability_id": "cap.b.y"}],
        "timeout_seconds": 60,
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert "fanout_id" in data
    assert len(data["task_ids"]) == 2
    assert data["status"] == "dispatched"


def test_coord_fanout_create_no_tasks_returns_400(client):
    r = client.post("/api/coord/fanout", headers=_AUTH, json={"tasks": []})
    assert r.status_code == 400
    assert r.get_json()["code"] == "NO_TASKS"


def test_coord_fanout_requires_auth(client):
    r = client.post("/api/coord/fanout", json={"tasks": [{"capability_id": "cap.x"}]})
    assert r.status_code == 401


def test_coord_fanout_get(client):
    r = client.post("/api/coord/fanout", headers=_AUTH, json={
        "tasks": [{"capability_id": "cap.z.test"}],
    })
    fanout_id = r.get_json()["fanout_id"]
    r2 = client.get(f"/api/coord/fanout/{fanout_id}", headers=_AUTH)
    assert r2.status_code == 200
    data = r2.get_json()
    assert data["ok"] is True
    assert data["fanout_id"] == fanout_id
    assert len(data["tasks"]) == 1


def test_coord_fanout_get_not_found(client):
    r = client.get("/api/coord/fanout/nonexistent-id", headers=_AUTH)
    assert r.status_code == 404


def test_coord_fanout_get_requires_auth(client):
    r = client.get("/api/coord/fanout/some-id")
    assert r.status_code == 401
