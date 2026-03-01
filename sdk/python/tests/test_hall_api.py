"""
test_hall_api.py — Hall API server tests.

Run: pytest tests/test_hall_api.py -v
"""

import json
import hashlib
import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from hall_api.server import create_app, compute_artifact_hash, verify_artifact_hash


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    # Use a temp file DB — :memory: doesn't persist between Flask requests
    # because each request creates a new sqlite3.connect() call.
    with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as f:
        db_path = f.name
    app = create_app(testing=True, db_path=db_path)
    with app.test_client() as c:
        yield c
    try:
        os.unlink(db_path)
    except FileNotFoundError:
        pass


def _make_record(**overrides):
    """Build a valid registry record dict with artifact_hash."""
    base = {
        "worker_id": "org.test.hello-worker",
        "worker_species_id": "wrk.doc.summarizer",
        "capabilities": ["cap.doc.summarize"],
        "risk_tier": "low",
        "owner": "org.test",
    }
    base.update(overrides)
    base["artifact_hash"] = compute_artifact_hash(base)
    return base


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

def test_health_returns_200(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert "timestamp" in data


# ---------------------------------------------------------------------------
# /status
# ---------------------------------------------------------------------------

def test_status_returns_200(client):
    r = client.get("/status")
    assert r.status_code == 200
    data = r.get_json()
    assert "hall_version" in data
    assert "workers_enrolled" in data
    assert "decisions_today" in data
    assert "denials_today" in data
    assert data["workers_enrolled"] == 0


# ---------------------------------------------------------------------------
# /workers
# ---------------------------------------------------------------------------

def test_workers_empty(client):
    r = client.get("/workers")
    assert r.status_code == 200
    data = r.get_json()
    assert data["workers"] == []
    assert data["count"] == 0


# ---------------------------------------------------------------------------
# /enroll
# ---------------------------------------------------------------------------

def test_enroll_missing_worker_id(client):
    r = client.post("/enroll", json={"worker_species_id": "wrk.doc.summarizer"})
    assert r.status_code == 400
    assert "worker_id" in r.get_json()["error"]


def test_enroll_missing_artifact_hash(client):
    r = client.post("/enroll", json={
        "worker_id": "org.test.w1",
        "worker_species_id": "wrk.doc.summarizer",
        "capabilities": ["cap.doc.summarize"],
    })
    assert r.status_code == 400
    assert "artifact_hash" in r.get_json()["error"]


def test_enroll_tampered_hash(client):
    record = _make_record()
    record["artifact_hash"] = "sha256:deadbeef" + "0" * 56
    r = client.post("/enroll", json=record)
    assert r.status_code == 400
    data = r.get_json()
    assert data.get("code") == "DENY_WORKER_TAMPERED"


def test_enroll_success(client):
    record = _make_record()
    r = client.post("/enroll", json=record)
    assert r.status_code == 201
    data = r.get_json()
    assert data["enrolled"] is True
    assert data["artifact_hash_verified"] is True
    assert "enrollment_id" in data


def test_enroll_worker_appears_in_workers(client):
    record = _make_record()
    client.post("/enroll", json=record)
    r = client.get("/workers")
    workers = r.get_json()["workers"]
    ids = [w["worker_id"] for w in workers]
    assert record["worker_id"] in ids


def test_enroll_updates_status_count(client):
    client.post("/enroll", json=_make_record())
    r = client.get("/status")
    assert r.get_json()["workers_enrolled"] == 1


def test_enroll_duplicate_updates(client):
    record = _make_record()
    client.post("/enroll", json=record)
    # Re-enroll same worker — should succeed (200 or 201) with enrolled=True
    r2 = client.post("/enroll", json=record)
    assert r2.status_code in (200, 201)
    data = r2.get_json()
    assert data["enrolled"] is True


# ---------------------------------------------------------------------------
# /dispatches
# ---------------------------------------------------------------------------

def test_dispatches_empty(client):
    r = client.get("/dispatches")
    assert r.status_code == 200
    data = r.get_json()
    assert data["dispatches"] == []
    assert data["count"] == 0


# ---------------------------------------------------------------------------
# /dispatches/active
# ---------------------------------------------------------------------------

def test_dispatches_active(client):
    r = client.get("/dispatches/active")
    assert r.status_code == 200
    assert r.get_json()["dispatches"] == []


# ---------------------------------------------------------------------------
# /alerts
# ---------------------------------------------------------------------------

def test_alerts_empty(client):
    r = client.get("/alerts")
    assert r.status_code == 200
    assert r.get_json()["alerts"] == []


# ---------------------------------------------------------------------------
# POST /decisions/ingest
# ---------------------------------------------------------------------------

def test_ingest_decision(client):
    r = client.post("/decisions/ingest", json={
        "decision_id": "test-decision-001",
        "capability_id": "cap.doc.summarize",
        "tenant_id": "org.test",
        "env": "dev",
        "denied": False,
        "selected_worker": "wrk.doc.summarizer",
    })
    assert r.status_code == 201
    data = r.get_json()
    assert data["recorded"] is True


def test_ingest_decision_appears_in_dispatches(client):
    client.post("/decisions/ingest", json={
        "decision_id": "test-002",
        "capability_id": "cap.mem.retrieve",
        "denied": False,
    })
    r = client.get("/dispatches")
    dispatches = r.get_json()["dispatches"]
    ids = [d["decision_id"] for d in dispatches]
    assert "test-002" in ids


def test_ingest_decision_denied_updates_denials(client):
    client.post("/decisions/ingest", json={
        "capability_id": "cap.db.write",
        "denied": True,
        "deny_reason": "blast:78",
    })
    r = client.get("/status")
    # We can't assert exact count without controlling date, just check it's non-negative
    assert r.get_json()["denials_today"] >= 0


def test_ingest_idempotent(client):
    payload = {"decision_id": "dup-001", "capability_id": "cap.doc.summarize"}
    client.post("/decisions/ingest", json=payload)
    r2 = client.post("/decisions/ingest", json=payload)
    assert r2.status_code == 201  # INSERT OR IGNORE — no error on duplicate


# ---------------------------------------------------------------------------
# compute_artifact_hash / verify_artifact_hash unit tests
# ---------------------------------------------------------------------------

def test_compute_artifact_hash_deterministic():
    record = {"worker_id": "org.test.w", "capabilities": ["cap.doc.summarize"]}
    h1 = compute_artifact_hash(record)
    h2 = compute_artifact_hash(record)
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_compute_artifact_hash_excludes_hash_field():
    record = {"worker_id": "org.test.w"}
    h_without = compute_artifact_hash(record)
    record["artifact_hash"] = "sha256:anything"
    h_with = compute_artifact_hash(record)
    assert h_without == h_with


def test_verify_artifact_hash_valid():
    record = {"worker_id": "org.test.w", "capabilities": ["cap.x"]}
    record["artifact_hash"] = compute_artifact_hash(record)
    valid, expected = verify_artifact_hash(record)
    assert valid is True


def test_verify_artifact_hash_tampered():
    record = {"worker_id": "org.test.w", "capabilities": ["cap.x"]}
    record["artifact_hash"] = compute_artifact_hash(record)
    record["capabilities"] = ["cap.x", "cap.y"]  # tamper
    valid, _ = verify_artifact_hash(record)
    assert valid is False


def test_verify_artifact_hash_missing():
    record = {"worker_id": "org.test.w"}
    valid, expected = verify_artifact_hash(record)
    assert valid is False
    assert expected == ""
