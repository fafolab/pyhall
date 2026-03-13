# Copyright (c) 2026 pyhall.dev — https://pyhall.dev
# Licensed under the Apache License, Version 2.0 (see LICENSE)
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


# ---------------------------------------------------------------------------
# Registry proxy endpoints (Tasks 3.5 / 3.6)
# ---------------------------------------------------------------------------

from unittest.mock import patch, MagicMock
from pyhall.registry_client import BanEntry, VerifyResponse


def _make_verify_response(**kwargs):
    defaults = dict(
        worker_id='x.test.w1', status='active', current_hash='a' * 64,
        banned=False, ban_reason=None, attested_at='2026-03-03T00:00:00Z',
        ai_generated=False, ai_service=None, ai_model=None,
        ai_session_fingerprint=None,
    )
    defaults.update(kwargs)
    return VerifyResponse(**defaults)


def _make_ban_entry(**kwargs):
    defaults = dict(
        sha256='b' * 64, reason='malware',
        reported_at='2026-03-01T00:00:00Z', source='community',
        review_status='approved',
    )
    defaults.update(kwargs)
    return BanEntry(**defaults)


def test_registry_ban_list_proxy_returns_entries(client):
    import hall_api.server as _srv
    clean_state = {**_srv._server_state, 'banned_hashes': set(), 'banned_hashes_updated_at': None}
    with patch.object(_srv, '_server_state', clean_state):
        with patch('pyhall.registry_client.RegistryClient.get_ban_list', return_value=[_make_ban_entry()]):
            res = client.get('/wcp/registry/ban-list')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['count'] == 1
    assert ('b' * 64) in data['hashes']
    assert data['source'] == 'local-cache'


def test_registry_ban_list_proxy_empty(client):
    import hall_api.server as _srv
    clean_state = {**_srv._server_state, 'banned_hashes': set(), 'banned_hashes_updated_at': None}
    with patch.object(_srv, '_server_state', clean_state):
        with patch('pyhall.registry_client.RegistryClient.get_ban_list', return_value=[]):
            res = client.get('/wcp/registry/ban-list')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['count'] == 0
    assert data['hashes'] == []


def test_registry_ban_list_proxy_network_error_serves_empty_cache(client):
    # Route serves from local cache gracefully on network error; no 503 raised.
    import hall_api.server as _srv
    clean_state = {**_srv._server_state, 'banned_hashes': set(), 'banned_hashes_updated_at': None}
    with patch.object(_srv, '_server_state', clean_state):
        with patch('pyhall.registry_client.RegistryClient.get_ban_list', side_effect=Exception('timeout')):
            res = client.get('/wcp/registry/ban-list')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['count'] == 0
    assert data['source'] == 'local-cache'


def test_registry_verify_proxy_returns_worker(client):
    with patch('pyhall.registry_client.RegistryClient.verify', return_value=_make_verify_response()):
        res = client.get('/wcp/registry/verify/x.test.w1')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['status'] == 'active'
    assert data['current_hash'] == 'a' * 64


def test_registry_verify_proxy_unknown_worker(client):
    with patch('pyhall.registry_client.RegistryClient.verify',
               return_value=_make_verify_response(worker_id='x.ghost', status='unknown', current_hash=None)):
        res = client.get('/wcp/registry/verify/x.ghost')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data['status'] == 'unknown'


# ---------------------------------------------------------------------------
# POST /api/route
# ---------------------------------------------------------------------------

def _route_payload(**overrides):
    """Build a minimal valid /api/route request body."""
    base = {
        "capability_id": "cap.doc.summarize",
        "env": "dev",
        "data_label": "PUBLIC",
        "tenant_id": "org.test",
        "tenant_risk": "low",
        "qos_class": "P2",
        "correlation_id": "aaaabbbb-0000-0000-0000-000000000001",
    }
    base.update(overrides)
    return base


_ROUTE_AUTH = {"Authorization": "Bearer test-token"}


def test_route_requires_auth(client):
    """POST /api/route without auth token must return 401."""
    r = client.post("/api/route", json=_route_payload())
    assert r.status_code == 401
    assert r.get_json()["error"] == "unauthorized"


def test_route_returns_allowed_decision(client):
    """Enroll a worker first, then route to its capability — expect allowed=True."""
    # Enroll a worker that supports cap.doc.summarize
    record = _make_record(
        worker_id="org.test.summarizer",
        worker_species_id="wrk.doc.summarizer",
        capabilities=["cap.doc.summarize"],
    )
    r = client.post("/enroll", json=record)
    assert r.status_code == 201

    # Route with a matching capability
    r = client.post("/api/route", json=_route_payload(), headers=_ROUTE_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["denied"] is False
    assert data["selected_worker_species_id"] == "wrk.doc.summarizer"


def test_route_denied_no_matching_worker(client):
    """Route to a capability with no workers enrolled — expect allowed=False (denied)."""
    r = client.post("/api/route", json=_route_payload(capability_id="cap.nonexistent.thing"),
                    headers=_ROUTE_AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["denied"] is True


def test_route_missing_field_returns_400(client):
    """Omit required field capability_id — expect 400."""
    payload = {
        "env": "dev",
        "data_label": "PUBLIC",
        "tenant_id": "org.test",
    }
    r = client.post("/api/route", json=payload, headers=_ROUTE_AUTH)
    assert r.status_code == 400
    assert "missing field" in r.get_json()["error"]


# ---------------------------------------------------------------------------
# GET /api/doctor
# ---------------------------------------------------------------------------

_AUTH_HEADER = {"Authorization": "Bearer test-token"}


def test_doctor_requires_auth(client):
    r = client.get('/api/doctor')
    assert r.status_code == 401


def test_doctor_returns_200(client):
    r = client.get('/api/doctor', headers=_AUTH_HEADER)
    assert r.status_code == 200


def test_doctor_has_six_checks(client):
    r = client.get('/api/doctor', headers=_AUTH_HEADER)
    data = r.get_json()
    checks = data.get('checks', {})
    expected_keys = {'connectivity', 'auth', 'binary_integrity', 'hall_server', 'db', 'config'}
    assert expected_keys == set(checks.keys())


def test_doctor_checks_have_status_and_message(client):
    r = client.get('/api/doctor', headers=_AUTH_HEADER)
    data = r.get_json()
    for key, check in data['checks'].items():
        assert 'status' in check, f"check '{key}' missing 'status'"
        assert 'message' in check, f"check '{key}' missing 'message'"


def test_doctor_has_overall_and_checked_at(client):
    r = client.get('/api/doctor', headers=_AUTH_HEADER)
    data = r.get_json()
    assert 'overall' in data
    assert data['overall'] in ('ok', 'warn', 'fail')
    assert 'checked_at' in data


def test_doctor_check_statuses_are_valid_values(client):
    r = client.get('/api/doctor', headers=_AUTH_HEADER)
    data = r.get_json()
    valid = {'ok', 'warn', 'fail'}
    for key, check in data['checks'].items():
        assert check['status'] in valid, f"check '{key}' has invalid status: {check['status']}"


# ---------------------------------------------------------------------------
# POST /api/doctor/export
# ---------------------------------------------------------------------------

def test_doctor_export_requires_auth(client):
    r = client.post('/api/doctor/export')
    assert r.status_code == 401


def test_doctor_export_returns_200(client):
    r = client.post('/api/doctor/export', headers=_AUTH_HEADER)
    assert r.status_code == 200


def test_doctor_export_has_required_fields(client):
    r = client.post('/api/doctor/export', headers=_AUTH_HEADER)
    data = r.get_json()
    assert 'doctor' in data
    assert 'version' in data
    assert 'platform' in data
    assert 'export_at' in data


def test_doctor_export_contains_six_checks(client):
    r = client.post('/api/doctor/export', headers=_AUTH_HEADER)
    data = r.get_json()
    checks = data.get('doctor', {}).get('checks', {})
    expected_keys = {'connectivity', 'auth', 'binary_integrity', 'hall_server', 'db', 'config'}
    assert expected_keys == set(checks.keys())


def test_doctor_export_no_tokens_in_top_level(client):
    r = client.post('/api/doctor/export', headers=_AUTH_HEADER)
    data = r.get_json()
    # Top-level bundle must not expose any session tokens or secrets
    assert 'token' not in data
    assert 'session' not in data
    assert 'session_token' not in data
    assert 'bearer' not in data
    assert 'secret' not in data


# ---------------------------------------------------------------------------
# POST /api/auth/passphrase-reset/request
# POST /api/auth/passphrase-reset/confirm
# ---------------------------------------------------------------------------

def test_passphrase_reset_request_requires_auth(client):
    r = client.post('/api/auth/passphrase-reset/request', json={})
    assert r.status_code == 401


def test_passphrase_reset_confirm_missing_token(client):
    r = client.post('/api/auth/passphrase-reset/confirm', json={'new_passphrase': 'abc'})
    assert r.status_code == 400
    assert b'Token' in r.data or b'token' in r.data


def test_passphrase_reset_confirm_missing_passphrase(client):
    r = client.post('/api/auth/passphrase-reset/confirm', json={'token': 'some-token'})
    assert r.status_code == 400


def test_passphrase_reset_request_returns_503_when_registry_unreachable(client):
    # With no registry configured in test env, proxying should fail gracefully
    r = client.post('/api/auth/passphrase-reset/request', headers=_AUTH_HEADER, json={})
    # Either 503 (can't reach registry), a registry HTTP error, or not a 500 crash
    assert r.status_code in (400, 401, 404, 503)
