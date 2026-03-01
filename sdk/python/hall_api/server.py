"""
hall_api/server.py — PyHall API Server

HTTP interface to the Hall registry and routing decision log.
Each organization runs their own instance.

Endpoints:
  GET  /health
  GET  /status
  GET  /workers
  GET  /dispatches?limit=50
  GET  /dispatches/active
  GET  /alerts
  POST /enroll
  POST /decisions/ingest

Run locally:
  pip install flask
  python hall_api/server.py

Run with a custom port / host:
  HALL_API_PORT=7777 HALL_API_HOST=127.0.0.1 python hall_api/server.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, UTC

from flask import Flask, g, jsonify, request

HALL_VERSION = "0.1.0"
DB_PATH = os.environ.get("HALL_DB_PATH", "hall.db")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS enrollments (
            enrollment_id TEXT PRIMARY KEY,
            worker_id TEXT NOT NULL UNIQUE,
            worker_species_id TEXT NOT NULL,
            capabilities TEXT NOT NULL,
            risk_tier TEXT NOT NULL,
            enrolled_at TEXT NOT NULL,
            artifact_hash TEXT NOT NULL,
            record_json TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS decisions (
            decision_id TEXT PRIMARY KEY,
            decided_at TEXT NOT NULL,
            capability_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT '',
            env TEXT NOT NULL DEFAULT 'dev',
            denied INTEGER NOT NULL DEFAULT 0,
            deny_reason TEXT,
            selected_worker TEXT,
            blast_score INTEGER,
            artifact_hash TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            level TEXT NOT NULL,
            code TEXT NOT NULL,
            message TEXT NOT NULL,
            worker_id TEXT,
            capability_id TEXT
        )
    """)
    db.commit()


# ---------------------------------------------------------------------------
# Cryptographic helpers — WCP §5.10 artifact attestation
# ---------------------------------------------------------------------------

def compute_artifact_hash(record: dict) -> str:
    """SHA-256 of the record without the artifact_hash field (sorted keys)."""
    clean = {k: v for k, v in record.items() if k != "artifact_hash"}
    payload = json.dumps(clean, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def verify_artifact_hash(record: dict) -> tuple[bool, str]:
    """Returns (valid, expected_hash)."""
    provided = record.get("artifact_hash", "")
    if not provided:
        return False, ""
    expected = compute_artifact_hash(record)
    return provided == expected, expected


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(testing: bool = False, db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = testing
    # Allow explicit DB path override (used by tests to get a real temp file
    # rather than :memory:, since each Flask request creates a new connection
    # and :memory: databases don't persist between connections).
    app.config["DB_PATH"] = db_path or (DB_PATH if not testing else None)

    # ---------------------------------------------------------------------------
    # Request lifecycle — open/close DB per request
    # ---------------------------------------------------------------------------

    @app.before_request
    def open_db() -> None:
        path = app.config["DB_PATH"] or DB_PATH
        g.db = sqlite3.connect(path)
        g.db.row_factory = sqlite3.Row
        init_db(g.db)

    @app.teardown_appcontext
    def close_db(exc: Exception | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # ---------------------------------------------------------------------------
    # CORS — allow any origin for local dev
    # In production, restrict to your own domain.
    # ---------------------------------------------------------------------------

    @app.after_request
    def add_cors(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    @app.route("/health", methods=["OPTIONS", "GET"])
    def health_preflight():
        if request.method == "OPTIONS":
            return jsonify({}), 204
        return get_health()

    # ---------------------------------------------------------------------------
    # GET /health
    # ---------------------------------------------------------------------------

    def get_health():
        return jsonify({"status": "ok", "timestamp": datetime.now(UTC).isoformat()})

    app.add_url_rule("/health", view_func=get_health)

    # ---------------------------------------------------------------------------
    # GET /status
    # ---------------------------------------------------------------------------

    @app.route("/status")
    def status():
        db = g.db
        workers_enrolled = db.execute("SELECT COUNT(*) FROM enrollments").fetchone()[0]
        decisions_total = db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        decisions_today = db.execute(
            "SELECT COUNT(*) FROM decisions WHERE decided_at LIKE ?", (f"{today}%",)
        ).fetchone()[0]
        denials_today = db.execute(
            "SELECT COUNT(*) FROM decisions WHERE decided_at LIKE ? AND denied=1", (f"{today}%",)
        ).fetchone()[0]
        return jsonify({
            "hall_version": HALL_VERSION,
            "hall_name": "PyHall",
            "workers_enrolled": workers_enrolled,
            "decisions_total": decisions_total,
            "decisions_today": decisions_today,
            "denials_today": denials_today,
            "timestamp": datetime.now(UTC).isoformat(),
        })

    # ---------------------------------------------------------------------------
    # GET /workers
    # ---------------------------------------------------------------------------

    @app.route("/workers")
    def workers():
        db = g.db
        rows = db.execute(
            "SELECT worker_id, worker_species_id, capabilities, risk_tier, enrolled_at "
            "FROM enrollments ORDER BY enrolled_at DESC"
        ).fetchall()
        return jsonify({
            "workers": [
                {
                    "worker_id": r["worker_id"],
                    "worker_species_id": r["worker_species_id"],
                    "capabilities": json.loads(r["capabilities"]),
                    "risk_tier": r["risk_tier"],
                    "enrolled_at": r["enrolled_at"],
                    "status": "active",
                }
                for r in rows
            ],
            "count": len(rows),
        })

    # ---------------------------------------------------------------------------
    # GET /dispatches?limit=50
    # ---------------------------------------------------------------------------

    @app.route("/dispatches")
    def dispatches():
        db = g.db
        limit = min(int(request.args.get("limit", 50)), 200)
        rows = db.execute(
            "SELECT * FROM decisions ORDER BY decided_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return jsonify({"dispatches": [dict(r) for r in rows], "count": len(rows)})

    # ---------------------------------------------------------------------------
    # GET /dispatches/active
    # ---------------------------------------------------------------------------

    @app.route("/dispatches/active")
    def dispatches_active():
        return jsonify({"dispatches": [], "count": 0})

    # ---------------------------------------------------------------------------
    # GET /alerts
    # ---------------------------------------------------------------------------

    @app.route("/alerts")
    def alerts():
        db = g.db
        rows = db.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
        return jsonify({"alerts": [dict(r) for r in rows], "count": len(rows)})

    # ---------------------------------------------------------------------------
    # POST /enroll
    # ---------------------------------------------------------------------------

    @app.route("/enroll", methods=["POST", "OPTIONS"])
    def enroll():
        if request.method == "OPTIONS":
            return jsonify({}), 204

        db = g.db
        record = request.get_json(force=True) or {}

        worker_id = record.get("worker_id", "").strip()
        if not worker_id:
            return jsonify({"error": "worker_id is required"}), 400

        species_id = record.get("worker_species_id", "").strip()
        if not species_id:
            return jsonify({"error": "worker_species_id is required"}), 400

        capabilities = record.get("capabilities", [])
        if not capabilities:
            return jsonify({"error": "capabilities must be a non-empty list"}), 400

        provided_hash = record.get("artifact_hash", "")
        if not provided_hash:
            return jsonify({
                "error": "artifact_hash is required. "
                         "Compute: sha256(json.dumps(record_without_hash, sort_keys=True, separators=(',',':')))"
            }), 400

        valid, expected = verify_artifact_hash(record)
        if not valid:
            return jsonify({
                "error": "artifact_hash mismatch — record was tampered",
                "provided": provided_hash,
                "expected": expected,
                "code": "DENY_WORKER_TAMPERED",
            }), 400

        enrollment_id = str(uuid.uuid4())
        enrolled_at = datetime.now(UTC).isoformat()

        try:
            db.execute(
                "INSERT INTO enrollments "
                "(enrollment_id, worker_id, worker_species_id, capabilities, risk_tier, enrolled_at, artifact_hash, record_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    enrollment_id,
                    worker_id,
                    species_id,
                    json.dumps(capabilities),
                    record.get("risk_tier", "unknown"),
                    enrolled_at,
                    provided_hash,
                    json.dumps(record),
                ),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # Worker already enrolled — update it
            db.execute(
                "UPDATE enrollments SET worker_species_id=?, capabilities=?, risk_tier=?, "
                "enrolled_at=?, artifact_hash=?, record_json=? WHERE worker_id=?",
                (
                    species_id,
                    json.dumps(capabilities),
                    record.get("risk_tier", "unknown"),
                    enrolled_at,
                    provided_hash,
                    json.dumps(record),
                    worker_id,
                ),
            )
            db.commit()
            return jsonify({
                "enrolled": True,
                "updated": True,
                "worker_id": worker_id,
                "artifact_hash_verified": True,
            }), 200

        return jsonify({
            "enrolled": True,
            "enrollment_id": enrollment_id,
            "worker_id": worker_id,
            "enrolled_at": enrolled_at,
            "artifact_hash_verified": True,
        }), 201

    # ---------------------------------------------------------------------------
    # POST /decisions/ingest
    # ---------------------------------------------------------------------------

    @app.route("/decisions/ingest", methods=["POST", "OPTIONS"])
    def ingest_decision():
        if request.method == "OPTIONS":
            return jsonify({}), 204

        db = g.db
        data = request.get_json(force=True) or {}
        decision_id = data.get("decision_id") or str(uuid.uuid4())

        try:
            db.execute(
                "INSERT OR IGNORE INTO decisions "
                "(decision_id, decided_at, capability_id, tenant_id, env, denied, deny_reason, selected_worker, blast_score, artifact_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    decision_id,
                    data.get("decided_at", datetime.now(UTC).isoformat()),
                    data.get("capability_id", ""),
                    data.get("tenant_id", ""),
                    data.get("env", "dev"),
                    1 if data.get("denied") else 0,
                    data.get("deny_reason"),
                    data.get("selected_worker"),
                    data.get("blast_score"),
                    data.get("artifact_hash"),
                ),
            )
            db.commit()
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        return jsonify({"recorded": True, "decision_id": decision_id}), 201

    return app


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("HALL_API_PORT", 7777))
    # Default to 127.0.0.1. Override with HALL_API_HOST if needed.
    # NEVER bind to 0.0.0.0 on a dev server exposed to the internet.
    host = os.environ.get("HALL_API_HOST", "127.0.0.1")
    print(f"[hall-api] PyHall API v{HALL_VERSION} starting on http://{host}:{port}")
    print(f"[hall-api] DB: {DB_PATH}")
    app = create_app()
    app.run(host=host, port=port, debug=False)
