"""
hello_worker/worker.py — Minimal canonical WCP worker example.

Implements: cap.hello.greet
Species:    wrk.hello.greeter

This is the simplest possible complete WCP worker. Use it as a template
when building your own workers.

Run directly:
    python worker.py '{"name": "Alice"}'

Or in stdio mode (used by MCP server):
    echo '{"name": "Alice"}' | python worker.py --stdio
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Standard WCP worker context and result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class WorkerContext:
    """Routing context propagated from the Hall's RouteDecision."""
    correlation_id: str
    tenant_id: str
    env: str
    data_label: str
    qos_class: str
    capability_id: str
    policy_version: str = "policy.v0"


@dataclass
class WorkerResult:
    """Standard WCP worker result envelope."""
    status: str                                      # "ok" | "denied" | "error"
    result: Dict[str, Any] = field(default_factory=dict)
    telemetry: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    deny_reason: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "result": self.result,
            "telemetry": self.telemetry,
            "evidence": self.evidence,
            "deny_reason": self.deny_reason,
        }


# ---------------------------------------------------------------------------
# Worker implementation
# ---------------------------------------------------------------------------

WORKER_ID = "org.example.hello-greeter"
WORKER_SPECIES_ID = "wrk.hello.greeter"
CAPABILITY_ID = "cap.hello.greet"
RISK_TIER = "low"


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def execute(request: dict) -> WorkerResult:
    """
    Execute the greeting capability.

    Input:
        {
          "name": "Alice",          (optional, defaults to "World")
          "correlation_id": "...",  (required for telemetry)
          "tenant_id": "...",       (required for telemetry)
          "capability_id": "cap.hello.greet"
        }

    Output:
        WorkerResult with:
          result.greeting  = "Hello, Alice!"
          telemetry        = [evt.worker.executed.v1]
          evidence         = [evidence_receipt]
    """
    correlation_id = request.get("correlation_id", "unknown")
    tenant_id = request.get("tenant_id", "unknown")
    name = request.get("name", "World")

    # The actual work — dead simple on purpose
    greeting = f"Hello, {name}!"

    # Telemetry event (workers should emit at minimum evt.worker.executed.v1)
    telemetry_event = {
        "event_id": "evt.worker.executed.v1",
        "timestamp": _now_utc(),
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "worker_id": WORKER_ID,
        "worker_species_id": WORKER_SPECIES_ID,
        "capability_id": CAPABILITY_ID,
        "status": "ok",
    }

    # Evidence receipt (WCP spec section 5.7)
    import hashlib
    payload_bytes = json.dumps(request, sort_keys=True).encode()
    artifact_hash = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()

    evidence_receipt = {
        "correlation_id": correlation_id,
        "dispatched_at": _now_utc(),
        "worker_id": WORKER_ID,
        "capability_id": CAPABILITY_ID,
        "policy_decision": "ALLOW",
        "controls_verified": ["ctrl.obs.audit-log-append-only"],
        "artifact_hash": artifact_hash,
    }

    return WorkerResult(
        status="ok",
        result={
            "greeting": greeting,
            "name": name,
            "worker_id": WORKER_ID,
        },
        telemetry=[telemetry_event],
        evidence=[evidence_receipt],
    )


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------

def run_stdio():
    """Read JSON from stdin, write JSON to stdout. Used by MCP server."""
    try:
        raw = sys.stdin.read().strip()
        if not raw:
            sys.stdout.write(json.dumps({"status": "error", "error": "Empty request"}) + "\n")
            return
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stdout.write(json.dumps({"status": "error", "error": f"Invalid JSON: {exc}"}) + "\n")
        return

    try:
        result = execute(request)
    except Exception as exc:
        result = WorkerResult(status="error", result={}, deny_reason={"message": str(exc)})

    sys.stdout.write(json.dumps(result.to_dict()) + "\n")
    sys.stdout.flush()


def run_cli():
    """Simple CLI: python worker.py '{"name": "Alice"}'"""
    args = sys.argv[1:]
    if "--stdio" in args:
        run_stdio()
        return

    if args:
        try:
            request = json.loads(args[0])
        except (json.JSONDecodeError, IndexError):
            request = {}
    else:
        request = {}

    try:
        result = execute(request)
    except Exception as exc:
        result = WorkerResult(status="error", result={}, deny_reason={"message": str(exc)})

    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    run_cli()
