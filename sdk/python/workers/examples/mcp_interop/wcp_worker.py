"""
wcp_worker.py — WCP worker implementing cap.doc.summarize / wrk.doc.summarizer.

This worker takes a document (text) and returns a summary. It is intentionally
simple so the focus stays on the WCP governance layer and the MCP interop
pattern in mcp_server.py.

Species:    wrk.doc.summarizer
Capability: cap.doc.summarize

Run directly:
    python wcp_worker.py '{"text": "Long document...", "correlation_id": "abc", "tenant_id": "demo"}'

Stdio mode (for MCP server):
    echo '{"text": "Long document..."}' | python wcp_worker.py --stdio
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Standard WCP worker context and result dataclasses
# Copied from hello_worker pattern — every worker carries these.
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
# Worker identity constants (WCP spec section 6)
# ---------------------------------------------------------------------------

WORKER_ID = "org.example.doc-summarizer"
WORKER_SPECIES_ID = "wrk.doc.summarizer"
CAPABILITY_ID = "cap.doc.summarize"
RISK_TIER = "low"


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Core implementation
# ---------------------------------------------------------------------------

def _summarize(text: str, max_sentences: int) -> str:
    """
    Naive extractive summarizer: return the first N sentences.

    Real workers would call an LLM here. This stays dependency-free so the
    example runs without any additional installs.
    """
    # Split on common sentence terminators followed by whitespace
    import re
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    sentences = [s.strip() for s in sentences if s.strip()]
    if not sentences:
        return "(empty document)"
    selected = sentences[:max_sentences]
    return " ".join(selected)


def execute(request: dict, context: Optional[WorkerContext] = None) -> WorkerResult:
    """
    Execute cap.doc.summarize.

    Input:
        {
          "text":             "Full document text to summarize",  (required)
          "max_sentences":    3,                                  (optional, default 3)
          "correlation_id":   "...",                              (required for telemetry)
          "tenant_id":        "...",                              (required for telemetry)
          "capability_id":    "cap.doc.summarize"
        }

    Output:
        WorkerResult with:
          result.summary         = first N sentences
          result.word_count      = word count of input
          result.sentence_count  = total sentences in input
          telemetry              = [evt.worker.executed.v1]
          evidence               = [evidence_receipt]
    """
    correlation_id = (
        context.correlation_id if context else request.get("correlation_id", "unknown")
    )
    tenant_id = (
        context.tenant_id if context else request.get("tenant_id", "unknown")
    )

    text = request.get("text", "")
    if not text or not text.strip():
        return WorkerResult(
            status="error",
            deny_reason={"code": "INVALID_INPUT", "message": "Field 'text' is required and cannot be empty."},
        )

    max_sentences = int(request.get("max_sentences", 3))
    max_sentences = max(1, min(max_sentences, 20))  # clamp 1..20

    summary = _summarize(text, max_sentences)

    import re
    word_count = len(text.split())
    sentence_count = len(re.split(r'(?<=[.!?])\s+', text.strip()))

    # Telemetry event — workers must emit at minimum evt.worker.executed.v1
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
    payload_bytes = json.dumps(request, sort_keys=True).encode()
    artifact_hash = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()

    evidence_receipt = {
        "correlation_id": correlation_id,
        "dispatched_at": _now_utc(),
        "worker_id": WORKER_ID,
        "capability_id": CAPABILITY_ID,
        "policy_decision": "ALLOW",
        "controls_verified": ["ctrl.obs.audit_log_append_only"],
        "artifact_hash": artifact_hash,
    }

    return WorkerResult(
        status="ok",
        result={
            "summary": summary,
            "word_count": word_count,
            "sentence_count": sentence_count,
            "max_sentences_requested": max_sentences,
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
    """Simple CLI: python wcp_worker.py '{"text": "..."}'"""
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
        # Demo input when run with no args
        request = {
            "text": (
                "The Worker Class Protocol (WCP) defines a governed dispatch layer "
                "between agents and the workers they orchestrate. "
                "Workers declare their capabilities, risk tier, and privilege envelope. "
                "The Hall routes capability requests through a rules engine and policy gate. "
                "Every routing decision produces a signed telemetry envelope for audit. "
                "MCP clients can surface WCP workers as MCP tools transparently."
            ),
            "max_sentences": 3,
            "correlation_id": "demo-cli-001",
            "tenant_id": "demo",
        }

    try:
        result = execute(request)
    except Exception as exc:
        result = WorkerResult(status="error", result={}, deny_reason={"message": str(exc)})

    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    run_cli()
