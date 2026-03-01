"""
mcp_server.py — MCP stdio server that exposes a WCP worker as an MCP tool.

This is the MCP interop pattern for WCP. It proves that WCP workers can be
surfaced as MCP tools with zero changes to the worker itself. The MCP server
is a thin adapter: it translates MCP tool calls into WCP RouteInput, runs the
Hall's governance check, and if APPROVED, calls the worker.

Architecture:

    MCP client (Claude, Cursor, etc.)
        |
        | JSON-RPC 2.0 over stdio (NDJSON)
        v
    mcp_server.py  <-- this file
        |
        | 1. Build RouteInput from MCP tool call params
        | 2. Call pyhall.make_decision() -- governance check
        | 3. If APPROVED: call wcp_worker.execute()
        | 4. If DENIED:   return MCP error with deny reason
        v
    MCP tool response

Transport: stdio (NDJSON — one JSON object per line)
Protocol:  JSON-RPC 2.0 (MCP 2024-11-05)

Handled requests:
    initialize      -- MCP handshake, returns server capabilities
    tools/list      -- Returns the summarize_document tool definition
    tools/call      -- Routes through WCP, executes worker, returns result

Run the server:
    python mcp_server.py

Test with a raw initialize request:
    echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}},"id":1}' | python mcp_server.py
"""

from __future__ import annotations

import json
import sys
import uuid
from typing import Any, Dict, Optional

# PyHall imports — WCP governance layer
from pyhall import (
    make_decision,
    RouteInput,
    PolicyGate,
    load_rules_from_dict,
)
from pyhall.registry import Registry

# The WCP worker this server wraps
import wcp_worker
from wcp_worker import WorkerContext


# ---------------------------------------------------------------------------
# Inline routing rules — no file dependency required
#
# Rules define: which capability maps to which worker species, under what
# conditions, with what controls and escalation policy.
#
# The policy_gate: True here means every call passes through PolicyGate.evaluate()
# before the worker runs. The default PolicyGate is a stub (ALLOW-all). Replace
# it with your org's policy engine to enforce real governance.
# ---------------------------------------------------------------------------

RULES = {
    "rules": [
        {
            "rule_id": "rr_doc_summarize_dev",
            "match": {
                "capability_id": "cap.doc.summarize",
                "env": "dev",
            },
            "decision": {
                "candidate_workers_ranked": [
                    {"worker_species_id": "wrk.doc.summarizer", "score_hint": 1.0}
                ],
                "required_controls_suggested": ["ctrl.obs.audit_log_append_only"],
                "escalation": {
                    "policy_gate": True,
                    "human_required_default": False,
                },
                "preconditions": {},
            },
        },
        {
            "rule_id": "rr_doc_summarize_stage_prod",
            "match": {
                "capability_id": "cap.doc.summarize",
                "env": {"in": ["stage", "prod"]},
            },
            "decision": {
                "candidate_workers_ranked": [
                    {"worker_species_id": "wrk.doc.summarizer", "score_hint": 1.0}
                ],
                "required_controls_suggested": ["ctrl.obs.audit_log_append_only"],
                "escalation": {
                    "policy_gate": True,
                    "human_required_default": False,
                },
                "preconditions": {},
            },
        },
    ]
}


# ---------------------------------------------------------------------------
# Registry — in-memory, populated from the worker's registry_record.json
# ---------------------------------------------------------------------------

def _build_registry() -> Registry:
    """Build an in-memory registry with the doc-summarizer enrolled."""
    import json
    from pathlib import Path

    registry = Registry()

    record_path = Path(__file__).parent / "registry_record.json"
    if record_path.exists():
        record = json.loads(record_path.read_text(encoding="utf-8"))
        registry.enroll(record)
    else:
        # Fallback: enroll inline so the server always starts
        registry.enroll({
            "worker_id": "org.example.doc-summarizer",
            "worker_species_id": "wrk.doc.summarizer",
            "capabilities": ["cap.doc.summarize"],
            "risk_tier": "low",
            "required_controls": ["ctrl.obs.audit_log_append_only"],
            "currently_implements": ["ctrl.obs.audit_log_append_only"],
            "allowed_environments": ["dev", "stage", "prod"],
            "blast_radius": {"data": 0, "network": 0, "financial": 0, "time": 1, "reversibility": "reversible"},
            "privilege_envelope": {"secrets_access": [], "network_egress": "none", "filesystem_writes": [], "tools": []},
            "owner": "org.example",
            "contact": "you@example.com",
        })

    return registry


# Module-level singletons (initialized once at startup)
_RULES = load_rules_from_dict(RULES)
_REGISTRY = _build_registry()
_POLICY_GATE = PolicyGate()


# ---------------------------------------------------------------------------
# MCP tool definition
# ---------------------------------------------------------------------------

TOOL_SUMMARIZE_DOCUMENT = {
    "name": "summarize_document",
    "description": (
        "Summarize a document using WCP-governed dispatch. "
        "The request passes through the WCP Hall (rules engine + policy gate) "
        "before the worker executes. Governance is enforced transparently."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The document text to summarize.",
            },
            "max_sentences": {
                "type": "integer",
                "description": "Maximum number of sentences to include in the summary (1-20, default 3).",
                "default": 3,
                "minimum": 1,
                "maximum": 20,
            },
            "env": {
                "type": "string",
                "description": "WCP environment: dev | stage | prod. Default: dev.",
                "enum": ["dev", "stage", "prod"],
                "default": "dev",
            },
        },
        "required": ["text"],
    },
}


# ---------------------------------------------------------------------------
# MCP request handlers
# ---------------------------------------------------------------------------

def handle_initialize(params: dict, req_id: Any) -> dict:
    """
    MCP initialize handshake.

    Returns server capabilities. The client sends this first; the server
    responds with its name, version, and what capabilities it supports.
    """
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": "pyhall-mcp-interop",
                "version": "0.1.0",
                "description": (
                    "WCP worker exposed as an MCP tool. "
                    "Every tool call passes through WCP Hall governance."
                ),
            },
        },
    }


def handle_tools_list(params: dict, req_id: Any) -> dict:
    """Return the list of tools this MCP server exposes."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "tools": [TOOL_SUMMARIZE_DOCUMENT],
        },
    }


def handle_tools_call(params: dict, req_id: Any) -> dict:
    """
    Handle a tools/call request.

    Flow:
        1. Extract tool name and arguments from the MCP request.
        2. Build a WCP RouteInput from the arguments.
        3. Call pyhall.make_decision() — governance check.
        4. If DENIED: return MCP error with WCP deny reason.
        5. If APPROVED: call wcp_worker.execute() with proper WorkerContext.
        6. Return worker result as MCP tool response.
    """
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    if tool_name != "summarize_document":
        return _mcp_error(req_id, -32601, f"Unknown tool: {tool_name!r}")

    # ------------------------------------------------------------------
    # Step 1: Build WCP RouteInput from MCP tool call parameters
    # ------------------------------------------------------------------
    correlation_id = str(uuid.uuid4())
    env = arguments.get("env", "dev")
    # Validate env value
    if env not in ("dev", "stage", "prod", "edge"):
        env = "dev"

    try:
        inp = RouteInput(
            capability_id="cap.doc.summarize",
            env=env,                   # type: ignore[arg-type]
            data_label="PUBLIC",
            tenant_risk="low",
            qos_class="P2",
            tenant_id="mcp-client",
            correlation_id=correlation_id,
            request={
                "text": arguments.get("text", ""),
                "max_sentences": arguments.get("max_sentences", 3),
            },
        )
    except Exception as exc:
        return _mcp_error(req_id, -32602, f"Invalid RouteInput: {exc}")

    # ------------------------------------------------------------------
    # Step 2: WCP governance check via the Hall
    # ------------------------------------------------------------------
    decision = make_decision(
        inp=inp,
        rules=_RULES,
        registry_controls_present=_REGISTRY.controls_present(),
        registry_worker_available=_REGISTRY.worker_available,
        registry_get_privilege_envelope=_REGISTRY.get_privilege_envelope,
        registry_policy_allows_privilege=_REGISTRY.policy_allows_privilege,
        policy_gate_eval=_POLICY_GATE.evaluate,
        task_id=f"mcp_tools_call_{correlation_id[:8]}",
    )

    # ------------------------------------------------------------------
    # Step 3: DENIED — return MCP error with WCP deny reason
    # ------------------------------------------------------------------
    if decision.denied:
        deny = decision.deny_reason_if_denied or {}
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "wcp_denied": True,
                            "deny_code": deny.get("code", "UNKNOWN"),
                            "deny_message": deny.get("message", "Request denied by WCP Hall."),
                            "matched_rule_id": decision.matched_rule_id,
                            "correlation_id": correlation_id,
                        }, indent=2),
                    }
                ],
                "isError": True,
            },
        }

    # ------------------------------------------------------------------
    # Step 4: APPROVED — build WorkerContext and call the worker
    # ------------------------------------------------------------------
    context = WorkerContext(
        correlation_id=correlation_id,
        tenant_id=inp.tenant_id,
        env=inp.env,
        data_label=inp.data_label,
        qos_class=inp.qos_class,
        capability_id=inp.capability_id,
        policy_version="policy.v0",
    )

    worker_request = {
        **inp.request,
        "correlation_id": correlation_id,
        "tenant_id": inp.tenant_id,
        "capability_id": inp.capability_id,
    }

    try:
        worker_result = wcp_worker.execute(worker_request, context)
    except Exception as exc:
        return _mcp_error(req_id, -32603, f"Worker execution error: {exc}")

    # ------------------------------------------------------------------
    # Step 5: Return worker result as MCP tool response
    # ------------------------------------------------------------------
    if worker_result.status != "ok":
        deny_info = worker_result.deny_reason or {"message": "Worker returned non-ok status"}
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "wcp_worker_error": True,
                            "status": worker_result.status,
                            "deny_reason": deny_info,
                            "correlation_id": correlation_id,
                        }, indent=2),
                    }
                ],
                "isError": True,
            },
        }

    # Success — return the worker result with WCP governance metadata attached
    response_payload = {
        "result": worker_result.result,
        "wcp_governance": {
            "decision_id": decision.decision_id,
            "matched_rule_id": decision.matched_rule_id,
            "selected_worker": decision.selected_worker_species_id,
            "correlation_id": correlation_id,
            "controls_enforced": decision.required_controls_effective,
            "telemetry_events": len(worker_result.telemetry),
            "evidence_receipts": len(worker_result.evidence),
        },
    }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(response_payload, indent=2),
                }
            ],
            "isError": False,
        },
    }


# ---------------------------------------------------------------------------
# MCP error helper
# ---------------------------------------------------------------------------

def _mcp_error(req_id: Any, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


# ---------------------------------------------------------------------------
# MCP stdio dispatch loop
# ---------------------------------------------------------------------------

HANDLERS = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
}

# Notifications (no id, no response required)
NOTIFICATIONS = {
    "notifications/initialized",
    "notifications/cancelled",
}


def dispatch(raw_line: str) -> Optional[dict]:
    """
    Parse one NDJSON line and dispatch to the appropriate handler.

    Returns a response dict, or None for notifications (which need no reply).
    """
    try:
        msg = json.loads(raw_line.strip())
    except json.JSONDecodeError as exc:
        return _mcp_error(None, -32700, f"Parse error: {exc}")

    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    # Notifications: no id, no response
    if method in NOTIFICATIONS or req_id is None:
        return None

    handler = HANDLERS.get(method)
    if handler is None:
        return _mcp_error(req_id, -32601, f"Method not found: {method!r}")

    try:
        return handler(params, req_id)
    except Exception as exc:
        return _mcp_error(req_id, -32603, f"Internal error: {exc}")


def run_stdio_loop():
    """
    Read NDJSON from stdin, write NDJSON responses to stdout.

    This is the MCP stdio transport. One JSON object per line in both
    directions. stderr is used for debug/log output so it does not
    pollute the protocol stream.
    """
    print(
        "[pyhall-mcp] WCP/MCP interop server started. Listening on stdin.",
        file=sys.stderr,
    )
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        response = dispatch(line)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_loop()
