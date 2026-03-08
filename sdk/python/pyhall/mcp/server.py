"""
pyhall.mcp.server — MCP stdio server that exposes a WCP worker as an MCP tool.

This is the MCP interop pattern for WCP. It proves that WCP workers can be
surfaced as MCP tools with zero changes to the worker itself. The MCP server
is a thin adapter: it translates MCP tool calls into WCP RouteInput, runs the
Hall's governance check, and if APPROVED, calls the worker.

Architecture:

    MCP client (Claude, Cursor, etc.)
        |
        | JSON-RPC 2.0 over stdio (NDJSON)
        v
    pyhall.mcp.server  <-- this file
        |
        | 1. Build RouteInput from MCP tool call params
        | 2. Call pyhall.make_decision() -- governance check
        | 3. If APPROVED: call worker.execute()
        | 4. If DENIED:   return MCP error with deny reason
        v
    MCP tool response

Transport: stdio (NDJSON — one JSON object per line)
Protocol:  JSON-RPC 2.0 (MCP 2024-11-05)

Handled requests:
    initialize         -- MCP handshake, returns server capabilities
    tools/list         -- Returns the summarize_document tool definition
    tools/call         -- Routes through WCP, executes worker, returns result
    resources/list     -- Lists available WCP resources (workers, catalog, dispatches)
    resources/read     -- Reads a resource by URI (wrk://, cap://, hall://)
    resources/subscribe    -- Stub (not yet implemented, returns empty result)
    resources/unsubscribe  -- Stub (not yet implemented, returns empty result)

Run the server:
    python -m pyhall.mcp
    pyhall-mcp

Test with a raw initialize request:
    echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}},"id":1}' | pyhall-mcp
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

# PyHall imports — WCP governance layer
from pyhall import (
    make_decision,
    RouteInput,
    PolicyGate,
    load_rules_from_dict,
)
from pyhall.registry import Registry

# Bundled example worker — swap this import to use your own WCP worker
from pyhall.mcp import example_worker as _worker_module
from pyhall.mcp.example_worker import WorkerContext


# ---------------------------------------------------------------------------
# Inline routing rules — no file dependency required
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
# Registry — in-memory, populated from the worker's registry record
# ---------------------------------------------------------------------------

def _build_registry() -> Registry:
    """Build an in-memory registry with the doc-summarizer enrolled."""
    registry = Registry()

    # Try loading from the examples directory (for backwards compat)
    record_path = Path(__file__).parent.parent.parent / "workers" / "examples" / "mcp_interop" / "registry_record.json"
    if record_path.exists():
        record = json.loads(record_path.read_text(encoding="utf-8"))
        registry.enroll(record)
    else:
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
try:
    _RULES = load_rules_from_dict(RULES)
except Exception as _rules_exc:
    raise RuntimeError(f"[pyhall-mcp] STARTUP FAILED: could not load routing rules: {_rules_exc}") from _rules_exc

try:
    _REGISTRY = _build_registry()
except Exception as _reg_exc:
    raise RuntimeError(f"[pyhall-mcp] STARTUP FAILED: could not build registry: {_reg_exc}") from _reg_exc

_POLICY_GATE = PolicyGate()
_WORKER_SPECIES_ID = "wrk.doc.summarizer"
_WORKER_SOURCE_FILE = Path(_worker_module.__file__ or __file__)
_MAX_TEXT_CHARS = 100_000

# ── Startup policy gate validation ──────────────────────────────────────────
# PYHALL_MCP_STRICT controls fail-safe behaviour for stub PolicyGate:
#   "1" (default) — stub PolicyGate is REJECTED at startup; all tool calls
#                   are blocked until a real PolicyGate subclass is injected.
#   "0"           — dev mode; stub PolicyGate is allowed; a warning is logged.
#
# PYHALL_ENV is a secondary guard: even with PYHALL_MCP_STRICT=0, a stub gate
# in stage/prod raises RuntimeError because the env labels carry explicit intent.
_STRICT_MODE = os.environ.get("PYHALL_MCP_STRICT", "1").strip() != "0"
_DEPLOYMENT_ENV = os.environ.get("PYHALL_ENV", "dev").lower()
_NON_DEV_ENVS = {"stage", "staging", "prod", "production"}

if getattr(_POLICY_GATE, "is_stub", True):
    if _STRICT_MODE:
        raise RuntimeError(
            "[pyhall-mcp] STARTUP FAILED: PolicyGate not configured — "
            "the default stub is ALLOW-all and cannot run in strict mode. "
            "Subclass PolicyGate, set is_stub=False, and inject a real policy. "
            "Set PYHALL_MCP_STRICT=0 for development mode or provide a policy provider."
        )
    elif _DEPLOYMENT_ENV in _NON_DEV_ENVS:
        raise RuntimeError(
            f"[pyhall-mcp] STARTUP FAILED: stub PolicyGate cannot run in "
            f"env='{_DEPLOYMENT_ENV}'. Governance would be silently ALLOW-all. "
            "Subclass PolicyGate, set is_stub=False, and inject a real policy. "
            "Set PYHALL_ENV=dev only for local development."
        )
    else:
        print(
            "[pyhall-mcp] WARNING: running in non-strict dev mode (PYHALL_MCP_STRICT=0). "
            "PolicyGate is a permissive stub — ALL tool calls will be ALLOWED without "
            "governance enforcement. Do NOT use this mode in production.",
            file=sys.stderr,
        )

# Register worker code attestation
try:
    _REGISTRY.register_attestation(_WORKER_SPECIES_ID, str(_WORKER_SOURCE_FILE))
except Exception as exc:
    print(f"[pyhall-mcp] attestation registration skipped: {exc}", file=sys.stderr)


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
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {
                    "subscribe": False,
                    "listChanged": False,
                },
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": "pyhall-mcp",
                "version": "0.3.0",
                "description": (
                    "WCP worker exposed as an MCP tool. "
                    "Every tool call passes through WCP Hall governance."
                ),
            },
        },
    }


def handle_tools_list(params: dict, req_id: Any) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "tools": [TOOL_SUMMARIZE_DOCUMENT],
        },
    }


def handle_tools_call(params: dict, req_id: Any) -> dict:
    if not isinstance(params, dict):
        return _mcp_error(req_id, -32602, "Invalid params: expected object")

    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    if tool_name != "summarize_document":
        return _mcp_error(req_id, -32601, f"Unknown tool: {tool_name!r}")
    if not isinstance(arguments, dict):
        return _mcp_error(req_id, -32602, "Invalid arguments: expected object")

    text_arg = arguments.get("text", "")
    if not isinstance(text_arg, str):
        return _mcp_error(req_id, -32602, "Invalid argument 'text': must be string")
    if len(text_arg) > _MAX_TEXT_CHARS:
        return _mcp_error(req_id, -32602, f"Input too large: text exceeds {_MAX_TEXT_CHARS} characters")

    max_sentences_raw = arguments.get("max_sentences", 3)
    try:
        max_sentences = int(max_sentences_raw)
    except Exception:
        return _mcp_error(req_id, -32602, "Invalid argument 'max_sentences': must be integer")
    max_sentences = max(1, min(max_sentences, 20))

    correlation_id = str(uuid.uuid4())
    env = arguments.get("env", "dev")
    if env not in ("dev", "stage", "prod", "edge"):
        env = "dev"

    # Defense-in-depth: if we somehow got past startup (e.g. PYHALL_MCP_STRICT=0),
    # still block non-dev envs with a stub gate, and block ALL envs in strict mode.
    if getattr(_POLICY_GATE, "is_stub", True):
        if _STRICT_MODE:
            return _mcp_error(
                req_id, -32603,
                "PolicyGate not configured — set PYHALL_MCP_STRICT=0 for "
                "development mode or provide a policy provider.",
            )
        elif env not in ("dev",):
            return _mcp_error(
                req_id, -32603,
                f"stub PolicyGate cannot evaluate '{env}' requests. "
                "Inject a real PolicyGate subclass for stage/prod governance.",
            )

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
                "text": text_arg,
                "max_sentences": max_sentences,
            },
        )
    except Exception as exc:
        return _mcp_error(req_id, -32602, f"Invalid RouteInput: {exc}")

    decision_kwargs: Dict[str, Any] = {}
    try:
        reg_hash, cur_hash = _REGISTRY.attestation_callables()
        decision_kwargs["registry_get_worker_hash"] = reg_hash
        decision_kwargs["get_current_worker_hash"] = cur_hash
    except Exception:
        pass

    decision = make_decision(
        inp=inp,
        rules=_RULES,
        registry_controls_present=_REGISTRY.controls_present(),
        registry_worker_available=_REGISTRY.worker_available,
        registry_get_privilege_envelope=_REGISTRY.get_privilege_envelope,
        registry_policy_allows_privilege=_REGISTRY.policy_allows_privilege,
        policy_gate_eval=_POLICY_GATE.evaluate,
        task_id=f"mcp_tools_call_{correlation_id[:8]}",
        **decision_kwargs,
    )

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
        worker_result = _worker_module.execute(worker_request, context)
    except Exception as exc:
        return _mcp_error(req_id, -32603, f"Worker execution error: {exc}")

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
# Prompt definitions
# ---------------------------------------------------------------------------

_PROMPTS = [
    {
        "name": "dispatch-worker",
        "description": "Dispatch a task to the best available WCP worker",
        "arguments": [
            {
                "name": "capability",
                "description": "WCP capability ID (e.g. cap.docs.summarize)",
                "required": True,
            },
            {
                "name": "task_description",
                "description": "What the worker should do",
                "required": True,
            },
            {
                "name": "agent_id",
                "description": "Your agent ID for attribution",
                "required": False,
            },
        ],
    },
    {
        "name": "explain-hold",
        "description": "Explain why a dispatch was put on steward hold",
        "arguments": [
            {
                "name": "dispatch_id",
                "description": "The dispatch event ID to look up",
                "required": True,
            },
        ],
    },
    {
        "name": "summarize-activity",
        "description": "Summarize recent Hall activity",
        "arguments": [
            {
                "name": "time_window",
                "description": "Time window to summarize (e.g. '1h', '24h'). Default: 1h",
                "required": False,
            },
        ],
    },
    {
        "name": "enroll-worker",
        "description": "Enroll a new WCP worker with Hall",
        "arguments": [
            {
                "name": "worker_spec",
                "description": "Description of the worker to enroll (capabilities, risk tier, etc.)",
                "required": True,
            },
        ],
    },
]

# Prompt message templates — arguments are interpolated at get time.
# Each value is a callable that receives the arguments dict and returns
# a list of MCP message objects.

def _prompt_dispatch_worker(args: dict) -> list:
    capability = args.get("capability", "<capability>")
    task_description = args.get("task_description", "<task_description>")
    agent_id = args.get("agent_id", "unspecified")
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": (
                    f"You need to dispatch a task to a WCP worker.\n\n"
                    f"Capability requested: {capability}\n"
                    f"Task description: {task_description}\n"
                    f"Agent ID: {agent_id}\n\n"
                    f"Steps:\n"
                    f"1. Read the wrk://workers resource to see enrolled workers that serve '{capability}'.\n"
                    f"2. Call the dispatch tool with capability='{capability}' and the task details.\n"
                    f"3. If the response contains wcp_denied=true, report the deny_code and message.\n"
                    f"4. If ALLOWED, relay the worker result and include the wcp_governance block for audit purposes.\n"
                    f"5. If the Hall Server is unreachable, inform the user and suggest running 'hall start'."
                ),
            },
        }
    ]


def _prompt_explain_hold(args: dict) -> list:
    dispatch_id = args.get("dispatch_id", "<dispatch_id>")
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": (
                    f"Explain why dispatch '{dispatch_id}' was put on steward hold.\n\n"
                    f"Steps:\n"
                    f"1. Read the hall://dispatches/recent resource and find the event with id='{dispatch_id}'.\n"
                    f"2. Identify the policy decision fields: deny_code, matched_rule_id, required_controls, policy_gate result.\n"
                    f"3. Explain in plain language why the request was held — which policy condition triggered it.\n"
                    f"4. Suggest remediation: what the operator or agent needs to change to get this dispatch approved.\n"
                    f"   Common reasons: missing required control, tenant risk too high, env restriction, policy gate escalation."
                ),
            },
        }
    ]


def _prompt_summarize_activity(args: dict) -> list:
    time_window = args.get("time_window", "1h")
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": (
                    f"Summarize Hall dispatch activity for the last {time_window}.\n\n"
                    f"Steps:\n"
                    f"1. Read the hall://dispatches/recent resource.\n"
                    f"2. Count total dispatches, ALLOWED vs DENIED outcomes, and unique capabilities.\n"
                    f"3. Identify any anomalies: repeated DENIED events for the same capability, "
                    f"unusual deny codes, or high-risk tenant dispatches.\n"
                    f"4. Present a concise summary: totals, top capabilities, top deny codes if any, "
                    f"and a one-sentence health assessment."
                ),
            },
        }
    ]


def _prompt_enroll_worker(args: dict) -> list:
    worker_spec = args.get("worker_spec", "<worker_spec>")
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": (
                    f"Enroll a new WCP worker with Hall.\n\n"
                    f"Worker specification: {worker_spec}\n\n"
                    f"Steps:\n"
                    f"1. Validate the spec — it must include: capability ID (cap.*), risk tier "
                    f"(low/medium/high/critical), and a brief description.\n"
                    f"2. Run 'hall scaffold <capability_id>' (or advise the user to) to generate "
                    f"the worker package: worker.py, registry_record.json, routing_rule_snippet.json.\n"
                    f"3. Review the generated registry_record.json — confirm required_controls, "
                    f"blast_radius, and privilege_envelope match the spec.\n"
                    f"4. Register with Hall Server: call the enroll tool or POST to /api/workers.\n"
                    f"5. Confirm enrollment by reading wrk://workers and finding the new worker."
                ),
            },
        }
    ]


_PROMPT_HANDLERS = {
    "dispatch-worker": _prompt_dispatch_worker,
    "explain-hold": _prompt_explain_hold,
    "summarize-activity": _prompt_summarize_activity,
    "enroll-worker": _prompt_enroll_worker,
}


# ---------------------------------------------------------------------------
# MCP prompt handlers
# ---------------------------------------------------------------------------

def handle_prompts_list(params: dict, req_id: Any) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "prompts": _PROMPTS,
        },
    }


def handle_prompts_get(params: dict, req_id: Any) -> dict:
    if not isinstance(params, dict):
        return _mcp_error(req_id, -32602, "Invalid params: expected object")

    name = params.get("name", "")
    if not name:
        return _mcp_error(req_id, -32602, "Missing required param: 'name'")

    prompt_def = next((p for p in _PROMPTS if p["name"] == name), None)
    if prompt_def is None:
        return _mcp_error(req_id, -32602, f"Unknown prompt: {name!r}")

    handler = _PROMPT_HANDLERS.get(name)
    if handler is None:
        return _mcp_error(req_id, -32603, f"No handler for prompt: {name!r}")

    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return _mcp_error(req_id, -32602, "Invalid 'arguments': expected object")

    # Validate required arguments
    for arg_def in prompt_def.get("arguments", []):
        if arg_def.get("required") and not arguments.get(arg_def["name"]):
            return _mcp_error(
                req_id, -32602,
                f"Missing required argument '{arg_def['name']}' for prompt '{name}'"
            )

    try:
        messages = handler(arguments)
    except Exception as exc:
        return _mcp_error(req_id, -32603, f"Error building prompt '{name}': {exc}")

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "description": prompt_def["description"],
            "messages": messages,
        },
    }


# ---------------------------------------------------------------------------
# completion/complete — stub handler (graceful empty response)
# ---------------------------------------------------------------------------

def handle_completion_complete(params: dict, req_id: Any) -> dict:
    """
    Stub completion handler. Returns an empty completions list.

    completions capability is NOT advertised in initialize (MCP spec: only
    advertise what you support). This handler exists to prevent -32601
    Method Not Found errors from clients that probe for completions support.
    """
    print(
        "[pyhall-mcp] completion/complete called (stub — returning empty completions)",
        file=sys.stderr,
    )
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "completion": {
                "values": [],
                "total": 0,
                "hasMore": False,
            },
        },
    }


# ---------------------------------------------------------------------------
# Resource helpers
# ---------------------------------------------------------------------------

_HALL_SERVER_BASE = "http://localhost:8765"
_HALL_SERVER_TIMEOUT = 2  # seconds

# Static resource descriptors returned by resources/list
_RESOURCE_LIST = [
    {
        "uri": "wrk://workers",
        "name": "Workers Registry",
        "description": "All enrolled WCP workers known to the Hall Server.",
        "mimeType": "application/json",
    },
    {
        "uri": "cap://catalog",
        "name": "Capability Catalog",
        "description": "WCP taxonomy of 245 capabilities across all packs.",
        "mimeType": "application/json",
    },
    {
        "uri": "hall://dispatches/recent",
        "name": "Dispatch History",
        "description": "Last 50 governed dispatch events with outcomes.",
        "mimeType": "application/json",
    },
]


def _fetch_hall_server(path: str) -> dict:
    """
    GET http://localhost:8765{path} with a short timeout.
    Returns parsed JSON dict, or a fallback dict with an 'error' key if
    the Hall Server is unreachable or returns a non-200 status.
    """
    url = f"{_HALL_SERVER_BASE}{path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pyhall-mcp/0.3.0"})
        with urllib.request.urlopen(req, timeout=_HALL_SERVER_TIMEOUT) as resp:
            raw = resp.read()
            return json.loads(raw)
    except Exception as exc:
        print(f"[pyhall-mcp] Hall Server unreachable ({url}): {exc}", file=sys.stderr)
        return {"error": f"Hall Server unreachable: {exc}", "data": []}


def _load_catalog() -> dict:
    """Load the WCP taxonomy catalog.json from the pyhall.taxonomy package."""
    try:
        import pyhall.taxonomy as _tax_pkg
        catalog_path = Path(_tax_pkg.__file__).parent / "catalog.json"
        return json.loads(catalog_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[pyhall-mcp] Failed to load taxonomy catalog: {exc}", file=sys.stderr)
        return {"error": f"Failed to load catalog: {exc}", "entities": []}


def _make_resource_content(uri: str, text: str) -> dict:
    """Wrap text in the MCP resource content envelope."""
    return {
        "uri": uri,
        "mimeType": "application/json",
        "text": text,
    }


# ---------------------------------------------------------------------------
# MCP resource handlers
# ---------------------------------------------------------------------------

def handle_resources_list(params: dict, req_id: Any) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "resources": _RESOURCE_LIST,
        },
    }


def handle_resources_read(params: dict, req_id: Any) -> dict:
    if not isinstance(params, dict):
        return _mcp_error(req_id, -32602, "Invalid params: expected object")

    uri = params.get("uri", "")
    if not isinstance(uri, str) or not uri:
        return _mcp_error(req_id, -32602, "Missing or invalid 'uri' param")

    # ── wrk://workers  ────────────────────────────────────────────────────
    if uri == "wrk://workers":
        data = _fetch_hall_server("/api/workers")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "contents": [_make_resource_content(uri, json.dumps(data, indent=2))]
            },
        }

    if uri.startswith("wrk://workers/"):
        worker_id = uri[len("wrk://workers/"):]
        data = _fetch_hall_server("/api/workers")
        workers = data.get("workers", [])
        match = next((w for w in workers if str(w.get("id", "")) == worker_id), None)
        if match is None:
            return _mcp_error(req_id, -32602, f"Worker not found: {worker_id!r}")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "contents": [_make_resource_content(uri, json.dumps(match, indent=2))]
            },
        }

    # ── cap://catalog  ────────────────────────────────────────────────────
    if uri == "cap://catalog":
        catalog = _load_catalog()
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "contents": [_make_resource_content(uri, json.dumps(catalog, indent=2))]
            },
        }

    if uri.startswith("cap://catalog/"):
        capability_id = uri[len("cap://catalog/"):]
        catalog = _load_catalog()
        entities = catalog.get("entities", [])
        match = next((e for e in entities if str(e.get("id", "")) == capability_id), None)
        if match is None:
            return _mcp_error(req_id, -32602, f"Capability not found: {capability_id!r}")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "contents": [_make_resource_content(uri, json.dumps(match, indent=2))]
            },
        }

    # ── hall://dispatches/recent  ─────────────────────────────────────────
    if uri == "hall://dispatches/recent":
        data = _fetch_hall_server("/api/dispatches/recent")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "contents": [_make_resource_content(uri, json.dumps(data, indent=2))]
            },
        }

    return _mcp_error(req_id, -32602, f"Unknown resource URI: {uri!r}")


def handle_resources_subscribe(params: dict, req_id: Any) -> dict:
    uri = (params or {}).get("uri", "<unknown>")
    print(f"[pyhall-mcp] resources/subscribe requested for {uri!r} (stub — not implemented)", file=sys.stderr)
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {},
    }


def handle_resources_unsubscribe(params: dict, req_id: Any) -> dict:
    uri = (params or {}).get("uri", "<unknown>")
    print(f"[pyhall-mcp] resources/unsubscribe requested for {uri!r} (stub — not implemented)", file=sys.stderr)
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {},
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
    "resources/list": handle_resources_list,
    "resources/read": handle_resources_read,
    "resources/subscribe": handle_resources_subscribe,
    "resources/unsubscribe": handle_resources_unsubscribe,
    "prompts/list": handle_prompts_list,
    "prompts/get": handle_prompts_get,
    "completion/complete": handle_completion_complete,
}

NOTIFICATIONS = {
    "notifications/initialized",
    "notifications/cancelled",
}


def dispatch(raw_line: str) -> Optional[dict]:
    """Parse one NDJSON line and dispatch to the appropriate handler."""
    try:
        msg = json.loads(raw_line.strip())
    except json.JSONDecodeError as exc:
        return _mcp_error(None, -32700, f"Parse error: {exc}")

    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method in NOTIFICATIONS or req_id is None:
        return None

    handler = HANDLERS.get(method)
    if handler is None:
        return _mcp_error(req_id, -32601, f"Method not found: {method!r}")

    try:
        return handler(params, req_id)
    except Exception as exc:
        return _mcp_error(req_id, -32603, f"Internal error: {exc}")


def run_stdio_loop() -> None:
    """
    Read NDJSON from stdin, write NDJSON responses to stdout.

    MCP stdio transport. One JSON object per line in both directions.
    stderr is used for debug/log output so it does not pollute the protocol stream.
    """
    print(
        "[pyhall-mcp] WCP/MCP interop server v0.3.0 started. Listening on stdin.",
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
