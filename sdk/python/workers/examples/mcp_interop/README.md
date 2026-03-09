# WCP / MCP Interop Example

This example answers the "why not just use MCP?" question.

**Short answer:** WCP is additive to MCP, not competitive with it. WCP workers can
be surfaced as MCP tools transparently. MCP clients see a standard tool. The WCP Hall
enforces governance before the worker ever runs.

---

## Architecture

```
MCP client (Claude Code, Cursor, any MCP-compatible agent)
    |
    | JSON-RPC 2.0 over stdio (NDJSON)
    v
mcp_server.py  (adapter — this example)
    |
    | 1. Build WCP RouteInput from MCP tool call params
    | 2. pyhall.make_decision() — rules engine + policy gate
    | 3. APPROVED: call wcp_worker.execute() with WorkerContext
    | 4. DENIED:   return MCP error with WCP deny reason
    v
MCP tool response (with wcp_governance metadata attached)
```

`wcp_worker.py` is unchanged. It has no knowledge of MCP.
`mcp_server.py` is a thin adapter layer.

---

## Files

| File | Purpose |
|------|---------|
| `wcp_worker.py` | WCP worker — `cap.doc.summarize` / `wrk.doc.summarizer` |
| `mcp_server.py` | MCP stdio server that wraps the WCP worker as an MCP tool |
| `registry_record.json` | Worker enrollment record (WCP spec section 6) |
| `README.md` | This file |

---

## Quick start

### Prerequisites

```bash
pip install pyhall-wcp
```

### Run the MCP server

The server reads NDJSON from stdin and writes NDJSON to stdout (MCP stdio transport).
By default it starts in strict mode — see [PolicyGate enforcement](#policygate-enforcement) below.

To run in dev mode (stub PolicyGate allowed):

```bash
PYHALL_MCP_STRICT=0 python mcp_server.py
```

---

## PolicyGate enforcement

The `PolicyGate` controls whether tool calls are actually governed. Two environment
variables control startup behavior.

### PYHALL_MCP_STRICT

| Value | Behavior |
|-------|----------|
| `1` (default) | **Strict mode.** Server fails at startup if the default stub `PolicyGate` is in use. All tool calls are blocked until a real `PolicyGate` subclass is injected. |
| `0` | **Dev mode.** Stub `PolicyGate` is allowed. A warning is printed to stderr. Tool calls proceed with ALLOW-all governance. |

### PYHALL_ENV

A secondary guard on top of `PYHALL_MCP_STRICT`.

Even with `PYHALL_MCP_STRICT=0`, if `PYHALL_ENV` is set to `stage`, `staging`,
`prod`, or `production`, the server fails at startup with a `RuntimeError`. Setting
`PYHALL_ENV=prod` signals explicit production intent — a stub gate is never
acceptable there regardless of the strict flag.

| PYHALL_MCP_STRICT | PYHALL_ENV | Result |
|---|---|---|
| `1` (default) | any | Fails startup if stub PolicyGate |
| `0` | `dev` (default) | Starts with warning — stub allowed |
| `0` | `prod` / `stage` | Fails startup — env label overrides |
| `0` | `dev` + non-dev `env` arg in tool call | Tool call blocked at request time |

**Defense-in-depth at request time:** Even if the server starts in dev mode
(`PYHALL_MCP_STRICT=0`), any `tools/call` that passes `env=stage` or `env=prod` in
the arguments is rejected immediately. The stub gate cannot evaluate non-dev requests.

### Providing a real PolicyGate

```python
# In mcp_server.py, replace:
_POLICY_GATE = PolicyGate()

# With your org's policy engine:
class MyPolicyGate(PolicyGate):
    is_stub = False

    def evaluate(self, context):
        if context["env"] == "prod" and context["data_label"] == "RESTRICTED":
            return ("REQUIRE_HUMAN", "policy.v1", "restricted_data_requires_review")
        return ("ALLOW", "policy.v1", "default_allow")

_POLICY_GATE = MyPolicyGate()
```

---

## Test with raw requests

Each line is one JSON-RPC 2.0 request. Pipe them to the server.

**Step 1 — MCP handshake (initialize):**

```bash
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}},"id":1}' \
  | PYHALL_MCP_STRICT=0 python mcp_server.py
```

Expected output:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"pyhall-mcp-interop","version":"0.1.0","description":"WCP worker exposed as an MCP tool. Every tool call passes through WCP Hall governance."}}}
```

**Step 2 — List tools:**

```bash
echo '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}' \
  | PYHALL_MCP_STRICT=0 python mcp_server.py
```

Returns the `summarize_document` tool definition with its full JSON Schema.

**Step 3 — Call the tool (APPROVED path):**

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"summarize_document","arguments":{"text":"WCP defines a governed dispatch layer. Workers declare capabilities and risk. The Hall routes requests through rules and a policy gate. Every call produces a telemetry envelope."}},"id":3}' \
  | PYHALL_MCP_STRICT=0 python mcp_server.py
```

The response includes both the worker result and WCP governance metadata:

```json
{
  "result": {
    "summary": "WCP defines a governed dispatch layer. Workers declare capabilities and risk.",
    "word_count": 30,
    "sentence_count": 4,
    "max_sentences_requested": 3,
    "worker_id": "org.example.doc-summarizer"
  },
  "wcp_governance": {
    "decision_id": "...",
    "matched_rule_id": "rr_doc_summarize_dev",
    "selected_worker": "wrk.doc.summarizer",
    "correlation_id": "...",
    "controls_enforced": ["ctrl.obs.audit_log_append_only"],
    "telemetry_events": 1,
    "evidence_receipts": 1
  }
}
```

**Step 4 — DENIED path (empty text):**

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"summarize_document","arguments":{"text":""}},"id":4}' \
  | PYHALL_MCP_STRICT=0 python mcp_server.py
```

Returns `isError: true` with the WCP deny reason:

```json
{
  "wcp_worker_error": true,
  "status": "error",
  "deny_reason": {
    "code": "INVALID_INPUT",
    "message": "Field 'text' is required and cannot be empty."
  }
}
```

---

## Use with Claude Code or Cursor

Add the server to your MCP config. Claude Code reads `.mcp.json` in the project root
(or `~/.claude/mcp.json` for global config).

### .mcp.json

```json
{
  "mcpServers": {
    "pyhall-wcp": {
      "command": "python",
      "args": ["/path/to/sdk/python/workers/examples/mcp_interop/mcp_server.py"],
      "env": {
        "PYHALL_MCP_STRICT": "0",
        "PYHALL_ENV": "dev"
      }
    }
  }
}
```

Replace `/path/to/sdk/python/...` with the absolute path on your machine.

For production, omit the `env` block and inject a real `PolicyGate` subclass
(see [PolicyGate enforcement](#policygate-enforcement) above).

### Cursor MCP config

Cursor uses `~/.cursor/mcp.json` with the same structure as `.mcp.json` above.

---

## What the MCP server handles

### initialize

Standard MCP handshake. Returns server name (`pyhall-mcp-interop`), version, and
capabilities (`tools: {listChanged: false}`).

### tools/list

Returns the `summarize_document` tool definition. Input schema:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | string | yes | Document text to summarize (max 100,000 chars) |
| `max_sentences` | integer | no | Sentences in summary, 1–20, default 3 |
| `env` | enum | no | WCP environment: `dev` \| `stage` \| `prod`, default `dev` |

### tools/call

Where WCP governance happens:

1. MCP tool arguments are mapped to a `RouteInput`:
   - `capability_id = "cap.doc.summarize"`
   - `env` from the argument (default `"dev"`)
   - `correlation_id` auto-generated (UUID v4) for the audit trail
   - `data_label = "PUBLIC"`, `tenant_risk = "low"`, `qos_class = "P2"`

2. `pyhall.make_decision()` runs the full WCP routing pipeline:
   - Rule matching (fail-closed on no match)
   - Preconditions check (correlation ID required)
   - Controls verification (registry must declare required controls)
   - Policy gate evaluation (`PolicyGate.evaluate()`)
   - Worker selection (first available candidate)

3. If `decision.denied`: return `isError: true` with WCP deny code and message.

4. If approved: build a `WorkerContext` from the decision, call
   `wcp_worker.execute(request, context)`.

5. Attach `wcp_governance` metadata to the response.

### Notifications

`notifications/initialized` and `notifications/cancelled` are received and silently
dropped (no response, as per MCP spec).

---

## wcp_governance field

Every successful tool response includes a `wcp_governance` object:

```json
{
  "wcp_governance": {
    "decision_id":      "unique ID for this routing decision",
    "matched_rule_id":  "rr_doc_summarize_dev",
    "selected_worker":  "wrk.doc.summarizer",
    "correlation_id":   "UUID v4 — trace this through your audit log",
    "controls_enforced": ["ctrl.obs.audit_log_append_only"],
    "telemetry_events": 1,
    "evidence_receipts": 1
  }
}
```

This metadata is surfaced to the MCP client. Any observability tooling that reads
MCP responses can extract it for audit or monitoring.

---

## Customizing

### Add routing rules

Edit the `RULES` dict in `mcp_server.py`. Rules evaluate top-to-bottom; first match
wins. The example includes rules for `env=dev` and `env=stage|prod`:

```python
{
    "rule_id": "rr_doc_summarize_dev",
    "match": {
        "capability_id": "cap.doc.summarize",
        "env": "dev",
    },
    "decision": { ... }
}
```

### Swap the worker

Replace the `wcp_worker` import with any WCP-compliant worker. The MCP adapter layer
is independent of the worker implementation.

---

## Why this matters

MCP defines a *transport and tool protocol* — how agents discover and invoke tools.

WCP defines a *governance and dispatch protocol* — which workers can run, under
what conditions, with what controls enforced, with what audit trail.

They solve different problems. This example shows they compose cleanly:

- The MCP client sees a standard tool. No WCP knowledge required.
- The WCP Hall enforces governance before anything executes.
- The worker is unchanged — it has no knowledge of MCP.
- The audit trail (correlation IDs, telemetry, evidence receipts) flows through
  every layer.

For more on WCP, see the [WCP Specification](https://github.com/workerclassprotocol/wcp/blob/main/WCP_SPEC.md).
