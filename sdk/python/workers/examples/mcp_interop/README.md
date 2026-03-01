# WCP / MCP Interop Example

This example answers the "why not just use MCP?" question.

**Short answer:** WCP is additive to MCP, not competitive with it. WCP workers can
be surfaced as MCP tools transparently. MCP clients see a tool. The WCP Hall
enforces governance before the worker ever runs.

---

## The Pattern

```
MCP client (Claude, Cursor, any MCP-compatible agent)
    |
    | JSON-RPC 2.0 over stdio (NDJSON)
    v
mcp_server.py  (adapter — this example)
    |
    | 1. Build WCP RouteInput from MCP tool call params
    | 2. pyhall.make_decision() -- rules engine + policy gate
    | 3. APPROVED: call wcp_worker.execute() with WorkerContext
    | 4. DENIED:   return MCP error with WCP deny reason
    v
MCP tool response (with wcp_governance metadata attached)
```

The WCP worker (`wcp_worker.py`) is unchanged. It has no knowledge of MCP.
The MCP server is a thin adapter layer.

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
pip install pyhall
```

### Run the MCP server

The server reads NDJSON from stdin and writes NDJSON to stdout (MCP stdio transport).

```bash
cd workers/examples/mcp_interop
python mcp_server.py
```

### Test with raw requests

Each line is one JSON-RPC 2.0 request. Pipe them to the server.

**Step 1 — MCP handshake (initialize):**

```bash
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}},"id":1}' \
  | python mcp_server.py
```

Expected output:
```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"pyhall-mcp-interop",...}}}
```

**Step 2 — List tools:**

```bash
echo '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}' \
  | python mcp_server.py
```

Returns the `summarize_document` tool definition.

**Step 3 — Call the tool (APPROVED path):**

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"summarize_document","arguments":{"text":"WCP defines a governed dispatch layer. Workers declare capabilities and risk. The Hall routes requests through rules and a policy gate. Every call produces a telemetry envelope."}},"id":3}' \
  | python mcp_server.py
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

**DENIED path (empty text):**

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"summarize_document","arguments":{"text":""}},"id":4}' \
  | python mcp_server.py
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

## What the MCP server does

### initialize

Standard MCP handshake. Returns server name, version, and capabilities
(`tools: {listChanged: false}`).

### tools/list

Returns the `summarize_document` tool definition with its JSON Schema input
schema. The MCP client uses this to know what tools are available and what
parameters they accept.

### tools/call

This is where WCP governance happens:

1. The MCP tool arguments are mapped to a `RouteInput`:
   - `capability_id = "cap.doc.summarize"`
   - `env` from the argument (default `"dev"`)
   - Standard governance fields: `data_label`, `tenant_risk`, `qos_class`
   - `correlation_id` auto-generated (UUID v4) for audit trail

2. `pyhall.make_decision()` runs the full WCP routing pipeline:
   - Rule matching (fail-closed on no match)
   - Preconditions check (correlation ID required)
   - Controls verification (registry must declare required controls)
   - Policy gate evaluation (`PolicyGate.evaluate()`)
   - Worker selection (first available candidate)

3. If `decision.denied == True`: return MCP error with WCP deny code and message.

4. If approved: build a `WorkerContext` from the decision, call
   `wcp_worker.execute(request, context)`.

5. Attach `wcp_governance` metadata to the response so the MCP client (and
   any observability tooling) can see the full audit trail.

---

## Customizing governance

### Replace the default PolicyGate

The default `PolicyGate` is a stub that allows everything. Override it:

```python
# In mcp_server.py, replace:
_POLICY_GATE = PolicyGate()

# With your org's policy engine:
class MyPolicyGate(PolicyGate):
    def evaluate(self, context):
        if context["env"] == "prod" and context["data_label"] == "RESTRICTED":
            return ("REQUIRE_HUMAN", "policy.v1", "restricted_data_requires_review")
        return ("ALLOW", "policy.v1", "default_allow")

_POLICY_GATE = MyPolicyGate()
```

### Add routing rules

Edit the `RULES` dict in `mcp_server.py`. Add rules for different environments,
data labels, or tenant risk tiers. The routing engine evaluates top-to-bottom;
first match wins.

### Swap the worker

Replace the `wcp_worker` import with any WCP-compliant worker. The MCP adapter
layer is independent of the worker implementation.

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

For more on WCP, see the [WCP Specification](https://github.com/fafolab/wcp/blob/main/WCP_SPEC.md).
