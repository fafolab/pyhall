# WCP Worker Examples (Python)

Canonical worker examples for the PyHall Python SDK.

---

## Examples

### hello_worker — Start here

The minimal complete WCP worker. Implements `cap.hello.greet` / `wrk.hello.greeter`.

Use it to understand the full worker contract before building your own.

```
hello_worker/
  worker.py            — implementation (~190 lines, fully commented)
  registry_record.json — enrollment record (required fields explained)
  rules.json           — routing rules for use with make_decision()
  README.md            — what it does, input/output, patterns
```

Run directly:

```bash
python hello_worker/worker.py '{"name": "Alice", "correlation_id": "test-001", "tenant_id": "demo"}'
```

Stdio mode:

```bash
echo '{"name": "Alice"}' | python hello_worker/worker.py --stdio
```

### mcp_interop — WCP worker exposed as an MCP tool

Shows how to surface a WCP worker as an MCP tool with zero changes to the
worker. An MCP client calls a standard tool. The WCP Hall runs governance
(rules engine + policy gate) before the worker executes.

```
mcp_interop/
  wcp_worker.py        — WCP worker: cap.doc.summarize / wrk.doc.summarizer
  mcp_server.py        — MCP stdio adapter that wraps the worker
  registry_record.json — Worker enrollment record
  README.md            — Architecture, PolicyGate enforcement, Claude Code config
```

Run the MCP server (dev mode):

```bash
PYHALL_MCP_STRICT=0 python mcp_interop/mcp_server.py
```

See `mcp_interop/README.md` for the full walkthrough, including how to add
this server to Claude Code or Cursor via `.mcp.json`.

---

## Building your own worker

1. Copy `hello_worker/` to a new directory.
2. Rename `worker_id` and `worker_species_id` in `registry_record.json`.
3. Change `capabilities` to the capability you want to implement.
4. Replace the `execute()` function body with your logic.
5. Enroll: `pyhall enroll registry_record.json --registry-dir enrolled/`

---

## Worker naming conventions

**Worker ID** (`worker_id`) — your unique instance:

```
org.<your-org>.<your-worker-name>
```

**Worker species** (`worker_species_id`) — the WCP class:

```
wrk.<domain>.<role>
```

**Capability** (`capabilities`) — what it implements:

```
cap.<domain>.<verb>
```

Example:

```json
{
  "worker_id":         "org.acme.pdf-summarizer",
  "worker_species_id": "wrk.doc.summarizer",
  "capabilities":      ["cap.doc.summarize"]
}
```

---

## The worker contract

Every canonical WCP worker:

- Accepts a JSON dict request.
- Returns a `WorkerResult` (`status`, `result`, `telemetry`, `evidence`).
- Never raises — all errors returned as `status: "error"`.
- Propagates `correlation_id` through all telemetry events.
- Produces an evidence receipt with `artifact_hash` (SHA-256 of the request).

See `hello_worker/worker.py` for the complete pattern.
