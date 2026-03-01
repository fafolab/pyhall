# hello_worker — Minimal Canonical WCP Worker

**capability_id:** `cap.hello.greet`
**worker_species_id:** `wrk.hello.greeter`
**risk_tier:** low

This is the simplest possible complete WCP worker. Use it as a template.

## What it does

Accepts a name and returns a greeting. That is all.

## Input

```json
{
  "name": "Alice",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "demo"
}
```

## Output

```json
{
  "status": "ok",
  "result": {
    "greeting": "Hello, Alice!",
    "name": "Alice",
    "worker_id": "org.example.hello-greeter"
  },
  "telemetry": [
    {
      "event_id": "evt.worker.executed.v1",
      "timestamp": "...",
      "correlation_id": "...",
      "worker_id": "org.example.hello-greeter",
      "capability_id": "cap.hello.greet",
      "status": "ok"
    }
  ],
  "evidence": [
    {
      "correlation_id": "...",
      "worker_id": "org.example.hello-greeter",
      "capability_id": "cap.hello.greet",
      "policy_decision": "ALLOW",
      "controls_verified": ["ctrl.obs.audit-log-append-only"],
      "artifact_hash": "sha256:..."
    }
  ]
}
```

## Run directly

```bash
python worker.py '{"name": "Alice", "correlation_id": "abc-123", "tenant_id": "demo"}'
```

## Enroll in the Hall

```bash
pyhall enroll registry_record.json --registry-dir /path/to/enrolled/
```

## Key patterns this demonstrates

1. **WorkerContext** — routing context propagated from the Hall
2. **WorkerResult** — standard response envelope (status, result, telemetry, evidence)
3. **Telemetry event** — `evt.worker.executed.v1` with correlation_id propagated
4. **Evidence receipt** — SHA-256 artifact hash proving what was executed
5. **Never raise** — all errors returned as WorkerResult with status="error"
6. **Stdio mode** — `--stdio` flag for MCP server integration
