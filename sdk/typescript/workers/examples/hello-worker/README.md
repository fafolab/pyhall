# hello-worker (TypeScript)

Minimal canonical WCP worker in TypeScript.

**Capability:** `cap.hello.greet`
**Species:** `wrk.hello.greeter`
**Worker ID:** `org.example.hello-greeter`
**Risk tier:** `low`

---

## What it does

Takes an optional `name` field and returns a greeting. Simple by design — the
focus is the worker contract, not the business logic.

Input:

```json
{
  "name": "Alice",
  "correlation_id": "test-123",
  "tenant_id": "demo",
  "capability_id": "cap.hello.greet"
}
```

Output (`WorkerResult`):

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
      "correlation_id": "test-123",
      "tenant_id": "demo",
      "worker_id": "org.example.hello-greeter",
      "worker_species_id": "wrk.hello.greeter",
      "capability_id": "cap.hello.greet",
      "status": "ok"
    }
  ],
  "evidence": [
    {
      "correlation_id": "test-123",
      "dispatched_at": "...",
      "worker_id": "org.example.hello-greeter",
      "capability_id": "cap.hello.greet",
      "policy_decision": "ALLOW",
      "controls_verified": ["ctrl.obs.audit-log-append-only"],
      "artifact_hash": "sha256:..."
    }
  ]
}
```

---

## Run

Build the SDK first (from the `sdk/typescript/` root):

```bash
npm run build
```

Then run the worker directly:

```bash
# Pass request as a CLI argument
node dist/workers/examples/hello-worker/worker.js '{"name": "Alice", "correlation_id": "test-123", "tenant_id": "demo"}'

# Default (name defaults to "World")
node dist/workers/examples/hello-worker/worker.js

# stdio mode — pipe JSON in, get JSON out
echo '{"name": "Alice"}' | node dist/workers/examples/hello-worker/worker.js --stdio
```

---

## Enroll

```bash
pyhall enroll registry-record.json --registry-dir enrolled/
```

`registry-record.json` declares:

- `worker_id`: `org.example.hello-greeter`
- `capabilities`: `["cap.hello.greet"]`
- `risk_tier`: `low`
- `allowed_environments`: `["dev", "stage", "prod"]`
- `required_controls` / `currently_implements`: `["ctrl.obs.audit-log-append-only"]`
- `blast_radius`: all zeros, `reversibility: reversible`

---

## Worker contract

This worker follows the canonical WCP worker pattern:

- `execute(request)` accepts a plain object, returns a `WorkerResult`.
- Never throws — all errors are returned as `status: "error"`.
- Emits `evt.worker.executed.v1` in `telemetry`.
- Produces an evidence receipt with `artifact_hash` (SHA-256 of the
  canonicalized request).
- `correlation_id` propagates through all telemetry and evidence fields.

Use this as a template for your own TypeScript workers.
