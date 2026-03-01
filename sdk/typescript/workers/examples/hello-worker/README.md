# hello-worker (TypeScript)

Minimal canonical WCP worker in TypeScript.

**Capability:** `cap.hello.greet`
**Species:** `wrk.hello.greeter`
**Risk tier:** `low`

## Usage

```bash
# After building: npm run build
node dist/workers/examples/hello-worker/worker.js '{"name": "Alice", "correlation_id": "test-123", "tenant_id": "demo"}'

# stdio mode
echo '{"name": "Alice"}' | node dist/workers/examples/hello-worker/worker.js --stdio
```

## Enroll

```bash
pyhall enroll registry-record.json --registry-dir enrolled/
```
