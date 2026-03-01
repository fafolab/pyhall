# WCP Worker Examples

This directory contains canonical worker examples for PyHall.

## hello_worker — Start Here

The minimal complete WCP worker. Implements `cap.hello.greet`.

Use it to understand the structure before building your own.

```
hello_worker/
  worker.py           — implementation (~100 lines, fully commented)
  registry_record.json — enrollment record (required fields explained)
  README.md            — what it does, input/output, patterns
```

## Building Your Own Worker

1. Copy `hello_worker/` to a new directory
2. Rename `worker_id` and `worker_species_id` in `registry_record.json`
3. Change `capabilities` to the capability you want to implement
4. Replace the `execute()` function body with your logic
5. Enroll: `pyhall enroll registry_record.json --registry-dir enrolled/`

## Worker Naming Conventions

**Worker ID** (`worker_id`) — your unique instance:
```
org.<your-org>.<your-worker-name>
```

**Worker Species** (`worker_species_id`) — the WCP class:
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

## The Worker Contract

Every canonical WCP worker:
- Accepts a JSON dict request
- Returns a WorkerResult (status, result, telemetry, evidence)
- Never raises — all errors returned as `status: "error"`
- Propagates `correlation_id` through all telemetry events
- Produces an evidence receipt with `artifact_hash`

See `hello_worker/worker.py` for the complete pattern.
