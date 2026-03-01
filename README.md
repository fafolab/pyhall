# PyHall

**PyHall** is the reference implementation of the [Worker Class Protocol (WCP)](https://github.com/fafolab/wcp) — an open standard for governing AI agent worker dispatch.

WCP defines how AI systems route capability requests to workers: which worker handles which task, under what controls, with a full audit trail. PyHall implements the complete routing engine, registry, policy gate, conformance validation, and telemetry layer.

---

## Implementations

| Language | Package | Status |
|----------|---------|--------|
| Python | `pip install pyhall` | Reference implementation — production ready |
| TypeScript | `npm install @pyhall/core` | Full port |
| Go | `go get github.com/fafolab/pyhall/sdk/go` | Scaffold / interfaces |

---

## Quick Start (Python)

```bash
pip install pyhall
```

```python
from pyhall import make_decision, RouteInput

decision = make_decision(RouteInput(
    capability_id="cap.doc.summarize",
    tenant_id="acme",
    environment="prod",
    requestor_id="agent-1",
    data_label="internal",
    qos_class="standard",
))

print(decision.outcome)   # ALLOW
print(decision.worker_id) # wrk.doc.summarizer
```

See [pyhall.dev](https://pyhall.dev) for full documentation.

---

## Repository Layout

```
sdk/python/          — Python SDK (pyhall)
sdk/typescript/      — TypeScript SDK (@pyhall/core)
sdk/go/              — Go SDK
apps/cli/typescript/ — pyhall CLI
apps/desktop/        — Hall Monitor desktop app (Tauri v2)
```

---

## Spec

The protocol specification lives at [github.com/fafolab/wcp](https://github.com/fafolab/wcp).

---

## License

Apache 2.0
