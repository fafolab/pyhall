# PyHall

**The Python reference implementation of WCP — Worker Class Protocol.**

The first open standard for governing AI worker dispatch.

PyHall is the governed layer between a capability request and its execution.
It answers the question every agentic system ignores: *should this worker be trusted with this job, under these conditions, with this data?*

## The Union Hall Metaphor

Agents are like contractors. Contractors who are signatory to a union can hire
trained, certified workers through the Hall. When an agent needs a worker,
they contact PyHall.

PyHall is the Hall.

- Workers **enroll** in the Hall with a registry record declaring their capabilities and controls.
- Agents make **capability requests** — not "call tool X", but "I need `cap.doc.summarize`".
- The Hall **routes** the request to the best available worker, verifying controls and computing blast radius.
- The Hall returns a **RouteDecision** — an evidence receipt of every governance decision made.

## Install

```bash
pip install pyhall
```

## Quick Start

```python
import uuid
from pyhall import make_decision, RouteInput, Registry, load_rules

# Load routing rules and enrolled workers
rules    = load_rules("rules.json")
registry = Registry(registry_dir="enrolled/")

# Build a capability request
inp = RouteInput(
    capability_id="cap.doc.summarize",
    env="dev",
    data_label="INTERNAL",
    tenant_risk="low",
    qos_class="P2",
    tenant_id="acme-corp",
    correlation_id=str(uuid.uuid4()),
)

# Ask the Hall
decision = make_decision(
    inp=inp,
    rules=rules,
    registry_controls_present=registry.controls_present(),
    registry_worker_available=registry.worker_available,
)

if decision.denied:
    print(f"Denied: {decision.deny_reason_if_denied}")
else:
    print(f"Dispatch to: {decision.selected_worker_species_id}")
    # -> "wrk.doc.summarizer"
```

## What PyHall Gives You

- **Governed dispatch** — every capability request goes through blast radius scoring, controls verification, and policy gate evaluation before a worker is selected.
- **Blast radius containment** — workers declare their potential damage scope before execution. High-risk operations in production automatically require human review.
- **Deterministic routing** — given identical inputs, routing decisions are identical. Golden snapshot testing catches regressions before they ship.
- **Evidence receipts** — every dispatch produces a signed, hashed evidence trail: what ran, when, under what policy, with what controls verified.

## WCP Compliance Levels

| Level | Requirements |
|-------|-------------|
| **WCP-Basic** | Capability routing, fail-closed, deterministic |
| **WCP-Standard** | + Controls enforcement, mandatory telemetry, dry-run |
| **WCP-Full** | + Blast radius, privilege envelopes, policy gate, evidence receipts, discovery API |

PyHall implements **WCP-Full**.

## CLI

```bash
# Route a capability request
pyhall route --capability cap.doc.summarize --env dev --rules rules.json

# Validate all test fixtures against routing rules
pyhall validate rules.json tests.json

# Show registry status
pyhall status --registry-dir enrolled/

# Enroll a worker
pyhall enroll my_worker/registry_record.json --registry-dir enrolled/

# Version
pyhall version
```

## The Five-Worker Pipeline

WCP excels at governed multi-worker pipelines. The canonical research ingestion
pipeline chains five workers with full correlation propagation:

```
cap.web.fetch -> cap.doc.chunk -> cap.ml.embed -> cap.doc.hash -> cap.research.register

  web_fetcher       (blast: 1, reversible)  — fetch URL, extract text
  doc_chunker       (blast: 0, reversible)  — semantic chunking ~500 tokens
  embedder          (blast: 1, reversible)  — embed with nomic-embed-text
  doc_hasher        (blast: 0, deterministic) — SHA-256 + optional signing
  research_registrar (blast: 2, reversible) — register to knowledge store

Total chain blast: 4 (within WCP-Standard threshold for dev/INTERNAL)
correlation_id: propagated through all 5 workers and all telemetry events
```

## Architecture

```
Agent (Claude, GPT, local LLM)
         |
         | capability request (RouteInput)
         v
   +------------------+
   |   PyHall / Hall  |
   |                  |
   |  1. Rule match   |   <- routing_rules.json
   |  2. Controls     |   <- Registry.controls_present()
   |  3. Blast radius |   <- computed or pre-scored
   |  4. Policy gate  |   <- PolicyGate.evaluate()
   |  5. Worker select|   <- Registry.worker_available()
   |  6. Telemetry    |   <- 3 mandatory events
   +------------------+
         |
         | RouteDecision (evidence receipt)
         v
   selected_worker_species_id
   telemetry_envelopes
   required_controls_effective
```

## Project Layout

```
pyhall/
  __init__.py      — public API
  router.py        — make_decision() — the core routing engine
  models.py        — RouteInput, RouteDecision (Pydantic v2)
  rules.py         — Rule, load_rules, route_first_match
  registry.py      — Registry class, worker enrollment
  policy_gate.py   — PolicyGate stub (replace with your engine)
  telemetry.py     — mandatory telemetry event builders
  conformance.py   — conformance validation for CI
  common.py        — shared utilities (timestamps, response envelopes)
  cli.py           — pyhall CLI (route, validate, status, enroll)

workers/examples/
  hello_worker/    — minimal complete worker (start here)

tests/
  test_router.py   — WCP compliance test suite

WCP spec           — see https://github.com/fafolab/wcp
```

## License

Apache 2.0 — see [LICENSE](LICENSE)

## Contributing

See CONTRIBUTING.md. WCP is an open concept — fork it, implement it, improve it.

---

Built by [FΔFΌ★LΔB](https://fafolab.ai)
