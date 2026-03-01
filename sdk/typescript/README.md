# @pyhall/core — TypeScript WCP Reference Implementation

The TypeScript/Node.js port of [PyHall](../pyhall/) — the Worker Class Protocol reference implementation.

**WCP version:** 0.1
**Package version:** 0.1.0

## Install

```bash
npm install @pyhall/core
```

## Quick start

```typescript
import { makeDecision, Registry, loadRulesFromDoc } from "@pyhall/core";

const rules = loadRulesFromDoc({
  rules: [
    {
      rule_id: "rr_hello_dev_001",
      match: { capability_id: "cap.hello.greet", env: { in: ["dev", "stage"] } },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 }
        ],
        required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
        escalation: { policy_gate: false },
        preconditions: {},
      },
    }
  ]
});

const registry = new Registry();
registry.enroll({
  worker_id: "org.example.hello-greeter",
  worker_species_id: "wrk.hello.greeter",
  capabilities: ["cap.hello.greet"],
  currently_implements: ["ctrl.obs.audit-log-append-only"],
});

const decision = makeDecision({
  inp: {
    capability_id: "cap.hello.greet",
    env: "dev",
    data_label: "PUBLIC",
    tenant_risk: "low",
    qos_class: "P2",
    tenant_id: "demo",
    correlation_id: "550e8400-e29b-41d4-a716-446655440000",
  },
  rules,
  registryControlsPresent: registry.controlsPresent(),
  registryWorkerAvailable: (id) => registry.workerAvailable(id),
});

console.log(decision.denied);                      // false
console.log(decision.selected_worker_species_id);  // "wrk.hello.greeter"
console.log(decision.telemetry_envelopes.length);  // 3
```

## Build

```bash
npm run build    # tsc → dist/
npm test         # jest (21 tests)
npm run typecheck  # tsc --noEmit
```

## Package structure

```
src/
  models.ts       — TypeScript interfaces for RouteInput, RouteDecision, etc.
  router.ts       — makeDecision() — the routing engine
  rules.ts        — Rule type, loadRulesFromDoc(), routeFirstMatch()
  registry.ts     — Registry class
  policyGate.ts   — PolicyGate stub
  telemetry.ts    — telemetry envelope builders
  conformance.ts  — conformance validation
  common.ts       — nowUtc(), sha256Hex(), ok/err/partial helpers
  index.ts        — public API exports
workers/examples/
  hello-worker/   — minimal canonical worker example
tests/
  router.test.ts  — Jest test suite (21 tests, mirrors Python)
```

## Design choices vs Python

| Concern | Python | TypeScript |
|---------|--------|------------|
| Data models | Pydantic `BaseModel` | TypeScript `interface` |
| `makeDecision()` signature | Positional args | Single options object |
| UUID | `uuid.uuid4()` | `crypto.randomUUID()` with fallback |
| SHA-256 | `hashlib.sha256` | Node `crypto.createHash` / `SubtleCrypto` for browser |
| Runtime validation | Pydantic | Optional Zod (peer dep) |
| Browser compat | N/A | `src/` has no Node-only APIs except `sha256Hex` |

See [WCP_SPEC.md](https://github.com/fafolab/wcp/blob/main/WCP_SPEC.md) for the protocol specification.
