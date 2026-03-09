# @pyhall/core — TypeScript WCP Reference Implementation

The TypeScript/Node.js port of [PyHall](../python/) — the Worker Class Protocol reference implementation.

**WCP version:** 0.1
**Package version:** 0.3.0

## Install

```bash
npm install @pyhall/core@0.3.0
```

## Quick Start

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

## Registry Client

`@pyhall/core` includes an HTTP client for the pyhall.dev registry API,
with the same interface as the Python `RegistryClient`.

```typescript
import { RegistryClient, RegistryRateLimitError } from "@pyhall/core";

const client = new RegistryClient({
  // baseUrl defaults to "https://api.pyhall.dev"
  // sessionToken: "your-session-jwt",  // for authenticated calls
  // timeout: 10000,                    // ms, default 10s
  // cacheTtl: 60000,                   // ms, default 60s
});

// Verify a worker's attestation status
const r = await client.verify("org.example.my-worker");
console.log(r.status);        // 'active' | 'revoked' | 'banned' | 'unknown'
console.log(r.current_hash);  // string | null
console.log(r.banned);        // boolean
console.log(r.ai_generated);  // boolean

// Check the ban-list
const banned = await client.isHashBanned(someHash);

// Fetch the full ban-list
const list = await client.getBanList();

// Report a bad hash (requires sessionToken)
await client.reportHash(hash, "Backdoored dependency", "https://evidence.url");

// Check registry health
const h = await client.health();
console.log(h.ok, h.version);
```

### Integration with `makeDecision()`

Pre-populate the cache before routing so the synchronous hash callback
has data available:

```typescript
const client = new RegistryClient({ sessionToken: token });

// Async pre-fetch
await client.prefetch(["org.example.worker-a", "org.example.worker-b"]);

// Synchronous callback for makeDecision()
const hashCallback = client.getWorkerHashCallback();

const decision = makeDecision({
  inp,
  rules,
  registryControlsPresent: registry.controlsPresent(),
  registryWorkerAvailable: (id) => registry.workerAvailable(id),
  // Pass hashCallback to verify attestation during routing
});
```

`VerifyResponse` fields: `worker_id`, `status`, `current_hash`, `banned`,
`ban_reason`, `attested_at`, `ai_generated`, `ai_service`, `ai_model`,
`ai_session_fingerprint`.

## Package Attestation

Full-package attestation is fully implemented in `@pyhall/core` v0.3.0:

```typescript
import {
  canonicalPackageHash, buildManifest, writeManifest, scaffoldPackage,
  PackageAttestationVerifier,
  ATTEST_MANIFEST_MISSING, ATTEST_HASH_MISMATCH, ATTEST_SIG_INVALID,
  ATTEST_SIGNATURE_MISSING, ATTEST_MANIFEST_ID_MISMATCH,
} from '@pyhall/core';

// Build + sign a manifest at CI/deploy time
const manifest = buildManifest({
  packageRoot: '/opt/workers/my-worker',
  workerId: 'org.example.my-worker.i-1',
  workerSpeciesId: 'wrk.example.my-worker',
  workerVersion: '1.0.0',
  signingSecret: process.env.WCP_ATTEST_HMAC_KEY!,
});
writeManifest(manifest, '/opt/workers/my-worker/manifest.json');

// Verify at runtime (fail-closed)
const verifier = new PackageAttestationVerifier({
  packageRoot: '/opt/workers/my-worker',
  manifestPath: '/opt/workers/my-worker/manifest.json',
  workerId: 'org.example.my-worker.i-1',
  workerSpeciesId: 'wrk.example.my-worker',
});
const { ok, denyCode, meta } = verifier.verify();
if (!ok) throw new Error(`Attestation denied: ${denyCode}`);
```

## Build

```bash
npm run build    # tsc → dist/
npm test         # jest
npm run typecheck  # tsc --noEmit
```

## Public API

```typescript
// Core routing
export { makeDecision } from "./router.js";
export type { MakeDecisionOptions } from "./router.js";

// Models / types
export type { RouteInput, RouteDecision, CandidateWorker, Escalation,
              PreconditionsChecked, Env, DataLabel, QoSClass, TenantRisk,
              WorkerRegistryRecord, PrivilegeEnvelope } from "./models.js";

// Rules engine
export { loadRulesFromDoc, loadRulesFromJson, routeFirstMatch,
         ruleMatches, matchMembership } from "./rules.js";
export type { Rule, RulesDocument } from "./rules.js";

// Local registry
export { Registry } from "./registry.js";

// Registry API client (pyhall.dev)
export { RegistryClient, RegistryRateLimitError } from "./registryClient.js";
export type { VerifyResponse, BanEntry, RegistryClientOptions } from "./registryClient.js";

// Policy gate
export { PolicyGate } from "./policyGate.js";
export type { PolicyGateEvaluator, PolicyGateContext,
              PolicyGateResult, PolicyDecision } from "./policyGate.js";

// Conformance
export { validateRequiredFields, validateRequiredTelemetry,
         defaultConformanceSpec, loadConformanceSpecFromJson } from "./conformance.js";

// Telemetry builders
export { osTaskRouted, osWorkerSelected, osPolicyGated,
         govBlastScored, govPrivilegeEnvelopeChecked } from "./telemetry.js";

// Utilities
export { nowUtc, uuidV4, sha256Hex, ok, err, partial } from "./common.js";
export type { ResultStatus, WorkerResultEnvelope } from "./common.js";

export const VERSION = "0.3.0";
export const WCP_VERSION = "0.1";
```

## Package Structure

```
src/
  models.ts         — TypeScript interfaces for RouteInput, RouteDecision, etc.
  router.ts         — makeDecision() — the routing engine
  rules.ts          — Rule type, loadRulesFromDoc(), routeFirstMatch()
  registry.ts       — Registry class
  registryClient.ts — RegistryClient (HTTP client for api.pyhall.dev)
  policyGate.ts     — PolicyGate stub
  telemetry.ts      — telemetry envelope builders
  conformance.ts    — conformance validation
  common.ts         — nowUtc(), sha256Hex(), ok/err/partial helpers
  index.ts          — public API exports
workers/examples/
  hello-worker/     — minimal canonical worker example
tests/
  router.test.ts    — Jest test suite (mirrors Python)
```

## Design Choices vs Python

| Concern | Python | TypeScript |
|---------|--------|------------|
| Data models | Pydantic `BaseModel` | TypeScript `interface` |
| `makeDecision()` signature | Positional args | Single options object |
| UUID | `uuid.uuid4()` | `crypto.randomUUID()` with fallback |
| SHA-256 | `hashlib.sha256` | Node `crypto.createHash` / `SubtleCrypto` for browser |
| Runtime validation | Pydantic | Optional Zod (peer dep) |
| Browser compat | N/A | `src/` has no Node-only APIs except `sha256Hex` |
| Package attestation | Full (v0.3.0) | Not yet implemented |
| `submit_attestation()` | `RegistryClient.submit_attestation()` | Not yet implemented |

See [WCP_SPEC.md](https://github.com/workerclassprotocol/wcp/blob/main/WCP_SPEC.md) for the protocol specification.
