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
pip install pyhall-wcp==0.3.0
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
- **Package attestation** — full-package HMAC-SHA256 signing and runtime verification of worker packages before dispatch.

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

# Scaffold a new worker package
pyhall scaffold my_worker/

# Version
pyhall version
```

## Package Attestation (v0.3.0)

PyHall v0.3.0 adds full-package attestation for worker packages. Attestation
binds a namespace signing key to the complete package content — code,
dependencies, config — using HMAC-SHA256. Fail-closed: no silent fallback.

### Worker Package Layout

```
worker-package/
  code/
    worker_logic.py       — business logic
    bootstrap.py          — entrypoint (calls worker_logic.run())
  requirements.lock       — pinned dependencies
  config.schema.json      — JSON Schema for worker config
  manifest.json           — signed manifest (written by build_manifest/write_manifest)
```

### Scaffold a Package

```python
from pathlib import Path
from pyhall import scaffold_package

scaffold_package(
    package_root=Path("my-worker/"),
    worker_logic_file=Path("src/my_logic.py"),  # optional — stub written if omitted
)
```

### Sign and Build a Manifest

```python
import os
from pathlib import Path
from pyhall import build_manifest, write_manifest

manifest = build_manifest(
    package_root=Path("my-worker/"),
    worker_id="org.example.my-worker.instance-1",
    worker_species_id="wrk.example.my-worker",
    worker_version="1.0.0",
    signing_secret=os.environ["WCP_ATTEST_HMAC_KEY"],
    build_source="ci",  # 'local' | 'ci' | 'agent'
)
write_manifest(manifest, Path("my-worker/manifest.json"))
```

The manifest contains:
- `package_hash` — deterministic SHA-256 over all package files
- `signature_hmac_sha256` — HMAC-SHA256 over the canonical signing payload
- `trust_statement` — human-readable namespace-key trust claim
- `built_at_utc` / `attested_at_utc` — ISO 8601 UTC timestamps
- `build_source` — origin label for audit trail

### Verify at Runtime

```python
from pathlib import Path
from pyhall import PackageAttestationVerifier

verifier = PackageAttestationVerifier(
    package_root=Path("/opt/workers/my-worker"),
    manifest_path=Path("/opt/workers/my-worker/manifest.json"),
    worker_id="org.example.my-worker.instance-1",
    worker_species_id="wrk.example.my-worker",
    # secret_env defaults to "WCP_ATTEST_HMAC_KEY"
)

ok, deny_code, meta = verifier.verify()
if not ok:
    raise SystemExit(f"Attestation denied: {deny_code}")

# meta["package_hash"]     — embed in evidence receipts
# meta["trust_statement"]  — canonical namespace-key trust claim
# meta["verified_at_utc"]  — UTC ISO 8601
```

### Compute the Package Hash Directly

```python
from pathlib import Path
from pyhall import canonical_package_hash

h = canonical_package_hash(Path("my-worker/"))
print(h)  # 64-char lowercase hex SHA-256
```

Hash input is deterministic: one record per file sorted by POSIX path:
`<relative_path>\n<size_bytes>\n<sha256_hex(content)>\n`. Excludes
`manifest.json`, `manifest.sig`, `.git/`, `__pycache__/`, `.pyc` files.

### Attestation Deny Codes

All fail-closed — no silent fallback execution.

| Code | Meaning |
|------|---------|
| `ATTEST_MANIFEST_MISSING` | `manifest.json` absent or unreadable |
| `ATTEST_MANIFEST_ID_MISMATCH` | manifest `worker_id`/`worker_species_id` != declared |
| `ATTEST_HASH_MISMATCH` | recomputed package hash != `manifest.package_hash` |
| `ATTEST_SIGNATURE_MISSING` | no signature in manifest or `WCP_ATTEST_HMAC_KEY` not set |
| `ATTEST_SIG_INVALID` | HMAC-SHA256 signature does not verify |

```python
from pyhall import (
    ATTEST_MANIFEST_MISSING,
    ATTEST_MANIFEST_ID_MISMATCH,
    ATTEST_HASH_MISMATCH,
    ATTEST_SIGNATURE_MISSING,
    ATTEST_SIG_INVALID,
)
```

### Signing Model

HMAC-SHA256 with `WCP_ATTEST_HMAC_KEY` env var for portability and
self-contained operation. For production, replace with Ed25519 asymmetric
signing and store the public key in the pyhall.dev registry.

## Registry Client

```python
from pyhall import RegistryClient, RegistryRateLimitError

client = RegistryClient()

# Verify a worker's attestation status
r = client.verify("org.example.my-worker.instance-1")
print(r.status)          # 'active' | 'revoked' | 'banned' | 'unknown'
print(r.current_hash)    # 64-char hex or None
print(r.banned)          # bool
print(r.ai_generated)    # bool — was this package AI-assisted?

# Submit a full-package attestation (requires bearer token)
resp = client.submit_attestation(
    worker_id="org.example.my-worker.instance-1",
    package_hash=h,
    label="v1.0.0 release",
    ai_generated=True,
    ai_service="claude",
    ai_model="claude-sonnet-4-6",
    ai_session_id="session-fingerprint",
    bearer_token="your-jwt-token",
)
print(resp.id)        # attestation record ID
print(resp.sha256)    # confirmed hash

# Check the ban-list
banned = client.is_hash_banned(h)

# Report a bad hash (requires session token)
client.report_hash(h, reason="Backdoored dependency", evidence_url="https://...")

# Pre-populate cache before make_decision()
client.prefetch(["org.example.worker-a", "org.example.worker-b"])
callback = client.get_worker_hash  # use as registry_get_worker_hash in make_decision()
```

`VerifyResponse` fields: `worker_id`, `status`, `current_hash`, `banned`,
`ban_reason`, `attested_at`, `ai_generated`, `ai_service`, `ai_model`,
`ai_session_fingerprint`.

`AttestationResponse` fields: `id`, `worker_id`, `sha256`.

Override the registry URL: `RegistryClient(base_url="https://...")` or
set `PYHALL_REGISTRY_URL` env var.

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
  cli.py           — pyhall CLI (route, validate, status, enroll, scaffold)
  attestation.py   — PackageAttestationVerifier, build_manifest, write_manifest,
                     scaffold_package, canonical_package_hash, ATTEST_* deny codes
  registry_client.py — RegistryClient (HTTP client for api.pyhall.dev)

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
