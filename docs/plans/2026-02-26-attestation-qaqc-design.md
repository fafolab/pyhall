# PyHall v0.1 — Attestation + QA/QC System Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:writing-plans to build the implementation plan from this design.

**Date:** 2026-02-26
**Status:** APPROVED
**Deadline:** Sunday March 1, 2026 (release gate)
**NIST Comment Deadline:** March 9, 2026

**Goal:** Ship worker attestation as a v0.1 feature across all three SDKs, backed by a Cloudflare-hosted attestation authority, a local audit database, and a QA/QC worker fleet that gates the release — all adversarially tested with Red+Blue+White team security testing.

**Architecture:**
The system has three layers: (1) SDK layer — all three language implementations enforce worker code attestation at dispatch time; (2) Cloud layer — Cloudflare Workers host a public attestation API at pyhall.dev that issues signed manifests and maintains a global ban list; (3) Audit layer — pyhall_audit.db provides a local hash-chained audit trail for the FAFO Lab proving ground. QA/QC workers built against the v0.1 SDK gate the release, and Round 9 adversarial security testing validates the full attestation chain.

**Tech Stack:** Python 3.12, TypeScript, Go 1.21, Cloudflare Workers, Cloudflare D1 (SQL), Cloudflare Vectorize, Neo4j Aura Free (HTTP Cypher API), Cloudflare KV, Ed25519 signing, SHA-256

---

## Section 1: SDK Attestation Parity

**Status today:**
- Python SDK: COMPLETE — `register_attestation()`, `get_worker_hash()`, `get_current_worker_hash()` wired into `make_decision()`
- TypeScript SDK: STUB — `@notImplemented`, returns `DENY_ATTESTATION_NOT_IMPLEMENTED`
- Go SDK: STUB — `DenyIfNoAttestationInProd bool` field, nothing in router

**What gets built:**

TypeScript and Go implement full attestation matching the Python reference:

```
Registry.registerAttestation(speciesId, sourceFile) → string (SHA-256)
Registry.getWorkerHash(speciesId) → string | null
Registry.getCurrentWorkerHash(speciesId) → string | null
```

Wired into the router: when `requireWorkerAttestation: true`, the router calls these before dispatch. Hash mismatch → `DENY_WORKER_TAMPERED`.

**New conformance vector CV-013 (release-blocking):**
1. Enroll worker with attestation registered
2. Dispatch → verify `worker_attestation_valid: true`
3. Mutate the worker file (change one byte)
4. Dispatch again → verify `DENY_WORKER_TAMPERED` fires
5. Verify evidence receipt contains `registered_hash`, `current_hash`, `attestation_checked: true`

All three SDKs must pass CV-013.

**Deny codes added (all three SDKs):**
- `DENY_WORKER_TAMPERED` — hash mismatch at dispatch
- `DENY_ATTESTATION_UNCONFIGURED` — `requireWorkerAttestation: true` but no hash callbacks provided

---

## Section 2: Cloudflare Attestation Authority API

**Hosted at:** `pyhall.dev/api/attest` (Cloudflare Workers)

**Free tier confirmed sufficient:**
- Workers: 100k req/day
- D1: 100k writes/day, 5GB storage
- Vectorize: 30M queried dimensions/month
- KV: 100k reads/day
- Pages: 500 builds/month

**Three-database pattern (mirrors ObraLogix NS architecture):**

| Store | Technology | What it holds |
|-------|-----------|--------------|
| SQL | Cloudflare D1 | Attestation records, ban list entries, tenant registry |
| Vector | Cloudflare Vectorize | Embedded worker descriptions for semantic worker discovery |
| Graph | Neo4j Aura Free (HTTP Cypher API) | Worker → capability → tenant relationships |

Note: Cloudflare Workers cannot reach Tailscale IPs. Big Sexy is not reachable from CF Workers. CF handles the public API only. The local artifact worker on Echo feeds pyhall_audit.db separately.

**API endpoints:**

```
POST /api/attest
  Body: { worker_species_id, code_hash, hash_method, attested_by, public_key }
  Returns: signed Ed25519 attestation manifest

GET  /api/attest/:species_id
  Returns: current attestation record for a worker species

GET  /api/ban-list
  Returns: list of known-compromised hashes (subscribed by Hall operators)

POST /api/ban
  Body: { code_hash, reason, reported_by }
  Adds hash to global ban list
```

**Signed manifest format:**
```json
{
  "worker_species_id": "wrk.doc.summarizer",
  "code_hash": "sha256:a3f9c2...",
  "hash_method": "file",
  "attested_at": "2026-02-26T00:00:00Z",
  "attested_by": "rob@fafolab.ai",
  "manifest_id": "uuid-v4",
  "signature": "ed25519:...",
  "public_key_id": "pyhall-authority-2026"
}
```

**What happens after a developer receives the signed manifest:**
The SDK writes the manifest to the local Hall registry. The artifact worker on the developer's machine picks it up and writes to pyhall_audit.db (hash-chained). The public API is stateless from the developer's perspective — the local audit trail is the authoritative record.

---

## Section 3: pyhall.dev/trust + pyhall_audit.db

### pyhall.dev/trust (public page)

Public-facing attestation registry at `pyhall.dev/trust`. Shows:
- All worker species with active attestation records
- Attestation timestamp, hash method, attested_by
- Ban list status (clean / compromised)
- Link to evidence receipt for each attestation

Vanilla JS, reads from Cloudflare D1 via the public API. No authentication required to view.

### pyhall_audit.db (internal FAFO Lab only)

Lives at `/mnt/fafolab/dev/pyhall/pyhall_audit.db`. Never pushed to any git repo.

**Tables:**
```sql
attestation_log   -- every attestation check: species_id, registered_hash, current_hash, matched, timestamp, correlation_id
qc_runs           -- every QA/QC worker run: worker_id, run_at, findings_count, pass/fail
qc_findings       -- individual findings: run_id, severity, file_path, finding_type, detail
hash_chain        -- hash-chained audit entries: entry_hash, previous_hash, timestamp, entry_type, entry_id
```

Hash chain formula: `SHA256(entry_content + previous_hash + timestamp)`

This is the FAFO Lab proving ground for the ObraLogix NS resident agent pattern. Every attestation check, every QC run, every finding — cryptographically chained. Proves in post-incident review exactly what ran, when, and whether it matched what was registered.

---

## Section 4: Catalog Rebuild + QA/QC Worker Fleet

### 4A: Catalog Generator (build step)

**Problem:** `catalog.json` was generated by an agent from original taxonomy markdown docs. It is now stale — the spec, SDK, and security testing rounds have all evolved. 241/245 entity IDs wrongly contain `.v1` (violates WCP spec §3.4). Entity schema is too minimal (5-6 fields; should reflect spec §6 registry record fields).

**Solution:** Catalog becomes a generated artifact, not a hand-edited file.

```
taxonomy/src/
  pack_01_sandboxing.py
  pack_02_secrets.py
  ... (one file per pack)
scripts/
  build_catalog.py  ← validates IDs against spec §3.2/§3.4, outputs catalog.json
```

Source files define entities as Python dicts. The generator:
1. Validates every ID against spec rules (no `.v1`, no underscores, 2-4 segments, lowercase)
2. Validates required fields per entity type
3. Emits `catalog.json` — if any entity violates spec rules, build fails, catalog is NOT written
4. Syncs to all 4 locations: Python CLI, TypeScript CLI, Go CLI, Web Playground

**Canonical entity schema per type:**

Capabilities:
```json
{
  "id": "cap.doc.summarize",
  "type": "capability",
  "pack_id": "pack.10",
  "name": "Summarize Document",
  "description": "...",
  "risk_tier": "low",
  "blast_radius_hint": {"data": 1, "network": 0, "financial": 0, "time": 1, "reversibility": "reversible"},
  "typical_controls": ["ctrl.obs.audit-log-append-only"],
  "idempotency": "full",
  "determinism": "captured",
  "tags": ["document", "llm"],
  "wcp_namespace": "reserved"
}
```

Worker species:
```json
{
  "id": "wrk.doc.summarizer",
  "type": "worker",
  "pack_id": "pack.10",
  "name": "Document Summarizer",
  "description": "...",
  "risk_tier": "low",
  "serves_capabilities": ["cap.doc.summarize"],
  "blast_radius_hint": {"data": 1, "network": 0, "financial": 0, "time": 1, "reversibility": "reversible"},
  "required_controls": ["ctrl.obs.audit-log-append-only"],
  "idempotency": "full",
  "determinism": "captured",
  "tags": ["document", "llm"],
  "wcp_namespace": "reserved"
}
```

Controls:
```json
{
  "id": "ctrl.obs.audit-log-append-only",
  "type": "control",
  "pack_id": "pack.03",
  "name": "Audit Log Append-Only",
  "description": "...",
  "enforcement_point": "worker",
  "required_for_risk_tiers": ["medium", "high"],
  "tags": ["observability", "audit"],
  "wcp_namespace": "reserved"
}
```

Profiles:
```json
{
  "id": "prof.secure.zero-trust",
  "type": "profile",
  "pack_id": "pack.02",
  "name": "Zero Trust Profile",
  "description": "...",
  "controls_required": ["ctrl.obs.audit-log-append-only", "ctrl.sandbox.no-egress-default-deny"],
  "recommended_for_risk_tiers": ["medium", "high"],
  "tags": ["security"],
  "wcp_namespace": "reserved"
}
```

Events:
```json
{
  "id": "evt.os.task.routed",
  "type": "event",
  "pack_id": "pack.03",
  "name": "Task Routed",
  "description": "Emitted when routing decision is made.",
  "mandatory": true,
  "tags": ["telemetry"],
  "wcp_namespace": "reserved"
}
```

### 4B: QA/QC Worker Fleet

Five workers built against pyhall v0.1 SDK. Registered in the Hall. Their code hashes are attested by the pyhall.dev authority. They are the first real demonstration that WCP works — pyhall uses pyhall to govern pyhall's own development.

| Worker | Capability | Purpose |
|--------|-----------|---------|
| `tools/qc/catalog_validator.py` | `cap.qc.catalog.validate` | Re-runs spec §3.2/§3.4 ID rules against catalog, reports violations |
| `tools/qc/stale_scanner.py` | `cap.qc.stale.scan` | Scans monorepo for unused/stale files, outputs archive candidates |
| `tools/qc/sdk_parity.py` | `cap.qc.sdk.check` | Diffs TypeScript + Go attestation against Python reference |
| `tools/qc/doc_consistency.py` | `cap.qc.doc.check` | Verifies docs reference real catalog entity IDs |
| `tools/qc/release_gate.py` | `cap.qc.release.check` | Runs all conformance vectors + test suite, generates go/no-go report |

QC runs write findings to `pyhall_audit.db` and reports to `release/qa-reports/`. The release gate worker is the final check before any push to the public repo.

### 4C: Auto-Archive Rule

Any file flagged by `stale_scanner.py` as unused or stale is moved to `archive/YYYY-MM-DD/<original-path>`. Never deleted. First targets:
- `lab/workforce-os/` → `archive/2026-02-26/workforce-os/`
- Any files referencing `.v1` entity IDs after catalog rebuild

---

## Section 5: Red+Blue+White Team Testing — Round 9

This is the security testing round that makes the NIST submission credible. WCP cannot be submitted as an AI agent governance standard without adversarial testing of its core attestation mechanism.

### Red Team: 7 Attacks

| # | Attack | Method |
|---|--------|--------|
| R1 | Hash substitution | Modify worker file AND registry hash simultaneously (registry write access) |
| R2 | Race condition | Modify worker between registration and dispatch |
| R3 | Path traversal | Register hash for `/workers/clean.py`, serve `../malicious.py` at dispatch |
| R4 | Symlink swap | Worker is a symlink; attacker swaps the symlink target after attestation |
| R5 | Encoding variant | Same logical content, different byte encoding — verify hash correctly differs |
| R6 | Registry poisoning | Attacker with registry write replaces stored hash — audit trail must record the change |
| R7 | Ban list bypass | Register clean hash, push banned content after registration |

### Blue Team: Required Defenses

All of the following must hold under every attack:
- Tamper detection fires → worker flagged in registry (not auto-cleared, requires operator action)
- Every check logged to `pyhall_audit.db` with `correlation_id`, `registered_hash`, `current_hash`
- Evidence receipt always includes `worker_attestation_checked: true` and both hashes
- Flagged workers cannot be re-dispatched without explicit registry clear

### White Team: Conformance Gate

CV-013 must pass in all three SDKs:
1. Enroll worker, register attestation
2. Dispatch → verify `worker_attestation_valid: true` in evidence receipt
3. Mutate worker file (change one byte)
4. Dispatch → verify `DENY_WORKER_TAMPERED`, verify both hashes in deny payload
5. Verify flagged worker is blocked from further dispatch

All 7 red team attacks must produce identical DENY behavior across Python, TypeScript, and Go.

Round 9 findings report: `release/qa-reports/round-9-attestation.md`
Security findings tracker: `docs/security/SECURITY_FINDINGS.md`

---

## Release Gate Checklist (RELEASING.md)

Before any push to `fafolab/pyhall` (public repo):

- [ ] CV-013 passes in Python, TypeScript, Go
- [ ] All existing conformance vectors (CV-001 through CV-012) still pass
- [ ] QC worker fleet: all 5 workers run clean, zero open findings
- [ ] Catalog rebuilt — zero `.v1` violations, zero schema violations
- [ ] Round 9 security report complete, all 7 attacks documented
- [ ] `pyhall_audit.db` hash chain intact (no broken links)
- [ ] TypeScript SDK: 83+ tests pass
- [ ] Python SDK: 105+ tests pass
- [ ] Go SDK: tests pass
- [ ] CHANGELOG.md updated with v0.1.0 attestation features
- [ ] pyhall.dev/trust page live on Cloudflare
- [ ] Attestation API live on Cloudflare Workers

---

## File Map

```
git/
├── sdk/
│   ├── python/pyhall/registry.py          ← attestation: COMPLETE
│   ├── typescript/src/registry.ts          ← attestation: IMPLEMENT
│   └── go/wcp/registry.go                  ← attestation: IMPLEMENT
├── tools/
│   └── qc/
│       ├── catalog_validator.py
│       ├── stale_scanner.py
│       ├── sdk_parity.py
│       ├── doc_consistency.py
│       └── release_gate.py
├── scripts/
│   └── build_catalog.py
├── taxonomy/
│   └── src/
│       ├── pack_01_sandboxing.py
│       └── ... (one per pack)
├── docs/
│   ├── conformance/wcp_conformance_vectors.json  ← add CV-013
│   ├── plans/2026-02-26-attestation-qaqc-design.md  ← THIS FILE
│   └── security/
│       └── round-9-attestation.md              ← generated by QC worker
└── .github/
    └── workflows/
        └── qa.yml                              ← runs QC worker fleet on PR + release tag
```
