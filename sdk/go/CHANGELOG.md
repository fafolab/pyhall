# Changelog — pyhall-go

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-02-24

### Added

- `wcp/models.go` — RouteInput, RouteDecision, CandidateWorker, Escalation,
  PreconditionsChecked, WorkerRegistryRecord, PrivilegeEnvelope structs.
  Full JSON tags. Mirrors pyhall/models.py and pyhall-ts/src/models.ts exactly.

- `wcp/router.go` — MakeDecision() entrypoint.
  - Fail-closed: unknown capabilities denied (WCP 5.1)
  - Deterministic: same inputs, same outputs (WCP 5.2)
  - Dry-run field honored (WCP 5.5)
  - Mandatory telemetry emitted on every decision (WCP 5.4)
  - RouterOptions: PolicyGate, WorkerAvailabilityFn, MaxBlastScore
  - Full rule-matching engine: TODO

- `wcp/registry.go` — in-memory Registry.
  - Enroll() — adds worker record with basic validation
  - WorkersForCapability() — capability lookup
  - AllWorkers() / AllCapabilities() — discovery support
  - Persistent storage: TODO

- `wcp/policy_gate.go` — PolicyGate interface + DefaultPolicyGate stub.
  - P0 in prod/edge flags human review
  - Real policy evaluation engine: TODO

- `wcp/common.go` — NowUTC(), SHA256Hex(), OK/Err generics.

- `workers/examples/hello_worker/worker.go` — minimal canonical worker.
  Demonstrates: receive RouteDecision, execute capability, return EvidenceReceipt.

- `workers/examples/hello_worker/registry_record.json` — enrollment record.

- `go.mod` — module github.com/fafolab/pyhall-go, go 1.22, zero external deps.

---

*v0.1.0 — scaffold only. Production routing: use PyHall (`pip install pyhall`).*
