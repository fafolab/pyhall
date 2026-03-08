# PyHall

**PyHall** is the reference implementation of the [Worker Class Protocol (WCP)](https://github.com/fafolab/wcp) — an open standard for governing AI agent worker dispatch.

WCP defines how AI systems route capability requests to workers: which worker handles which task, under what controls, with a full audit trail. PyHall implements the complete routing engine, registry, policy gate, attestation layer, MCP interop, and telemetry.

**Version:** 0.3.0 | **WCP spec:** 0.1

---

## Implementations

| Language | Package | Version | Status |
|----------|---------|---------|--------|
| Python | `pip install pyhall-wcp` | 0.3.0 | Reference implementation — production ready |
| TypeScript | `npm install @pyhall/core` | 0.3.0 | Full port |
| Go | `go get github.com/fafolab/pyhall/sdk/go` | 0.3.0 | Scaffold / interfaces |

---

## Quick Start (Python)

```bash
pip install pyhall-wcp
```

```python
from pyhall import make_decision, RouteInput

decision = make_decision(RouteInput(
    capability_id="cap.doc.summarize",
    tenant_id="acme",
    env="dev",
    data_label="internal",
    tenant_risk="low",
    qos_class="P2",
    correlation_id="550e8400-e29b-41d4-a716-446655440000",
))

print(decision.denied)                    # False
print(decision.selected_worker_species_id)  # "wrk.doc.summarizer"
```

See [pyhall.dev](https://pyhall.dev) for full documentation.

---

## Quick Start (CLI)

```bash
npm install -g @pyhall/cli

# Search the taxonomy
pyhall search "document summarize"

# Explain a capability
pyhall explain cap.doc.summarize

# Scaffold a new worker
pyhall scaffold

# Check registry health
pyhall registry status

# Verify a worker's attestation status
pyhall registry verify x.my.worker
```

---

## Full-Package Attestation (v0.3.0)

The unit of attestation in WCP is the complete worker package — code, dependencies, config, all. Attestation is bound to namespace-key authorization, not personal authorship.

```python
from pathlib import Path
from pyhall.attestation import (
    scaffold_package,
    build_manifest,
    write_manifest,
    PackageAttestationVerifier,
)

# 1. Create worker package layout
scaffold_package(Path("my-worker/"))

# 2. Sign the package (requires WCP_ATTEST_HMAC_KEY env var, or pass signing_secret)
manifest = build_manifest(
    package_root=Path("my-worker/"),
    worker_id="org.example.my-worker.i-1",
    worker_species_id="wrk.example.my-worker",
    worker_version="1.0.0",
    signing_secret="your-hmac-key",
)
write_manifest(manifest, Path("my-worker/manifest.json"))

# 3. Verify at runtime (fail-closed — no silent fallback)
verifier = PackageAttestationVerifier(
    package_root=Path("my-worker/"),
    manifest_path=Path("my-worker/manifest.json"),
    worker_id="org.example.my-worker.i-1",
    worker_species_id="wrk.example.my-worker",
)
ok, deny_code, meta = verifier.verify()
if not ok:
    raise SystemExit(f"Attestation denied: {deny_code}")

print(meta["trust_statement"])  # "Package attested by namespace wrk at <UTC>; package hash sha256:<hash>."
```

**Deny codes:**

| Code | Meaning |
|------|---------|
| `ATTEST_MANIFEST_MISSING` | `manifest.json` absent or unreadable |
| `ATTEST_MANIFEST_ID_MISMATCH` | Manifest identity does not match declared worker |
| `ATTEST_HASH_MISMATCH` | Recomputed package hash does not match manifest |
| `ATTEST_SIGNATURE_MISSING` | No signature in manifest or `WCP_ATTEST_HMAC_KEY` not set |
| `ATTEST_SIG_INVALID` | HMAC-SHA256 signature does not verify |

Signing model: HMAC-SHA256 (reference implementation). For production, replace with Ed25519 asymmetric signing and store the public key in the registry.

---

## MCP Interop

WCP workers can be surfaced as MCP tools with no changes to the worker itself. The MCP server is a thin adapter that enforces WCP governance before the worker runs.

```
MCP client (Claude, Cursor, etc.)
    |
    | JSON-RPC 2.0 over stdio
    v
pyhall.mcp.server  — WCP governance adapter
    |
    | 1. Build RouteInput from MCP tool call params
    | 2. pyhall.make_decision() — rules engine + policy gate
    | 3. APPROVED: call worker.execute()
    | 4. DENIED:   return MCP error with deny reason
    v
MCP tool response (+ wcp_governance metadata)
```

Run the built-in MCP server:

```bash
python -m pyhall.mcp
# or:
pyhall-mcp
```

The worker is unchanged. The MCP client sees a standard tool. WCP governance — rule matching, policy gate, controls verification, audit trail — runs transparently on every call.

See [`sdk/python/workers/examples/mcp_interop/`](sdk/python/workers/examples/mcp_interop/) for a complete example with raw request traces.

---

## Hall Monitor (Desktop App)

Hall Monitor is a Tauri v2 desktop application for monitoring and managing a local Hall Server deployment.

Features:
- Connect to a local Hall API server (`hall_api/server.py`)
- Worker status monitoring
- Active dispatch and alert feeds
- GitHub OAuth login via api.pyhall.dev
- Namespace and worker enrollment management
- First-time setup wizard

Source: [`apps/desktop/`](apps/desktop/)

To run the Hall API server locally:

```bash
pip install flask
python sdk/python/hall_api/server.py
# Default: http://localhost:8001
# Override: HALL_API_PORT=7777 HALL_API_HOST=127.0.0.1 python ...
```

---

## Registry

Live registry at [api.pyhall.dev](https://api.pyhall.dev).

- GitHub OAuth authentication
- Namespace registration (`x.*` community, `org.*` paid)
- Worker enrollment and attestation submission
- Ban list (self-report and admin review)
- Tier limits: free / pro / enterprise

---

## Skills

The `pyhall-wcp` Claude Code skill is available at [`skills/pyhall-wcp/`](skills/pyhall-wcp/).

Install it to give any Claude Code session governed access to WCP taxonomy browsing, worker registration, namespace operations, routing decisions, and attestation checks.

---

## Repository Layout

```
sdk/python/              — Python SDK (pyhall-wcp)
  pyhall/                — Core package
    attestation.py       — Full-package attestation (v0.3.0)
    mcp/                 — MCP interop server
    cli.py               — Python CLI (pyhall)
  hall_api/              — Local Hall API server (Flask)
  workers/examples/      — Example workers (hello, mcp_interop)
sdk/typescript/          — TypeScript SDK (@pyhall/core)
sdk/go/                  — Go SDK
apps/cli/typescript/     — pyhall CLI (@pyhall/cli)
apps/desktop/            — Hall Monitor desktop app (Tauri v2)
skills/pyhall-wcp/       — Claude Code skill
```

---

## Spec

The protocol specification lives at [workerclassprotocol.dev](https://workerclassprotocol.dev) and [github.com/fafolab/wcp](https://github.com/fafolab/wcp).

---

## License

Apache 2.0
