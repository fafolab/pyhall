# @pyhall/cli — Worker Class Protocol CLI

The `pyhall` command-line tool for the [Worker Class Protocol](https://workerclassprotocol.dev). Browse the WCP taxonomy, search capabilities and workers, scaffold new workers, and query the pyhall.dev registry.

**WCP version:** 0.1
**Package version:** 0.3.0

## Install

```bash
npm install -g @pyhall/cli
```

## Commands

```
pyhall version                          Print CLI, SDK, and WCP spec versions
pyhall search <query>                   Fuzzy search across the taxonomy catalog
pyhall explain <entity-id>              Show detailed info for a taxonomy entity
pyhall browse                           Browse namespaces and entities
pyhall browse --namespace <prefix>      Filter to a namespace prefix
pyhall browse --type <type>             Filter by type: cap|wrk|ctrl|pol|prof
pyhall scaffold                         Interactive worker scaffold wizard
pyhall registry verify <worker-id>      Show attestation status for a worker
pyhall registry check-hash <sha256>     Check if a hash is on the confirmed ban-list
pyhall registry ban-list                Show the confirmed ban-list
pyhall registry ban-list --limit <n>    Limit ban-list output
pyhall registry status                  Check registry API health and version
pyhall help                             Show command list and usage
```

## Quick start

```bash
# Search the taxonomy
pyhall search "file write"

# Explain a capability or worker species
pyhall explain cap.fs.write.local.v1
pyhall explain wrk.doc.pipeline.orchestrator
pyhall explain ctrl.sandbox.no_egress_default_deny

# Browse by namespace or type
pyhall browse --namespace cap.doc
pyhall browse --type wrk

# Scaffold a new worker (interactive wizard)
pyhall scaffold

# Registry operations
pyhall registry status
pyhall registry verify x.my.worker
pyhall registry check-hash <sha256>
pyhall registry ban-list --limit 10
```

## scaffold

The `scaffold` command is an interactive wizard that generates a complete worker stub:

1. Describe what the worker does — the CLI fuzzy-searches the taxonomy catalog for matching capabilities
2. Select (or enter) a capability ID
3. Choose a delivery guarantee: `best-effort` | `at-least-once` | `exactly-once`
4. Name the worker
5. Choose an output directory

Generated files:

| File | Purpose |
|------|---------|
| `worker.ts` | TypeScript worker class stub with `WorkerContext` and `WorkerResultEnvelope` |
| `registry-record.json` | WCP worker enrollment record |
| `README.md` | Worker card with capability, guarantee, and usage example |

## registry commands

The `registry` subcommand queries [api.pyhall.dev](https://api.pyhall.dev). Override with `PYHALL_REGISTRY_URL`.

```bash
pyhall registry status                          # API health check + version
pyhall registry verify <worker-id>              # Worker attestation status
pyhall registry check-hash <sha256>             # Ban-list hash lookup
pyhall registry ban-list                        # Show confirmed ban-list (default: 20 entries)
pyhall registry ban-list --limit 50             # Show up to 50 entries
```

## Environment variables

```bash
PYHALL_REGISTRY_URL=https://api.pyhall.dev   # Default registry URL (override for self-hosted)
```

## Related packages

- [`@pyhall/core`](https://www.npmjs.com/package/@pyhall/core) — TypeScript routing engine (SDK)
- [`pyhall-wcp`](https://pypi.org/project/pyhall-wcp/) — Python SDK and Python CLI

## Links

- [pyhall.dev](https://pyhall.dev) — Documentation and registry
- [WCP Spec](https://workerclassprotocol.dev) — Protocol specification
- [GitHub](https://github.com/fafolab/pyhall) — Source code

## License

Apache-2.0
