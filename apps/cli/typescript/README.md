# @pyhall/cli — Worker Class Protocol CLI

The `pyhall` command-line tool for the [Worker Class Protocol](https://workerclassprotocol.dev). Browse the WCP taxonomy, search capabilities and workers, explain WCP concepts, scaffold new workers, and query the pyhall.dev registry.

**WCP version:** 0.1
**Package version:** 0.2.0

## Install

```bash
npm install -g @pyhall/cli
```

## Commands

```
pyhall browse              Browse the WCP taxonomy interactively
pyhall search <query>      Search capabilities, workers, and controls
pyhall explain <id>        Explain a WCP entity (cap.*, wrk.*, ctrl.*)
pyhall scaffold            Scaffold a new WCP worker
pyhall registry status     Check pyhall.dev registry health
pyhall registry verify <id>  Verify a worker's attestation status
pyhall version             Print version info
```

## Quick start

```bash
# Search the taxonomy
pyhall search "file write"

# Explain a capability
pyhall explain cap.fs.write.local.v1

# Check registry health
pyhall registry status

# Verify a worker
pyhall registry verify x.my.worker
```

## Registry commands

The `registry` subcommand queries [api.pyhall.dev](https://pyhall.dev):

```bash
pyhall registry status                          # API health check
pyhall registry verify <worker-id>              # Worker attestation status
pyhall registry verify <worker-id> --registry-url https://api.pyhall.dev
```

## Related packages

- [`@pyhall/core`](https://www.npmjs.com/package/@pyhall/core) — TypeScript routing engine (SDK)
- [`pyhall-wcp`](https://pypi.org/project/pyhall-wcp/) — Python SDK

## Links

- [pyhall.dev](https://pyhall.dev) — Documentation and registry
- [WCP Spec](https://workerclassprotocol.dev) — Protocol specification
- [GitHub](https://github.com/fafolab/pyhall) — Source code

## License

Apache-2.0
