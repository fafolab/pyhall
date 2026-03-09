---
name: pyhall-wcp
description: >
  Govern, register, and attest AI workers using the Worker Class Protocol (WCP) and pyhall CLI.
  Use when you need to register AI workers, check capability namespaces, query routing decisions,
  inspect attestation records, manage the ban list, or enforce WCP governance on any AI agent
  pipeline. Works with Anthropic MCP, OpenAI function tools, Gemini, LangChain, CrewAI, and AutoGen.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Worker Class Protocol Governance

You have access to the `pyhall` CLI and the PyHall WCP SDK for governing AI workers.

## What you can do

- **Register workers** — give an AI agent a verified identity with capability declarations
- **Check namespaces** — look up what worker identities are available or taken
- **Route decisions** — ask pyhall whether a worker is authorized to run a capability
- **Inspect attestation** — verify a worker's signed capability card
- **Manage the ban list** — check, report, or query banned workers
- **Install skills** — pull governed skills from the registry into your environment
- **Query decisions** — audit the history of routing decisions and denials

## CLI quick reference

```bash
# Install the CLI
npm install -g @pyhall/cli        # or: pip install pyhall-wcp

# Worker registration
pyhall worker register            # register a new worker
pyhall worker status <worker-id>  # check registration + attestation status
pyhall worker attest <worker-id>  # trigger attestation check

# Namespace operations
pyhall namespace check x.<name>          # check availability
pyhall namespace register x.<name>       # register community namespace
pyhall namespace register org.<name>.*   # register org namespace (paid plan)

# Capability routing
pyhall decision make --worker <id> --cap <capability-id>   # get a routing decision
pyhall decision query --worker <id> --limit 20              # query decision history

# Ban list
pyhall ban check <sha256>         # check if a worker hash is banned
pyhall ban report <sha256>        # report a worker for review

# Skills
pyhall skill install <org>/<skill>   # install a governed skill
pyhall skill list                    # list installed skills
pyhall skill verify <org>/<skill>    # check integrity since last certify
pyhall skill publish                 # publish a skill to the registry (requires cert)

# Registry
pyhall auth login                    # authenticate via GitHub OAuth
pyhall auth status                   # check current auth state
```

## Safe execution defaults

Use least privilege by default:

1. Prefer read-only commands first (`status`, `check`, `query`, `list`, `verify`).
2. Require explicit operator confirmation before mutation commands (`register`, `attest`, `revoke`, `report`, `publish`, `install`).
3. Never print raw secrets/tokens in output.
4. Deny-by-default on ambiguous context (unknown namespace, missing worker owner, missing policy context).

## Python SDK quick reference

```python
from pyhall import Hall, Worker, Capability

# Initialize
hall = Hall(api_key="your-key")  # or uses PYHALL_API_KEY env var

# Register a worker
worker = hall.workers.register(
    name="my-agent",
    namespace="x.myagent",
    capabilities=["cap.data.read.v1", "cap.report.generate.v1"],
    policy_tier=2
)

# Make a routing decision
decision = hall.decisions.make(
    worker_id=worker.id,
    capability="cap.data.read.v1"
)
print(decision.allowed)   # True / False
print(decision.proof)     # cryptographic proof hash

# Check attestation
attest = hall.workers.attest(worker.id)
print(attest.status)      # "attested" | "pending" | "denied"
```

## TypeScript / Node SDK

```typescript
import { Hall } from '@pyhall/core';

const hall = new Hall({ apiKey: process.env.PYHALL_API_KEY });

const decision = await hall.decisions.make({
  workerId: 'wrk_abc123',
  capability: 'cap.data.read.v1',
});

console.log(decision.allowed);  // boolean
console.log(decision.proof);    // attestation proof hash
```

## Namespace convention

| Prefix | Use case | Who can register |
|---|---|---|
| `x.*` | Community / personal workers | Anyone (free) |
| `org.<name>.*` | Organization workers | Paid plan |
| `cap.*` | WCP-reserved capabilities | pyhall core team |
| `wrk.*` | WCP-reserved worker types | pyhall core team |

## WCP governance chain

Every decision goes through:

1. Manifest hash verification
2. Worker attestation check
3. WCP policy evaluation
4. Ban list check
5. ALLOW or DENY → immutable audit record

Deny-by-default. No silent fallbacks.

## Environment variables

```bash
PYHALL_API_KEY=your-api-key         # registry authentication
PYHALL_REGISTRY=https://api.pyhall.dev   # default, override for self-hosted
PYHALL_NAMESPACE=x.myorg            # default namespace for new workers
```

## Getting started

1. `npm install -g @pyhall/cli` or `pip install pyhall-wcp`
2. `pyhall auth login` — authenticate with your GitHub account
3. `pyhall namespace check x.yourname` — claim your namespace
4. `pyhall worker register` — register your first worker
5. `pyhall decision make --worker <id> --cap cap.data.read.v1` — make your first governed decision

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
