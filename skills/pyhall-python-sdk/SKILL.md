---
name: pyhall-python-sdk
description: >
  Govern AI workers in any Python application using the pyhall-wcp SDK.
  Use this skill to register workers, make routing decisions, verify attestation,
  and enforce WCP policy controls in Python scripts, services, FastAPI apps,
  and AI agent pipelines — all with deny-by-default governance and immutable audit trails.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall Python SDK

Add WCP governance to any Python application. One `make_decision()` call wraps any worker capability in the full governance chain: registration, attestation, policy evaluation, ban list check, and audit record.

## Installation

```bash
pip install pyhall-wcp
```

## What you can do

- **Register workers** — give AI agents verified identities with capability declarations
- **Make routing decisions** — check authorization before every capability execution
- **Verify attestation** — confirm a worker's signed capability card is valid and unrevoked
- **Enforce policy tiers** — apply WCP risk controls (L0–L8) to every invocation
- **Query audit history** — inspect every ALLOW/DENY decision with timestamps and worker IDs
- **Manage namespaces** — claim and check `x.*` community or `org.<name>.*` org namespaces

## Quick start

```python
import os
from pyhall import Hall

hall = Hall(api_key=os.environ["PYHALL_API_KEY"])

# Register a worker
worker = hall.workers.register(
    name="my-agent",
    namespace="x.myagent",
    capabilities=["cap.data.read.v1", "cap.report.generate.v1"],
    policy_tier=2,
)
print(worker.id)          # wrk_abc123
print(worker.namespace)   # x.myagent

# Make a routing decision before executing a capability
decision = hall.decisions.make(
    worker_id=worker.id,
    capability="cap.data.read.v1",
    env="dev",
    data_label="PUBLIC",
    tenant_id="org.acme",
)

if decision.denied:
    raise PermissionError(f"Denied: {decision.deny_reason}")

# Safe to proceed — worker is authorized
result = run_my_capability()
print(decision.proof)     # cryptographic proof hash for audit
```

## Wrapping any function with governance

```python
import functools
from pyhall import Hall

hall = Hall(api_key=os.environ["PYHALL_API_KEY"])

def governed(capability: str, worker_id: str):
    """Decorator that gates any function behind a pyhall routing decision."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            decision = hall.decisions.make(
                worker_id=worker_id,
                capability=capability,
                env=os.environ.get("PYHALL_ENV", "dev"),
                data_label="PUBLIC",
            )
            if decision.denied:
                raise PermissionError(
                    f"pyhall denied {capability} for {worker_id}: {decision.deny_reason}"
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@governed("cap.data.read.v1", worker_id="wrk_abc123")
def fetch_sensitive_data(query: str) -> dict:
    # Only runs when pyhall says ALLOW
    return {"rows": [...]}
```

## FastAPI middleware example

```python
from fastapi import FastAPI, Request, HTTPException
from pyhall import Hall

app = FastAPI()
hall = Hall(api_key=os.environ["PYHALL_API_KEY"])

@app.middleware("http")
async def pyhall_governance(request: Request, call_next):
    worker_id = request.headers.get("X-Worker-ID")
    capability = request.headers.get("X-Capability")

    if worker_id and capability:
        decision = hall.decisions.make(
            worker_id=worker_id,
            capability=capability,
            env="prod",
            data_label="INTERNAL",
        )
        if decision.denied:
            raise HTTPException(status_code=403, detail=decision.deny_reason)

    return await call_next(request)
```

## Checking worker attestation

```python
attest = hall.workers.attest(worker_id="wrk_abc123")

print(attest.status)          # "attested" | "pending" | "denied"
print(attest.artifact_hash)   # SHA-256 of the attested worker package
print(attest.attested_at)     # ISO timestamp

if attest.status != "attested":
    raise RuntimeError("Worker is not attested — refusing to proceed")
```

## Querying decision history

```python
history = hall.decisions.query(worker_id="wrk_abc123", limit=20)

for d in history.decisions:
    status = "ALLOW" if not d.denied else f"DENY ({d.deny_reason})"
    print(f"{d.decided_at}  {d.capability_id}  →  {status}")
```

## Local Hall Server (Hall Monitor)

When Hall Monitor is running locally on port 8765:

```python
import os, requests

token = os.environ["HALL_SESSION_TOKEN"]
url   = os.environ.get("HALL_SERVER_URL", "http://localhost:8765")

resp = requests.post(
    f"{url}/api/route",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "capability_id": "cap.data.read.v1",
        "worker_id": "wrk_abc123",
        "env": "dev",
        "data_label": "PUBLIC",
        "tenant_id": "org.acme",
    },
    timeout=5,
)
resp.raise_for_status()
decision = resp.json()

if decision["denied"]:
    raise PermissionError(decision.get("deny_reason", "Denied by pyhall"))
```

## Environment variables

```bash
PYHALL_API_KEY=your-api-key          # registry authentication (required)
PYHALL_REGISTRY=https://api.pyhall.dev   # default registry URL (override for self-hosted)
PYHALL_NAMESPACE=x.myorg            # default namespace for new worker registrations
PYHALL_ENV=dev                       # environment tag (dev | staging | prod)
HALL_SESSION_TOKEN=your-token        # local Hall Server auth (Hall Monitor)
HALL_SERVER_URL=http://localhost:8765 # local Hall Server URL
```

## Getting started

```bash
# 1. Install
pip install pyhall-wcp

# 2. Authenticate
pyhall auth login

# 3. Claim a namespace
pyhall namespace check x.yourname

# 4. Register your first worker
pyhall worker register

# 5. Make a governed decision
pyhall decision make --worker <id> --cap cap.data.read.v1
```

Full documentation: https://pyhall.dev/docs/reference/python/
WCP specification: https://workerclassprotocol.dev/spec/
