---
name: pyhall-dify
description: >
  Add WCP governance checkpoints to Dify workflows using the HTTP Request node or a Python Code
  node. Use this skill when a Dify LLM app needs to authorize an AI worker before invoking a
  tool, calling an external API, or branching into sensitive logic. The pyhall Hall Server returns
  a structured JSON decision that Dify can inspect in an IF/ELSE branch — denials halt the
  workflow, approvals pass the decision_id downstream for audit tracing.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Dify Workflow Governance Integration

Insert a pyhall routing decision into any Dify workflow. Governed decisions are immutable, signed,
and logged before any sensitive tool or LLM call executes.

## What you can do

- **Block unauthorized capabilities** — use IF/ELSE after the HTTP node to halt on `denied: true`
- **Capture audit proof** — forward `decision_id` and `artifact_hash` to downstream nodes
- **Support any Dify app type** — Chatflow, Workflow, Agent, and Chatbot all support HTTP Request nodes
- **No code required** — the HTTP Request node handles auth headers and JSON body natively
- **Python fallback** — use a Code node if you need preprocessing or dynamic capability IDs

## Option A — HTTP Request node (no-code)

Insert an **HTTP Request** node in your Dify workflow before any sensitive step.

### Node configuration

| Field | Value |
|---|---|
| Method | `POST` |
| URL | `http://localhost:8765/api/route` (or your Hall Server URL) |
| Authorization | `Bearer` → value: your `HALL_SESSION_TOKEN` |
| Content-Type | `application/json` |

### Request body (JSON)

```json
{
  "capability_id": "{{#sys.query#}}",
  "worker_id": "wrk_abc123",
  "env": "prod",
  "data_label": "INTERNAL",
  "tenant_id": "org.acme"
}
```

Replace `"{{#sys.query#}}"` with a static capability ID or a variable reference from an earlier
node — for example `{{#node.capability_selector.output.capability_id#}}`.

### Variable references from the HTTP response

Dify maps the JSON response body into node output variables automatically. Reference them in
downstream nodes:

| Variable | Path | Example value |
|---|---|---|
| `decision_id` | `body.decision_id` | `dec_7f3a...` |
| `denied` | `body.denied` | `true` or `false` |
| `selected_worker_species_id` | `body.selected_worker_species_id` | `ws_llm_basic` |
| `artifact_hash` | `body.artifact_hash` | `sha256:4c2a...` |

### IF/ELSE branch after the HTTP node

Add an **IF/ELSE** node immediately after the HTTP Request node:

- **IF:** `{{#http_node.body.denied#}} == false`  → continue to the governed tool
- **ELSE:** end the workflow or return an error message to the user

```
[HTTP Request: pyhall /api/route]
        |
    [IF/ELSE]
   denied == false?
      /        \
  [YES]        [NO]
  Continue     End / Error message
```

## Option B — Python Code node

Use a **Code** node when you need to build the capability ID dynamically or handle errors
explicitly before branching.

```python
import requests

def main(worker_id: str, capability_id: str, tenant_id: str) -> dict:
    """
    pyhall WCP governance check.
    Returns decision fields for downstream nodes.
    """
    HALL_URL = "http://localhost:8765/api/route"
    HALL_TOKEN = "hst_your_token_here"   # use Dify secret variable in production

    try:
        resp = requests.post(
            HALL_URL,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {HALL_TOKEN}",
            },
            json={
                "capability_id": capability_id,
                "worker_id": worker_id,
                "env": "prod",
                "data_label": "INTERNAL",
                "tenant_id": tenant_id,
            },
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "decision_id": data["decision_id"],
            "denied": data["denied"],
            "selected_worker_species_id": data["selected_worker_species_id"],
            "artifact_hash": data["artifact_hash"],
        }
    except Exception as e:
        # Fail closed — deny on any error
        return {
            "decision_id": "error",
            "denied": True,
            "selected_worker_species_id": "",
            "artifact_hash": "",
        }
```

**Code node inputs:**

| Name | Type | Source |
|---|---|---|
| `worker_id` | String | upstream variable or static `wrk_abc123` |
| `capability_id` | String | start node variable or classifier output |
| `tenant_id` | String | user session context or static `org.acme` |

**Code node outputs:** `decision_id`, `denied`, `selected_worker_species_id`, `artifact_hash`

After the Code node, add an IF/ELSE: `denied == false` → proceed.

## Storing `HALL_SESSION_TOKEN` securely

In Dify, go to **Settings → Secret Variables** and add:

```
HALL_SESSION_TOKEN = hst_your_token_here
```

Reference it in the HTTP Request node Authorization field as `{{HALL_SESSION_TOKEN}}`.
In Code nodes, inject it via the input variable panel — never hardcode tokens in workflow exports.

## Environment variables

```bash
HALL_SESSION_TOKEN=hst_...           # Hall Server session token
HALL_API_URL=http://localhost:8765   # Hall Server base URL
PYHALL_API_KEY=your-registry-key     # Registry auth (for pyhall CLI, not Dify nodes)
```

## Getting started

1. Start your Hall Server: `pyhall server start` (local) or point to `https://api.pyhall.dev`
2. In Dify, open your workflow and add an **HTTP Request** node before any sensitive tool
3. Configure method `POST`, URL, and `Authorization: Bearer <token>` header
4. Set the JSON body with your `capability_id` and `worker_id`
5. Add an **IF/ELSE** node branching on `body.denied == false`
6. Verify decisions in the Hall Server log: `pyhall decision query --limit 20`

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
