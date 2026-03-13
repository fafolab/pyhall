---
name: pyhall-n8n
description: >
  Integrate WCP governance gates into any n8n workflow using the HTTP Request node or an inline
  Code node. Use when you need to verify that an AI worker is registered, attested, and
  policy-authorized before n8n executes downstream operations — database writes, AI calls,
  or outbound notifications. Branch on the `denied` field via an IF node to allow compliant
  paths and halt or alert on policy violations, with full cryptographic audit trails via
  decision_id. Works with self-hosted and n8n Cloud instances.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — n8n Governance Gate

Add a pyhall governance checkpoint to any n8n workflow. Use an **HTTP Request** node (no code
required) or a **Code** node (for dynamic capability resolution or multi-check logic). Branch on
the `denied` field using an **IF** node.

## What you can do

- **Gate workflow nodes** — require a valid pyhall routing decision before AI agent calls,
  database writes, or outbound API requests
- **Branch on policy** — use an IF node with `denied` to route allowed vs. denied execution paths
- **Inline governance** — use the Code node for dynamic capability checks within a single step
- **Enforce data classification** — pass `data_label` to apply PUBLIC / INTERNAL / CONFIDENTIAL /
  RESTRICTED policies at the Hall Server
- **Audit decisions** — capture `decision_id` and `artifact_hash` in any n8n-connected datastore

## Step 1 — Configure credentials in n8n

In n8n, go to **Settings → Credentials → New Credential → Header Auth**.

Create a credential named `pyhall-hall-server`:

| Field | Value |
|---|---|
| **Name** | `Authorization` |
| **Value** | `Bearer <your HALL_SESSION_TOKEN>` |

Store your Hall Server URL as an **n8n environment variable** (self-hosted: `N8N_CUSTOM_VARIABLES`
in your `.env` file; n8n Cloud: **Settings → Variables**):

```bash
PYHALL_HALL_URL=http://your-hall-host:8765
PYHALL_API_KEY=your-api-key
```

Reference in nodes as `{{ $env.PYHALL_HALL_URL }}`.

## Option A — HTTP Request node (no-code)

Insert an **HTTP Request** node at the governance checkpoint.

### HTTP Request node settings

| Setting | Value |
|---|---|
| **Method** | `POST` |
| **URL** | `{{ $env.PYHALL_HALL_URL }}/api/route` |
| **Authentication** | `Header Auth` → select `pyhall-hall-server` credential |
| **Send Body** | `JSON` |
| **Specify Body** | `Using JSON` |
| **Response Format** | `JSON` |

**JSON body:**

```json
{
  "capability_id": "cap.data.write.v1",
  "worker_id": "{{ $json.worker_id }}",
  "env": "prod",
  "data_label": "{{ $json.data_label }}",
  "tenant_id": "org.acme"
}
```

Replace `$json.worker_id` and `$json.data_label` with field references from the upstream node.
If the upstream payload does not carry a `worker_id`, use a fixed registered worker ID (e.g.,
`wrk_n8n_acme_prod`).

### Response fields available downstream

| Field | Type | Description |
|---|---|---|
| `decision_id` | string | Immutable audit record ID |
| `denied` | boolean | `true` = blocked, `false` = allowed |
| `selected_worker_species_id` | string | Matched WCP worker species |
| `artifact_hash` | string | Cryptographic proof of the decision |
| `reason` | string | Denial reason (only when `denied: true`) |

Reference in the next node as `{{ $json.denied }}`, `{{ $json.decision_id }}`, etc.

## Option B — Code node (inline governance)

Use a **Code** node when you need dynamic capability resolution, multiple checks, or want to
encapsulate governance logic in a single reusable step.

```javascript
// pyhall governance gate — Code node (JavaScript)
const hallUrl = $env.PYHALL_HALL_URL ?? 'http://localhost:8765';
const token   = $env.HALL_SESSION_TOKEN;

const payload = {
  capability_id: 'cap.data.write.v1',
  worker_id:     $input.first().json.worker_id ?? 'wrk_n8n_acme_prod',
  env:           'prod',
  data_label:    $input.first().json.data_label ?? 'INTERNAL',
  tenant_id:     'org.acme',
};

const response = await $http.request({
  method:  'POST',
  url:     `${hallUrl}/api/route`,
  headers: { Authorization: `Bearer ${token}` },
  body:    payload,
  json:    true,
});

// Surface decision fields for downstream nodes
return [{
  json: {
    ...response,                          // includes denied, decision_id, artifact_hash
    _governance_checked: true,
    _capability: payload.capability_id,
    _worker_id:  payload.worker_id,
  },
}];
```

`$http` is available natively in n8n Code nodes (no import required).

## Step 2 — Branch on `denied` with an IF node

After the HTTP Request or Code node, add an **IF** node:

**True branch (allowed):**
| Setting | Value |
|---|---|
| **Value 1** | `{{ $json.denied }}` |
| **Operation** | `Equal` |
| **Value 2** | `false` |

**True path** → continue with downstream nodes (write record, call AI, send notification).

**False path** → denied route: log denial, send alert, or halt.

## Step 3 — Denied path: alert and log

On the false (denied) path, add:

**Slack / email node** (alert):
```
Subject: Governance denial — {{ $json.decision_id }}
Body:    Worker {{ $json._worker_id }} denied for {{ $json._capability }}
         Reason: {{ $json.reason }}
         Artifact: {{ $json.artifact_hash }}
```

**Append to Google Sheets or Postgres node** (audit log):

| Column | Value |
|---|---|
| `decision_id` | `{{ $json.decision_id }}` |
| `worker_id` | `{{ $json._worker_id }}` |
| `capability_id` | `cap.data.write.v1` |
| `denied` | `{{ $json.denied }}` |
| `artifact_hash` | `{{ $json.artifact_hash }}` |
| `timestamp` | `{{ $now }}` |

Write the same audit row on the allowed path to maintain a complete decision log.

## Error handling

In the HTTP Request node, enable **On Error: Continue (using error output)** and wire the error
output to a Set node that forces `denied: true` with `reason: "hall_server_unreachable"`. This
ensures the workflow fails closed rather than open if the Hall Server is down.

For strict production governance, set the HTTP Request node **Timeout** to `10000 ms` and treat
any non-200 response as a denial.

## Common capability IDs

```
cap.data.read.v1          Read structured data
cap.data.write.v1         Write or mutate records
cap.notify.send.v1        Send notifications or messages
cap.report.generate.v1    Generate and deliver reports
cap.auth.verify.v1        Identity/auth operations
cap.workflow.trigger.v1   Trigger downstream workflows
```

Full taxonomy: https://pyhall.dev/workers/taxonomy/

## Environment variables

```bash
HALL_SESSION_TOKEN    # Required — Hall Server session token (local or hosted)
PYHALL_API_KEY        # Required — pyhall registry API key
PYHALL_HALL_URL       # Optional — defaults to http://localhost:8765
PYHALL_REGISTRY       # Optional — defaults to https://api.pyhall.dev
```

## Getting started

1. `pip install pyhall-wcp` or `npm install -g @pyhall/cli`
2. `pyhall auth login` — authenticate
3. `pyhall worker register` — register a worker to represent your n8n instance
4. Create a `Header Auth` credential in n8n with your `HALL_SESSION_TOKEN`
5. Add an **HTTP Request** node to your workflow pointing at `/api/route`
6. Add an **IF** node branching on `{{ $json.denied }}`

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
