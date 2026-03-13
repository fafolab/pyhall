---
name: pyhall-make
description: >
  Embed WCP governance gates into any Make (formerly Integromat) scenario using the HTTP module.
  Use when you need to verify that a worker is registered, attested, and policy-authorized before
  a Make scenario executes AI operations, writes database records, or sends outbound messages.
  Route on the `denied` field via Make's Router module to allow compliant paths and quarantine
  or alert on policy violations — with full cryptographic audit trails via decision_id.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Make (Integromat) Governance Gate

Add a pyhall governance checkpoint to any Make scenario. Insert an HTTP module before any step
that calls an AI worker, writes data, or moves sensitive records. Branch the scenario using a
Router module: allowed decisions continue downstream, denied decisions trigger alerts or quarantine.

## What you can do

- **Gate scenario steps** — require a valid pyhall routing decision before AI calls, database
  writes, or outbound API calls execute
- **Branch on policy** — use Make's Router module with filter conditions on `denied`
- **Enforce data classification** — pass `data_label` to enforce PUBLIC / INTERNAL / CONFIDENTIAL /
  RESTRICTED policies at the Hall Server
- **Audit every decision** — capture `decision_id` and `artifact_hash` in Airtable, Google Sheets,
  or a Make Datastore for compliance records

## Step 1 — Store credentials in Make

In Make, go to **Organization → Variables** (Teams plan) or configure credentials per-scenario
using a **Set Variable** module at the start of the flow. Store:

```
HALL_SESSION_TOKEN    <your Hall Server session token>
PYHALL_API_KEY        <your pyhall registry API key>
PYHALL_HALL_URL       http://your-hall-host:8765
```

Reference with `{{variable.HALL_SESSION_TOKEN}}` in HTTP module headers.

## Step 2 — Add the HTTP governance module

Insert an **HTTP → Make a Request** module at the governance checkpoint in your scenario.

### HTTP module configuration

| Setting | Value |
|---|---|
| **URL** | `{{variable.PYHALL_HALL_URL}}/api/route` |
| **Method** | `POST` |
| **Headers** | `Authorization: Bearer {{variable.HALL_SESSION_TOKEN}}` |
| **Body type** | `Raw` |
| **Content type** | `application/json` |
| **Parse response** | `Yes` |

**Request body:**

```json
{
  "capability_id": "cap.data.write.v1",
  "worker_id": "{{1.worker_id}}",
  "env": "prod",
  "data_label": "{{1.data_label}}",
  "tenant_id": "org.acme"
}
```

Replace `{{1.worker_id}}` and `{{1.data_label}}` with mappings from the trigger or earlier modules
in your scenario. If your trigger does not carry a `worker_id`, use a fixed registered worker ID
that represents your Make integration (e.g., `wrk_make_acme_prod`).

### Field reference

| Field | Required | Description |
|---|---|---|
| `capability_id` | Yes | WCP capability being requested, e.g. `cap.data.write.v1` |
| `worker_id` | Yes | Registered pyhall worker ID |
| `env` | Yes | `dev` or `prod` |
| `data_label` | No | `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, or `RESTRICTED` |
| `tenant_id` | No | Org namespace, e.g. `org.acme` |

### Response fields

With **Parse response: Yes**, Make exposes these fields from the pyhall response:

| Field | Type | Description |
|---|---|---|
| `decision_id` | string | Immutable audit record ID |
| `denied` | boolean | `true` = blocked, `false` = allowed |
| `selected_worker_species_id` | string | Matched worker species |
| `artifact_hash` | string | Cryptographic proof of the decision |
| `reason` | string | Denial reason (only present when `denied: true`) |

Reference in downstream modules as `{{2.denied}}`, `{{2.decision_id}}`, etc.
(module number depends on position in your scenario).

## Step 3 — Branch on `denied` using a Router module

After the HTTP module, add a **Router** module. Configure two routes:

### Route 1 — Allowed

**Filter condition:**

| Setting | Value |
|---|---|
| **Label** | `Allowed` |
| **Condition** | `{{2.denied}}` **Equal to** `false` |

Continue with downstream modules: write records, call AI, send notifications.

### Route 2 — Denied

**Filter condition:**

| Setting | Value |
|---|---|
| **Label** | `Denied` |
| **Condition** | `{{2.denied}}` **Equal to** `true` |

Downstream actions on this route:
- Send a Slack or email alert with `{{2.decision_id}}` and `{{2.reason}}`
- Write a denial record to Airtable or Google Sheets
- Set a Make Datastore flag for downstream monitoring

## Step 4 — Log decision_id for audit

On both routes, add a module to write the governance record. Example for Google Sheets:

| Column | Value |
|---|---|
| decision_id | `{{2.decision_id}}` |
| worker_id | `{{1.worker_id}}` |
| capability_id | `cap.data.write.v1` |
| denied | `{{2.denied}}` |
| artifact_hash | `{{2.artifact_hash}}` |
| timestamp | `{{now}}` |

## Error handling

Add an error handler to the HTTP module (**right-click → Add error handler**):

- **Ignore** for non-critical flows (continues scenario even if Hall Server is unreachable)
- **Break** for strict governance (halts scenario on any HTTP error)
- **Rollback** if the scenario includes transactional operations

For production, configure the HTTP module with:
- **Timeout:** 10000 ms
- **Follow redirect:** Yes
- **Evaluate all states as errors except:** 200

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
3. `pyhall worker register` — register a worker to represent your Make integration
4. Store credentials in **Make → Organization → Variables**
5. Add an **HTTP → Make a Request** module to your scenario pointing at `/api/route`
6. Add a **Router** module branching on `{{http_module.denied}}`

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
