---
name: pyhall-zapier
description: >
  Add WCP governance checkpoints to any Zapier workflow using the Webhooks by Zapier action.
  Use when you need to gate downstream Zap steps behind a pyhall routing decision — ensuring
  the worker or integration invoking a capability is registered, attested, and policy-compliant
  before data moves, notifications fire, or records are written. Works with any Zap trigger
  and any downstream action via Zapier's built-in Filter or Paths logic.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Zapier Governance Gate

Add a pyhall governance check to any Zap. Any step that calls an AI worker, writes records, or
moves sensitive data should route through pyhall first. If the decision comes back `denied: true`,
use a Zapier Filter or Paths step to halt or redirect the Zap.

## What you can do

- **Gate any Zap step** — insert a governance checkpoint before AI agent actions, database writes,
  or notification sends
- **Branch on policy** — use the `denied` field with Zapier Paths or Filter to allow/block downstream steps
- **Capture audit records** — every pyhall decision returns a `decision_id` you can log to a
  spreadsheet, Airtable base, or Slack channel
- **Enforce data labels** — pass `data_label` from your trigger payload to enforce PUBLIC / INTERNAL /
  CONFIDENTIAL / RESTRICTED policies at the routing layer

## Step 1 — Store credentials in Zapier

In your Zapier account go to **My Apps → Zapier Manager → Environment Variables** (or use Zapier's
Secret Manager if on a Teams/Enterprise plan). Add:

```
HALL_SESSION_TOKEN   =  <your Hall Server session token>
PYHALL_API_KEY       =  <your pyhall registry API key>
```

For a self-hosted Hall Server, also store:

```
PYHALL_HALL_URL      =  http://your-hall-host:8765
```

Reference these as `{{zap_meta.bundle.environment.HALL_SESSION_TOKEN}}` in your Zap steps.

## Step 2 — Add the governance check step

Insert a **Webhooks by Zapier** action (choose action event: **POST**) at the point in your Zap
where governance should fire.

### Zap step configuration

| Field | Value |
|---|---|
| **URL** | `http://your-hall-host:8765/api/route` |
| **Payload Type** | `json` |
| **Headers** | `Authorization: Bearer {{zap_meta.bundle.environment.HALL_SESSION_TOKEN}}` |
| **Data (JSON body)** | see below |

**JSON body** — map fields from your trigger or earlier Zap steps:

```json
{
  "capability_id": "cap.data.write.v1",
  "worker_id": "{{1.worker_id}}",
  "env": "prod",
  "data_label": "{{1.data_label}}",
  "tenant_id": "org.acme"
}
```

Replace `{{1.worker_id}}` and `{{1.data_label}}` with the field mappings from your trigger step.
If your trigger does not carry a `worker_id`, use a fixed registered worker ID that represents the
Zapier integration (e.g., `org.acme.zapier-worker`).

### Field reference

| Field | Required | Description |
|---|---|---|
| `capability_id` | Yes | WCP capability being requested, e.g. `cap.data.write.v1` |
| `worker_id` | Yes | Registered pyhall worker ID making the request |
| `env` | Yes | `dev` or `prod` |
| `data_label` | No | `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, or `RESTRICTED` |
| `tenant_id` | No | Org namespace, e.g. `org.acme` |

### Response fields

Zapier will parse the JSON response. Key fields available in subsequent steps:

| Field | Type | Description |
|---|---|---|
| `decision_id` | string | Immutable audit record ID |
| `denied` | boolean | `true` = blocked, `false` = allowed |
| `selected_worker_species_id` | string | Matched worker species from WCP taxonomy |
| `artifact_hash` | string | Cryptographic proof of the decision |
| `reason` | string | Human-readable denial reason (only present when `denied: true`) |

## Step 3 — Branch on the `denied` field

### Option A — Filter (halt the Zap)

After the Webhooks step, add a **Filter by Zapier** step:

- **Only continue if:** `(Webhooks) denied` **Exactly Matches** `false`

This stops the Zap silently when the worker is denied.

### Option B — Paths (branch allowed vs. denied)

After the Webhooks step, add a **Paths by Zapier** step with two paths:

**Path A — Allowed:**
- Condition: `(Webhooks) denied` **Exactly Matches** `false`
- Continue with downstream actions (write record, send notification, etc.)

**Path B — Denied:**
- Condition: `(Webhooks) denied` **Exactly Matches** `true`
- Send a Slack alert, log to a spreadsheet, or create a task:
  ```
  Subject: Governance denial — {{(Webhooks) decision_id}}
  Body:    Worker {{1.worker_id}} denied for {{cap.data.write.v1}}
           Reason: {{(Webhooks) reason}}
  ```

## Step 4 — Log decision_id for audit

Add a **Google Sheets** or **Airtable** action in both paths to write:

```
decision_id      {{(Webhooks) decision_id}}
worker_id        {{1.worker_id}}
capability_id    cap.data.write.v1
denied           {{(Webhooks) denied}}
artifact_hash    {{(Webhooks) artifact_hash}}
timestamp        {{zap_meta.human_now}}
```

This gives you a full audit trail tied to immutable pyhall decision records.

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
3. `pyhall worker register` — register a worker to represent your Zapier integration
4. Store `HALL_SESSION_TOKEN` in Zapier's Secret Manager or environment variables
5. Add a **Webhooks by Zapier → POST** step to your Zap pointing at `/api/route`
6. Add a **Filter** or **Paths** step branching on `denied`

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
