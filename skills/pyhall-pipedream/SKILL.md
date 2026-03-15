---
name: pyhall-pipedream
description: >
  Add WCP governance gates to any Pipedream workflow using Node.js code steps. Use when you
  need to verify that an AI worker is registered, attested, and policy-authorized before a
  Pipedream step executes an AI call, writes data, or sends an outbound request. Export the
  pyhall routing decision via $.export() so downstream steps can branch on `denied`, log
  decision_id for audit, and surface artifact_hash for cryptographic proof — all from a
  single reusable governance step.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Pipedream Governance Gate

Add a pyhall governance step to any Pipedream workflow. A Node.js code step calls the Hall Server,
exports the decision fields via `$.export()`, and downstream steps branch on `steps.pyhall_gate.denied`.

## What you can do

- **Gate workflow steps** — require a valid pyhall routing decision before AI agent invocations,
  database writes, or outbound API calls
- **Export decision to downstream steps** — `$.export()` makes `denied`, `decision_id`, and
  `artifact_hash` available to every subsequent step in the workflow
- **Throw on denial** — optionally call `$.flow.exit()` or throw to halt the workflow immediately
  on a denied decision
- **Enforce data classification** — pass `data_label` from trigger or event data to apply
  PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED policies at the Hall Server
- **Audit every decision** — write `decision_id` and `artifact_hash` to any connected datastore
  using built-in Pipedream actions

## Step 1 — Configure environment variables in Pipedream

In your Pipedream account go to **Settings → Environment Variables** and add:

| Key | Value |
|---|---|
| `HALL_SESSION_TOKEN` | Your Hall Server session token |
| `PYHALL_API_KEY` | Your pyhall registry API key |
| `PYHALL_HALL_URL` | `http://your-hall-host:8765` |

Reference in code steps via `process.env.HALL_SESSION_TOKEN`, etc.

## Step 2 — Add the governance code step

In your Pipedream workflow, click **+** to add a step, select **Run Node.js code**, and paste the
following. Name the step `pyhall_gate`.

```javascript
// pyhall WCP governance gate — Pipedream Node.js step
// Step name: pyhall_gate
// Downstream steps reference: steps.pyhall_gate.<field>

export default defineComponent({
  async run({ steps, $ }) {
    const hallUrl   = process.env.PYHALL_HALL_URL ?? 'http://localhost:8765';
    const token     = process.env.HALL_SESSION_TOKEN;

    if (!token) throw new Error('HALL_SESSION_TOKEN is not set');

    // Pull worker_id and data_label from trigger or an earlier step.
    // Adjust field paths to match your workflow's event shape.
    const workerId  = steps.trigger.event?.worker_id  ?? 'org.acme.pipedream-worker';
    const dataLabel = steps.trigger.event?.data_label ?? 'INTERNAL';

    const payload = {
      capability_id: 'cap.data.write.v1',
      worker_id:     workerId,
      env:           'prod',
      data_label:    dataLabel,
      tenant_id:     'org.acme',
    };

    const response = await fetch(`${hallUrl}/api/route`, {
      method:  'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      // Fail closed — treat Hall Server errors as denials
      $.export('denied',       true);
      $.export('decision_id',  null);
      $.export('reason',       `hall_server_error: HTTP ${response.status}`);
      $.export('artifact_hash', null);
      $.flow.exit('Hall Server returned an error — failing closed');
      return;
    }

    const decision = await response.json();

    // Export all decision fields for downstream steps
    $.export('denied',                    decision.denied);
    $.export('decision_id',               decision.decision_id);
    $.export('selected_worker_species_id', decision.selected_worker_species_id);
    $.export('artifact_hash',             decision.artifact_hash);
    $.export('reason',                    decision.reason ?? null);
    $.export('capability_id',             payload.capability_id);
    $.export('worker_id',                 payload.worker_id);

    // Optional: halt the workflow immediately on denial.
    // Comment this out if you want downstream steps to handle denial logic.
    if (decision.denied) {
      $.flow.exit(`Governance denial: ${decision.reason ?? 'policy violation'}`);
    }
  },
});
```

### Field reference — payload

| Field | Required | Description |
|---|---|---|
| `capability_id` | Yes | WCP capability being requested, e.g. `cap.data.write.v1` |
| `worker_id` | Yes | Registered pyhall worker ID |
| `env` | Yes | `dev` or `prod` |
| `data_label` | No | `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, or `RESTRICTED` |
| `tenant_id` | No | Org namespace, e.g. `org.acme` |

### Exported fields — available in downstream steps

| Export key | Type | Access in downstream step |
|---|---|---|
| `denied` | boolean | `steps.pyhall_gate.denied` |
| `decision_id` | string | `steps.pyhall_gate.decision_id` |
| `selected_worker_species_id` | string | `steps.pyhall_gate.selected_worker_species_id` |
| `artifact_hash` | string | `steps.pyhall_gate.artifact_hash` |
| `reason` | string \| null | `steps.pyhall_gate.reason` |
| `capability_id` | string | `steps.pyhall_gate.capability_id` |
| `worker_id` | string | `steps.pyhall_gate.worker_id` |

## Step 3 — Branch on `denied` in a downstream step

### Option A — Conditional logic inside a code step

```javascript
export default defineComponent({
  async run({ steps, $ }) {
    if (steps.pyhall_gate.denied) {
      // governance denied — do not proceed
      console.log(`Denied. Decision: ${steps.pyhall_gate.decision_id}`);
      $.flow.exit('Blocked by pyhall governance');
      return;
    }

    // Allowed — continue with actual work
    console.log(`Allowed. Decision: ${steps.pyhall_gate.decision_id}`);
    // ... your downstream logic here
  },
});
```

### Option B — Use a Pipedream Filter step

After `pyhall_gate`, click **+** and select **Filter**:

- **Continue if:** `steps.pyhall_gate.denied` **is equal to** `false`

This halts the workflow without throwing an error when denied.

## Step 4 — Log decision_id for audit

Add a downstream step to write the governance record. Example using the built-in Google Sheets action:

```javascript
// Or write directly using fetch to any HTTP-accessible datastore
export default defineComponent({
  async run({ steps, $ }) {
    const record = {
      decision_id:   steps.pyhall_gate.decision_id,
      worker_id:     steps.pyhall_gate.worker_id,
      capability_id: steps.pyhall_gate.capability_id,
      denied:        steps.pyhall_gate.denied,
      artifact_hash: steps.pyhall_gate.artifact_hash,
      reason:        steps.pyhall_gate.reason,
      timestamp:     new Date().toISOString(),
    };

    await fetch(process.env.AUDIT_LOG_WEBHOOK_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(record),
    });

    $.export('audit_logged', true);
  },
});
```

## Reusable governance step component

For multi-workflow governance, publish the governance step as a reusable Pipedream component in
your account or organization. Create a file `pyhall_gate.mjs`:

```javascript
// pyhall_gate.mjs — reusable Pipedream component
export default {
  name:        'PyHall WCP Governance Gate',
  description: 'Check WCP policy before executing downstream steps',
  key:         'pyhall_gate',
  version:     '0.3.0',
  type:        'action',
  props: {
    capability_id: {
      type:        'string',
      label:       'Capability ID',
      description: 'WCP capability to check, e.g. cap.data.write.v1',
    },
    worker_id: {
      type:        'string',
      label:       'Worker ID',
      description: 'Registered pyhall worker ID',
    },
    env: {
      type:    'string',
      label:   'Environment',
      options: ['dev', 'prod'],
      default: 'prod',
    },
    data_label: {
      type:    'string',
      label:   'Data Label',
      options: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'],
      default: 'INTERNAL',
    },
    tenant_id: {
      type:    'string',
      label:   'Tenant ID',
      default: 'org.acme',
    },
    halt_on_denial: {
      type:    'boolean',
      label:   'Halt workflow on denial',
      default: true,
    },
  },
  async run({ $ }) {
    const hallUrl = process.env.PYHALL_HALL_URL ?? 'http://localhost:8765';
    const token   = process.env.HALL_SESSION_TOKEN;

    const response = await fetch(`${hallUrl}/api/route`, {
      method:  'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify({
        capability_id: this.capability_id,
        worker_id:     this.worker_id,
        env:           this.env,
        data_label:    this.data_label,
        tenant_id:     this.tenant_id,
      }),
    });

    const decision = await response.json();

    $.export('denied',       decision.denied);
    $.export('decision_id',  decision.decision_id);
    $.export('artifact_hash', decision.artifact_hash);
    $.export('reason',       decision.reason ?? null);

    if (decision.denied && this.halt_on_denial) {
      $.flow.exit(`Governance denial: ${decision.reason ?? 'policy violation'}`);
    }
  },
};
```

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
3. `pyhall worker register` — register a worker to represent your Pipedream integration
4. In Pipedream **Settings → Environment Variables**, add `HALL_SESSION_TOKEN` and `PYHALL_HALL_URL`
5. Add a **Node.js code step** named `pyhall_gate` using the template above
6. Reference `steps.pyhall_gate.denied` in downstream steps or Filter actions

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
