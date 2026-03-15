---
name: pyhall-flowise
description: >
  Add WCP governance to Flowise agent flows using a Custom Tool node. Use this skill when a
  Flowise ChatAgent or Tool Agent needs to authorize an AI worker before executing a capability.
  The pyhall tool makes a POST to the Hall Server and returns a structured JSON object that the
  agent can inspect — denied decisions halt the action, approved decisions pass the artifact_hash
  forward for audit tracing, all without modifying Flowise core.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Flowise Custom Tool Integration

Add a pyhall governance tool to any Flowise agent. The tool is called by the LLM before
sensitive operations and returns an immutable WCP routing decision.

## What you can do

- **Gate agent actions** — the LLM calls the pyhall tool and reads `denied` before proceeding
- **Audit everything** — each decision produces a signed `artifact_hash` and `decision_id`
- **Work with any Flowise agent** — ChatAgent, Tool Agent, OpenAI Function Agent all support
  Custom Tool nodes with the same JSON schema
- **No Flowise plugin required** — the Custom Tool node runs plain JavaScript in Flowise's
  sandboxed function executor
- **Fail closed** — network errors and missing tokens always return `denied: true`

## Step 1 — Add a Custom Tool node

In Flowise, open your flow and drag in a **Custom Tool** node. Configure:

| Field | Value |
|---|---|
| Tool Name | `pyhall_governance_check` |
| Tool Description | `Check WCP authorization before executing a capability. Always call this before sensitive operations. Returns denied (bool) and decision_id.` |
| Return Direct | `false` (let the agent decide what to do with the result) |

## Step 2 — Tool JSON schema

Paste this into the **Input Schema** field of the Custom Tool:

```json
{
  "type": "object",
  "properties": {
    "capability_id": {
      "type": "string",
      "description": "WCP capability to authorize, e.g. cap.content.generate.v1"
    },
    "worker_id": {
      "type": "string",
      "description": "Registered pyhall worker ID, e.g. org.acme.my-worker.i-1"
    },
    "tenant_id": {
      "type": "string",
      "description": "Tenant namespace, e.g. org.acme. Defaults to org.default if omitted."
    },
    "env": {
      "type": "string",
      "enum": ["dev", "prod"],
      "description": "Deployment environment. Use prod for live systems."
    }
  },
  "required": ["capability_id", "worker_id"]
}
```

## Step 3 — Custom Tool function body (JavaScript)

Paste this into the **Function** field of the Custom Tool node:

```javascript
const https = require('https');
const http = require('http');

const HALL_API_URL = process.env.HALL_API_URL || 'http://localhost:8765';
const HALL_SESSION_TOKEN = process.env.HALL_SESSION_TOKEN || '';

if (!HALL_SESSION_TOKEN) {
  return JSON.stringify({ denied: true, decision_id: 'error', error: 'HALL_SESSION_TOKEN not set' });
}

const payload = JSON.stringify({
  capability_id: $capability_id,
  worker_id: $worker_id,
  env: $env || 'dev',
  data_label: 'INTERNAL',
  tenant_id: $tenant_id || 'org.default',
});

const url = new URL(HALL_API_URL + '/api/route');
const lib = url.protocol === 'https:' ? https : http;

const result = await new Promise((resolve) => {
  const req = lib.request(
    {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${HALL_SESSION_TOKEN}`,
        'Content-Length': Buffer.byteLength(payload),
      },
    },
    (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          resolve({ denied: true, decision_id: 'parse_error', artifact_hash: '' });
        }
      });
    }
  );
  req.on('error', (err) => {
    resolve({ denied: true, decision_id: 'network_error', error: err.message, artifact_hash: '' });
  });
  req.write(payload);
  req.end();
});

return JSON.stringify(result);
```

Flowise injects the schema properties as `$capability_id`, `$worker_id`, `$tenant_id`, `$env`
in the function scope.

## Step 4 — Wire the tool into a ChatAgent flow

```
[Chat Input]
      |
[ChatAgent]  ←——  [pyhall_governance_check Custom Tool]
      |            [Other Tool A]
      |            [Other Tool B]
[Chat Output]
```

The agent will call `pyhall_governance_check` before any sensitive tool. Include a system prompt
instruction:

```
Before executing any capability, call pyhall_governance_check with the appropriate capability_id
and worker_id. If the result contains "denied": true, respond with "Action denied by WCP
governance — decision_id: <id>" and do not proceed.
```

## Full Flowise tool JSON (export/import)

You can import this configuration directly via **Flowise → Tools → Import**:

```json
{
  "name": "pyhall_governance_check",
  "description": "Check WCP authorization before executing a capability. Returns denied (bool), decision_id, and artifact_hash.",
  "schema": "{\"type\":\"object\",\"properties\":{\"capability_id\":{\"type\":\"string\"},\"worker_id\":{\"type\":\"string\"},\"tenant_id\":{\"type\":\"string\"},\"env\":{\"type\":\"string\",\"enum\":[\"dev\",\"prod\"]}},\"required\":[\"capability_id\",\"worker_id\"]}",
  "func": "/* paste the JavaScript function body from Step 3 here */"
}
```

## Environment variables

Set these in your Flowise server environment (`.env` file or system environment):

```bash
HALL_SESSION_TOKEN=hst_...             # Hall Server session token (required)
HALL_API_URL=http://localhost:8765     # Hall Server base URL
PYHALL_API_KEY=your-registry-key       # Registry auth (for pyhall CLI only, not the tool)
```

In Flowise Cloud, add these in **Settings → Environment Variables**.

## Getting started

1. Start your Hall Server: `pyhall server start` (or point to `https://api.pyhall.dev`)
2. Set `HALL_SESSION_TOKEN` and `HALL_API_URL` in your Flowise environment
3. In Flowise, create a new **Custom Tool** with the schema and function above
4. Add the tool to a **ChatAgent** or **Tool Agent** node
5. Add a system prompt instructing the agent to call the tool before sensitive operations
6. Test: send a chat message that triggers a capability; check the tool output in Flowise debug panel
7. Verify decisions: `pyhall decision query --limit 20`

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
