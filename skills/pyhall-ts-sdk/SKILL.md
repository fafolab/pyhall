---
name: pyhall-ts-sdk
description: >
  Govern AI workers in any TypeScript or JavaScript application using the @pyhall/core SDK.
  Use this skill to register workers, make routing decisions, verify attestation, and enforce
  WCP policy controls in Node.js services, Next.js apps, Cloudflare Workers, Deno, and any
  JS/TS AI agent pipeline — deny-by-default governance with immutable audit trails.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall TypeScript / JavaScript SDK

Add WCP governance to any TypeScript or JavaScript application with `@pyhall/core`. One `hall.decisions.make()` call wraps any worker capability in the full governance chain: registration, attestation, policy evaluation, ban list check, and audit record.

## Installation

```bash
npm install @pyhall/core
# or
pnpm add @pyhall/core
```

## What you can do

- **Register workers** — give AI agents verified identities with capability declarations
- **Make routing decisions** — check authorization before every capability execution
- **Verify attestation** — confirm a worker's signed capability card is valid and unrevoked
- **Enforce policy tiers** — apply WCP risk controls to every invocation
- **Query audit history** — inspect every ALLOW/DENY decision
- **Manage namespaces** — claim `x.*` community or `org.<name>.*` org namespaces

## Quick start

```typescript
import { Hall } from '@pyhall/core';

const hall = new Hall({ apiKey: process.env.PYHALL_API_KEY! });

// Register a worker
const worker = await hall.workers.register({
  name: 'my-agent',
  namespace: 'x.myagent',
  capabilities: ['cap.data.read.v1', 'cap.report.generate.v1'],
  policyTier: 2,
});
console.log(worker.id);          // org.acme.my-worker.i-1
console.log(worker.namespace);   // x.myagent

// Make a routing decision before executing a capability
const decision = await hall.decisions.make({
  workerId: worker.id,
  capability: 'cap.data.read.v1',
  env: 'dev',
  dataLabel: 'PUBLIC',
  tenantId: 'org.acme',
});

if (decision.denied) {
  throw new Error(`pyhall denied: ${decision.denyReason}`);
}

// Safe to proceed
const result = await runMyCapability();
console.log(decision.proof);     // attestation proof hash
```

## Wrapping any function with governance

```typescript
import { Hall } from '@pyhall/core';

const hall = new Hall({ apiKey: process.env.PYHALL_API_KEY! });

function governed(capability: string, workerId: string) {
  return function <T extends (...args: any[]) => Promise<any>>(fn: T): T {
    return (async (...args: any[]) => {
      const decision = await hall.decisions.make({
        workerId,
        capability,
        env: process.env.PYHALL_ENV ?? 'dev',
        dataLabel: 'PUBLIC',
      });

      if (decision.denied) {
        throw new Error(`pyhall denied ${capability}: ${decision.denyReason}`);
      }

      return fn(...args);
    }) as T;
  };
}

const fetchSensitiveData = governed(
  'cap.data.read.v1',
  'org.acme.my-worker.i-1'
)(async (query: string) => {
  // Only runs when pyhall says ALLOW
  return { rows: [] };
});
```

## Next.js API route example

```typescript
// app/api/data/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { Hall } from '@pyhall/core';

const hall = new Hall({ apiKey: process.env.PYHALL_API_KEY! });

export async function POST(req: NextRequest) {
  const workerId = req.headers.get('x-worker-id');
  const capability = req.headers.get('x-capability');

  if (!workerId || !capability) {
    return NextResponse.json({ error: 'Missing governance headers' }, { status: 400 });
  }

  const decision = await hall.decisions.make({
    workerId,
    capability,
    env: 'prod',
    dataLabel: 'INTERNAL',
  });

  if (decision.denied) {
    return NextResponse.json({ error: decision.denyReason }, { status: 403 });
  }

  // Proceed with the actual request
  return NextResponse.json({ ok: true, proof: decision.proof });
}
```

## Cloudflare Worker example

```typescript
import { Hall } from '@pyhall/core';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const hall = new Hall({ apiKey: env.PYHALL_API_KEY });

    const decision = await hall.decisions.make({
      workerId: env.WORKER_ID,
      capability: 'cap.data.read.v1',
      env: 'prod',
      dataLabel: 'PUBLIC',
    });

    if (decision.denied) {
      return new Response(JSON.stringify({ error: decision.denyReason }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Authorized', { status: 200 });
  },
};

interface Env {
  PYHALL_API_KEY: string;
  WORKER_ID: string;
}
```

## Local Hall Server (Hall Monitor)

When Hall Monitor is running locally on port 8765:

```typescript
const token = process.env.HALL_SESSION_TOKEN!;
const serverUrl = process.env.HALL_SERVER_URL ?? 'http://localhost:8765';

const resp = await fetch(`${serverUrl}/api/route`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    capability_id: 'cap.data.read.v1',
    worker_id: 'org.acme.my-worker.i-1',
    env: 'dev',
    data_label: 'PUBLIC',
    tenant_id: 'org.acme',
  }),
});

const decision = await resp.json();

if (decision.denied) {
  throw new Error(decision.deny_reason ?? 'Denied by pyhall');
}
```

## Checking attestation

```typescript
const attest = await hall.workers.attest('org.acme.my-worker.i-1');

console.log(attest.status);        // "attested" | "pending" | "denied"
console.log(attest.artifactHash);  // SHA-256 of attested worker package
console.log(attest.attestedAt);    // ISO timestamp

if (attest.status !== 'attested') {
  throw new Error('Worker is not attested — refusing to proceed');
}
```

## Environment variables

```bash
PYHALL_API_KEY=your-api-key              # registry authentication (required)
PYHALL_REGISTRY=https://api.pyhall.dev   # default registry URL
PYHALL_ENV=dev                           # environment tag (dev | staging | prod)
HALL_SESSION_TOKEN=your-token            # local Hall Server auth (Hall Monitor)
HALL_SERVER_URL=http://localhost:8765    # local Hall Server URL
```

## Getting started

```bash
# 1. Install
npm install @pyhall/core

# 2. Authenticate (CLI)
npm install -g @pyhall/cli
pyhall auth login

# 3. Claim a namespace
pyhall namespace check x.yourname

# 4. Register a worker
pyhall worker register

# 5. Make a governed decision
pyhall decision make --worker <id> --cap cap.data.read.v1
```

Full documentation: https://pyhall.dev/docs/reference/typescript/
WCP specification: https://workerclassprotocol.dev/spec/
