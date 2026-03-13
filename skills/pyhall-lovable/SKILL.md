---
name: pyhall-lovable
description: >
  Add WCP governance to Lovable-generated React and TypeScript web apps. Use this skill when a
  Lovable app needs AI worker routing decisions, capability authorization checks, or audit trails
  before calling downstream AI services. Installs @pyhall/core into the Vite/React project,
  wraps the Hall Server routing call in a typed React hook, and wires the decision result into
  conditional UI or API logic — all without leaving the Lovable editor.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Lovable / React Governance Integration

Add WCP routing decisions to any Lovable-generated React app so every AI worker call is governed,
attested, and auditable before it reaches your backend.

## What you can do

- **Gate AI features** — block a capability before it fires if pyhall returns `denied: true`
- **Attribute actions** — every decision is stamped with `worker_id`, `tenant_id`, and an `artifact_hash`
- **Audit in real time** — decisions land in your Hall Server log the moment they're made
- **Stay type-safe** — `@pyhall/core` ships full TypeScript types; no casting required
- **Work inside Lovable** — add the npm package and hook via the Lovable editor's package manager or `package.json`

## Install

Add the package to your Lovable project. In the Lovable editor open the terminal panel or edit
`package.json` directly:

```bash
npm install @pyhall/core
```

Set your environment variable in the Lovable project settings (or a `.env` file at project root —
Vite exposes `VITE_*` prefixed vars to the browser):

```bash
VITE_HALL_SESSION_TOKEN=hst_your_token_here
VITE_HALL_API_URL=http://localhost:8765   # or https://api.pyhall.dev for cloud
```

## React hook — `useHallDecision`

Create `src/hooks/useHallDecision.ts` in your Lovable project:

```typescript
import { useState, useCallback } from 'react';

export interface HallDecisionRequest {
  capability_id: string;   // e.g. "cap.content.generate.v1"
  worker_id: string;       // e.g. "wrk_abc123"
  env?: 'dev' | 'prod';
  data_label?: string;     // "PUBLIC" | "INTERNAL" | "CONFIDENTIAL"
  tenant_id?: string;
}

export interface HallDecisionResult {
  decision_id: string;
  denied: boolean;
  selected_worker_species_id: string;
  artifact_hash: string;
}

export function useHallDecision() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [decision, setDecision] = useState<HallDecisionResult | null>(null);

  const decide = useCallback(async (req: HallDecisionRequest): Promise<HallDecisionResult | null> => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `${import.meta.env.VITE_HALL_API_URL}/api/route`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${import.meta.env.VITE_HALL_SESSION_TOKEN}`,
          },
          body: JSON.stringify({
            capability_id: req.capability_id,
            worker_id: req.worker_id,
            env: req.env ?? 'dev',
            data_label: req.data_label ?? 'PUBLIC',
            tenant_id: req.tenant_id ?? 'org.default',
          }),
        }
      );
      if (!res.ok) throw new Error(`Hall Server returned ${res.status}`);
      const data: HallDecisionResult = await res.json();
      setDecision(data);
      return data;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return { decide, decision, loading, error };
}
```

## Using the hook in a Lovable component

```typescript
import { useHallDecision } from '@/hooks/useHallDecision';

export function GenerateButton({ workerId }: { workerId: string }) {
  const { decide, decision, loading, error } = useHallDecision();

  const handleGenerate = async () => {
    const result = await decide({
      capability_id: 'cap.content.generate.v1',
      worker_id: workerId,
      env: 'prod',
      data_label: 'INTERNAL',
      tenant_id: 'org.acme',
    });

    if (!result || result.denied) {
      // Governance denied — do not call downstream AI service
      console.warn('WCP denied:', result?.artifact_hash);
      return;
    }

    // Allowed — proceed with your AI call
    await callMyAIBackend({ decisionId: result.decision_id });
  };

  return (
    <button onClick={handleGenerate} disabled={loading}>
      {loading ? 'Checking governance...' : 'Generate'}
    </button>
  );
}
```

## Using `@pyhall/core` directly

If you prefer the SDK over a raw fetch:

```typescript
import { Hall } from '@pyhall/core';

const hall = new Hall({
  apiKey: import.meta.env.VITE_HALL_SESSION_TOKEN,
  baseUrl: import.meta.env.VITE_HALL_API_URL,
});

const decision = await hall.decisions.make({
  workerId: 'wrk_abc123',
  capability: 'cap.content.generate.v1',
  tenantId: 'org.acme',
});

if (decision.allowed) {
  // proceed
}
```

## Environment variables

```bash
VITE_HALL_SESSION_TOKEN=hst_...        # Hall Server session token (required)
VITE_HALL_API_URL=http://localhost:8765  # Hall Server base URL
# For registry operations (server-side only — never expose in browser bundle):
PYHALL_API_KEY=your-registry-api-key
```

Vite exposes `VITE_*` variables to the browser bundle. Keep `PYHALL_API_KEY` in server-side
code (API routes, Edge Functions) only — never in a Vite frontend bundle.

## Getting started

1. In the Lovable editor, open **Settings → Packages** and add `@pyhall/core`
2. Add `VITE_HALL_SESSION_TOKEN` in **Settings → Environment Variables**
3. Create `src/hooks/useHallDecision.ts` with the hook above
4. Call `decide(...)` before any AI feature button — gate on `denied`
5. Check decisions in your Hall Server log: `pyhall decision query --limit 20`

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
