---
name: pyhall-langflow
description: >
  Add WCP governance to Langflow pipelines using a custom Python component. Use this skill when
  a Langflow agent or chain needs to authorize an AI worker before invoking a tool, calling an
  LLM, or writing to storage. The pyhall component calls the Hall Server, returns a structured
  decision message, and halts the flow on denial — keeping your LangChain graph governed and
  fully auditable without modifying Langflow core.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Langflow Custom Component

Drop a pyhall governance checkpoint into any Langflow flow. Every decision is signed, logged, and
deny-by-default — you get an immutable audit record before any downstream LLM or tool call fires.

## What you can do

- **Authorize workers inline** — the component calls `POST /api/route` and returns a `Message`
  with `decision_id`, `denied`, and `artifact_hash` for downstream nodes to consume
- **Gate agent tools** — connect the output to a Conditional Router to halt the chain on denial
- **Propagate proof** — forward `artifact_hash` to storage or logging components downstream
- **Parameterize per flow** — `capability_id`, `worker_id`, and `tenant_id` are exposed as
  Langflow UI inputs, so different flows can govern different capabilities with no code change
- **Fail closed** — any network or auth error returns `denied: true`; the flow never silently
  proceeds past a broken governance check

## Install dependency

pyhall uses only the Python standard library for the HTTP call, but install the SDK for the
`make_decision()` helper:

```bash
pip install pyhall-wcp
```

Or add `pyhall-wcp` to your Langflow custom components dependency list in
`~/.langflow/components/requirements.txt`.

## Custom component — `PyHallGovernanceCheck`

Create a new custom component in Langflow (**Components → Custom Component → New**) and paste:

```python
from langflow.custom import CustomComponent
from langflow.schema import Message
from pyhall import Hall
import os


class PyHallGovernanceCheck(CustomComponent):
    """
    WCP governance checkpoint.
    Calls the pyhall Hall Server and returns a structured decision.
    Connect the output to a Conditional Router: route on `denied == False`.
    """

    display_name = "PyHall Governance Check"
    description = "WCP worker authorization via pyhall Hall Server"
    icon = "shield"

    def build_config(self):
        return {
            "capability_id": {
                "display_name": "Capability ID",
                "info": "WCP capability to authorize, e.g. cap.content.generate.v1",
                "required": True,
            },
            "worker_id": {
                "display_name": "Worker ID",
                "info": "Registered pyhall worker ID, e.g. wrk_abc123",
                "required": True,
            },
            "tenant_id": {
                "display_name": "Tenant ID",
                "info": "Tenant namespace, e.g. org.acme",
                "value": "org.default",
                "required": False,
            },
            "env": {
                "display_name": "Environment",
                "options": ["dev", "prod"],
                "value": "dev",
                "required": False,
            },
            "data_label": {
                "display_name": "Data Label",
                "options": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"],
                "value": "PUBLIC",
                "required": False,
            },
            "hall_api_url": {
                "display_name": "Hall Server URL",
                "value": "http://localhost:8765",
                "required": False,
            },
        }

    def build(
        self,
        capability_id: str,
        worker_id: str,
        tenant_id: str = "org.default",
        env: str = "dev",
        data_label: str = "PUBLIC",
        hall_api_url: str = "http://localhost:8765",
    ) -> Message:
        import requests

        token = os.environ.get("HALL_SESSION_TOKEN", "")
        if not token:
            return Message(text="DENIED: HALL_SESSION_TOKEN not set", data={"denied": True})

        try:
            resp = requests.post(
                f"{hall_api_url}/api/route",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                json={
                    "capability_id": capability_id,
                    "worker_id": worker_id,
                    "env": env,
                    "data_label": data_label,
                    "tenant_id": tenant_id,
                },
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            # Fail closed on any error
            return Message(
                text=f"DENIED: governance check failed ({exc})",
                data={"denied": True, "decision_id": "error", "artifact_hash": ""},
            )

        status = "ALLOWED" if not data.get("denied") else "DENIED"
        return Message(
            text=f"{status}: {data.get('decision_id')} | hash={data.get('artifact_hash')}",
            data={
                "denied": data.get("denied", True),
                "decision_id": data.get("decision_id", ""),
                "selected_worker_species_id": data.get("selected_worker_species_id", ""),
                "artifact_hash": data.get("artifact_hash", ""),
            },
        )
```

## Connecting the component in a Langflow flow

```
[Chat Input]
      |
[PyHall Governance Check]
  capability_id = "cap.content.generate.v1"
  worker_id     = "wrk_abc123"
  tenant_id     = "org.acme"
      |
[Conditional Router]
  condition: data.denied == False
      |              \
  [TRUE]           [FALSE]
  [OpenAI LLM]   [Chat Output: "Request denied by WCP governance"]
      |
[Chat Output]
```

The **Conditional Router** component reads `data.denied` from the Message output of
`PyHallGovernanceCheck`. Wire:
- `True` branch → your LLM / tool component
- `False` branch → a static Message component returning the denial text

## Using `pyhall-wcp` SDK directly inside the component

If you prefer the SDK's `make_decision()` helper over a raw `requests` call:

```python
from pyhall import Hall
import os

hall = Hall(
    api_key=os.environ["HALL_SESSION_TOKEN"],
    base_url=os.environ.get("HALL_API_URL", "http://localhost:8765"),
)

decision = hall.decisions.make(
    worker_id="wrk_abc123",
    capability="cap.content.generate.v1",
    tenant_id="org.acme",
)

if decision.allowed:
    # proceed
    pass
```

## Environment variables

```bash
HALL_SESSION_TOKEN=hst_...             # Hall Server session token (required)
HALL_API_URL=http://localhost:8765     # Hall Server base URL
PYHALL_API_KEY=your-registry-key       # Registry auth (for pyhall CLI only)
```

Set these in your Langflow server environment or in a `.env` file loaded at startup.

## Getting started

1. `pip install pyhall-wcp` in your Langflow Python environment
2. Set `HALL_SESSION_TOKEN` in the Langflow server environment
3. In Langflow, go to **Components → Custom Component → New**, paste the component above
4. Drag `PyHall Governance Check` into your flow before any LLM or tool node
5. Connect its output to a **Conditional Router** — branch on `data.denied == False`
6. Run the flow; verify decisions: `pyhall decision query --limit 20`

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
