---
name: pyhall-composio
description: >
  Use Composio to manage pyhall as an authenticated, governed action for AI agents built with
  LangChain, CrewAI, AutoGen, or any Composio-supported framework. Use this skill when you want
  to expose the pyhall WCP routing decision as a structured tool that agent frameworks can call
  via Composio's toolset abstraction — with auth managed by Composio, decision audit trails logged
  by pyhall, and zero manual token plumbing per-agent.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Composio Integration

Expose pyhall governance as a Composio-managed action so any LangChain, CrewAI, or AutoGen
agent can call `pyhall_governance_check` through the standard Composio toolset interface.

## What you can do

- **Single auth config** — Composio stores the `HALL_SESSION_TOKEN` as a connected account; agents
  never handle tokens directly
- **LangChain toolset** — `ComposioToolSet` wraps pyhall as a standard LangChain `BaseTool`
- **CrewAI toolset** — same action, zero extra code — `ComposioToolSet` returns CrewAI-compatible tools
- **Custom HTTP action** — register pyhall's `/api/route` endpoint as a Composio custom action
  with a typed input/output schema
- **Multi-agent governance** — every agent in a CrewAI crew or LangGraph graph hits the same
  pyhall Hall Server; decisions are correlated by `worker_id` and `tenant_id`

## Install

```bash
pip install composio-core composio-langchain pyhall-wcp
```

For CrewAI:

```bash
pip install composio-crewai
```

Two integration paths exist:

- **Path A (full packaged worker):** The worker runs as a registered, attested pyhall package. Worker ID follows the `org.<name>.<worker>.<instance>` format. Re-attest after any code or dependency change.
- **Path B (API-only):** The worker calls the Hall Server API directly without a local pyhall package. Suitable for integrations that do not own a deployable worker binary.

The examples below use Path A (packaged worker with a canonical `org.*` worker ID).

## Option A — Custom HTTP action (recommended)

Register pyhall's `/api/route` as a Composio custom action. This is the cleanest approach:
Composio manages the bearer token; agents call the action by name.

```python
import os
from composio import ComposioToolSet, Action
from composio.client.collections import ActionModel

toolset = ComposioToolSet(api_key=os.environ["COMPOSIO_API_KEY"])

# Register pyhall as a custom HTTP action
toolset.register_action(
    action=ActionModel(
        name="PYHALL_GOVERNANCE_CHECK",
        description=(
            "Check WCP authorization before executing a capability. "
            "Returns denied (bool), decision_id, and artifact_hash. "
            "Always call this before sensitive agent operations."
        ),
        parameters={
            "type": "object",
            "properties": {
                "capability_id": {
                    "type": "string",
                    "description": "WCP capability ID, e.g. cap.content.generate.v1",
                },
                "worker_id": {
                    "type": "string",
                    "description": "Registered pyhall worker ID, e.g. org.acme.my-worker.i-1",
                },
                "tenant_id": {
                    "type": "string",
                    "description": "Tenant namespace, e.g. org.acme",
                    "default": "org.default",
                },
                "env": {
                    "type": "string",
                    "enum": ["dev", "prod"],
                    "default": "dev",
                },
                "data_label": {
                    "type": "string",
                    "enum": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"],
                    "default": "PUBLIC",
                },
            },
            "required": ["capability_id", "worker_id"],
        },
        response={
            "type": "object",
            "properties": {
                "decision_id": {"type": "string"},
                "denied": {"type": "boolean"},
                "selected_worker_species_id": {"type": "string"},
                "artifact_hash": {"type": "string"},
            },
        },
    )
)
```

## Option B — Direct HTTP execution via Composio

If you prefer not to pre-register the action schema, execute the HTTP call through Composio's
`execute_action` with a custom HTTP action:

```python
import os
from composio import ComposioToolSet

toolset = ComposioToolSet(api_key=os.environ["COMPOSIO_API_KEY"])

response = toolset.execute_action(
    action="HTTPTOOL_POST",
    params={
        "url": os.environ.get("HALL_API_URL", "http://localhost:8765") + "/api/route",
        "headers": {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['HALL_SESSION_TOKEN']}",
        },
        "body": {
            "capability_id": "cap.content.generate.v1",
            "worker_id": "org.acme.my-worker.i-1",
            "env": "prod",
            "data_label": "INTERNAL",
            "tenant_id": "org.acme",
        },
    },
)

decision = response.get("data", {})
if decision.get("denied"):
    raise PermissionError(f"WCP denied: {decision.get('decision_id')}")
```

## LangChain integration

```python
import os
from composio_langchain import ComposioToolSet, Action
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

toolset = ComposioToolSet(api_key=os.environ["COMPOSIO_API_KEY"])

# Get pyhall action as a LangChain tool
pyhall_tools = toolset.get_tools(actions=["PYHALL_GOVERNANCE_CHECK"])

# Add your other agent tools
all_tools = pyhall_tools + your_other_tools

llm = ChatOpenAI(model="gpt-4o")
prompt = ChatPromptTemplate.from_messages([
    ("system", (
        "You are a governed AI agent. Before executing any capability, "
        "call PYHALL_GOVERNANCE_CHECK with the appropriate capability_id and worker_id. "
        "If denied is true, stop and report the decision_id. Never skip the governance check."
    )),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(llm, all_tools, prompt)
executor = AgentExecutor(agent=agent, tools=all_tools, verbose=True)

result = executor.invoke({"input": "Generate a report for Q1 sales"})
```

## CrewAI integration

```python
import os
from composio_crewai import ComposioToolSet, Action
from crewai import Agent, Task, Crew

toolset = ComposioToolSet(api_key=os.environ["COMPOSIO_API_KEY"])

pyhall_tools = toolset.get_tools(actions=["PYHALL_GOVERNANCE_CHECK"])

governance_agent = Agent(
    role="Governance Officer",
    goal="Authorize all AI worker actions via WCP before they execute",
    backstory=(
        "You enforce Worker Class Protocol governance. You call pyhall before "
        "any capability executes and halt the workflow if denied."
    ),
    tools=pyhall_tools,
    verbose=True,
)

execution_agent = Agent(
    role="Content Generator",
    goal="Generate content only after receiving WCP approval",
    backstory="You act only on capabilities approved by the Governance Officer.",
    tools=your_other_tools,
    verbose=True,
)

authorize_task = Task(
    description=(
        "Check WCP authorization for capability_id=cap.content.generate.v1 "
        "worker_id=org.acme.my-worker.i-1 tenant_id=org.acme. "
        "Return the decision_id and denied status."
        # Note: if the worker package or binary changes, re-attest before using in prod.
    ),
    expected_output="JSON with decision_id and denied field",
    agent=governance_agent,
)

generate_task = Task(
    description="Generate the Q1 sales report if the governance check passed.",
    expected_output="Generated report or denial message",
    agent=execution_agent,
    context=[authorize_task],
)

crew = Crew(agents=[governance_agent, execution_agent], tasks=[authorize_task, generate_task])
crew.kickoff()
```

## AutoGen integration

```python
import os
from composio_autogen import ComposioToolSet, Action
import autogen

toolset = ComposioToolSet(api_key=os.environ["COMPOSIO_API_KEY"])

assistant = autogen.AssistantAgent(
    name="GovernedAssistant",
    llm_config={"config_list": [{"model": "gpt-4o"}]},
    system_message=(
        "Always call PYHALL_GOVERNANCE_CHECK before any capability execution. "
        "Stop if denied is true."
    ),
)

user_proxy = autogen.UserProxyAgent(
    name="UserProxy",
    human_input_mode="NEVER",
    code_execution_config=False,
)

toolset.register_tools(
    actions=["PYHALL_GOVERNANCE_CHECK"],
    caller=assistant,
    executor=user_proxy,
)

user_proxy.initiate_chat(assistant, message="Generate the Q1 report")
```

## Environment variables

```bash
COMPOSIO_API_KEY=your-composio-key       # Composio platform API key
HALL_SESSION_TOKEN=hst_...               # Hall Server session token
HALL_API_URL=http://localhost:8765       # Hall Server base URL
PYHALL_API_KEY=your-registry-key         # pyhall registry auth (CLI only)
```

Store `HALL_SESSION_TOKEN` as a Composio connected account credential so agents retrieve it
automatically — run `composio add pyhall` after implementing the custom connector, or pass it
via environment variable for self-hosted deployments.

## Getting started

1. `pip install composio-core composio-langchain pyhall-wcp`
2. `composio login` — authenticate your Composio account
3. Set `HALL_SESSION_TOKEN` and `HALL_API_URL` in your environment
4. Register the `PYHALL_GOVERNANCE_CHECK` custom action (Option A above)
5. Use `toolset.get_tools(actions=["PYHALL_GOVERNANCE_CHECK"])` in your agent
6. Add a system prompt requiring the governance check before any capability execution
7. Verify decisions: `pyhall decision query --limit 20`

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
