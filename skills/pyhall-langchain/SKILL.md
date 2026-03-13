---
name: pyhall-langchain
description: >
  Integrate pyhall WCP governance into LangChain agents and pipelines. Wrap any capability
  decision gate as a native LangChain BaseTool so every tool invocation passes through
  the Worker Class Protocol before execution. Gives LangChain agents auditable, deny-by-default
  governance — registered worker identity, capability authorization, cryptographic proof,
  and an immutable audit trail — without changing your existing agent architecture.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — LangChain Governance Integration

Add WCP governance to any LangChain agent. Every tool call goes through a pyhall routing
decision before execution. Denied calls are blocked with a structured reason — never silently
skipped or retried.

## What you can do

- **Gate tool execution** — require a pyhall ALLOW decision before any LangChain tool runs
- **Enforce worker identity** — bind your agent to a registered worker ID with declared capabilities
- **Audit every invocation** — decisions produce a `decision_id` and `artifact_hash` stored in the registry
- **Block banned workers** — pyhall ban list check is automatic on every decision
- **Mix governed and ungoverned tools** — wrap only the tools that need governance; leave others as-is

## Installation

```bash
pip install pyhall-wcp langchain langchain-openai
```

## Environment variables

```bash
PYHALL_API_KEY=your-api-key          # registry authentication
HALL_SESSION_TOKEN=your-session-tok  # local Hall Server auth (if running local server)
PYHALL_REGISTRY=https://api.pyhall.dev   # default; override for self-hosted
```

## Core pattern — PyhallGovernanceTool

Subclass `BaseTool` and call `make_decision()` in `_run`. If the decision is denied, raise
`ToolException` rather than proceeding. The wrapped tool only executes on ALLOW.

```python
import os
from typing import Optional, Type
from langchain.tools import BaseTool
from langchain.tools.base import ToolException
from pydantic import BaseModel, Field
from pyhall import make_decision

class PyhallGovernanceInput(BaseModel):
    query: str = Field(description="The input query or data to process")

class PyhallGovernanceTool(BaseTool):
    """A LangChain tool that checks pyhall WCP governance before executing."""

    name: str = "pyhall_governance_check"
    description: str = (
        "Check whether the current worker is authorized to execute a capability "
        "under WCP governance. Returns authorization status and decision proof."
    )
    args_schema: Type[BaseModel] = PyhallGovernanceInput

    # WCP parameters — set these on instantiation
    worker_id: str
    capability_id: str
    tenant_id: str = "org.default"
    env: str = "dev"
    data_label: str = "PUBLIC"

    def _run(self, query: str) -> str:
        decision = make_decision(
            capability_id=self.capability_id,
            worker_id=self.worker_id,
            env=self.env,
            data_label=self.data_label,
            tenant_id=self.tenant_id,
        )
        if decision.denied:
            raise ToolException(
                f"WCP governance denied capability '{self.capability_id}' "
                f"for worker '{self.worker_id}'. "
                f"Reason: {decision.reason}. "
                f"Decision ID: {decision.decision_id}"
            )
        return (
            f"ALLOWED. decision_id={decision.decision_id} "
            f"worker_species={decision.selected_worker_species_id} "
            f"artifact_hash={decision.artifact_hash}"
        )

    async def _arun(self, query: str) -> str:
        # For async agents — delegate to sync for now; swap in async SDK when available
        return self._run(query)
```

## Wrapping an existing tool with governance

Use `PyhallGovernanceTool` as a pre-flight check, or subclass it to wrap another tool:

```python
from langchain.tools import BaseTool
from langchain.tools.base import ToolException
from pyhall import make_decision
from my_tools import DatabaseQueryTool  # your existing tool

class GovernedDatabaseTool(DatabaseQueryTool):
    """DatabaseQueryTool with pyhall WCP pre-flight governance."""

    worker_id: str
    capability_id: str = "cap.data.read.v1"
    tenant_id: str
    env: str = "prod"
    data_label: str = "INTERNAL"

    def _run(self, query: str) -> str:
        # 1. Governance gate
        decision = make_decision(
            capability_id=self.capability_id,
            worker_id=self.worker_id,
            env=self.env,
            data_label=self.data_label,
            tenant_id=self.tenant_id,
        )
        if decision.denied:
            raise ToolException(
                f"Governance denied: {decision.reason} [{decision.decision_id}]"
            )

        # 2. Execute the underlying tool only after ALLOW
        return super()._run(query)
```

## Full agent example — AgentExecutor with governed tools

```python
import os
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain.tools.base import ToolException
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]       # your registered pyhall worker ID
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


def make_governed_tool(capability_id: str, env: str = "dev"):
    """Factory: returns a @tool-decorated function gated by a pyhall decision."""

    def governance_gate(action_input: str) -> str:
        decision = make_decision(
            capability_id=capability_id,
            worker_id=WORKER_ID,
            env=env,
            data_label="INTERNAL",
            tenant_id=TENANT_ID,
        )
        if decision.denied:
            raise ToolException(
                f"pyhall denied '{capability_id}': {decision.reason} "
                f"(decision_id={decision.decision_id})"
            )
        # Decision passed — return proof so the agent can log it
        return f"Authorized. proof={decision.artifact_hash}"

    governance_gate.__name__ = f"govern_{capability_id.replace('.', '_')}"
    return tool(governance_gate)


# Build governed tools
data_read_gate = make_governed_tool("cap.data.read.v1", env="prod")
report_gate    = make_governed_tool("cap.report.generate.v1", env="prod")

# Also include your real execution tools (ungoverned, or pre-wrapped)
@tool
def fetch_data(query: str) -> str:
    """Fetch data from the internal database."""
    # ... real implementation
    return f"Data for: {query}"

@tool
def generate_report(content: str) -> str:
    """Generate a formatted report from content."""
    # ... real implementation
    return f"Report: {content}"


tools = [data_read_gate, report_gate, fetch_data, generate_report]

llm = ChatOpenAI(model="gpt-4o", temperature=0)

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a governed AI agent. Always check governance before accessing data."),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])

agent = create_openai_tools_agent(llm, tools, prompt)
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    handle_tool_error=True,   # surfaces ToolException as a message instead of crashing
    verbose=True,
)

result = agent_executor.invoke({"input": "Fetch the Q1 sales data and generate a report."})
print(result["output"])
```

## Using the local Hall Server (self-hosted)

If you run a local Hall Server instead of the cloud registry, route decisions via HTTP:

```python
import os
import requests
from langchain.tools.base import ToolException

HALL_URL   = os.environ.get("HALL_SERVER_URL", "http://localhost:8765")
HALL_TOKEN = os.environ["HALL_SESSION_TOKEN"]

def local_decision(capability_id: str, worker_id: str, tenant_id: str) -> dict:
    resp = requests.post(
        f"{HALL_URL}/api/route",
        json={
            "capability_id": capability_id,
            "worker_id": worker_id,
            "env": "dev",
            "data_label": "PUBLIC",
            "tenant_id": tenant_id,
        },
        headers={"Authorization": f"Bearer {HALL_TOKEN}"},
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()

def governed_run(capability_id: str, worker_id: str, tenant_id: str, action: str) -> str:
    result = local_decision(capability_id, worker_id, tenant_id)
    if result.get("denied"):
        raise ToolException(
            f"Hall Server denied '{capability_id}'. decision_id={result['decision_id']}"
        )
    return f"ALLOWED [{result['decision_id']}] → executing: {action}"
```

## WCP governance chain (every decision)

1. Manifest hash verification — worker binary matches registered hash
2. Worker attestation check — worker is attested and not expired
3. WCP policy evaluation — capability is in worker's declared set
4. Ban list check — worker hash not on global or tenant ban list
5. ALLOW or DENY → immutable audit record written

Deny-by-default. No silent fallbacks.

## Getting started

1. `pip install pyhall-wcp langchain langchain-openai`
2. `pyhall auth login` — authenticate
3. `pyhall worker register` — get your `worker_id`
4. Set `PYHALL_API_KEY` and `MY_WORKER_ID` in your environment
5. Wrap your tools using the patterns above
6. `pyhall decision query --worker <id>` — audit your decision history

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
