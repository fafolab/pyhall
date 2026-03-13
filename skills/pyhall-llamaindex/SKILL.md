---
name: pyhall-llamaindex
description: >
  Integrate pyhall WCP governance into LlamaIndex agents and query pipelines. Expose
  pyhall capability decisions as native LlamaIndex FunctionTools so every agent action
  passes through the Worker Class Protocol before it executes. Gives LlamaIndex
  ReActAgents and FunctionCallingAgents auditable, deny-by-default governance with
  registered worker identity, cryptographic proof, and an immutable audit trail.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — LlamaIndex Governance Integration

Add WCP governance to any LlamaIndex agent. Wrap pyhall capability decisions as
`FunctionTool` objects and attach them to a `ReActAgent` or `FunctionCallingAgent`.
Every governed tool call is authorized before execution and produces an immutable
audit record.

## What you can do

- **Gate agent actions** — require a pyhall ALLOW before any LlamaIndex tool executes
- **Attach to any agent type** — `ReActAgent`, `FunctionCallingAgent`, or custom pipelines
- **Produce audit trails** — every decision writes `decision_id` and `artifact_hash` to the registry
- **Block banned workers** — ban list check is automatic on every routing decision
- **Compose with query engines** — wrap a `QueryEngineTool` with a governance pre-flight

## Installation

```bash
pip install pyhall-wcp llama-index llama-index-llms-openai
```

## Environment variables

```bash
PYHALL_API_KEY=your-api-key           # registry authentication
HALL_SESSION_TOKEN=your-session-tok   # local Hall Server auth (if self-hosted)
OPENAI_API_KEY=your-openai-key        # for LlamaIndex LLM backend
PYHALL_REGISTRY=https://api.pyhall.dev    # default; override for self-hosted
```

## Core pattern — FunctionTool wrapping a pyhall decision

`FunctionTool.from_defaults()` is the simplest way to expose pyhall governance as a
LlamaIndex-native tool. The function docstring becomes the tool description the agent reads.

```python
import os
from pyhall import make_decision
from llama_index.core.tools import FunctionTool

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


def check_data_read_capability(action_description: str) -> str:
    """
    Check WCP governance before reading data. Call this before any data access.
    Returns authorization status and cryptographic proof. Raises on denial.
    action_description: brief description of what data operation will be performed.
    """
    decision = make_decision(
        capability_id="cap.data.read.v1",
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        raise PermissionError(
            f"WCP governance denied cap.data.read.v1 for worker '{WORKER_ID}'. "
            f"Reason: {decision.reason}. Decision ID: {decision.decision_id}"
        )
    return (
        f"ALLOWED. decision_id={decision.decision_id} "
        f"worker_species={decision.selected_worker_species_id} "
        f"artifact_hash={decision.artifact_hash}"
    )


def check_report_capability(report_type: str) -> str:
    """
    Check WCP governance before generating a report. Call this before report generation.
    report_type: the kind of report to be generated (e.g., 'sales', 'audit', 'summary').
    """
    decision = make_decision(
        capability_id="cap.report.generate.v1",
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        raise PermissionError(
            f"WCP governance denied cap.report.generate.v1. "
            f"Reason: {decision.reason}. Decision ID: {decision.decision_id}"
        )
    return f"ALLOWED for report_type='{report_type}'. proof={decision.artifact_hash}"


# Wrap as LlamaIndex FunctionTools
data_read_tool   = FunctionTool.from_defaults(fn=check_data_read_capability)
report_gen_tool  = FunctionTool.from_defaults(fn=check_report_capability)
```

## Full agent example — ReActAgent with governed tools

```python
import os
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


def pyhall_governance_check(capability_id: str, context: str) -> str:
    """
    Check WCP governance for a given capability before execution.
    capability_id: the pyhall capability to check (e.g., 'cap.data.read.v1').
    context: brief description of why this capability is needed.
    Returns decision proof on ALLOW; raises PermissionError on DENY.
    """
    decision = make_decision(
        capability_id=capability_id,
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        raise PermissionError(
            f"[WCP DENY] capability='{capability_id}' worker='{WORKER_ID}' "
            f"reason='{decision.reason}' decision_id='{decision.decision_id}'"
        )
    return (
        f"[WCP ALLOW] capability='{capability_id}' "
        f"decision_id='{decision.decision_id}' "
        f"artifact_hash='{decision.artifact_hash}'"
    )


def fetch_data(query: str) -> str:
    """Fetch internal data matching the query. Always call governance check first."""
    # real implementation here
    return f"[DATA] results for: {query}"


def generate_report(content: str, report_type: str = "summary") -> str:
    """Generate a structured report from content. Always call governance check first."""
    # real implementation here
    return f"[REPORT:{report_type}] {content[:200]}"


# Build tool list
governance_tool = FunctionTool.from_defaults(fn=pyhall_governance_check)
data_tool       = FunctionTool.from_defaults(fn=fetch_data)
report_tool     = FunctionTool.from_defaults(fn=generate_report)

llm = OpenAI(model="gpt-4o", temperature=0)

agent = ReActAgent.from_tools(
    tools=[governance_tool, data_tool, report_tool],
    llm=llm,
    verbose=True,
    system_prompt=(
        "You are a governed AI agent. Before calling fetch_data, call "
        "pyhall_governance_check with capability_id='cap.data.read.v1'. "
        "Before calling generate_report, call pyhall_governance_check with "
        "capability_id='cap.report.generate.v1'. Never skip governance."
    ),
)

response = agent.chat("Fetch the Q1 sales records and generate a summary report.")
print(response)
```

## FunctionCallingAgent example

```python
from llama_index.core.agent import FunctionCallingAgent
from llama_index.llms.openai import OpenAI

llm = OpenAI(model="gpt-4o")

agent = FunctionCallingAgent.from_tools(
    tools=[governance_tool, data_tool, report_tool],
    llm=llm,
    verbose=True,
)

response = agent.chat("Check if I can read data, then fetch the latest sales figures.")
print(response)
```

## Wrapping a QueryEngineTool with governance

Gate an existing query engine behind a pyhall decision before it handles any query:

```python
from llama_index.core.tools import QueryEngineTool, ToolMetadata
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
from pyhall import make_decision

def build_governed_query_tool(
    index: VectorStoreIndex,
    worker_id: str,
    tenant_id: str,
    capability_id: str = "cap.data.read.v1",
) -> FunctionTool:
    """Wrap a VectorStoreIndex query engine with a pyhall governance pre-flight."""

    query_engine = index.as_query_engine()

    def governed_query(query_text: str) -> str:
        """
        Query the document index with WCP governance pre-flight.
        query_text: the natural language question to answer from the index.
        """
        # Governance gate
        decision = make_decision(
            capability_id=capability_id,
            worker_id=worker_id,
            env="prod",
            data_label="INTERNAL",
            tenant_id=tenant_id,
        )
        if decision.denied:
            raise PermissionError(
                f"WCP denied '{capability_id}': {decision.reason} "
                f"[{decision.decision_id}]"
            )

        # Authorized — run the query
        response = query_engine.query(query_text)
        return str(response)

    return FunctionTool.from_defaults(fn=governed_query)


# Usage
# documents = SimpleDirectoryReader("./data").load_data()
# index = VectorStoreIndex.from_documents(documents)
# governed_tool = build_governed_query_tool(index, WORKER_ID, TENANT_ID)
# agent = ReActAgent.from_tools([governed_tool], llm=llm)
```

## Using the local Hall Server (self-hosted)

```python
import os
import requests

HALL_URL   = os.environ.get("HALL_SERVER_URL", "http://localhost:8765")
HALL_TOKEN = os.environ["HALL_SESSION_TOKEN"]

def local_pyhall_check(capability_id: str, worker_id: str, tenant_id: str) -> str:
    """
    Check WCP governance via local Hall Server.
    capability_id: capability to authorize. worker_id: registered worker. tenant_id: org scope.
    """
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
    result = resp.json()
    if result.get("denied"):
        raise PermissionError(
            f"Hall Server denied '{capability_id}'. decision_id={result['decision_id']}"
        )
    return f"ALLOWED [{result['decision_id']}] artifact_hash={result.get('artifact_hash')}"

local_governance_tool = FunctionTool.from_defaults(fn=local_pyhall_check)
```

## WCP governance chain (every decision)

1. Manifest hash verification — worker binary matches registered hash
2. Worker attestation check — worker is attested and not expired
3. WCP policy evaluation — capability is in worker's declared set
4. Ban list check — worker hash not on global or tenant ban list
5. ALLOW or DENY → immutable audit record written

Deny-by-default. No silent fallbacks.

## Getting started

1. `pip install pyhall-wcp llama-index llama-index-llms-openai`
2. `pyhall auth login` — authenticate
3. `pyhall worker register` — get your `worker_id`
4. Set `PYHALL_API_KEY`, `MY_WORKER_ID`, `OPENAI_API_KEY` in your environment
5. Add governed tools to your agent using the patterns above
6. `pyhall decision query --worker <id>` — audit your decision history

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
