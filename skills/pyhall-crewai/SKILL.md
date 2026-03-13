---
name: pyhall-crewai
description: >
  Integrate pyhall WCP governance into CrewAI multi-agent pipelines. Expose pyhall
  capability decisions as native CrewAI tools using the @tool decorator so every agent
  action passes through the Worker Class Protocol before it executes. Gives CrewAI
  crews auditable, deny-by-default governance with registered worker identity,
  cryptographic proof, and an immutable audit trail — across all agents in a Crew.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — CrewAI Governance Integration

Add WCP governance to any CrewAI crew. Define pyhall decision checks as `@tool`-decorated
functions and assign them to your `Agent` instances. Every governed step is authorized before
execution and produces an immutable audit record in the pyhall registry.

## What you can do

- **Gate crew tasks** — require a pyhall ALLOW before any crew agent executes a capability
- **Per-agent worker IDs** — bind each CrewAI agent to its own registered pyhall worker identity
- **Audit every task** — decisions produce `decision_id` and `artifact_hash` stored in the registry
- **Block banned workers** — ban list check is automatic on every routing decision
- **Mix governed and ungoverned tools** — add the pyhall tool alongside your existing tools

## Installation

```bash
pip install pyhall-wcp crewai crewai-tools
```

## Environment variables

```bash
PYHALL_API_KEY=your-api-key           # registry authentication
HALL_SESSION_TOKEN=your-session-tok   # local Hall Server auth (if self-hosted)
OPENAI_API_KEY=your-openai-key        # CrewAI default LLM
PYHALL_REGISTRY=https://api.pyhall.dev    # default; override for self-hosted
```

## Core pattern — @tool decorated governance check

Use the `crewai.tools` `@tool` decorator to define a pyhall governance check as a CrewAI
tool. The docstring is what the agent reads to decide when to call the tool.

```python
import os
from crewai.tools import tool
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


@tool("pyhall_governance_check")
def pyhall_governance_check(capability_id: str) -> str:
    """
    Check WCP governance before executing a capability.
    Use this tool before any data access, report generation, or privileged action.
    Pass the capability ID string (e.g., 'cap.data.read.v1').
    Returns authorization proof on ALLOW; returns a denial message on DENY.
    """
    decision = make_decision(
        capability_id=capability_id,
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        return (
            f"DENIED. capability='{capability_id}' worker='{WORKER_ID}' "
            f"reason='{decision.reason}' decision_id='{decision.decision_id}'. "
            f"Do not proceed with this action."
        )
    return (
        f"ALLOWED. capability='{capability_id}' "
        f"decision_id='{decision.decision_id}' "
        f"worker_species='{decision.selected_worker_species_id}' "
        f"artifact_hash='{decision.artifact_hash}'"
    )
```

## Per-capability tool factories

For stricter enforcement, define one tool per capability so agents cannot pass arbitrary
capability IDs:

```python
import os
from crewai.tools import tool
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


@tool("check_data_read_authorization")
def check_data_read_authorization(context: str) -> str:
    """
    Verify WCP authorization for reading internal data (cap.data.read.v1).
    Call this before any database query or file read operation.
    context: brief description of the data access being performed.
    """
    decision = make_decision(
        capability_id="cap.data.read.v1",
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        return f"DENIED: data read not authorized. Reason: {decision.reason} [{decision.decision_id}]"
    return f"ALLOWED: data read authorized. proof={decision.artifact_hash}"


@tool("check_report_generation_authorization")
def check_report_generation_authorization(report_type: str) -> str:
    """
    Verify WCP authorization for generating reports (cap.report.generate.v1).
    Call this before creating any report or summary document.
    report_type: the type of report to be generated (e.g., 'quarterly', 'audit').
    """
    decision = make_decision(
        capability_id="cap.report.generate.v1",
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        return f"DENIED: report generation not authorized. Reason: {decision.reason} [{decision.decision_id}]"
    return f"ALLOWED: report generation authorized for '{report_type}'. proof={decision.artifact_hash}"
```

## Full crew example — Crew + Agent + Task with pyhall governance

```python
import os
from crewai import Agent, Task, Crew, Process
from crewai.tools import tool
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


# --- Governance tools ---

@tool("pyhall_data_access_check")
def pyhall_data_access_check(data_description: str) -> str:
    """
    Check WCP governance before accessing any data source.
    ALWAYS call this tool first before reading data or querying databases.
    data_description: what data you intend to read.
    """
    decision = make_decision(
        capability_id="cap.data.read.v1",
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        return (
            f"ACCESS DENIED. You are not authorized to read data. "
            f"Reason: {decision.reason}. Stop and report this to the crew."
        )
    return f"ACCESS GRANTED. proof={decision.artifact_hash} [{decision.decision_id}]"


@tool("pyhall_report_check")
def pyhall_report_check(report_description: str) -> str:
    """
    Check WCP governance before generating any report or analysis output.
    ALWAYS call this before producing a report.
    report_description: what report you intend to generate.
    """
    decision = make_decision(
        capability_id="cap.report.generate.v1",
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        return (
            f"REPORT DENIED. You are not authorized to generate reports. "
            f"Reason: {decision.reason}. Stop and report this."
        )
    return f"REPORT AUTHORIZED. proof={decision.artifact_hash} [{decision.decision_id}]"


# --- Real execution tools (add your own) ---

@tool("fetch_sales_data")
def fetch_sales_data(period: str) -> str:
    """Retrieve sales data for the specified period. Requires governance check first."""
    # real implementation
    return f"Sales data for {period}: [records would appear here]"


@tool("write_report")
def write_report(content: str, title: str) -> str:
    """Write a formatted report with the given title and content. Requires governance check first."""
    # real implementation
    return f"Report '{title}' written successfully."


# --- Agents ---

data_analyst = Agent(
    role="Data Analyst",
    goal="Retrieve and analyze sales data under WCP governance",
    backstory=(
        "You are a governed data analyst. Before accessing any data, you MUST call "
        "pyhall_data_access_check to verify your authorization. Never skip this step."
    ),
    tools=[pyhall_data_access_check, fetch_sales_data],
    verbose=True,
)

report_writer = Agent(
    role="Report Writer",
    goal="Generate authorized reports from analyzed data",
    backstory=(
        "You are a governed report writer. Before generating any report, you MUST call "
        "pyhall_report_check. Only proceed if the check returns AUTHORIZED."
    ),
    tools=[pyhall_report_check, write_report],
    verbose=True,
)

# --- Tasks ---

data_task = Task(
    description=(
        "Check governance authorization for data access, then fetch Q1 2026 sales data. "
        "If governance is denied, stop and report the denial."
    ),
    expected_output="Authorized sales data for Q1 2026 with governance proof.",
    agent=data_analyst,
)

report_task = Task(
    description=(
        "Check governance authorization for report generation, then write a summary report "
        "from the Q1 sales data. Include the governance proof hash in the report header."
    ),
    expected_output="A formatted Q1 2026 sales summary report with governance proof.",
    agent=report_writer,
    context=[data_task],
)

# --- Crew ---

crew = Crew(
    agents=[data_analyst, report_writer],
    tasks=[data_task, report_task],
    process=Process.sequential,
    verbose=True,
)

result = crew.kickoff()
print(result)
```

## Multi-agent crew with per-agent worker IDs

Bind different pyhall worker IDs to different agents for finer access control:

```python
import os
from crewai.tools import tool
from pyhall import make_decision

def make_governed_tool(tool_name: str, capability_id: str, worker_id: str, tenant_id: str):
    """Factory: produce a @tool for a specific worker + capability pair."""

    @tool(tool_name)
    def governed_tool(action_context: str) -> str:
        f"""
        WCP governance check for {capability_id}.
        action_context: describe the action about to be performed.
        """
        decision = make_decision(
            capability_id=capability_id,
            worker_id=worker_id,
            env="prod",
            data_label="INTERNAL",
            tenant_id=tenant_id,
        )
        if decision.denied:
            return f"DENIED [{worker_id}] {capability_id}: {decision.reason}"
        return f"ALLOWED [{worker_id}] {capability_id} proof={decision.artifact_hash}"

    return governed_tool


analyst_governance = make_governed_tool(
    "analyst_governance_check",
    "cap.data.read.v1",
    os.environ["ANALYST_WORKER_ID"],
    "org.acme",
)

writer_governance = make_governed_tool(
    "writer_governance_check",
    "cap.report.generate.v1",
    os.environ["WRITER_WORKER_ID"],
    "org.acme",
)
```

## Using the local Hall Server (self-hosted)

```python
import os
import requests
from crewai.tools import tool

HALL_URL   = os.environ.get("HALL_SERVER_URL", "http://localhost:8765")
HALL_TOKEN = os.environ["HALL_SESSION_TOKEN"]
WORKER_ID  = os.environ["MY_WORKER_ID"]


@tool("pyhall_local_governance_check")
def pyhall_local_governance_check(capability_id: str) -> str:
    """
    Check WCP governance via local Hall Server before executing a capability.
    capability_id: the capability to authorize (e.g., 'cap.data.read.v1').
    """
    resp = requests.post(
        f"{HALL_URL}/api/route",
        json={
            "capability_id": capability_id,
            "worker_id": WORKER_ID,
            "env": "dev",
            "data_label": "PUBLIC",
            "tenant_id": "org.default",
        },
        headers={"Authorization": f"Bearer {HALL_TOKEN}"},
        timeout=5,
    )
    resp.raise_for_status()
    result = resp.json()
    if result.get("denied"):
        return f"DENIED: {capability_id}. decision_id={result['decision_id']}"
    return f"ALLOWED: {capability_id}. proof={result.get('artifact_hash')} [{result['decision_id']}]"
```

## WCP governance chain (every decision)

1. Manifest hash verification — worker binary matches registered hash
2. Worker attestation check — worker is attested and not expired
3. WCP policy evaluation — capability is in worker's declared set
4. Ban list check — worker hash not on global or tenant ban list
5. ALLOW or DENY → immutable audit record written

Deny-by-default. No silent fallbacks.

## Getting started

1. `pip install pyhall-wcp crewai crewai-tools`
2. `pyhall auth login` — authenticate
3. `pyhall worker register` — get your `worker_id` (one per agent role if needed)
4. Set `PYHALL_API_KEY`, `MY_WORKER_ID`, `OPENAI_API_KEY` in your environment
5. Add governed tools to each `Agent` using the patterns above
6. `pyhall decision query --worker <id>` — audit your crew's decision history

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
