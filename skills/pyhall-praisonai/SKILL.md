---
name: pyhall-praisonai
description: >
  Integrate pyhall WCP governance into Praison AI agents and multi-agent pipelines.
  Expose pyhall capability decisions as native Praison AI tools using the @tool decorator
  so every agent action passes through the Worker Class Protocol before it executes.
  Gives Praison AI agents auditable, deny-by-default governance with registered worker
  identity, cryptographic proof, and an immutable audit trail across all agents and tasks.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — Praison AI Governance Integration

Add WCP governance to any Praison AI agent. Define pyhall decision checks as `@tool`-decorated
functions, wire them into your agent YAML config or Python setup, and every governed step is
authorized before execution with an immutable audit record.

## What you can do

- **Gate agent actions** — require a pyhall ALLOW before any Praison AI agent executes a capability
- **Use YAML or Python config** — governance tools work with both Praison AI config styles
- **Audit every task** — decisions produce `decision_id` and `artifact_hash` stored in the registry
- **Block banned workers** — ban list check is automatic on every routing decision
- **Mix governed and ungoverned tools** — add pyhall alongside your existing tool functions

## Installation

```bash
pip install pyhall-wcp praisonai praisonai-tools
```

## Environment variables

```bash
PYHALL_API_KEY=your-api-key           # registry authentication
HALL_SESSION_TOKEN=your-session-tok   # local Hall Server auth (if self-hosted)
OPENAI_API_KEY=your-openai-key        # Praison AI default model backend
MY_WORKER_ID=org.acme.my-worker.i-1   # your registered pyhall worker ID
TENANT_ID=org.default                 # your tenant/org scope
PYHALL_REGISTRY=https://api.pyhall.dev    # default; override for self-hosted
```

## Core pattern — @tool decorated governance check

```python
import os
from praisonai_tools import tool
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


@tool
def pyhall_governance_check(capability_id: str) -> str:
    """
    Check WCP governance for a capability before executing it.

    Use this tool before any data access, report generation, or privileged action.
    Pass the capability ID string (e.g., 'cap.data.read.v1').
    Returns ALLOWED with cryptographic proof on success, or DENIED with reason.
    Do not proceed if the result contains 'DENIED'.

    Args:
        capability_id: The WCP capability to authorize.

    Returns:
        Authorization result string.
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
            f"Do NOT proceed with this action."
        )
    return (
        f"ALLOWED. capability='{capability_id}' "
        f"decision_id='{decision.decision_id}' "
        f"worker_species='{decision.selected_worker_species_id}' "
        f"artifact_hash='{decision.artifact_hash}'"
    )
```

## Per-capability tools (stricter enforcement)

```python
import os
from praisonai_tools import tool
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


@tool
def check_data_read_authorization(context: str) -> str:
    """
    Verify WCP authorization for reading internal data (cap.data.read.v1).

    ALWAYS call this before any database query, file read, or data retrieval.
    Returns ALLOWED with proof hash, or DENIED with reason.

    Args:
        context: Brief description of the data access being performed.

    Returns:
        Authorization result string.
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
    return f"ALLOWED: data read authorized. proof={decision.artifact_hash} [{decision.decision_id}]"


@tool
def check_report_generation_authorization(report_type: str) -> str:
    """
    Verify WCP authorization for generating reports (cap.report.generate.v1).

    ALWAYS call this before creating any report, summary, or analysis output.
    Returns ALLOWED with proof hash, or DENIED with reason.

    Args:
        report_type: Type of report to generate (e.g., 'quarterly', 'audit', 'summary').

    Returns:
        Authorization result string.
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

## Python agent config example

```python
import os
from praisonai import PraisonAI
from praisonai_tools import tool
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


# --- Governance tools ---

@tool
def pyhall_governance_check(capability_id: str) -> str:
    """
    Check WCP governance before executing a capability.
    Call before data access (cap.data.read.v1) or report generation (cap.report.generate.v1).
    Returns ALLOWED with proof, or DENIED with reason. Stop if DENIED.

    Args:
        capability_id: WCP capability to authorize.

    Returns:
        Authorization result string.
    """
    decision = make_decision(
        capability_id=capability_id,
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        return f"DENIED [{capability_id}]: {decision.reason} [{decision.decision_id}]"
    return f"ALLOWED [{capability_id}] proof={decision.artifact_hash} [{decision.decision_id}]"


# --- Execution tools ---

@tool
def fetch_sales_data(period: str) -> str:
    """
    Retrieve sales data for the specified period. Call pyhall_governance_check first.

    Args:
        period: The time period to query (e.g., 'Q1-2026').

    Returns:
        Sales data records as a string.
    """
    # real implementation
    return f"Sales data for {period}: [records here]"


@tool
def write_summary_report(content: str, title: str) -> str:
    """
    Write a formatted summary report. Call pyhall_governance_check first.

    Args:
        content: The content to include in the report.
        title: Report title.

    Returns:
        Formatted report string.
    """
    # real implementation
    return f"REPORT: {title}\n\n{content}"


# --- Agent config ---

agents_config = {
    "framework": "praisonai",
    "topic": "Governed sales data analysis and reporting",
    "roles": {
        "data_analyst": {
            "backstory": (
                "You are a governed data analyst. You MUST call pyhall_governance_check "
                "with capability_id='cap.data.read.v1' before calling fetch_sales_data. "
                "Never skip governance. If DENIED, stop and report."
            ),
            "goal": "Retrieve authorized sales data and prepare it for reporting.",
            "role": "Data Analyst",
            "tasks": {
                "data_retrieval_task": {
                    "description": (
                        "1. Call pyhall_governance_check with capability_id='cap.data.read.v1'. "
                        "2. If ALLOWED, call fetch_sales_data for period='Q1-2026'. "
                        "3. Return the data with the governance proof hash."
                    ),
                    "expected_output": "Q1 2026 sales data with WCP governance proof.",
                },
            },
            "tools": [pyhall_governance_check, fetch_sales_data],
        },
        "report_writer": {
            "backstory": (
                "You are a governed report writer. You MUST call pyhall_governance_check "
                "with capability_id='cap.report.generate.v1' before writing any report. "
                "Never skip governance. If DENIED, stop and report."
            ),
            "goal": "Generate authorized summary reports from analyzed data.",
            "role": "Report Writer",
            "tasks": {
                "report_generation_task": {
                    "description": (
                        "1. Call pyhall_governance_check with capability_id='cap.report.generate.v1'. "
                        "2. If ALLOWED, call write_summary_report with the Q1 sales data. "
                        "3. Include the governance proof hash in the report header."
                    ),
                    "expected_output": "Formatted Q1 2026 sales summary report with governance proof.",
                },
            },
            "tools": [pyhall_governance_check, write_summary_report],
        },
    },
}

praisonai = PraisonAI(agents_config=agents_config)
result = praisonai.run()
print(result)
```

## YAML agent config example

Save as `agents.yaml` and load with `PraisonAI(config_path="agents.yaml")`.
Define the governance tool in a companion `tools.py` file.

```yaml
# agents.yaml
framework: praisonai
topic: Governed data analysis

roles:
  governed_analyst:
    role: Governed Data Analyst
    goal: Analyze data with full WCP governance on every action
    backstory: >
      You are a governed AI analyst. Before any data access, call
      pyhall_governance_check with capability_id='cap.data.read.v1'.
      Before any report, call pyhall_governance_check with
      capability_id='cap.report.generate.v1'. If governance returns
      DENIED, stop immediately and report the denial. Never skip this step.
    tasks:
      governed_analysis_task:
        description: >
          Step 1: Call pyhall_governance_check (capability_id='cap.data.read.v1').
          Step 2: If ALLOWED, fetch Q1-2026 sales data.
          Step 3: Call pyhall_governance_check (capability_id='cap.report.generate.v1').
          Step 4: If ALLOWED, generate a summary report including the governance proof hashes.
        expected_output: >
          Q1 2026 sales summary report with WCP governance proof for each authorized step.
    tools:
      - pyhall_governance_check
      - fetch_sales_data
      - write_summary_report
```

```python
# tools.py — companion file for YAML config
import os
from praisonai_tools import tool
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


@tool
def pyhall_governance_check(capability_id: str) -> str:
    """
    Check WCP governance before executing a capability.
    Pass the capability_id (e.g., 'cap.data.read.v1').
    Returns ALLOWED with proof, or DENIED with reason.

    Args:
        capability_id: WCP capability to authorize.

    Returns:
        Authorization result string.
    """
    decision = make_decision(
        capability_id=capability_id,
        worker_id=WORKER_ID,
        env="prod",
        data_label="INTERNAL",
        tenant_id=TENANT_ID,
    )
    if decision.denied:
        return f"DENIED [{capability_id}]: {decision.reason} [{decision.decision_id}]"
    return f"ALLOWED [{capability_id}] proof={decision.artifact_hash} [{decision.decision_id}]"


@tool
def fetch_sales_data(period: str) -> str:
    """Retrieve sales data for the given period. Requires governance check first.

    Args:
        period: Time period to query (e.g., 'Q1-2026').

    Returns:
        Sales records as a string.
    """
    return f"Sales data for {period}: [records here]"


@tool
def write_summary_report(content: str, title: str) -> str:
    """Write a formatted summary report. Requires governance check first.

    Args:
        content: Report content.
        title: Report title.

    Returns:
        Formatted report.
    """
    return f"REPORT: {title}\n\n{content}"
```

```python
# main.py — load YAML config
from praisonai import PraisonAI
import tools  # registers @tool functions

praisonai = PraisonAI(config_path="agents.yaml")
result = praisonai.run()
print(result)
```

## Using the local Hall Server (self-hosted)

```python
import os
import requests
from praisonai_tools import tool

HALL_URL   = os.environ.get("HALL_SERVER_URL", "http://localhost:8765")
HALL_TOKEN = os.environ["HALL_SESSION_TOKEN"]
WORKER_ID  = os.environ["MY_WORKER_ID"]


@tool
def pyhall_local_governance_check(capability_id: str) -> str:
    """
    Check WCP governance via local Hall Server before executing a capability.
    Call before any privileged action. Returns ALLOWED or DENIED.

    Args:
        capability_id: WCP capability to authorize (e.g., 'cap.data.read.v1').

    Returns:
        Authorization result string.
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
        return f"DENIED: {capability_id}. decision_id={result['decision_id']}. Do not proceed."
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

1. `pip install pyhall-wcp praisonai praisonai-tools`
2. `pyhall auth login` — authenticate
3. `pyhall worker register` — get your `worker_id`
4. Set `PYHALL_API_KEY`, `MY_WORKER_ID`, `OPENAI_API_KEY` in your environment
5. Define `@tool` governance functions and add to your agent config
6. `pyhall decision query --worker <id>` — audit your decision history

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
