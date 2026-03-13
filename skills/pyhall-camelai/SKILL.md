---
name: pyhall-camelai
description: >
  Integrate pyhall WCP governance into CAMEL-AI agents and role-playing pipelines.
  Expose pyhall capability decisions as OpenAIFunction tools so every ChatAgent action
  passes through the Worker Class Protocol before execution. Gives CAMEL-AI agents
  auditable, deny-by-default governance with registered worker identity, cryptographic
  proof, and an immutable audit trail — without changing your existing role-play setup.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: fafolab
  version: "0.3.0"
  homepage: https://pyhall.dev
  repository: https://github.com/pyhall
  registry: https://api.pyhall.dev
---

# PyHall WCP — CAMEL-AI Governance Integration

Add WCP governance to any CAMEL-AI `ChatAgent` or role-playing pipeline. Wrap pyhall
capability decisions as `OpenAIFunction` objects and pass them to your agent's tool list.
Every governed action is authorized before execution and produces an immutable audit record.

## What you can do

- **Gate agent function calls** — require a pyhall ALLOW before any ChatAgent tool executes
- **Attach to any CAMEL agent** — `ChatAgent`, role-playing agents, or task-solving agents
- **Audit every call** — decisions produce `decision_id` and `artifact_hash` stored in the registry
- **Block banned workers** — ban list check is automatic on every routing decision
- **Compose with existing tools** — add pyhall alongside your current `OpenAIFunction` tools

## Installation

```bash
pip install pyhall-wcp camel-ai
```

## Environment variables

```bash
PYHALL_API_KEY=your-api-key           # registry authentication
HALL_SESSION_TOKEN=your-session-tok   # local Hall Server auth (if self-hosted)
OPENAI_API_KEY=your-openai-key        # CAMEL-AI default model backend
PYHALL_REGISTRY=https://api.pyhall.dev    # default; override for self-hosted
```

## Core pattern — OpenAIFunction wrapping a pyhall decision

Define a standard Python function with type annotations and a docstring, then wrap it as a
`OpenAIFunction`. CAMEL's function calling mechanism uses the signature and docstring to
build the JSON schema the model sees.

```python
import os
from pyhall import make_decision
from camel.functions import OpenAIFunction

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


def pyhall_governance_check(capability_id: str, action_context: str) -> str:
    """
    Check WCP governance for a capability before executing it.

    Call this function before any data access, report generation, or privileged action.
    Returns an authorization result with cryptographic proof on ALLOW, or a denial
    message with reason on DENY. Do not proceed if the result is DENIED.

    Args:
        capability_id: The WCP capability to check (e.g., 'cap.data.read.v1').
        action_context: Brief description of the action about to be performed.

    Returns:
        Authorization result string: ALLOWED with proof, or DENIED with reason.
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


# Wrap as OpenAIFunction
pyhall_governance_fn = OpenAIFunction(pyhall_governance_check)
```

## Per-capability function definitions

For stricter enforcement, one function per capability — agents cannot pass arbitrary IDs:

```python
import os
from pyhall import make_decision
from camel.functions import OpenAIFunction

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


def check_data_read_authorization(context: str) -> str:
    """
    Verify WCP authorization for reading internal data (capability: cap.data.read.v1).

    ALWAYS call this before any database query, file read, or data retrieval operation.
    Returns ALLOWED with proof hash, or DENIED with reason. Stop if DENIED.

    Args:
        context: Brief description of the data read being performed.

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
        return f"DENIED: data read unauthorized. Reason: {decision.reason} [{decision.decision_id}]"
    return f"ALLOWED: data read authorized. proof={decision.artifact_hash} [{decision.decision_id}]"


def check_report_generation_authorization(report_type: str) -> str:
    """
    Verify WCP authorization for generating reports (capability: cap.report.generate.v1).

    ALWAYS call this before producing any report, summary, or analysis document.
    Returns ALLOWED with proof hash, or DENIED with reason. Stop if DENIED.

    Args:
        report_type: The type of report to be generated (e.g., 'quarterly', 'audit').

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
        return f"DENIED: report generation unauthorized. Reason: {decision.reason} [{decision.decision_id}]"
    return f"ALLOWED: report generation authorized for '{report_type}'. proof={decision.artifact_hash}"


data_read_fn   = OpenAIFunction(check_data_read_authorization)
report_gen_fn  = OpenAIFunction(check_report_generation_authorization)
```

## Full agent example — ChatAgent with governed tools

```python
import os
from camel.agents import ChatAgent
from camel.messages import BaseMessage
from camel.types import ModelType, RoleType
from camel.functions import OpenAIFunction
from camel.models import ModelFactory
from pyhall import make_decision

WORKER_ID = os.environ["MY_WORKER_ID"]
TENANT_ID = os.environ.get("TENANT_ID", "org.default")


# --- Governance function ---

def pyhall_governance_check(capability_id: str, action_context: str) -> str:
    """
    Check WCP governance for a capability before executing it.
    Call before any data access, report generation, or privileged operation.
    Returns ALLOWED with cryptographic proof, or DENIED with reason.

    Args:
        capability_id: WCP capability to authorize (e.g., 'cap.data.read.v1').
        action_context: Brief description of the intended action.

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
            f"DENIED [{capability_id}]: {decision.reason}. "
            f"decision_id={decision.decision_id}. Do not proceed."
        )
    return (
        f"ALLOWED [{capability_id}]. "
        f"decision_id={decision.decision_id} "
        f"artifact_hash={decision.artifact_hash}"
    )


# --- Execution functions (your real tools) ---

def fetch_sales_data(period: str, region: str = "all") -> str:
    """
    Retrieve sales data for the given period and region. Always call governance check first.

    Args:
        period: Time period (e.g., 'Q1-2026', 'March-2026').
        region: Geographic region filter (default: 'all').

    Returns:
        Sales data as a structured string.
    """
    # real implementation
    return f"Sales data for period='{period}' region='{region}': [records here]"


def generate_summary_report(data: str, title: str) -> str:
    """
    Generate a formatted summary report from structured data. Call governance check first.

    Args:
        data: The data content to summarize.
        title: Report title.

    Returns:
        Formatted report string.
    """
    # real implementation
    return f"REPORT: {title}\n\n{data}"


# --- Wrap all as OpenAIFunction ---

governance_fn  = OpenAIFunction(pyhall_governance_check)
fetch_fn       = OpenAIFunction(fetch_sales_data)
report_fn      = OpenAIFunction(generate_summary_report)

tools = [governance_fn, fetch_fn, report_fn]

# --- Build the ChatAgent ---

system_message = BaseMessage(
    role_name="Governed Analyst",
    role_type=RoleType.ASSISTANT,
    meta_dict={},
    content=(
        "You are a governed AI analyst. You MUST call pyhall_governance_check before "
        "calling fetch_sales_data (capability_id='cap.data.read.v1') and before "
        "calling generate_summary_report (capability_id='cap.report.generate.v1'). "
        "If governance returns DENIED, stop and report the denial. Never skip governance."
    ),
)

model = ModelFactory.create(
    model_platform="openai",
    model_type="gpt-4o",
    model_config_dict={"temperature": 0},
)

agent = ChatAgent(
    system_message=system_message,
    model=model,
    tools=tools,
)

# --- Run the agent ---

user_msg = BaseMessage.make_user_message(
    role_name="User",
    content="Fetch Q1 2026 sales data for the APAC region and generate a summary report.",
)

response = agent.step(user_msg)
print(response.msg.content)
```

## Role-playing pipeline with governance

For CAMEL role-playing between two agents, add the governance function to the tools list
of the agent that needs authorization:

```python
from camel.agents import ChatAgent
from camel.societies import RolePlaying
from camel.functions import OpenAIFunction

# governance_fn defined as above

# Attach governance to the assistant agent's tool list
assistant_agent_kwargs = {
    "tools": [governance_fn, fetch_fn, report_fn],
}

role_play_session = RolePlaying(
    assistant_role_name="Governed Data Analyst",
    user_role_name="Project Manager",
    assistant_agent_kwargs=assistant_agent_kwargs,
    task_prompt=(
        "Analyze Q1 2026 sales data and generate an executive summary. "
        "Ensure all data access and report generation passes WCP governance."
    ),
    with_task_specify=False,
)

# Run several turns
chat_history = []
n_turns = 5
for _ in range(n_turns):
    assistant_response, user_response = role_play_session.step()
    chat_history.append((assistant_response, user_response))
    if assistant_response.terminated or user_response.terminated:
        break
```

## Using the local Hall Server (self-hosted)

```python
import os
import requests
from camel.functions import OpenAIFunction

HALL_URL   = os.environ.get("HALL_SERVER_URL", "http://localhost:8765")
HALL_TOKEN = os.environ["HALL_SESSION_TOKEN"]
WORKER_ID  = os.environ["MY_WORKER_ID"]


def pyhall_local_governance_check(capability_id: str, action_context: str) -> str:
    """
    Check WCP governance via local Hall Server before executing a capability.
    Call before any privileged action. Returns ALLOWED or DENIED.

    Args:
        capability_id: WCP capability to authorize (e.g., 'cap.data.read.v1').
        action_context: Brief description of the intended action.

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


local_governance_fn = OpenAIFunction(pyhall_local_governance_check)
```

## WCP governance chain (every decision)

1. Manifest hash verification — worker binary matches registered hash
2. Worker attestation check — worker is attested and not expired
3. WCP policy evaluation — capability is in worker's declared set
4. Ban list check — worker hash not on global or tenant ban list
5. ALLOW or DENY → immutable audit record written

Deny-by-default. No silent fallbacks.

## Getting started

1. `pip install pyhall-wcp camel-ai`
2. `pyhall auth login` — authenticate
3. `pyhall worker register` — get your `worker_id`
4. Set `PYHALL_API_KEY`, `MY_WORKER_ID`, `OPENAI_API_KEY` in your environment
5. Wrap your functions as `OpenAIFunction` and add to your `ChatAgent`
6. `pyhall decision query --worker <id>` — audit your decision history

Full documentation: https://pyhall.dev/introduction/
WCP specification: https://workerclassprotocol.dev/spec/
Registry API: https://api.pyhall.dev
