"""
pyhall/cli.py — PyHall command-line interface.

Commands:
  route      Route a capability request from a JSON file or inline args
  validate   Run all test fixtures against routing rules
  status     Show registry status
  enroll     Enroll a worker from a registry record JSON file
  build      Interactive wizard to scaffold a complete WCP worker package
  search     Fuzzy search across taxonomy catalog entities
  explain    Detailed lookup for a specific catalog entity
  browse     Browse the taxonomy catalog by type
  dispatch   Simulate routing a capability request
  version    Show PyHall and WCP spec versions

Usage:
  pyhall route --capability cap.doc.summarize --env dev --tenant-id demo
  pyhall validate --rules rules.json --tests tests.json
  pyhall status --registry-dir enrolled/
  pyhall enroll my_worker/registry_record.json
  pyhall build
  pyhall search "summarize documents"
  pyhall explain cap.doc.summarize
  pyhall browse
  pyhall browse --type cap
  pyhall dispatch cap.doc.summarize --env prod
  pyhall version
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from rich.text import Text
from rich.columns import Columns

from . import __version__, __wcp_version__
from .rules import load_rules
from .models import RouteInput
from .router import make_decision
from .registry import Registry
from .policy_gate import PolicyGate
from .conformance import load_conformance_spec, check_worker_compliance
from .registry_client import RegistryClient, RegistryRateLimitError

app = typer.Typer(
    name="pyhall",
    help="PyHall — The Python reference implementation of WCP (Worker Class Protocol).",
    no_args_is_help=True,
)

console = Console()

BANNER = (
    "\n[bold cyan]PyHall[/bold cyan] [dim]v{version}[/dim]"
    "  |  WCP {wcp}  |  The Hall"
    "\n"
)


def _print_banner():
    console.print(
        BANNER.format(version=__version__, wcp=__wcp_version__)
    )


# ---------------------------------------------------------------------------
# route
# ---------------------------------------------------------------------------

@app.command()
def route(
    capability: str = typer.Option(..., help="Capability ID, e.g. cap.doc.summarize"),
    env: str = typer.Option("dev", help="Environment: dev | stage | prod | edge"),
    data_label: str = typer.Option("PUBLIC", help="Data label: PUBLIC | INTERNAL | RESTRICTED"),
    tenant_risk: str = typer.Option("low", help="Tenant risk: low | medium | high"),
    qos_class: str = typer.Option("P2", help="QoS class: P0 | P1 | P2 | P3"),
    tenant_id: str = typer.Option("demo", help="Tenant identifier"),
    correlation_id: Optional[str] = typer.Option(None, help="Correlation ID (UUID). Auto-generated if not provided."),
    rules_file: Optional[Path] = typer.Option(None, "--rules", help="Path to routing rules JSON file"),
    registry_dir: Optional[Path] = typer.Option(None, "--registry-dir", help="Path to enrolled worker records directory"),
    request_json: Optional[str] = typer.Option(None, "--request", help="Request payload as JSON string"),
    pretty: bool = typer.Option(True, help="Pretty-print the decision output"),
):
    """
    Route a capability request and print the routing decision.

    Example:
        pyhall route --capability cap.hello.greet --env dev --rules rules.json
    """
    _print_banner()

    corr_id = correlation_id or str(uuid.uuid4())

    request_payload = {}
    if request_json:
        try:
            request_payload = json.loads(request_json)
        except json.JSONDecodeError as exc:
            console.print(f"[red]Invalid --request JSON: {exc}[/red]")
            raise typer.Exit(1)

    try:
        inp = RouteInput(
            capability_id=capability,
            env=env,  # type: ignore[arg-type]
            data_label=data_label,  # type: ignore[arg-type]
            tenant_risk=tenant_risk,  # type: ignore[arg-type]
            qos_class=qos_class,  # type: ignore[arg-type]
            tenant_id=tenant_id,
            correlation_id=corr_id,
            request=request_payload,
        )
    except Exception as exc:
        console.print(f"[red]Invalid input: {exc}[/red]")
        raise typer.Exit(1)

    if rules_file is None:
        console.print("[yellow]No --rules file provided. Using empty rules list (will deny).[/yellow]")
        rules = []
    else:
        try:
            rules = load_rules(rules_file)
        except Exception as exc:
            console.print(f"[red]Could not load rules: {exc}[/red]")
            raise typer.Exit(1)

    registry = Registry(registry_dir=str(registry_dir) if registry_dir else None)
    policy_gate = PolicyGate()

    decision = make_decision(
        inp=inp,
        rules=rules,
        registry_controls_present=registry.controls_present(),
        registry_worker_available=registry.worker_available,
        registry_get_privilege_envelope=registry.get_privilege_envelope,
        registry_policy_allows_privilege=registry.policy_allows_privilege,
        policy_gate_eval=policy_gate.evaluate,
        task_id="pyhall_cli_route",
    )

    output = decision.model_dump()
    if pretty:
        console.print_json(json.dumps(output))
    else:
        print(json.dumps(output))

    if decision.denied:
        console.print(f"\n[red]DENIED[/red] — {decision.deny_reason_if_denied}")
        raise typer.Exit(1)
    else:
        console.print(
            f"\n[green]ALLOWED[/green] — worker: [bold]{decision.selected_worker_species_id}[/bold]"
            f"  rule: {decision.matched_rule_id}"
        )


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@app.command()
def validate(
    rules_file: Path = typer.Argument(..., help="Path to routing rules JSON file"),
    tests_file: Path = typer.Argument(..., help="Path to test fixtures JSON file"),
    registry_dir: Optional[Path] = typer.Option(None, "--registry-dir"),
    with_goldens: bool = typer.Option(False, "--with-goldens", help="Compare against golden snapshots"),
    goldens_file: Optional[Path] = typer.Option(None, "--goldens-file"),
    conformance_file: Optional[Path] = typer.Option(None, "--conformance"),
):
    """
    Run all test fixtures against routing rules. Exit 0 on pass, 1 on failure.

    Test fixtures JSON format:
        {
          "tests": [
            {
              "test_id": "test_001",
              "input": { ... RouteInput fields ... },
              "expect": { "expected_rule_id": "rr_example_001" }
            }
          ]
        }
    """
    _print_banner()

    try:
        rules = load_rules(rules_file)
        tests_doc = json.loads(rules_file.parent.joinpath(tests_file).read_text()
                               if not tests_file.is_absolute() else tests_file.read_text())
    except Exception as exc:
        console.print(f"[red]Load error: {exc}[/red]")
        raise typer.Exit(1)

    registry = Registry(registry_dir=str(registry_dir) if registry_dir else None)
    # In validate mode: make all rule workers available
    all_workers: set[str] = set()
    rules_doc = json.loads(rules_file.read_text())
    for r in rules_doc.get("rules", []):
        for c in r.get("decision", {}).get("candidate_workers_ranked", []):
            if c.get("worker_species_id"):
                all_workers.add(c["worker_species_id"])
    registry.set_workers_available(sorted(all_workers))

    all_controls: set[str] = set()
    for r in rules_doc.get("rules", []):
        for c in r.get("decision", {}).get("required_controls_suggested", []):
            all_controls.add(c)
    registry.set_controls_present(sorted(all_controls))

    spec = None
    if conformance_file:
        spec = load_conformance_spec(conformance_file)

    goldens_by_test = {}
    if with_goldens and goldens_file:
        gold_doc = json.loads(goldens_file.read_text())
        goldens_by_test = {s["test_id"]: s for s in gold_doc.get("snapshots", [])}

    policy_gate = PolicyGate()
    failures = []

    for t in tests_doc.get("tests", []):
        try:
            inp = RouteInput(**t["input"])
        except Exception as exc:
            failures.append((t["test_id"], "invalid_input", str(exc), ""))
            continue

        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            registry_get_privilege_envelope=registry.get_privilege_envelope,
            registry_policy_allows_privilege=registry.policy_allows_privilege,
            policy_gate_eval=policy_gate.evaluate,
            conformance_spec=spec,
            task_id=f"task_{t['test_id']}",
        )

        expected_rule = t.get("expect", {}).get("expected_rule_id")
        if expected_rule and dec.matched_rule_id != expected_rule:
            failures.append((t["test_id"], "matched_rule_id", expected_rule, dec.matched_rule_id))
            continue

        if with_goldens:
            g = goldens_by_test.get(t["test_id"])
            if g and g.get("matched_rule_id") != dec.matched_rule_id:
                failures.append((
                    t["test_id"],
                    "golden_mismatch",
                    g.get("matched_rule_id"),
                    dec.matched_rule_id,
                ))

    total = len(tests_doc.get("tests", []))
    if failures:
        table = Table(title=f"Failures ({len(failures)}/{total})")
        table.add_column("Test ID")
        table.add_column("Check")
        table.add_column("Expected")
        table.add_column("Got")
        for f in failures[:50]:
            table.add_row(str(f[0]), f[1], str(f[2]), str(f[3]))
        console.print(table)
        console.print(f"\n[red]FAILED[/red]: {len(failures)} of {total} tests")
        raise typer.Exit(1)

    console.print(f"\n[green]PASSED[/green]: {total} tests")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@app.command()
def status(
    registry_dir: Optional[Path] = typer.Option(None, "--registry-dir", help="Path to enrolled workers directory"),
):
    """Show registry status — enrolled workers, capabilities, controls."""
    _print_banner()

    registry = Registry(registry_dir=str(registry_dir) if registry_dir else None)
    summary = registry.summary()

    table = Table(title="PyHall Registry Status")
    table.add_column("Item", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Enrolled workers", str(summary["enrolled_workers"]))
    table.add_row("Available species", str(len(summary["available_species"])))
    table.add_row("Controls present", str(summary["controls_present_count"]))
    table.add_row("Capabilities mapped", str(len(summary["capabilities_mapped"])))
    console.print(table)

    if summary["available_species"]:
        console.print("\n[bold]Available Species:[/bold]")
        for s in summary["available_species"]:
            console.print(f"  {s}")

    if summary["capabilities_mapped"]:
        console.print("\n[bold]Capabilities Mapped:[/bold]")
        for c in summary["capabilities_mapped"]:
            console.print(f"  {c}")


# ---------------------------------------------------------------------------
# enroll
# ---------------------------------------------------------------------------

@app.command()
def enroll(
    record_file: Path = typer.Argument(..., help="Path to registry record JSON file"),
    registry_dir: Optional[Path] = typer.Option(None, "--registry-dir", help="Target enrolled directory"),
):
    """
    Enroll a worker from a registry record JSON file.

    Copies the record into the registry directory and validates its schema.
    """
    _print_banner()

    if not record_file.exists():
        console.print(f"[red]File not found: {record_file}[/red]")
        raise typer.Exit(1)

    try:
        record = json.loads(record_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON: {exc}[/red]")
        raise typer.Exit(1)

    # Validate required fields
    required = ["worker_id", "worker_species_id", "capabilities"]
    missing = [f for f in required if f not in record]
    if missing:
        console.print(f"[red]Registry record missing required fields: {missing}[/red]")
        raise typer.Exit(1)

    if registry_dir:
        registry_dir.mkdir(parents=True, exist_ok=True)
        dest = registry_dir / record_file.name
        dest.write_text(record_file.read_text(encoding="utf-8"), encoding="utf-8")
        console.print(f"[green]Enrolled:[/green] {record['worker_id']} -> {dest}")
    else:
        # Dry run: just validate
        console.print(f"[green]Valid record:[/green] {record['worker_id']}")
        console.print(f"  species:      {record.get('worker_species_id')}")
        console.print(f"  capabilities: {record.get('capabilities')}")
        console.print(f"  controls:     {record.get('currently_implements', [])}")
        console.print("\n[dim]Pass --registry-dir to persist enrollment.[/dim]")


# ---------------------------------------------------------------------------
# build — interactive worker scaffold wizard
# ---------------------------------------------------------------------------

# Common WCP capability IDs shown in the picker
_CAPABILITY_OPTIONS = [
    "cap.doc.summarize",
    "cap.doc.extract",
    "cap.doc.classify",
    "cap.mem.retrieve",
    "cap.mem.write",
    "cap.web.fetch",
    "cap.notify.send",
    "cap.db.read",
    "cap.db.write",
    "cap.ml.embed",
    "cap.ml.infer",
    "cap.research.register",
    "cap.data.transform",
]

# Blast radius dimension defaults by risk tier
_BLAST_BY_RISK: dict = {
    "low":      {"data": 0, "network": 0, "financial": 0, "time": 1, "reversibility": "reversible"},
    "medium":   {"data": 1, "network": 1, "financial": 0, "time": 2, "reversibility": "partially-reversible"},
    "high":     {"data": 2, "network": 2, "financial": 1, "time": 3, "reversibility": "irreversible"},
    "critical": {"data": 3, "network": 3, "financial": 3, "time": 3, "reversibility": "irreversible"},
}

# Controls suggested by tier
_CONTROLS_BY_TIER: dict = {
    "low":      ["ctrl.obs.audit-log-append-only"],
    "medium":   ["ctrl.obs.audit-log-append-only", "ctrl.blast_radius_scoring"],
    "high":     ["ctrl.obs.audit-log-append-only", "ctrl.blast_radius_scoring", "ctrl.privilege_envelopes_required"],
    "critical": ["ctrl.obs.audit-log-append-only", "ctrl.blast_radius_scoring", "ctrl.privilege_envelopes_required", "ctrl.msavx_step_up_required"],
}


def _slugify(name: str) -> str:
    """Convert a human name to a kebab-case slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")


def _worker_id_from_name(slug: str) -> str:
    return f"org.example.{slug}"


def _species_id_from_cap(cap: str, slug: str) -> str:
    # cap.doc.summarize + my-worker -> wrk.doc.my-worker
    parts = cap.split(".")
    if len(parts) >= 2:
        domain = parts[1]
        return f"wrk.{domain}.{slug}"
    return f"wrk.{slug}"


def _generate_worker_py(
    worker_id: str,
    species_id: str,
    capability_id: str,
    risk_tier: str,
    description: str,
    has_network: bool,
    has_secrets: bool,
    has_external_writes: bool,
) -> str:
    """Build the worker.py source as a string, avoiding nested triple-quote collisions."""
    notes = []
    if has_network:
        notes.append("    # NOTE: network egress enabled — ensure dest is on egress allowlist")
    if has_secrets:
        notes.append("    # NOTE: secrets access enabled — retrieve via secrets manager, never hardcode")
    if has_external_writes:
        notes.append("    # NOTE: external writes enabled — record artifact hash before mutating")
    notes_block = ("\n" + "\n".join(notes) + "\n") if notes else ""

    lines = [
        '"""',
        f"{worker_id}/worker.py \u2014 WCP Worker: {capability_id}",
        "",
        f"Description: {description}",
        "",
        f"Species:    {species_id}",
        f"Capability: {capability_id}",
        f"Risk tier:  {risk_tier}",
        "",
        "Run directly:",
        '    python worker.py \'{"key": "value"}\'',
        "",
        "Or in stdio mode (for MCP server):",
        '    echo \'{"key": "value"}\' | python worker.py --stdio',
        "",
        "Generated by: pyhall build",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "import hashlib",
        "import json",
        "import sys",
        "from dataclasses import dataclass, field",
        "from datetime import datetime, timezone",
        "from typing import Any, Dict, List, Optional",
        "",
        "",
        "# ---------------------------------------------------------------------------",
        "# Standard WCP worker context and result dataclasses",
        "# ---------------------------------------------------------------------------",
        "",
        "@dataclass",
        "class WorkerContext:",
        '    """Routing context propagated from the Hall\'s RouteDecision."""',
        "    correlation_id: str",
        "    tenant_id: str",
        "    env: str",
        "    data_label: str",
        "    qos_class: str",
        "    capability_id: str",
        '    policy_version: str = "policy.v0"',
        "",
        "",
        "@dataclass",
        "class WorkerResult:",
        '    """Standard WCP worker result envelope."""',
        '    status: str                                      # "ok" | "denied" | "error"',
        "    result: Dict[str, Any] = field(default_factory=dict)",
        "    telemetry: List[Dict[str, Any]] = field(default_factory=list)",
        "    evidence: List[Dict[str, Any]] = field(default_factory=list)",
        "    deny_reason: Optional[Dict[str, Any]] = None",
        "",
        "    def to_dict(self) -> dict:",
        "        return {",
        '            "status": self.status,',
        '            "result": self.result,',
        '            "telemetry": self.telemetry,',
        '            "evidence": self.evidence,',
        '            "deny_reason": self.deny_reason,',
        "        }",
        "",
        "",
        "# ---------------------------------------------------------------------------",
        "# Worker identity constants",
        "# ---------------------------------------------------------------------------",
        "",
        f'WORKER_ID = "{worker_id}"',
        f'WORKER_SPECIES_ID = "{species_id}"',
        f'CAPABILITY_ID = "{capability_id}"',
        f'RISK_TIER = "{risk_tier}"',
        "",
        "",
        "def _now_utc() -> str:",
        '    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")',
        "",
        "",
        "# ---------------------------------------------------------------------------",
        "# Core implementation",
        "# ---------------------------------------------------------------------------",
        "",
        "def execute(request: dict) -> WorkerResult:",
        '    """',
        f"    Execute {capability_id}.",
        "",
        f"    Description: {description}",
        "",
        "    Input:",
        "        {",
        '          "correlation_id": "...",   (required for telemetry)',
        '          "tenant_id": "...",        (required for telemetry)',
        f'          "capability_id": "{capability_id}",',
        "          # --- add your own fields here ---",
        "        }",
        "",
        "    Output:",
        "        WorkerResult with:",
        "          result.*        = your output fields",
        "          telemetry       = [evt.worker.executed]",
        "          evidence        = [evidence_receipt]",
        '    """',
        '    correlation_id = request.get("correlation_id", "unknown")',
        '    tenant_id = request.get("tenant_id", "unknown")',
        "",
        "    # -------------------------------------------------------------------",
        f"    # TODO: implement {capability_id} logic here",
        "    # -------------------------------------------------------------------",
    ]

    if notes:
        lines.extend(notes)

    lines += [
        "    result_payload: Dict[str, Any] = {",
        "        # Replace with your actual output",
        '        "worker_id": WORKER_ID,',
        f'        "message": "TODO: implement {capability_id}",',
        "    }",
        "    # -------------------------------------------------------------------",
        "",
        "    # Telemetry event (workers must emit at minimum evt.worker.executed)",
        "    telemetry_event = {",
        '        "event_id": "evt.worker.executed",',
        '        "timestamp": _now_utc(),',
        '        "correlation_id": correlation_id,',
        '        "tenant_id": tenant_id,',
        '        "worker_id": WORKER_ID,',
        '        "worker_species_id": WORKER_SPECIES_ID,',
        '        "capability_id": CAPABILITY_ID,',
        '        "status": "ok",',
        "    }",
        "",
        "    # Evidence receipt (WCP spec section 5.7)",
        "    payload_bytes = json.dumps(request, sort_keys=True).encode()",
        '    artifact_hash = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()',
        "",
        "    evidence_receipt = {",
        '        "correlation_id": correlation_id,',
        '        "dispatched_at": _now_utc(),',
        '        "worker_id": WORKER_ID,',
        '        "capability_id": CAPABILITY_ID,',
        '        "policy_decision": "ALLOW",',
        '        "controls_verified": ["ctrl.obs.audit-log-append-only"],',
        '        "artifact_hash": artifact_hash,',
        "    }",
        "",
        "    return WorkerResult(",
        '        status="ok",',
        "        result=result_payload,",
        "        telemetry=[telemetry_event],",
        "        evidence=[evidence_receipt],",
        "    )",
        "",
        "",
        "# ---------------------------------------------------------------------------",
        "# Run modes",
        "# ---------------------------------------------------------------------------",
        "",
        "def run_stdio():",
        '    """Read JSON from stdin, write JSON to stdout. Used by MCP server."""',
        "    try:",
        "        raw = sys.stdin.read().strip()",
        "        if not raw:",
        '            sys.stdout.write(json.dumps({"status": "error", "error": "Empty request"}) + "\\n")',
        "            return",
        "        request = json.loads(raw)",
        "    except json.JSONDecodeError as exc:",
        '        sys.stdout.write(json.dumps({"status": "error", "error": f"Invalid JSON: {exc}"}) + "\\n")',
        "        return",
        "",
        "    try:",
        "        result = execute(request)",
        "    except Exception as exc:",
        '        result = WorkerResult(status="error", result={}, deny_reason={"message": str(exc)})',
        "",
        '    sys.stdout.write(json.dumps(result.to_dict()) + "\\n")',
        "    sys.stdout.flush()",
        "",
        "",
        "def run_cli():",
        "    \"\"\"Simple CLI: python worker.py '{\"key\": \"value\"}'\"\"\"",
        "    args = sys.argv[1:]",
        '    if "--stdio" in args:',
        "        run_stdio()",
        "        return",
        "",
        "    if args:",
        "        try:",
        "            request = json.loads(args[0])",
        "        except (json.JSONDecodeError, IndexError):",
        "            request = {}",
        "    else:",
        "        request = {}",
        "",
        "    try:",
        "        result = execute(request)",
        "    except Exception as exc:",
        '        result = WorkerResult(status="error", result={}, deny_reason={"message": str(exc)})',
        "",
        "    print(json.dumps(result.to_dict(), indent=2))",
        "",
        "",
        'if __name__ == "__main__":',
        "    run_cli()",
        "",
    ]

    return "\n".join(lines)


def _generate_registry_record(
    worker_id: str,
    species_id: str,
    capability_id: str,
    risk_tier: str,
    has_external_writes: bool,
    has_network: bool,
    has_secrets: bool,
) -> dict:
    blast = dict(_BLAST_BY_RISK[risk_tier])
    if has_network:
        blast["network"] = max(blast["network"], 1)
    if has_external_writes:
        blast["data"] = max(blast["data"], 1)

    controls = _CONTROLS_BY_TIER[risk_tier]

    privilege_envelope: dict = {
        "secrets_access": ["your-secret-name"] if has_secrets else [],
        "network_egress": "allowlisted" if has_network else "none",
        "filesystem_writes": [] if not has_external_writes else ["/tmp/"],
        "tools": [],
    }

    return {
        "worker_id": worker_id,
        "worker_species_id": species_id,
        "capabilities": [capability_id],
        "risk_tier": risk_tier,
        "idempotency": "full",
        "determinism": "deterministic",
        "required_controls": controls,
        "currently_implements": ["ctrl.obs.audit-log-append-only"],
        "allowed_environments": ["dev", "stage", "prod"],
        "blast_radius": blast,
        "privilege_envelope": privilege_envelope,
        "owner": "org.example",
        "contact": "you@example.com",
        "notes": f"Generated by pyhall build.",
        "catalog_version_min": "1.0.0",
    }


def _generate_routing_rule_snippet(
    worker_id: str,
    species_id: str,
    capability_id: str,
    risk_tier: str,
) -> dict:
    controls = _CONTROLS_BY_TIER[risk_tier]
    rule_slug = _slugify(capability_id.replace(".", "-"))
    return {
        "_comment": "Paste this into your routing rules JSON file under the 'rules' array.",
        "rule_id": f"rr_{rule_slug}_dev_001",
        "match": {
            "capability_id": capability_id,
            "env": {"in": ["dev", "stage"]},
        },
        "decision": {
            "candidate_workers_ranked": [
                {"worker_species_id": species_id, "score_hint": 1.0}
            ],
            "required_controls_suggested": controls,
            "recommended_profiles": [],
            "escalation": {
                "policy_gate": risk_tier in ("high", "critical"),
                "human_required_default": risk_tier == "critical",
            },
            "preconditions": {},
        },
    }


def _generate_readme(
    worker_id: str,
    species_id: str,
    capability_id: str,
    risk_tier: str,
    description: str,
    has_network: bool,
    has_secrets: bool,
    has_external_writes: bool,
) -> str:
    flags = []
    if has_network:
        flags.append("- Network egress: YES — configure egress allowlist in registry")
    else:
        flags.append("- Network egress: NO")
    if has_secrets:
        flags.append("- Secrets access: YES — configure secrets manager integration")
    else:
        flags.append("- Secrets access: NO")
    if has_external_writes:
        flags.append("- External writes: YES — ensure audit logging is active")
    else:
        flags.append("- External writes: NO")

    flags_str = "\n".join(flags)

    return f"""# {worker_id}

**Capability:** `{capability_id}`
**Species:** `{species_id}`
**Risk tier:** `{risk_tier}`

## Description

{description}

## Privilege flags

{flags_str}

## Usage

Run directly:
```bash
python worker.py '{{"correlation_id": "test-123", "tenant_id": "demo"}}'
```

Stdio mode (for MCP server):
```bash
echo '{{"correlation_id": "test-123", "tenant_id": "demo"}}' | python worker.py --stdio
```

## Enroll

```bash
pyhall enroll registry_record.json --registry-dir /path/to/enrolled/
```

## Next steps

1. Implement the `execute()` function in `worker.py` (look for the `TODO` block).
2. Update `registry_record.json` — set your real `owner`, `contact`, and `catalog_version_min`.
3. Add the routing rule from `routing_rule_snippet.json` to your routing rules file.
4. Enroll: `pyhall enroll registry_record.json --registry-dir enrolled/`
5. Test: `python worker.py '{{"correlation_id": "test-123", "tenant_id": "demo"}}'`

## Files

| File | Purpose |
|------|---------|
| `worker.py` | Worker implementation (edit the TODO block) |
| `registry_record.json` | WCP worker enrollment record |
| `routing_rule_snippet.json` | Paste into your routing rules file |
| `README.md` | This file |

---
*Generated by `pyhall build` — PyHall {__version__} / WCP {__wcp_version__}*
"""


@app.command()
def build():
    """
    Interactive wizard — scaffold a complete WCP worker package.

    Asks a series of questions and generates:
      <worker-name>/
        worker.py
        registry_record.json
        routing_rule_snippet.json
        README.md

    Example:
        pyhall build
    """
    _print_banner()

    console.print(
        Panel(
            Text.from_markup(
                "[bold #FF6F20]Worker Build Wizard[/bold #FF6F20]\n"
                "[dim]Answer a few questions and PyHall will scaffold a complete WCP worker package.[/dim]"
            ),
            border_style="#FFB300",
            padding=(1, 2),
        )
    )

    # -----------------------------------------------------------------------
    # 1. Worker name
    # -----------------------------------------------------------------------
    console.print("\n[bold #FFB300]Step 1 of 8[/bold #FFB300]  Worker name")
    raw_name = Prompt.ask(
        "[cyan]Worker name[/cyan] [dim](e.g. 'document summarizer')[/dim]"
    ).strip()
    if not raw_name:
        console.print("[red]Worker name cannot be empty.[/red]")
        raise typer.Exit(1)

    slug = _slugify(raw_name)
    worker_id = _worker_id_from_name(slug)
    console.print(f"  [dim]worker_id:[/dim] [green]{worker_id}[/green]")

    # -----------------------------------------------------------------------
    # 2. Capability picker
    # -----------------------------------------------------------------------
    console.print("\n[bold #FFB300]Step 2 of 8[/bold #FFB300]  Primary capability")

    cap_table = Table(show_header=False, box=None, padding=(0, 2))
    cap_table.add_column("Num", style="bold #FF6F20", width=4)
    cap_table.add_column("Capability ID", style="cyan")
    for i, cap in enumerate(_CAPABILITY_OPTIONS, 1):
        cap_table.add_row(str(i), cap)
    cap_table.add_row(str(len(_CAPABILITY_OPTIONS) + 1), "[dim]custom — type your own[/dim]")
    console.print(cap_table)

    cap_choice_raw = Prompt.ask(
        "[cyan]Choice[/cyan] [dim](number or type a custom cap.* ID)[/dim]"
    ).strip()

    if cap_choice_raw.isdigit():
        idx = int(cap_choice_raw) - 1
        if 0 <= idx < len(_CAPABILITY_OPTIONS):
            capability_id = _CAPABILITY_OPTIONS[idx]
        else:
            # Custom
            capability_id = Prompt.ask("[cyan]Enter custom capability ID[/cyan]").strip()
    else:
        # Treat direct text input as a capability ID
        capability_id = cap_choice_raw

    if not capability_id.startswith("cap."):
        console.print("[yellow]Warning: capability IDs should start with 'cap.'[/yellow]")

    species_id = _species_id_from_cap(capability_id, slug)
    console.print(f"  [dim]capability_id:[/dim] [green]{capability_id}[/green]")
    console.print(f"  [dim]species_id:   [/dim] [green]{species_id}[/green]")

    # -----------------------------------------------------------------------
    # 3. Description
    # -----------------------------------------------------------------------
    console.print("\n[bold #FFB300]Step 3 of 8[/bold #FFB300]  Description")
    description = Prompt.ask(
        "[cyan]What does this worker do?[/cyan] [dim](one sentence)[/dim]"
    ).strip()
    if not description:
        description = f"Implements {capability_id}."

    # -----------------------------------------------------------------------
    # 4. Risk tier
    # -----------------------------------------------------------------------
    console.print("\n[bold #FFB300]Step 4 of 8[/bold #FFB300]  Risk tier")
    tier_table = Table(show_header=False, box=None, padding=(0, 2))
    tier_table.add_column("Tier", style="bold")
    tier_table.add_column("When to use")
    tier_table.add_row("[green]low[/green]",      "Read-only, no external calls, reversible")
    tier_table.add_row("[yellow]medium[/yellow]", "Limited external calls, partially reversible")
    tier_table.add_row("[red]high[/red]",         "External writes, financial impact, hard to reverse")
    tier_table.add_row("[bold red]critical[/bold red]", "Irreversible, financial, requires human approval")
    console.print(tier_table)

    risk_tier = Prompt.ask(
        "[cyan]Risk tier[/cyan]",
        choices=["low", "medium", "high", "critical"],
        default="low",
    )

    # -----------------------------------------------------------------------
    # 5. External writes
    # -----------------------------------------------------------------------
    console.print("\n[bold #FFB300]Step 5 of 8[/bold #FFB300]  Blast radius — external writes")
    has_external_writes = Confirm.ask(
        "[cyan]Does this worker write to external systems?[/cyan] [dim](databases, APIs, filesystems)[/dim]",
        default=False,
    )

    # -----------------------------------------------------------------------
    # 6. Network egress
    # -----------------------------------------------------------------------
    console.print("\n[bold #FFB300]Step 6 of 8[/bold #FFB300]  Blast radius — network egress")
    has_network = Confirm.ask(
        "[cyan]Does this worker need network egress?[/cyan] [dim](outbound HTTP, API calls)[/dim]",
        default=False,
    )

    # -----------------------------------------------------------------------
    # 7. Secrets
    # -----------------------------------------------------------------------
    console.print("\n[bold #FFB300]Step 7 of 8[/bold #FFB300]  Privilege — secrets access")
    has_secrets = Confirm.ask(
        "[cyan]Does this worker need secrets?[/cyan] [dim](API keys, credentials)[/dim]",
        default=False,
    )

    # -----------------------------------------------------------------------
    # 8. Output directory
    # -----------------------------------------------------------------------
    console.print("\n[bold #FFB300]Step 8 of 8[/bold #FFB300]  Output directory")
    default_out = f"./{slug}"
    out_dir_raw = Prompt.ask(
        "[cyan]Output directory[/cyan]",
        default=default_out,
    ).strip()
    out_dir = Path(out_dir_raw)

    # -----------------------------------------------------------------------
    # Generate files
    # -----------------------------------------------------------------------
    console.print("\n[bold #FF6F20]Generating worker package...[/bold #FF6F20]")

    try:
        out_dir.mkdir(parents=True, exist_ok=True)

        worker_py = _generate_worker_py(
            worker_id=worker_id,
            species_id=species_id,
            capability_id=capability_id,
            risk_tier=risk_tier,
            description=description,
            has_network=has_network,
            has_secrets=has_secrets,
            has_external_writes=has_external_writes,
        )
        (out_dir / "worker.py").write_text(worker_py, encoding="utf-8")

        registry_record = _generate_registry_record(
            worker_id=worker_id,
            species_id=species_id,
            capability_id=capability_id,
            risk_tier=risk_tier,
            has_external_writes=has_external_writes,
            has_network=has_network,
            has_secrets=has_secrets,
        )
        (out_dir / "registry_record.json").write_text(
            json.dumps(registry_record, indent=2), encoding="utf-8"
        )

        routing_snippet = _generate_routing_rule_snippet(
            worker_id=worker_id,
            species_id=species_id,
            capability_id=capability_id,
            risk_tier=risk_tier,
        )
        (out_dir / "routing_rule_snippet.json").write_text(
            json.dumps(routing_snippet, indent=2), encoding="utf-8"
        )

        readme = _generate_readme(
            worker_id=worker_id,
            species_id=species_id,
            capability_id=capability_id,
            risk_tier=risk_tier,
            description=description,
            has_network=has_network,
            has_secrets=has_secrets,
            has_external_writes=has_external_writes,
        )
        (out_dir / "README.md").write_text(readme, encoding="utf-8")

    except Exception as exc:
        console.print(f"[red]Error generating files: {exc}[/red]")
        raise typer.Exit(1)

    # -----------------------------------------------------------------------
    # Success output
    # -----------------------------------------------------------------------
    files_table = Table(show_header=True, box=None, padding=(0, 2))
    files_table.add_column("File", style="green")
    files_table.add_column("Purpose", style="dim")
    files_table.add_row(f"{out_dir}/worker.py",                  "Worker implementation (edit the TODO block)")
    files_table.add_row(f"{out_dir}/registry_record.json",       "WCP enrollment record")
    files_table.add_row(f"{out_dir}/routing_rule_snippet.json",  "Routing rule — paste into your rules file")
    files_table.add_row(f"{out_dir}/README.md",                  "Usage guide")

    console.print(
        Panel(
            files_table,
            title="[bold #FF6F20]Worker package created[/bold #FF6F20]",
            border_style="#FFB300",
            padding=(1, 2),
        )
    )

    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Edit [cyan]{out_dir}/worker.py[/cyan] — implement the TODO block")
    console.print(f"  2. Enroll:   [bold]pyhall enroll {out_dir}/registry_record.json[/bold]")
    console.print(f"  3. Test:     [bold]python3 {out_dir}/worker.py '{{\"correlation_id\": \"test-123\", \"tenant_id\": \"demo\"}}'[/bold]")
    console.print()


# ---------------------------------------------------------------------------
# check — WCP compliance evaluation
# ---------------------------------------------------------------------------

# Ordered compliance level display
_COMPLIANCE_LEVELS = ["WCP-Basic", "WCP-Standard", "WCP-Full"]

# Level key name mapping (label → result dict key)
_LEVEL_KEY = {
    "WCP-Basic": "basic",
    "WCP-Standard": "standard",
    "WCP-Full": "full",
}

# Controls that WCP-Standard mandates be present and declared
_STANDARD_MANDATORY_CONTROLS = [
    "ctrl.obs.audit_log_append_only",
    "ctrl.pol.default_deny",
]


def _check_icon(passed: bool) -> str:
    return "[green]OK[/green]" if passed else "[red]FAIL[/red]"


def _render_check_result(result: dict, target_level: str | None) -> None:
    """Render a Rich-formatted compliance report for one worker."""
    worker_id = result["worker_id"]
    species_id = result["worker_species_id"]
    risk_tier = result["risk_tier"]
    achieved = result["achieved_level"]
    caps = result["capabilities"]
    curr_impl = result["currently_implements"]
    blast = result["blast_radius"]
    priv_env = result["privilege_envelope"]
    idempotency = result["idempotency"]

    # -----------------------------------------------------------------------
    # Header
    # -----------------------------------------------------------------------
    console.print(f"\n[bold]Worker:[/bold] [cyan]{worker_id}[/cyan]")

    # Basic fields
    basic_checks = result["checks"]["basic"]
    cap_ok = basic_checks["capabilities_non_empty"]["passed"]
    cap_icon = "[green]OK[/green]" if cap_ok else "[red]FAIL[/red]"
    console.print(f"  Capability:    {cap_icon}  {caps[0] if caps else '(none)'}" +
                  (f"  [dim]+{len(caps)-1} more[/dim]" if len(caps) > 1 else ""))

    species_ok = basic_checks["worker_species_id_present"]["passed"]
    species_icon = "[green]OK[/green]" if species_ok else "[red]FAIL[/red]"
    console.print(f"  Species:       {species_icon}  {species_id}")

    tier_ok = basic_checks["risk_tier_present"]["passed"]
    tier_icon = "[green]OK[/green]" if tier_ok else "[red]FAIL[/red]"
    console.print(f"  Risk tier:     {tier_icon}  {risk_tier}")

    # Blast radius
    full_checks = result["checks"]["full"]
    blast_ok = full_checks["blast_radius_declared"]["passed"]
    blast_score = full_checks["blast_radius_declared"]["score"]
    blast_icon = "[green]OK[/green]" if blast_ok else "[red]FAIL[/red]"
    blast_suffix = f"(score: {blast_score})" if blast_score is not None else ""
    console.print(f"  Blast radius:  {blast_icon}  {blast_suffix}")

    # Controls breakdown — show what Standard requires
    std_checks = result["checks"]["standard"]
    req_controls = result["required_controls"]
    all_impl = set(curr_impl) | set(req_controls)

    # Count how many of the 2 mandatory Standard controls are satisfied
    audit_ok = std_checks["ctrl_audit_log_declared"]["passed"]
    deny_ok = std_checks["ctrl_default_deny_declared"]["passed"]
    satisfied = sum([audit_ok, deny_ok])
    total_req = len(_STANDARD_MANDATORY_CONTROLS)
    ctrl_icon = "[green]OK[/green]" if satisfied == total_req else "[yellow]PARTIAL[/yellow]" if satisfied > 0 else "[red]FAIL[/red]"

    console.print(f"  Controls:      {ctrl_icon}  ({satisfied}/{total_req} mandatory)")
    ctrl_display = [
        ("ctrl.obs.audit_log_append_only", audit_ok),
        ("ctrl.pol.default_deny", deny_ok),
    ]
    for ctrl_id, ok in ctrl_display:
        icon = "[green]OK[/green]" if ok else "[red]MISS[/red]"
        console.print(f"    {icon}  {ctrl_id}")

    if curr_impl:
        for ctrl in sorted(curr_impl)[:5]:
            if ctrl not in [c for c, _ in ctrl_display]:
                console.print(f"    [dim]    {ctrl}[/dim]")
        if len(curr_impl) > 5:
            console.print(f"    [dim]    ... +{len(curr_impl)-5} more[/dim]")

    # Privilege envelope
    priv_ok = full_checks["privilege_envelope_declared"]["passed"]
    priv_icon = "[green]OK[/green]" if priv_ok else "[red]FAIL[/red]"
    console.print(f"  Privilege env: {priv_icon}  {list(priv_env.keys()) if priv_env else '(none)'}")

    # Idempotency
    idem_ok = full_checks["idempotency_declared"]["passed"]
    idem_icon = "[green]OK[/green]" if idem_ok else "[red]FAIL[/red]"
    console.print(f"  Idempotency:   {idem_icon}  {idempotency or '(not declared)'}")

    # Artifact hash / evidence receipts
    ah_ok = full_checks["artifact_hash_declared"]["passed"]
    ah_icon = "[green]OK[/green]" if ah_ok else "[red]FAIL[/red]"
    console.print(f"  Artifact hash: {ah_icon}")

    # -----------------------------------------------------------------------
    # Compliance level summary bar
    # -----------------------------------------------------------------------
    console.print()
    level_parts = []
    for lvl in _COMPLIANCE_LEVELS:
        key = _LEVEL_KEY[lvl]
        lvl_result = result["levels"][key]
        if lvl_result["achieved"]:
            level_parts.append(f"[bold green]{lvl} OK[/bold green]")
        else:
            level_parts.append(f"[bold red]{lvl} FAIL[/bold red]")

    console.print("  Compliance:  " + "  |  ".join(level_parts))

    # -----------------------------------------------------------------------
    # Gap analysis: what's missing for the next level
    # -----------------------------------------------------------------------
    if achieved == "WCP-Full":
        console.print("  [green]Achieved WCP-Full — fully compliant.[/green]")
    else:
        # Find next level above achieved
        if achieved == "none":
            next_level = "WCP-Basic"
        elif achieved == "WCP-Basic":
            next_level = "WCP-Standard"
        else:
            next_level = "WCP-Full"

        next_key = _LEVEL_KEY[next_level]
        next_missing = result["levels"][next_key]["missing"]

        if next_missing:
            console.print(f"\n  Missing for [bold]{next_level}[/bold]:")
            for item in next_missing:
                console.print(f"    [red]x[/red]  {item}")

    # If --level was specified, show targeted gap
    if target_level and target_level.upper() in [lvl.upper().replace("WCP-", "") for lvl in _COMPLIANCE_LEVELS]:
        # Normalize: "full" -> "WCP-Full"
        normalized = f"WCP-{target_level.capitalize()}"
        if normalized != "WCP-Full" or achieved != "WCP-Full":
            tgt_key = _LEVEL_KEY.get(normalized)
            if tgt_key:
                tgt_missing = result["levels"][tgt_key]["missing"]
                if tgt_missing and normalized != (
                    "WCP-Basic" if achieved == "none" else
                    "WCP-Standard" if achieved == "WCP-Basic" else
                    "WCP-Full"
                ):
                    console.print(f"\n  Missing for [bold]{normalized}[/bold] (targeted):")
                    for item in tgt_missing:
                        console.print(f"    [red]x[/red]  {item}")


@app.command()
def check(
    path: str = typer.Argument(..., help="registry_record.json file or directory of them"),
    level: str = typer.Option("standard", help="Target compliance level: basic | standard | full"),
):
    """
    Check WCP compliance level of enrolled worker(s).

    Evaluates a registry_record.json (or a directory of them) against
    WCP-Basic, WCP-Standard, and WCP-Full criteria and reports what
    each worker achieves and what is missing.

    Examples:

        pyhall check ./my-worker/registry_record.json

        pyhall check ./registry/enrolled/

        pyhall check --level full registry_record.json
    """
    _print_banner()

    console.print(
        Panel(
            Text.from_markup("[bold]PyHall WCP Compliance Check[/bold]"),
            border_style="cyan",
            padding=(0, 2),
        )
    )

    # Resolve files to check
    target = Path(path)
    if target.is_dir():
        record_files = sorted(target.glob("*.json"))
        if not record_files:
            console.print(f"[yellow]No *.json files found in {target}[/yellow]")
            raise typer.Exit(0)
    elif target.is_file():
        record_files = [target]
    else:
        console.print(f"[red]Path not found: {path}[/red]")
        raise typer.Exit(1)

    # Normalize --level
    level_normalized = level.lower().strip()
    valid_levels = {"basic", "standard", "full"}
    if level_normalized not in valid_levels:
        console.print(f"[red]Invalid --level '{level}'. Must be one of: basic, standard, full[/red]")
        raise typer.Exit(1)

    results = []
    errors = []

    for record_file in record_files:
        try:
            record = json.loads(record_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append((record_file, str(exc)))
            continue

        result = check_worker_compliance(record)
        result["_source_file"] = str(record_file)
        results.append(result)
        _render_check_result(result, level_normalized)

    # -----------------------------------------------------------------------
    # Error summary
    # -----------------------------------------------------------------------
    if errors:
        console.print()
        for f, err in errors:
            console.print(f"[red]Could not parse {f}: {err}[/red]")

    # -----------------------------------------------------------------------
    # Aggregate summary table (only when multiple files)
    # -----------------------------------------------------------------------
    if len(results) > 1:
        console.print()
        table = Table(title="Compliance Summary", show_header=True)
        table.add_column("Worker ID", style="cyan")
        table.add_column("Risk", style="white")
        table.add_column("WCP-Basic", style="white")
        table.add_column("WCP-Standard", style="white")
        table.add_column("WCP-Full", style="white")
        table.add_column("Achieved", style="bold")

        for r in results:
            def _cell(key: str) -> str:
                return "[green]OK[/green]" if r["levels"][key]["achieved"] else "[red]FAIL[/red]"

            achieved_color = {
                "WCP-Full": "green",
                "WCP-Standard": "yellow",
                "WCP-Basic": "cyan",
                "none": "red",
            }.get(r["achieved_level"], "white")

            table.add_row(
                r["worker_id"],
                r["risk_tier"],
                _cell("basic"),
                _cell("standard"),
                _cell("full"),
                f"[{achieved_color}]{r['achieved_level']}[/{achieved_color}]",
            )

        console.print(table)

    # Exit 1 if any worker fails the target level
    target_key = {"basic": "basic", "standard": "standard", "full": "full"}[level_normalized]
    failed = [r for r in results if not r["levels"][target_key]["achieved"]]
    if failed:
        console.print(
            f"\n[red]{len(failed)} worker(s) did not achieve WCP-{level_normalized.capitalize()}[/red]"
        )
        raise typer.Exit(1)
    elif results:
        console.print(
            f"\n[green]All {len(results)} worker(s) meet WCP-{level_normalized.capitalize()}[/green]"
        )


# ---------------------------------------------------------------------------
# demo — pre-configured routing demonstration, no setup required
# ---------------------------------------------------------------------------

@app.command()
def demo():
    """
    Run a pre-configured routing demonstration — no files or setup needed.

    Shows the full WCP routing pipeline with bundled rules and an in-memory
    registry. Use this to see pyhall working before you have your own rules.

    Demonstrates:
      1. ALLOWED decision  — rule matches, worker available
      2. DENIED decision   — no rule matches (fail-closed)
      3. DENIED decision   — required control missing from registry
    """
    _print_banner()

    from .rules import load_rules_from_dict

    DEMO_RULES = {
        "rules": [
            {
                "rule_id": "rr_hello_dev_001",
                "match": {
                    "capability_id": "cap.hello.greet",
                    "env": {"in": ["dev", "stage"]},
                },
                "decision": {
                    "candidate_workers_ranked": [
                        {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0}
                    ],
                    "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                    "escalation": {"policy_gate": False, "human_required_default": False},
                    "preconditions": {},
                },
            },
            {
                "rule_id": "rr_doc_summarize_dev",
                "match": {
                    "capability_id": "cap.doc.summarize",
                    "env": {"in": ["dev", "stage"]},
                },
                "decision": {
                    "candidate_workers_ranked": [
                        {"worker_species_id": "wrk.doc.summarizer", "score_hint": 1.0}
                    ],
                    "required_controls_suggested": [
                        "ctrl.obs.audit-log-append-only",
                        "ctrl.obs.rate-limit",
                    ],
                    "escalation": {"policy_gate": False, "human_required_default": False},
                    "preconditions": {},
                },
            },
        ]
    }

    rules = load_rules_from_dict(DEMO_RULES)

    registry = Registry()
    registry.enroll({
        "worker_id": "org.example.hello-greeter",
        "worker_species_id": "wrk.hello.greeter",
        "capabilities": ["cap.hello.greet"],
        "risk_tier": "low",
        "required_controls": ["ctrl.obs.audit-log-append-only"],
        "currently_implements": ["ctrl.obs.audit-log-append-only"],
        "allowed_environments": ["dev", "stage", "prod"],
        "blast_radius": {"data": 0, "network": 0, "financial": 0, "time": 0},
        "privilege_envelope": {
            "secrets_access": [],
            "network_egress": "none",
            "filesystem_writes": [],
            "tools": [],
        },
        "owner": "org.example",
        "contact": "demo@example.com",
    })
    # Note: wrk.doc.summarizer is intentionally NOT enrolled.
    # This demonstrates DENY_MISSING_REQUIRED_CONTROLS in scenario 3.

    policy_gate = PolicyGate()
    corr_id = str(uuid.uuid4())

    scenarios = [
        {
            "label": "cap.hello.greet  |  env=dev  |  rule matches, worker enrolled",
            "inp": RouteInput(
                capability_id="cap.hello.greet",
                env="dev",
                data_label="PUBLIC",
                tenant_risk="low",
                qos_class="P2",
                tenant_id="demo",
                correlation_id=corr_id,
            ),
        },
        {
            "label": "cap.unknown.thing  |  env=dev  |  no rule matches (fail-closed)",
            "inp": RouteInput(
                capability_id="cap.unknown.thing",
                env="dev",
                data_label="PUBLIC",
                tenant_risk="low",
                qos_class="P2",
                tenant_id="demo",
                correlation_id=corr_id,
            ),
        },
        {
            "label": "cap.doc.summarize  |  env=dev  |  rule matches, ctrl.obs.rate-limit missing",
            "inp": RouteInput(
                capability_id="cap.doc.summarize",
                env="dev",
                data_label="PUBLIC",
                tenant_risk="low",
                qos_class="P2",
                tenant_id="demo",
                correlation_id=corr_id,
            ),
        },
    ]

    for i, s in enumerate(scenarios, 1):
        decision = make_decision(
            inp=s["inp"],
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            registry_get_privilege_envelope=registry.get_privilege_envelope,
            registry_policy_allows_privilege=registry.policy_allows_privilege,
            policy_gate_eval=policy_gate.evaluate,
            task_id=f"demo_task_{i}",
        )

        outcome = "[green]ALLOWED[/green]" if not decision.denied else "[red]DENIED[/red]"
        console.print(f"\n[bold]Scenario {i}:[/bold] {s['label']}")
        console.print(f"  Decision:     {outcome}")
        console.print(f"  Rule matched: {decision.matched_rule_id}")
        if decision.denied:
            reason = decision.deny_reason_if_denied or {}
            console.print(f"  Deny code:    [yellow]{reason.get('code', 'unknown')}[/yellow]")
            console.print(f"  Message:      {reason.get('message', '')}")
        else:
            console.print(f"  Worker:       [cyan]{decision.selected_worker_species_id}[/cyan]")
            console.print(f"  Controls:     {decision.required_controls_effective}")

    console.print(
        "\n[dim]Run [bold]pyhall --help[/bold] to see all commands.[/dim]"
        "\n[dim]See [bold]workers/examples/[/bold] for complete worker examples.[/dim]\n"
    )


# ---------------------------------------------------------------------------
# Catalog helpers (shared by search, explain, browse, dispatch)
# ---------------------------------------------------------------------------

_CATALOG_PATH = Path(__file__).parent / "taxonomy" / "catalog.json"

# pyhall.dev blue color theme
_BLUE = "#0050D4"
_BLUE_LIGHT = "#0078D4"
_GREEN = "#107C10"
_RED = "#D13438"
_ORANGE = "#FF8C00"

_ASCII_BANNER = r"""
  ██████╗ ██╗   ██╗██╗  ██╗ █████╗ ██╗     ██╗
  ██╔══██╗╚██╗ ██╔╝██║  ██║██╔══██╗██║     ██║
  ██████╔╝ ╚████╔╝ ███████║███████║██║     ██║
  ██╔═══╝   ╚██╔╝  ██╔══██║██╔══██║██║     ██║
  ██║        ██║   ██║  ██║██║  ██║███████╗███████╗
  ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝"""

_ASCII_SUBTITLE = "  Worker Class Protocol  ·  pyhall v{version}"
_ASCII_RULE = "  " + "─" * 51


def _load_catalog() -> dict:
    """Load the bundled taxonomy catalog."""
    with open(_CATALOG_PATH) as f:
        return json.load(f)


def _print_catalog_banner(quiet: bool = False):
    """Print the ASCII banner for user-facing catalog commands."""
    if quiet:
        return
    console.print(f"[bold {_BLUE}]{_ASCII_BANNER}[/bold {_BLUE}]")
    console.print(f"[{_BLUE_LIGHT}]{_ASCII_SUBTITLE.format(version=__version__)}[/{_BLUE_LIGHT}]")
    console.print(f"[dim]{_ASCII_RULE}[/dim]")
    console.print()


def _score_entity(entity: dict, query: str) -> int:
    """Score a catalog entity against a search query. Higher = better match."""
    q = query.lower()
    eid = entity.get("id", "").lower()
    name = entity.get("name", "").lower()
    description = entity.get("description", "").lower()
    tags = " ".join(entity.get("tags", [])).lower()

    score = 0

    # Exact ID match
    if eid == q:
        score = max(score, 100)
    # ID prefix
    elif eid.startswith(q) or q in eid:
        score = max(score, 80)

    # Name match
    if q in name:
        score = max(score, 70)
    elif any(word in name for word in q.split()):
        score = max(score, 55)

    # Tag match
    if q in tags or any(word in tags for word in q.split()):
        score = max(score, 50)

    # Description keyword match
    if q in description:
        score = max(score, 40)
    elif any(word in description for word in q.split() if len(word) > 2):
        score = max(score, 25)

    return score


def _type_label(entity_type: str) -> str:
    """Short display label for entity type."""
    return {
        "capability": "cap",
        "worker_species": "wrk",
        "control": "ctrl",
        "profile": "prof",
        "policy": "pol",
    }.get(entity_type, entity_type)


def _risk_color(risk_tier: str) -> str:
    """Color for risk tier display."""
    return {
        "low": _GREEN,
        "medium": _ORANGE,
        "high": _RED,
        "critical": _RED,
    }.get(risk_tier, "white")


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

@app.command()
def search(
    query: str = typer.Argument(..., help="Search query — entity IDs, names, descriptions"),
    type_filter: Optional[str] = typer.Option(
        None, "--type", help="Filter by type: cap | wrk | ctrl | prof | pol"
    ),
    limit: int = typer.Option(10, "--limit", help="Max results to return"),
    output_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress banner"),
):
    """
    Fuzzy search across taxonomy catalog entities.

    Searches entity IDs, names, and descriptions. Results are ranked by
    relevance with type and risk tier shown.

    Examples:

        pyhall search "summarize documents"

        pyhall search "sandbox" --type ctrl

        pyhall search "doc" --limit 5
    """
    if not output_json:
        _print_catalog_banner(quiet=quiet)

    catalog = _load_catalog()
    entities = catalog.get("entities", [])

    # Build type prefix map for filter
    _type_prefix_map = {
        "cap": "capability",
        "wrk": "worker_species",
        "ctrl": "control",
        "prof": "profile",
        "pol": "policy",
    }

    # Apply filters
    if type_filter:
        full_type = _type_prefix_map.get(type_filter.lower(), type_filter.lower())
        entities = [e for e in entities if e.get("type") == full_type]

    # Score and rank
    scored = [(e, _score_entity(e, query)) for e in entities]
    scored = [(e, s) for e, s in scored if s > 0]
    scored.sort(key=lambda x: x[1], reverse=True)
    results = scored[:limit]

    if output_json:
        out = [
            {
                "id": e["id"],
                "type": e.get("type"),
                "name": e.get("name"),
                "description": e.get("description"),
                "risk_tier": e.get("risk_tier"),
                "tags": e.get("tags", []),
                "score": s,
            }
            for e, s in results
        ]
        print(json.dumps(out, indent=2))
        return

    if not results:
        console.print(f"[{_ORANGE}]No results for '{query}'.[/{_ORANGE}]")
        console.print(
            f"[dim]Try broader terms or remove --type filter.[/dim]"
        )
        raise typer.Exit(0)

    table = Table(
        title=f"Search: '{query}'  ({len(results)} of {len(scored)} matches)",
        border_style=_BLUE,
        show_lines=False,
        highlight=True,
    )
    table.add_column("ID", style=f"bold {_BLUE}", no_wrap=True)
    table.add_column("Type", style="dim", width=5)
    table.add_column("Name", style="white")
    table.add_column("Risk", style="dim", width=8)
    table.add_column("Score", style="dim", width=5, justify="right")

    for entity, score in results:
        risk = entity.get("risk_tier", "")
        risk_colored = f"[{_risk_color(risk)}]{risk}[/{_risk_color(risk)}]" if risk else "—"
        table.add_row(
            entity["id"],
            _type_label(entity.get("type", "")),
            entity.get("name", ""),
            risk_colored,
            str(score),
        )

    console.print(table)
    console.print(
        f"\n[dim]Run [bold]pyhall explain <id>[/bold] for full entity details.[/dim]"
    )


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------

@app.command()
def explain(
    entity_id: str = typer.Argument(..., help="Entity ID, e.g. cap.doc.summarize"),
    output_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress banner"),
):
    """
    Show full details for a catalog entity.

    For capabilities: risk tier, tags, workers that serve it.
    For worker species: risk tier, serves_capabilities, required controls.
    For controls: description, which workers use it.

    Examples:

        pyhall explain cap.doc.summarize

        pyhall explain wrk.doc.pipeline.orchestrator

        pyhall explain ctrl.sandbox.no-egress-default-deny
    """
    if not output_json:
        _print_catalog_banner(quiet=quiet)

    catalog = _load_catalog()
    entities = catalog.get("entities", [])

    # Find exact match first, then case-insensitive
    entity = next((e for e in entities if e["id"] == entity_id), None)
    if entity is None:
        entity = next(
            (e for e in entities if e["id"].lower() == entity_id.lower()), None
        )

    if entity is None:
        if output_json:
            print(json.dumps({"error": f"Entity not found: {entity_id}"}))
        else:
            console.print(
                f"[{_RED}]Entity not found:[/{_RED}] [bold]{entity_id}[/bold]"
            )
            console.print(
                f"[dim]Run [bold]pyhall search {entity_id.split('.')[0]}[/bold] to find similar entities.[/dim]"
            )
        raise typer.Exit(1)

    if output_json:
        print(json.dumps(entity, indent=2))
        return

    # Build rich panel
    entity_type = entity.get("type", "")

    # Header
    type_label = _type_label(entity_type)
    console.print(
        Panel(
            Text.from_markup(
                f"[bold {_BLUE}]{entity['id']}[/bold {_BLUE}]\n"
                f"[{_BLUE_LIGHT}]{entity.get('name', '')}[/{_BLUE_LIGHT}]"
            ),
            border_style=_BLUE,
            subtitle=f"[dim]{type_label}[/dim]",
            padding=(0, 2),
        )
    )

    # Core fields table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="dim", width=22)
    table.add_column("Value", style="white")

    table.add_row("Type", entity_type)

    if "description" in entity:
        table.add_row("Description", entity["description"])

    # Type-specific fields
    if entity_type == "capability":
        risk = entity.get("risk_tier", "")
        if risk:
            color = _risk_color(risk)
            table.add_row("Risk tier", f"[{color}]{risk}[/{color}]")
        namespace = entity.get("wcp_namespace", "")
        if namespace:
            table.add_row("WCP namespace", namespace)
        tags = entity.get("tags", [])
        if tags:
            table.add_row("Tags", ", ".join(tags))

        # Find workers that serve this capability
        workers_for_cap = [
            e for e in entities
            if e.get("type") == "worker_species"
            and entity["id"] in e.get("serves_capabilities", [])
        ]
        if workers_for_cap:
            worker_ids = ", ".join(w["id"] for w in workers_for_cap)
            table.add_row("Served by", worker_ids)

    elif entity_type == "worker_species":
        risk = entity.get("risk_tier", "")
        if risk:
            color = _risk_color(risk)
            table.add_row("Risk tier", f"[{color}]{risk}[/{color}]")
        determinism = entity.get("determinism")
        if determinism:
            table.add_row("Determinism", determinism)
        serves = entity.get("serves_capabilities", [])
        if serves:
            table.add_row("Serves capabilities", "\n".join(serves))
        required_controls = entity.get("required_controls", [])
        if required_controls:
            table.add_row("Required controls", "\n".join(required_controls))
        tags = entity.get("tags", [])
        if tags:
            table.add_row("Tags", ", ".join(tags))

    elif entity_type == "control":
        tags = entity.get("tags", [])
        if tags:
            table.add_row("Tags", ", ".join(tags))
        # Find workers that require this control
        workers_using = [
            e for e in entities
            if e.get("type") == "worker_species"
            and entity["id"] in e.get("required_controls", [])
        ]
        if workers_using:
            worker_ids = ", ".join(w["id"] for w in workers_using[:5])
            if len(workers_using) > 5:
                worker_ids += f"  (+{len(workers_using) - 5} more)"
            table.add_row("Used by workers", worker_ids)

    elif entity_type == "profile":
        tags = entity.get("tags", [])
        if tags:
            table.add_row("Tags", ", ".join(tags))

    elif entity_type == "policy":
        tags = entity.get("tags", [])
        if tags:
            table.add_row("Tags", ", ".join(tags))

    console.print(table)


# ---------------------------------------------------------------------------
# browse
# ---------------------------------------------------------------------------

@app.command()
def browse(
    type_filter: Optional[str] = typer.Option(
        None, "--type", help="Filter by type: cap | wrk | ctrl | prof | pol"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress banner"),
):
    """
    Browse the taxonomy catalog.

    Without flags: show entity counts by type.
    With --type: list all entities of that type.

    Examples:

        pyhall browse

        pyhall browse --type cap

        pyhall browse --type wrk --json
    """
    if not output_json:
        _print_catalog_banner(quiet=quiet)

    catalog = _load_catalog()
    entities = catalog.get("entities", [])
    meta = catalog.get("_meta", {})

    _type_prefix_map = {
        "cap": "capability",
        "wrk": "worker_species",
        "ctrl": "control",
        "prof": "profile",
        "pol": "policy",
    }

    # Resolve type filter to full type name
    full_type = None
    if type_filter:
        full_type = _type_prefix_map.get(type_filter.lower(), type_filter.lower())

    # --- Mode 1: summary by entity type (no --type) ---
    if not full_type:
        from collections import Counter
        counts = Counter(e.get("type", "other") for e in entities)

        if output_json:
            by_type = {t: n for t, n in counts.items()}
            print(json.dumps({"by_type": by_type, "total": len(entities), "meta": meta}, indent=2))
            return

        table = Table(
            title=f"WCP Taxonomy  ·  {meta.get('total_entities', len(entities))} entities",
            border_style=_BLUE,
            show_lines=False,
        )
        table.add_column("Type", style=f"bold {_BLUE}", no_wrap=True)
        table.add_column("Short", style="dim", width=5)
        table.add_column("Count", style="white", justify="right", width=6)

        type_labels = [
            ("capability",    "cap"),
            ("worker_species","wrk"),
            ("control",       "ctrl"),
            ("profile",       "prof"),
            ("policy",        "pol"),
        ]
        for full, short in type_labels:
            n = counts.get(full, 0)
            table.add_row(full, short, str(n) if n else "—")

        console.print(table)
        console.print(
            f"\n[dim]Run [bold]pyhall browse --type cap|wrk|ctrl|prof|pol[/bold] to list entities by type.[/dim]"
        )
        return

    # --- Mode 2: filter entities by type ---
    filtered = [e for e in entities if e.get("type") == full_type]

    if output_json:
        print(json.dumps({"entities": filtered, "count": len(filtered)}, indent=2))
        return

    if not filtered:
        console.print(f"[{_ORANGE}]No entities found with the given filters.[/{_ORANGE}]")
        raise typer.Exit(0)

    title = f"Type: {full_type}  ({len(filtered)} entities)"

    table = Table(title=title, border_style=_BLUE, show_lines=False)
    table.add_column("ID", style=f"bold {_BLUE}", no_wrap=True)
    table.add_column("Type", style="dim", width=5)
    table.add_column("Name", style="white")
    table.add_column("Risk", style="dim", width=8)

    for entity in filtered:
        risk = entity.get("risk_tier", "")
        risk_colored = f"[{_risk_color(risk)}]{risk}[/{_risk_color(risk)}]" if risk else "—"
        table.add_row(
            entity["id"],
            _type_label(entity.get("type", "")),
            entity.get("name", ""),
            risk_colored,
        )

    console.print(table)
    console.print(
        f"\n[dim]Run [bold]pyhall explain <id>[/bold] for full entity details.[/dim]"
    )


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

@app.command()
def dispatch(
    capability_id: str = typer.Argument(..., help="Capability ID to dispatch, e.g. cap.doc.summarize"),
    env: str = typer.Option("dev", "--env", help="Environment: dev | stage | prod | edge"),
    data_label: str = typer.Option("PUBLIC", "--data-label", help="Data label: PUBLIC | INTERNAL | RESTRICTED"),
    tenant_risk: str = typer.Option("low", "--tenant-risk", help="Tenant risk: low | medium | high"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show routing plan without executing"),
    output_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress banner"),
):
    """
    Simulate routing a capability request through the WCP engine.

    Uses bundled routing rules derived from the taxonomy catalog. Shows a
    step-by-step decision trace: rule match, control verification, worker
    selection, and final verdict.

    Examples:

        pyhall dispatch cap.doc.summarize

        pyhall dispatch cap.doc.summarize --env prod --tenant-risk high

        pyhall dispatch cap.doc.summarize --dry-run --json
    """
    if not output_json:
        _print_catalog_banner(quiet=quiet)

    from .rules import load_rules_from_dict

    catalog = _load_catalog()
    entities = catalog.get("entities", [])

    # Build synthetic routing rules from catalog worker_species entries
    # Each worker species declares which capabilities it handles.
    rules_list = []
    registry_workers: dict[str, dict] = {}

    for entity in entities:
        if entity.get("type") != "worker_species":
            continue
        handles = entity.get("handles_capabilities", [])
        if not handles:
            continue

        species_id = entity["id"]
        required_controls = entity.get("required_controls", [])

        for cap_id in handles:
            rule_slug = cap_id.replace(".", "_")
            rule = {
                "rule_id": f"rr_catalog_{rule_slug}",
                "match": {
                    "capability_id": cap_id,
                    "env": {"in": ["dev", "stage", "prod", "edge"]},
                },
                "decision": {
                    "candidate_workers_ranked": [
                        {"worker_species_id": species_id, "score_hint": 1.0}
                    ],
                    "required_controls_suggested": required_controls,
                    "escalation": {
                        "policy_gate": entity.get("risk_tier") in ("high", "critical"),
                        "human_required_default": False,
                    },
                    "preconditions": {},
                },
            }
            rules_list.append(rule)

        # Register the worker in the in-memory registry
        registry_workers[species_id] = {
            "worker_id": f"catalog.{species_id}",
            "worker_species_id": species_id,
            "capabilities": handles,
            "risk_tier": entity.get("risk_tier", "medium"),
            "required_controls": required_controls,
            "currently_implements": required_controls,  # catalog workers are fully compliant
            "allowed_environments": ["dev", "stage", "prod", "edge"],
            "blast_radius": {
                "data": 1, "network": 0, "financial": 0, "time": 1, "reversibility": "reversible"
            },
            "privilege_envelope": {
                "secrets_access": [],
                "network_egress": "none",
                "filesystem_writes": [],
                "tools": [],
            },
            "owner": "catalog",
            "contact": "catalog@pyhall.dev",
        }

    # Build in-memory registry
    registry = Registry()
    for worker_record in registry_workers.values():
        registry.enroll(worker_record)

    # Validate input before routing
    try:
        inp = RouteInput(
            capability_id=capability_id,
            env=env,  # type: ignore[arg-type]
            data_label=data_label,  # type: ignore[arg-type]
            tenant_risk=tenant_risk,  # type: ignore[arg-type]
            qos_class="P2",
            tenant_id="dispatch-sim",
            correlation_id=str(uuid.uuid4()),
        )
    except Exception as exc:
        if output_json:
            print(json.dumps({"error": str(exc)}))
        else:
            console.print(f"[{_RED}]Invalid input: {exc}[/{_RED}]")
        raise typer.Exit(1)

    # Check if capability exists in catalog
    catalog_entity = next(
        (e for e in entities if e["id"] == capability_id and e.get("type") == "capability"),
        None,
    )

    if not catalog_entity:
        # Try without version suffix for a fuzzy hint
        base_id = ".".join(capability_id.split(".")[:3])
        similar = [
            e for e in entities
            if e.get("type") == "capability" and e["id"].startswith(base_id)
        ]
        if not output_json:
            console.print(
                f"[{_ORANGE}]Warning:[/{_ORANGE}] '{capability_id}' is not in the bundled catalog."
            )
            if similar:
                console.print(f"[dim]Similar catalog IDs: {', '.join(e['id'] for e in similar[:3])}[/dim]")
            console.print(
                "[dim]Dispatch will attempt routing with catalog rules anyway.[/dim]\n"
            )

    # Build trace output
    trace_steps = []

    def _trace(step: str, detail: str):
        trace_steps.append({"step": step, "detail": detail})
        if not output_json:
            console.print(f"  [dim]{step}:[/dim] {detail}")

    if not output_json:
        console.print(
            Panel(
                Text.from_markup(
                    f"[bold {_BLUE}]Dispatch Simulation[/bold {_BLUE}]\n"
                    f"Capability: [bold]{capability_id}[/bold]  ·  env={env}  ·  "
                    f"data_label={data_label}  ·  tenant_risk={tenant_risk}"
                ),
                border_style=_BLUE,
                padding=(0, 2),
            )
        )
        console.print()
        console.print(f"[{_BLUE_LIGHT}]Routing trace:[/{_BLUE_LIGHT}]")

    _trace("1. input", f"capability_id={capability_id}, env={env}, data_label={data_label}, tenant_risk={tenant_risk}")
    _trace("2. rules", f"{len(rules_list)} catalog rules loaded")
    _trace("3. registry", f"{len(registry_workers)} catalog workers enrolled")

    if dry_run:
        _trace("4. decision", "DRY RUN — routing engine not invoked")

        # Check manually if any rule would match
        matching_rules = [
            r for r in rules_list
            if r["match"].get("capability_id") == capability_id
        ]
        if matching_rules:
            r = matching_rules[0]
            candidates = r["decision"].get("candidate_workers_ranked", [])
            _trace("5. rule match", f"{r['rule_id']}")
            if candidates:
                _trace("6. candidate worker", candidates[0]["worker_species_id"])
        else:
            _trace("5. rule match", "NO MATCH — would be DENIED (fail-closed)")

        if output_json:
            print(json.dumps({
                "capability_id": capability_id,
                "env": env,
                "data_label": data_label,
                "tenant_risk": tenant_risk,
                "dry_run": True,
                "trace": trace_steps,
            }, indent=2))
        return

    # Actually route
    rules = load_rules_from_dict({"rules": rules_list})
    policy_gate = PolicyGate()

    decision = make_decision(
        inp=inp,
        rules=rules,
        registry_controls_present=registry.controls_present(),
        registry_worker_available=registry.worker_available,
        registry_get_privilege_envelope=registry.get_privilege_envelope,
        registry_policy_allows_privilege=registry.policy_allows_privilege,
        policy_gate_eval=policy_gate.evaluate,
        task_id="pyhall_dispatch_sim",
    )

    _trace("4. matched rule", str(decision.matched_rule_id))

    if decision.denied:
        deny_reason = decision.deny_reason_if_denied or {}
        _trace("5. decision", f"DENIED — {deny_reason.get('code', 'unknown')}: {deny_reason.get('message', '')}")
    else:
        _trace("5. decision", f"ALLOWED — worker: {decision.selected_worker_species_id}")
        if decision.required_controls_effective:
            _trace("6. controls", ", ".join(decision.required_controls_effective))

    if output_json:
        out = decision.model_dump()
        out["_trace"] = trace_steps
        out["_meta"] = {
            "capability_id": capability_id,
            "env": env,
            "data_label": data_label,
            "tenant_risk": tenant_risk,
            "rules_loaded": len(rules_list),
            "workers_enrolled": len(registry_workers),
            "dry_run": False,
        }
        print(json.dumps(out, indent=2))
        return

    console.print()
    if decision.denied:
        deny_reason = decision.deny_reason_if_denied or {}
        console.print(
            Panel(
                Text.from_markup(
                    f"[bold {_RED}]DENIED[/bold {_RED}]\n"
                    f"Code: {deny_reason.get('code', 'unknown')}\n"
                    f"Message: {deny_reason.get('message', '')}"
                ),
                border_style=_RED,
                padding=(0, 2),
            )
        )
        raise typer.Exit(1)
    else:
        console.print(
            Panel(
                Text.from_markup(
                    f"[bold {_GREEN}]ALLOWED[/bold {_GREEN}]\n"
                    f"Worker: [bold]{decision.selected_worker_species_id}[/bold]\n"
                    f"Rule:   {decision.matched_rule_id}\n"
                    f"Controls: {', '.join(decision.required_controls_effective or []) or 'none'}"
                ),
                border_style=_GREEN,
                padding=(0, 2),
            )
        )


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------

@app.command()
def version():
    """Show PyHall and WCP spec versions."""
    console.print(f"PyHall {__version__}  (WCP spec {__wcp_version__})")


# ---------------------------------------------------------------------------
# discord-lab
# ---------------------------------------------------------------------------

_LAB_DISCORD_CHANNELS = [
    "agent-bulletin-board",
    "lab-alerts",
    "worker-status",
    "deploy",
    "agent-updates",
    "monty",
]

_LAB_DISCORD_WEBHOOKS = {
    "agent-bulletin-board": "DISCORD_WEBHOOK_BULLETIN",
    "lab-alerts": "DISCORD_WEBHOOK_ALERTS",
    "worker-status": "DISCORD_WEBHOOK_WORKER_STATUS",
    "deploy": "DISCORD_WEBHOOK_DEPLOY",
    "agent-updates": "DISCORD_WEBHOOK_AGENTS",
    "monty": "DISCORD_WEBHOOK_MONTY",
}


def _discord_oauth_url(client_id: str) -> str:
    params = urlencode({
        "client_id": client_id,
        "scope": "bot applications.commands",
        "permissions": "2147560512",
    })
    return f"https://discord.com/oauth2/authorize?{params}"


def _discord_api_request(
    method: str,
    path: str,
    token: str,
    payload: Optional[dict] = None,
) -> dict | list:
    url = f"https://discord.com/api/v10{path}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(url, data=body, method=method.upper())
    request.add_header("Authorization", f"Bot {token}")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "DiscordBot (https://fafolab.ai, 0.1) Python/3")

    try:
        with urlopen(request) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Discord API {method.upper()} {path} failed: HTTP {exc.code} {details}"
        ) from exc
    except URLError as exc:
        raise RuntimeError(f"Discord API {method.upper()} {path} failed: {exc.reason}") from exc


def _discord_get_guild_channels(guild_id: str, token: str) -> list[dict]:
    result = _discord_api_request("GET", f"/guilds/{guild_id}/channels", token)
    if not isinstance(result, list):
        raise RuntimeError("Discord API returned unexpected channel payload")
    return result


def _discord_ensure_text_channel(guild_id: str, token: str, channel_name: str) -> dict:
    for channel in _discord_get_guild_channels(guild_id, token):
        if channel.get("type") == 0 and channel.get("name") == channel_name:
            return channel

    result = _discord_api_request(
        "POST",
        f"/guilds/{guild_id}/channels",
        token,
        {"name": channel_name, "type": 0},
    )
    if not isinstance(result, dict):
        raise RuntimeError(f"Discord API returned unexpected channel object for #{channel_name}")
    return result


def _discord_find_text_channel(guild_id: str, token: str, channel_name: str) -> Optional[dict]:
    for channel in _discord_get_guild_channels(guild_id, token):
        if channel.get("type") == 0 and channel.get("name") == channel_name:
            return channel
    return None


def _discord_create_webhook(channel_id: str, token: str, name: str) -> dict:
    result = _discord_api_request(
        "POST",
        f"/channels/{channel_id}/webhooks",
        token,
        {"name": name},
    )
    if not isinstance(result, dict):
        raise RuntimeError(f"Discord API returned unexpected webhook object for channel {channel_id}")
    return result


def _discord_webhook_url(webhook: dict) -> str:
    webhook_id = webhook.get("id")
    webhook_token = webhook.get("token")
    if not webhook_id or not webhook_token:
        raise RuntimeError("Webhook response missing id/token")
    return f"https://discord.com/api/webhooks/{webhook_id}/{webhook_token}"


def _lab_discord_env_template(server_name: str, guild_id: str = "", client_id: str = "") -> str:
    oauth_url = _discord_oauth_url(client_id) if client_id else ""
    lines = [
        "# FAFO Lab Discord secrets",
        f"# Server: {server_name}",
        "",
        f"export DISCORD_GUILD_ID={guild_id or 'replace_me'}",
        "export DISCORD_BOT_TOKEN=replace_me",
        "export DISCORD_BULLETIN_CHANNEL_ID=replace_me",
        "",
    ]
    for env_name in _LAB_DISCORD_WEBHOOKS.values():
        lines.append(f"export {env_name}=https://discord.com/api/webhooks/replace_me/replace_me")
    lines.extend([
        "",
        "export FAFOLAB_SECRETS_ENV=/home/fafo/secrets/fafo_secrets.env",
        "export FAFOLAB_DISCORD_QUEUE=/tmp/fafolab_discord_queue.jsonl",
    ])
    if oauth_url:
        lines.extend(["", f"# Bot invite URL", f"# {oauth_url}"])
    lines.append("")
    return "\n".join(lines)


def _lab_discord_exports_from_bootstrap(
    guild_id: str,
    bulletin_channel_id: str,
    webhook_urls: dict[str, str],
) -> str:
    lines = [
        f"export DISCORD_GUILD_ID={guild_id}",
        "export DISCORD_BOT_TOKEN=replace_me",
        f"export DISCORD_BULLETIN_CHANNEL_ID={bulletin_channel_id}",
        "",
    ]
    for channel_name in _LAB_DISCORD_CHANNELS:
        env_name = _LAB_DISCORD_WEBHOOKS[channel_name]
        lines.append(f"export {env_name}={webhook_urls[channel_name]}")
    lines.extend(
        [
            "",
            "export FAFOLAB_SECRETS_ENV=/home/fafo/secrets/fafo_secrets.env",
            "export FAFOLAB_DISCORD_QUEUE=/tmp/fafolab_discord_queue.jsonl",
        ]
    )
    return "\n".join(lines)


@app.command("discord-lab")
def discord_lab(
    server_name: str = typer.Option("fafolab", "--server-name", help="Discord server name"),
    client_id: Optional[str] = typer.Option(None, "--client-id", help="Discord application client ID"),
    guild_id: Optional[str] = typer.Option(None, "--guild-id", help="Discord guild/server ID"),
    write_env_template: Optional[Path] = typer.Option(
        None,
        "--write-env-template",
        help="Write a ready-to-fill env template file for Big Sexy secrets",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress banner"),
):
    """
    Generate the exact private lab Discord setup plan for Big Sexy.

    This does not call the Discord API. It gives you:
    - the channel list
    - the webhook env var map
    - the bot invite URL if a client ID is provided
    - an optional secrets template file for Big Sexy
    """
    if not quiet and not output_json:
        _print_banner()

    oauth_url = _discord_oauth_url(client_id) if client_id else None
    env_template_text = _lab_discord_env_template(server_name, guild_id or "", client_id or "")

    if write_env_template is not None:
        write_env_template.parent.mkdir(parents=True, exist_ok=True)
        write_env_template.write_text(env_template_text, encoding="utf-8")

    payload = {
        "server_name": server_name,
        "channels": _LAB_DISCORD_CHANNELS,
        "webhook_map": _LAB_DISCORD_WEBHOOKS,
        "guild_id": guild_id,
        "client_id": client_id,
        "oauth_url": oauth_url,
        "env_template_path": str(write_env_template) if write_env_template else None,
        "next_steps": [
            "Create the private lab channels in Discord",
            "Create one webhook per automation channel",
            "Paste the webhook URLs and bot token into the Big Sexy secrets file",
            "Sync the pyhall tree to Big Sexy and enable the Discord bot service",
        ],
    }

    if output_json:
        print(json.dumps(payload, indent=2))
        return

    console.print(Panel.fit(
        Text.from_markup(
            f"[bold cyan]Lab Discord Setup[/bold cyan]\n"
            f"Server: [bold]{server_name}[/bold]\n"
            f"Runtime host: [bold]Big Sexy[/bold]\n"
            f"Clients: Echo + phone"
        ),
        border_style="cyan",
    ))

    chan_table = Table(title="Channels")
    chan_table.add_column("Channel", style="cyan")
    chan_table.add_column("Webhook Env Var", style="white")
    for channel in _LAB_DISCORD_CHANNELS:
        chan_table.add_row(f"#{channel}", _LAB_DISCORD_WEBHOOKS.get(channel, "manual"))
    console.print(chan_table)

    if oauth_url:
        console.print(Panel(oauth_url, title="Bot Invite URL", border_style="green"))
    else:
        console.print("[yellow]No --client-id provided, so no bot invite URL was generated.[/yellow]")

    if write_env_template is not None:
        console.print(f"[green]Wrote secrets template:[/green] {write_env_template}")

    console.print("\n[bold]Next steps:[/bold]")
    for idx, step in enumerate(payload["next_steps"], start=1):
        console.print(f"  {idx}. {step}")


@app.command("discord-bootstrap")
def discord_bootstrap(
    guild_id: str = typer.Option(..., "--guild-id", help="Discord guild/server ID"),
    token_env: str = typer.Option("DISCORD_BOT_TOKEN", "--token-env", help="Env var holding the Discord bot token"),
    webhook_name: str = typer.Option("fafolab-bot", "--webhook-name", help="Webhook name to create per channel"),
    existing_only: bool = typer.Option(
        False,
        "--existing-only",
        help="Do not create channels. Use only existing text channels by expected names.",
    ),
    write_env_file: Optional[Path] = typer.Option(
        None,
        "--write-env-file",
        help="Write the resolved Discord env exports to a file",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress banner"),
):
    """
    Bootstrap the private lab Discord server through the Discord API.

    Requires the bot token to be present in the selected environment variable and
    the bot to have permission to manage channels and webhooks in the guild.
    """
    token = os.getenv(token_env, "").strip()
    if not token:
        console.print(f"[red]Missing bot token in environment variable:[/red] {token_env}")
        raise typer.Exit(1)

    if not quiet and not output_json:
        _print_banner()

    created_channels: list[dict[str, str]] = []
    webhook_urls: dict[str, str] = {}
    bulletin_channel_id = ""

    missing_channels: list[str] = []
    existing_channels: dict[str, dict] = {}

    if existing_only:
        for channel_name in _LAB_DISCORD_CHANNELS:
            channel = _discord_find_text_channel(guild_id, token, channel_name)
            if channel is None:
                missing_channels.append(channel_name)
            else:
                existing_channels[channel_name] = channel
        if missing_channels:
            raise RuntimeError(
                "Missing required existing channels for --existing-only: "
                + ", ".join(f"#{name}" for name in missing_channels)
            )

    for channel_name in _LAB_DISCORD_CHANNELS:
        if existing_only:
            channel = existing_channels[channel_name]
        else:
            channel = _discord_ensure_text_channel(guild_id, token, channel_name)
        channel_id = str(channel["id"])
        created_channels.append({"name": channel_name, "id": channel_id})
        if channel_name == "agent-bulletin-board":
            bulletin_channel_id = channel_id

        webhook = _discord_create_webhook(channel_id, token, webhook_name)
        webhook_urls[channel_name] = _discord_webhook_url(webhook)

    exports_text = _lab_discord_exports_from_bootstrap(guild_id, bulletin_channel_id, webhook_urls)

    if write_env_file is not None:
        write_env_file.parent.mkdir(parents=True, exist_ok=True)
        write_env_file.write_text(exports_text + "\n", encoding="utf-8")

    payload = {
        "guild_id": guild_id,
        "channels": created_channels,
        "webhook_map": {
            _LAB_DISCORD_WEBHOOKS[name]: webhook_urls[name]
            for name in _LAB_DISCORD_CHANNELS
        },
        "bulletin_channel_id": bulletin_channel_id,
        "env_file": str(write_env_file) if write_env_file else None,
    }

    if output_json:
        print(json.dumps(payload, indent=2))
        return

    console.print(Panel.fit(
        Text.from_markup(
            f"[bold cyan]Discord Bootstrap Complete[/bold cyan]\n"
            f"Guild: [bold]{guild_id}[/bold]\n"
            f"Channels created/verified: [bold]{len(created_channels)}[/bold]"
        ),
        border_style="green",
    ))
    console.print("[bold]Exports:[/bold]")
    console.print(exports_text)

    if write_env_file is not None:
        console.print(f"\n[green]Wrote env file:[/green] {write_env_file}")


# ---------------------------------------------------------------------------
# pyhall registry — pyhall.dev registry operations
# ---------------------------------------------------------------------------

registry_app = typer.Typer(name="registry", help="pyhall.dev registry operations — verify workers, check hashes, view ban-list")
app.add_typer(registry_app)


@registry_app.command("verify")
def cmd_registry_verify(
    worker_id: str = typer.Argument(..., help="Worker ID to look up"),
    registry_url: str = typer.Option(
        None, "--registry-url", help="Registry base URL (default: $PYHALL_REGISTRY_URL or https://api.pyhall.dev)"
    ),
) -> None:
    """Show current attestation status for a worker."""
    rc = RegistryClient(base_url=registry_url) if registry_url else RegistryClient()
    try:
        r = rc.verify(worker_id)
    except RegistryRateLimitError:
        console.print("[red]Rate limited — try again later[/red]")
        raise typer.Exit(1)

    status_color = "green" if r.status == "active" else "red" if r.status == "banned" else "yellow"
    t = Table(show_header=False, box=None, padding=(0, 1))
    t.add_column("key", style="dim")
    t.add_column("value")
    t.add_row("Worker:", f"[bold]{r.worker_id}[/bold]")
    t.add_row("Status:", f"[bold {status_color}]{r.status.upper()}[/{status_color}]")
    t.add_row("Current hash:", r.current_hash or "[dim]none[/dim]")
    t.add_row("Banned:", "[red]yes[/red]" if r.banned else "[green]no[/green]")
    if r.ban_reason:
        t.add_row("Ban reason:", r.ban_reason)
    t.add_row("Attested at:", r.attested_at or "[dim]never[/dim]")
    t.add_row("AI generated:", "yes" if r.ai_generated else "no")
    if r.ai_service:
        t.add_row("AI service:", r.ai_service)
    if r.ai_model:
        t.add_row("AI model:", r.ai_model)
    console.print()
    console.print(t)
    console.print()


@registry_app.command("check-hash")
def cmd_registry_check_hash(
    sha256: str = typer.Argument(..., help="SHA-256 hash to check (64 hex chars)"),
    registry_url: str = typer.Option(None, "--registry-url"),
) -> None:
    """Check if a SHA-256 hash appears on the confirmed ban-list."""
    if not re.match(r'^[0-9a-f]{64}$', sha256, re.IGNORECASE):
        console.print("[red]Invalid sha256: must be 64 hex characters[/red]")
        raise typer.Exit(1)

    rc = RegistryClient(base_url=registry_url) if registry_url else RegistryClient()
    try:
        banned = rc.is_hash_banned(sha256)
    except RegistryRateLimitError:
        console.print("[red]Rate limited — try again later[/red]")
        raise typer.Exit(1)

    console.print()
    if banned:
        console.print(f"  [bold red]BANNED[/bold red]   {sha256}")
        entry = next((e for e in rc.get_ban_list() if e.sha256 == sha256), None)
        if entry:
            console.print(f"  [dim]Reason:[/dim]  {entry.reason}")
            console.print(f"  [dim]Source:[/dim]  {entry.source}")
    else:
        console.print(f"  [bold green]CLEAN[/bold green]    {sha256}")
        console.print("  [dim]Not found on the confirmed ban-list.[/dim]")
    console.print()
    raise typer.Exit(1 if banned else 0)


@registry_app.command("ban-list")
def cmd_registry_ban_list(
    limit: int = typer.Option(20, "--limit", help="Maximum entries to show"),
    registry_url: str = typer.Option(None, "--registry-url"),
) -> None:
    """Show the confirmed ban-list."""
    rc = RegistryClient(base_url=registry_url) if registry_url else RegistryClient()
    try:
        entries = rc.get_ban_list(limit=limit)
    except RegistryRateLimitError:
        console.print("[red]Rate limited — try again later[/red]")
        raise typer.Exit(1)

    console.print()
    if not entries:
        console.print("[dim]  Ban-list is empty.[/dim]")
        console.print()
        return

    t = Table(title=f"Confirmed ban-list ({len(entries)} entries)", show_header=True)
    t.add_column("Hash (first 12)", style="red")
    t.add_column("Date", style="dim")
    t.add_column("Source", style="dim")
    t.add_column("Reason")
    for e in entries:
        t.add_row(e.sha256[:12] + "…", e.reported_at[:10], e.source, e.reason[:60])
    console.print(t)
    console.print()


@registry_app.command("status")
def cmd_registry_status(
    registry_url: str = typer.Option(None, "--registry-url"),
) -> None:
    """Check registry API health and version."""
    rc = RegistryClient(base_url=registry_url) if registry_url else RegistryClient()
    base = rc.base_url
    try:
        h = rc.health()
        ok = h.get('ok', False)
        version = h.get('version', 'unknown')
        console.print()
        console.print(f"  [dim]Registry:[/dim]  {base}")
        console.print(f"  [{'green' if ok else 'yellow'}]Status:[/{'green' if ok else 'yellow'}]    {'ok' if ok else 'degraded'}")
        console.print(f"  [dim]Version:[/dim]   {version}")
        console.print()
    except Exception as exc:
        console.print()
        console.print(f"  [dim]Registry:[/dim]  {base}")
        console.print(f"  [red]Status:[/red]    unreachable ({exc})")
        console.print()
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app()


if __name__ == "__main__":
    main()
