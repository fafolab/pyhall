"""
pyhall/telemetry.py — WCP telemetry envelope builders.

Every WCP dispatch MUST emit three minimum telemetry events (spec section 5.4):
  - evt.os.task.routed.v1
  - evt.os.worker.selected.v1
  - evt.os.policy.gated.v1

The correlation_id MUST be propagated through all three events.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def now_iso() -> str:
    """ISO 8601 UTC timestamp for telemetry events."""
    return datetime.now(timezone.utc).isoformat()


def new_decision_id() -> str:
    """Generate a unique decision ID (UUID v4)."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Required telemetry events (WCP spec section 5.4)
# ---------------------------------------------------------------------------

def os_task_routed(
    correlation_id: str,
    tenant_id: str,
    task_id: str,
    capability_id: str,
    matched_rule_id: str,
    selected_worker_species_id: Optional[str],
    policy_version: Optional[str],
    qos_class: str,
) -> Dict[str, Any]:
    """
    evt.os.task.routed.v1 — routing decision was made.

    Required for all WCP-Standard and WCP-Full implementations.
    """
    return {
        "event_id": "evt.os.task.routed",
        "timestamp": now_iso(),
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "task_id": task_id,
        "capability_id": capability_id,
        "matched_rule_id": matched_rule_id,
        "selected_worker_species_id": selected_worker_species_id,
        "policy_version": policy_version,
        "qos_class": qos_class,
    }


def os_worker_selected(
    correlation_id: str,
    tenant_id: str,
    capability_id: str,
    selected_worker_species_id: Optional[str],
    reason: str,
) -> Dict[str, Any]:
    """
    evt.os.worker.selected.v1 — worker species was selected.

    Required for all WCP-Standard and WCP-Full implementations.
    """
    return {
        "event_id": "evt.os.worker.selected",
        "timestamp": now_iso(),
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "capability_id": capability_id,
        "selected_worker_species_id": selected_worker_species_id,
        "reason": reason,
    }


def os_policy_gated(
    correlation_id: str,
    tenant_id: str,
    capability_id: str,
    decision: str,
    policy_version: Optional[str],
    reason: str,
) -> Dict[str, Any]:
    """
    evt.os.policy.gated.v1 — policy gate was evaluated.

    Required for all WCP-Standard and WCP-Full implementations.
    """
    return {
        "event_id": "evt.os.policy.gated",
        "timestamp": now_iso(),
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "capability_id": capability_id,
        "decision": decision,
        "policy_version": policy_version,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Denial telemetry (emitted on ALL deny paths — WCP §5.4)
# ---------------------------------------------------------------------------

def os_task_denied(
    correlation_id: str,
    tenant_id: str,
    capability_id: str,
    deny_code: str,
    deny_message: str,
    matched_rule_id: str = "PRE_ROUTING",
) -> Dict[str, Any]:
    """
    evt.os.task.denied — routing decision was DENIED.

    Emitted on every deny path so the audit trail captures attempted
    dispatches regardless of whether the caller logs the RouteDecision.
    """
    return {
        "event_id": "evt.os.task.denied",
        "timestamp": now_iso(),
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "capability_id": capability_id,
        "deny_code": deny_code,
        "deny_message": deny_message,
        "matched_rule_id": matched_rule_id,
    }


# ---------------------------------------------------------------------------
# Optional governance events (WCP-Full)
# ---------------------------------------------------------------------------

def gov_blast_scored(
    correlation_id: str,
    tenant_id: str,
    env: str,
    data_label: str,
    policy_version: str,
    blast_score: int,
    decision: str,
) -> Dict[str, Any]:
    """evt.gov.blast_scored.v1 — blast radius was computed and gated."""
    return {
        "event_id": "evt.gov.blast_scored",
        "timestamp": now_iso(),
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "env": env,
        "data_label": data_label,
        "policy_version": policy_version,
        "blast_score": blast_score,
        "decision": decision,
    }


def gov_privilege_envelope_checked(
    correlation_id: str,
    tenant_id: str,
    env: str,
    data_label: str,
    policy_version: str,
    worker_species_id: Optional[str],
    decision: str,
) -> Dict[str, Any]:
    """evt.gov.privilege_envelope.checked.v1 — privilege envelope was validated."""
    return {
        "event_id": "evt.gov.privilege_envelope.checked",
        "timestamp": now_iso(),
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "env": env,
        "data_label": data_label,
        "policy_version": policy_version,
        "worker_species_id": worker_species_id,
        "decision": decision,
    }
