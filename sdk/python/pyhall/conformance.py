"""
pyhall/conformance.py — WCP conformance validation.

Validates routing decisions against a conformance spec. Use this in CI
to ensure that routing rules produce decisions that meet WCP requirements.

Conformance spec JSON format:
    {
      "spec_version": "1.0",
      "decision_output_schema": {
        "required_fields": [
          "decision_id",
          "timestamp",
          "correlation_id",
          "capability_id",
          "matched_rule_id",
          "denied",
          "telemetry_envelopes"
        ]
      },
      "telemetry_requirements": {
        "required_events": [
          {
            "event": "evt.os.task.routed",
            "must_include_dimensions": [
              "correlation_id", "tenant_id", "capability_id", "qos_class"
            ]
          },
          {
            "event": "evt.os.worker.selected",
            "must_include_dimensions": ["correlation_id", "capability_id"]
          },
          {
            "event": "evt.os.policy.gated",
            "must_include_dimensions": ["correlation_id", "decision"]
          }
        ]
      }
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def load_conformance_spec(path: str | Path) -> Dict[str, Any]:
    """
    Load a conformance spec from a JSON file.

    Args:
        path: Path to the JSON conformance spec file.

    Returns:
        Parsed spec dict.
    """
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_required_fields(
    decision: Dict[str, Any],
    spec: Dict[str, Any],
) -> List[str]:
    """
    Validate that a RouteDecision dict contains all required fields.

    Args:
        decision: RouteDecision serialized as dict (model.model_dump()).
        spec:     Loaded conformance spec dict.

    Returns:
        List of missing field names. Empty list means compliant.
    """
    required = spec.get("decision_output_schema", {}).get("required_fields", [])
    return [f for f in required if f not in decision]


def validate_required_telemetry(
    telemetry_events: List[Dict[str, Any]],
    spec: Dict[str, Any],
) -> List[str]:
    """
    Validate that mandatory WCP telemetry events are present and complete.

    Per WCP spec section 5.4, every dispatch MUST emit:
      - evt.os.task.routed.v1
      - evt.os.worker.selected.v1
      - evt.os.policy.gated.v1

    Args:
        telemetry_events: List of telemetry dicts from RouteDecision.telemetry_envelopes.
        spec:             Loaded conformance spec dict.

    Returns:
        List of error strings. Empty list means compliant.
    """
    errors = []
    required = spec.get("telemetry_requirements", {}).get("required_events", [])

    by_event: Dict[str, List[Dict[str, Any]]] = {}
    for event in telemetry_events:
        by_event.setdefault(event.get("event_id"), []).append(event)

    for req in required:
        event_id = req["event"]
        must_dims = req.get("must_include_dimensions", [])

        if event_id not in by_event:
            errors.append(f"missing_required_event:{event_id}")
            continue

        # At least one instance must have all required dimensions
        satisfied = False
        for instance in by_event[event_id]:
            if all(k in instance and instance[k] is not None for k in must_dims):
                satisfied = True
                break
        if not satisfied:
            errors.append(f"event_missing_dimensions:{event_id}")

    return errors


def check_worker_compliance(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate a registry_record dict against WCP compliance levels.

    Returns a structured result dict with:
      - worker_id
      - worker_species_id
      - risk_tier
      - checks: per-criterion pass/fail details
      - levels: {basic, standard, full} each with {achieved, missing}
      - achieved_level: highest level achieved ("none"|"WCP-Basic"|"WCP-Standard"|"WCP-Full")
    """
    # -----------------------------------------------------------------------
    # WCP-Basic criteria
    # -----------------------------------------------------------------------
    # Required: worker_id, capabilities (non-empty), worker_species_id, risk_tier
    basic_checks: Dict[str, Any] = {}

    basic_checks["worker_id_present"] = {
        "label": "worker_id declared",
        "passed": bool(record.get("worker_id")),
    }
    caps = record.get("capabilities", [])
    basic_checks["capabilities_non_empty"] = {
        "label": "capabilities[] non-empty",
        "passed": bool(caps),
    }
    basic_checks["worker_species_id_present"] = {
        "label": "worker_species_id declared",
        "passed": bool(record.get("worker_species_id")),
    }
    risk_tier = record.get("risk_tier", "")
    basic_checks["risk_tier_present"] = {
        "label": "risk_tier declared",
        "passed": bool(risk_tier),
    }

    basic_passed = all(c["passed"] for c in basic_checks.values())
    basic_missing = [c["label"] for c in basic_checks.values() if not c["passed"]]

    # -----------------------------------------------------------------------
    # WCP-Standard criteria (requires Basic first)
    # -----------------------------------------------------------------------
    # Must have: required_controls[], currently_implements[], allowed_environments[]
    # Must declare at minimum: ctrl.obs.audit_log_append_only (or hyphen variant),
    #   ctrl.pol.default_deny (or similar)
    standard_checks: Dict[str, Any] = {}

    req_controls = record.get("required_controls", [])
    curr_impl = record.get("currently_implements", [])
    allowed_envs = record.get("allowed_environments", [])

    standard_checks["required_controls_declared"] = {
        "label": "required_controls[] declared",
        "passed": bool(req_controls),
    }
    standard_checks["currently_implements_declared"] = {
        "label": "currently_implements[] declared",
        "passed": bool(curr_impl),
    }
    standard_checks["allowed_environments_declared"] = {
        "label": "allowed_environments[] declared",
        "passed": bool(allowed_envs),
    }

    # Check for audit-log control (flexible matching — hyphens or underscores, prefix variations)
    def _has_control(controls: List[str], *fragments: str) -> bool:
        normalized = [c.lower().replace("-", "_").replace(".", "_") for c in controls]
        for frag in fragments:
            frag_n = frag.lower().replace("-", "_").replace(".", "_")
            if any(frag_n in c for c in normalized):
                return True
        return False

    all_controls = list(set(req_controls) | set(curr_impl))

    audit_log_ok = _has_control(all_controls, "audit_log", "audit-log", "ctrl_audit")
    standard_checks["ctrl_audit_log_declared"] = {
        "label": "ctrl.obs.audit_log_append_only (or equivalent) declared",
        "passed": audit_log_ok,
        "control_id": "ctrl.obs.audit_log_append_only",
    }

    default_deny_ok = _has_control(
        all_controls,
        "default_deny",
        "ctrl_pol_default_deny",
        "deny_default",
        "ctrl.pol.default_deny",
    )
    standard_checks["ctrl_default_deny_declared"] = {
        "label": "ctrl.pol.default_deny (or equivalent) declared",
        "passed": default_deny_ok,
        "control_id": "ctrl.pol.default_deny",
    }

    standard_passed = basic_passed and all(c["passed"] for c in standard_checks.values())
    standard_missing = [c["label"] for c in standard_checks.values() if not c["passed"]]

    # -----------------------------------------------------------------------
    # WCP-Full criteria (requires Standard first)
    # -----------------------------------------------------------------------
    # Must have: blast_radius{data,network,financial,time,reversibility},
    #   privilege_envelope{}, idempotency, artifact_hash
    full_checks: Dict[str, Any] = {}

    blast = record.get("blast_radius", {})
    blast_dims_required = ["data", "network", "financial", "time", "reversibility"]
    blast_dims_present = [d for d in blast_dims_required if d in blast]
    blast_ok = len(blast_dims_present) == len(blast_dims_required)
    full_checks["blast_radius_declared"] = {
        "label": "blast_radius declared (data,network,financial,time,reversibility)",
        "passed": blast_ok,
        "score": sum(
            int(v) if isinstance(v, (int, float)) else 0
            for k, v in blast.items()
            if k != "reversibility"
        ) if blast else None,
        "missing_dims": [d for d in blast_dims_required if d not in blast],
    }

    priv_env = record.get("privilege_envelope", {})
    full_checks["privilege_envelope_declared"] = {
        "label": "privilege_envelope declared",
        "passed": isinstance(priv_env, dict) and len(priv_env) > 0,
    }

    idempotency = record.get("idempotency", "")
    full_checks["idempotency_declared"] = {
        "label": "idempotency declared",
        "passed": bool(idempotency),
    }

    # artifact_hash: either the record itself has it, or currently_implements has evidence-receipts
    artifact_hash_ok = bool(record.get("artifact_hash")) or _has_control(
        all_controls, "artifact_hash", "evidence_receipt", "evidence-receipt"
    )
    full_checks["artifact_hash_declared"] = {
        "label": "artifact_hash or evidence_receipt control declared",
        "passed": artifact_hash_ok,
    }

    full_passed = standard_passed and all(c["passed"] for c in full_checks.values())
    full_missing = [c["label"] for c in full_checks.values() if not c["passed"]]

    # -----------------------------------------------------------------------
    # Achieved level
    # -----------------------------------------------------------------------
    if full_passed:
        achieved_level = "WCP-Full"
    elif standard_passed:
        achieved_level = "WCP-Standard"
    elif basic_passed:
        achieved_level = "WCP-Basic"
    else:
        achieved_level = "none"

    return {
        "worker_id": record.get("worker_id", "(unknown)"),
        "worker_species_id": record.get("worker_species_id", "(unknown)"),
        "risk_tier": risk_tier or "(undeclared)",
        "capabilities": caps,
        "currently_implements": curr_impl,
        "required_controls": req_controls,
        "blast_radius": blast,
        "privilege_envelope": priv_env,
        "idempotency": idempotency,
        "checks": {
            "basic": basic_checks,
            "standard": standard_checks,
            "full": full_checks,
        },
        "levels": {
            "basic": {"achieved": basic_passed, "missing": basic_missing},
            "standard": {"achieved": standard_passed, "missing": standard_missing},
            "full": {"achieved": full_passed, "missing": full_missing},
        },
        "achieved_level": achieved_level,
    }


def default_conformance_spec() -> Dict[str, Any]:
    """
    Return the default WCP conformance spec (WCP-Standard requirements).

    Use this when you don't have a custom spec file. Validates the three
    mandatory telemetry events and core decision fields.
    """
    return {
        "spec_version": "1.0",
        "decision_output_schema": {
            "required_fields": [
                "decision_id",
                "timestamp",
                "correlation_id",
                "tenant_id",
                "capability_id",
                "matched_rule_id",
                "denied",
                "telemetry_envelopes",
            ]
        },
        "telemetry_requirements": {
            "required_events": [
                {
                    "event": "evt.os.task.routed",
                    "must_include_dimensions": [
                        "correlation_id",
                        "tenant_id",
                        "capability_id",
                        "qos_class",
                    ],
                },
                {
                    "event": "evt.os.worker.selected",
                    "must_include_dimensions": [
                        "correlation_id",
                        "capability_id",
                    ],
                },
                {
                    "event": "evt.os.policy.gated",
                    "must_include_dimensions": [
                        "correlation_id",
                        "decision",
                    ],
                },
            ]
        },
    }
