"""
pyhall/rules.py — WCP routing rules engine.

Routing rules are declared in JSON. The router evaluates them top-to-bottom
and returns the first match (fail-closed on no match per WCP spec section 5.1).

Rule JSON format:
    {
      "rules": [
        {
          "rule_id": "rr_example_001",
          "match": {
            "capability_id": "cap.doc.summarize",
            "env": {"in": ["dev", "stage"]},
            "data_label": "INTERNAL",
            "tenant_risk": "low",
            "qos_class": {"in": ["P1", "P2"]}
          },
          "decision": {
            "candidate_workers_ranked": [
              {"worker_species_id": "wrk.doc.summarizer", "score_hint": 1.0}
            ],
            "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
            "recommended_profiles": [],
            "escalation": {"policy_gate": false, "human_required_default": false},
            "preconditions": {}
          }
        }
      ]
    }

Match fields support:
  - Exact match:       "data_label": "INTERNAL"
  - Membership match:  "env": {"in": ["dev", "stage"]}
  - Wildcard:          "capability_id": {"any": true}

Rules are evaluated top to bottom. First match wins.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Rule:
    """A single WCP routing rule."""

    rule_id: str
    """Unique rule identifier, e.g. 'rr_doc_summarize_dev_001'."""

    match: Dict[str, Any]
    """Match conditions. Keys: capability_id, env, data_label, tenant_risk, qos_class."""

    decision: Dict[str, Any]
    """Decision payload: candidate_workers_ranked, required_controls_suggested, etc."""


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _match_membership(cond: Any, value: Any) -> bool:
    """
    Evaluate a match condition against a value.

    Supports:
      - {"in": ["a", "b"]}  — membership test
      - {"any": true}       — wildcard (always matches)
      - "exact_value"       — equality
    """
    if isinstance(cond, dict):
        if cond.get("any") is True:
            return True
        if "in" in cond:
            return value in cond["in"]
    return value == cond


def rule_matches(rule: Rule, inp: Dict[str, Any]) -> bool:
    """
    Return True if a RouteInput (as dict) matches the given rule.

    Evaluates all match conditions. All must pass for a match.
    A missing condition key is treated as a wildcard (passes automatically).
    """
    m = rule.match or {}

    cap = m.get("capability_id")
    if cap is not None:
        if not _match_membership(cap, inp.get("capability_id")):
            return False

    for field in ("env", "data_label", "tenant_risk", "qos_class"):
        cond = m.get(field)
        if cond is None:
            continue
        if not _match_membership(cond, inp.get(field)):
            return False

    return True


def route_first_match(rules: List[Rule], inp: Dict[str, Any]) -> Optional[Rule]:
    """
    Return the first rule that matches inp, or None if no rule matches.

    Per WCP spec section 5.1 (Fail Closed): a None result MUST produce
    a denied routing decision. The router handles this; callers must not
    execute workers on a None return.
    """
    for rule in rules:
        if rule_matches(rule, inp):
            return rule
    return None


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def load_rules(seed_path: str | Path) -> List[Rule]:
    """
    Load routing rules from a JSON file.

    Args:
        seed_path: Path to a JSON file with a top-level "rules" array.

    Returns:
        List of Rule objects in declaration order.

    Raises:
        FileNotFoundError: if the file does not exist.
        KeyError: if the JSON is missing the "rules" key.
        json.JSONDecodeError: if the file is not valid JSON.
    """
    path = Path(seed_path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    rules = []
    for r in doc["rules"]:
        rules.append(
            Rule(
                rule_id=r["rule_id"],
                match=r.get("match", {}),
                decision=r.get("decision", {}),
            )
        )
    return rules


def load_rules_from_dict(doc: Dict[str, Any]) -> List[Rule]:
    """
    Load routing rules from an already-parsed dict (useful for testing).

    Args:
        doc: Dict with a top-level "rules" list.

    Returns:
        List of Rule objects.
    """
    rules = []
    for r in doc.get("rules", []):
        rules.append(
            Rule(
                rule_id=r["rule_id"],
                match=r.get("match", {}),
                decision=r.get("decision", {}),
            )
        )
    return rules
