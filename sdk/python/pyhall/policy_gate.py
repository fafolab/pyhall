"""
pyhall/policy_gate.py — WCP Policy Gate (stub implementation).

The PolicyGate evaluates whether a capability request is permitted under
the active policy, and whether escalation or human review is required.

This stub allows by default. Replace the evaluate() method with your
own policy engine to implement real governance rules.

WCP compliance:
  - WCP-Basic: not required
  - WCP-Standard: must support evaluate() with ALLOW/DENY/REQUIRE_HUMAN
  - WCP-Full: policy_gate must integrate with privilege envelopes and
              blast radius gating
"""

from __future__ import annotations

from typing import Any, Dict, Tuple


class PolicyGate:
    """
    WCP Policy Gate.

    Evaluates a capability request context and returns a (decision, policy_version,
    reason) triple.

    To implement real governance, subclass PolicyGate and override evaluate():

        class MyPolicyGate(PolicyGate):
            def evaluate(self, context):
                if context["env"] == "prod" and context["data_label"] == "RESTRICTED":
                    return ("REQUIRE_HUMAN", "policy.v1", "restricted_data_in_prod")
                return ("ALLOW", "policy.v1", "default_allow")

    Then pass your instance to make_decision():

        gate = MyPolicyGate()
        decision = make_decision(inp, rules, ..., policy_gate_eval=gate.evaluate)
    """

    def evaluate(self, context: Dict[str, Any]) -> Tuple[str, str, str]:
        """
        Evaluate a routing context against the active policy.

        Args:
            context: Dict containing routing context fields:
                - capability_id
                - tenant_id
                - env
                - data_label
                - tenant_risk
                - qos_class
                - policy_version (current policy version string)

        Returns:
            Tuple of (decision, policy_version, reason) where:
                decision:       "ALLOW" | "DENY" | "REQUIRE_HUMAN"
                policy_version: the policy version string that was evaluated
                reason:         human-readable reason string
        """
        # Default stub: allow everything. Replace with real policy logic.
        policy_version = context.get("policy_version") or "policy.v0"
        return ("ALLOW", policy_version, "stub_allow")
