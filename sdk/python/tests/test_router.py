"""
tests/test_router.py — PyHall core router test suite.

Tests WCP compliance:
  - Fail-closed on no matching rule
  - Deterministic routing
  - Controls enforcement
  - Blast radius gating
  - Policy gate integration
  - Mandatory telemetry emission
  - Correlation ID enforcement
  - Dry-run mode
"""

from __future__ import annotations

import uuid
import pytest

from pyhall import make_decision, RouteInput, Registry, PolicyGate, load_rules_from_dict
from pyhall.conformance import default_conformance_spec
from pyhall.rules import Rule, route_first_match


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _corr() -> str:
    return str(uuid.uuid4())


def _inp(**kwargs) -> RouteInput:
    """Build a minimal valid RouteInput with sane defaults."""
    defaults = dict(
        capability_id="cap.hello.greet",
        env="dev",
        data_label="PUBLIC",
        tenant_risk="low",
        qos_class="P2",
        tenant_id="test-tenant",
        correlation_id=_corr(),
    )
    defaults.update(kwargs)
    return RouteInput(**defaults)


HELLO_RULES_DOC = {
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
                "escalation": {
                    "policy_gate": False,
                    "human_required_default": False,
                },
                "preconditions": {},
            },
        },
        {
            "rule_id": "rr_hello_prod_001",
            "match": {
                "capability_id": "cap.hello.greet",
                "env": "prod",
                "data_label": {"in": ["PUBLIC", "INTERNAL"]},
            },
            "decision": {
                "candidate_workers_ranked": [
                    {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0}
                ],
                "required_controls_suggested": [
                    "ctrl.obs.audit-log-append-only",
                    "ctrl.blast_radius_scoring",
                ],
                "escalation": {
                    "policy_gate": True,
                    "human_required_default": False,
                },
                "preconditions": {},
            },
        },
        {
            "rule_id": "rr_default_deny",
            "match": {"capability_id": {"any": True}},
            "decision": {
                "candidate_workers_ranked": [],
                "required_controls_suggested": [],
                "escalation": {},
                "preconditions": {},
            },
        },
    ]
}


def _registry_with_worker(species: str = "wrk.hello.greeter") -> Registry:
    registry = Registry()
    registry.enroll({
        "worker_id": "org.test.hello-greeter",
        "worker_species_id": species,
        "capabilities": ["cap.hello.greet"],
        "currently_implements": ["ctrl.obs.audit-log-append-only"],
    })
    return registry


# ---------------------------------------------------------------------------
# WCP 5.1 — Fail Closed
# ---------------------------------------------------------------------------

class TestFailClosed:
    def test_no_rules_denies(self):
        """When rules list is empty, must deny."""
        registry = Registry()
        inp = _inp()
        dec = make_decision(
            inp=inp,
            rules=[],
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is True
        assert dec.matched_rule_id == "NO_MATCH"
        assert dec.deny_reason_if_denied["code"] == "DENY_NO_MATCHING_RULE"

    def test_unknown_capability_denies(self):
        """Unknown capability with no catch-all rule must deny."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])
        inp = _inp(capability_id="cap.does.not.exist")

        # Remove the default catch-all to get a true NO_MATCH
        filtered_rules = [r for r in rules if r.rule_id != "rr_default_deny"]
        dec = make_decision(
            inp=inp,
            rules=filtered_rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is True
        assert dec.matched_rule_id == "NO_MATCH"


# ---------------------------------------------------------------------------
# WCP 5.2 — Deterministic Routing
# ---------------------------------------------------------------------------

class TestDeterministicRouting:
    def test_identical_inputs_produce_identical_rule(self):
        """Same inputs must match the same rule every time."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        corr = _corr()
        results = []
        for _ in range(10):
            inp = RouteInput(
                capability_id="cap.hello.greet",
                env="dev",
                data_label="PUBLIC",
                tenant_risk="low",
                qos_class="P2",
                tenant_id="test-tenant",
                correlation_id=corr,
            )
            dec = make_decision(
                inp=inp,
                rules=rules,
                registry_controls_present=registry.controls_present(),
                registry_worker_available=registry.worker_available,
            )
            results.append(dec.matched_rule_id)

        assert len(set(results)) == 1, "Routing must be deterministic"
        assert results[0] == "rr_hello_dev_001"

    def test_env_routes_correct_rule(self):
        """dev vs prod routes to different rules."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.blast_radius_scoring",
        ])
        gate = PolicyGate()

        dev_inp = _inp(env="dev")
        prod_inp = _inp(env="prod", data_label="PUBLIC")

        dev_dec = make_decision(
            inp=dev_inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            policy_gate_eval=gate.evaluate,
        )
        prod_dec = make_decision(
            inp=prod_inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            policy_gate_eval=gate.evaluate,
        )

        assert dev_dec.matched_rule_id == "rr_hello_dev_001"
        assert prod_dec.matched_rule_id == "rr_hello_prod_001"


# ---------------------------------------------------------------------------
# WCP 5.3 — Declared Controls Enforcement
# ---------------------------------------------------------------------------

class TestControlsEnforcement:
    def test_missing_controls_denies(self):
        """Missing required controls must produce a deny."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = Registry()
        registry.set_workers_available(["wrk.hello.greeter"])
        # No controls registered — should deny

        inp = _inp(env="dev")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_MISSING_REQUIRED_CONTROLS"
        assert "ctrl.obs.audit-log-append-only" in dec.deny_reason_if_denied["missing"]

    def test_present_controls_allows(self):
        """When required controls are present, routing proceeds."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="dev")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is False
        assert dec.selected_worker_species_id == "wrk.hello.greeter"


# ---------------------------------------------------------------------------
# WCP 5.4 — Mandatory Telemetry
# ---------------------------------------------------------------------------

class TestMandatoryTelemetry:
    def test_three_mandatory_events_emitted(self):
        """Every successful dispatch must emit the three mandatory events."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="dev")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        event_ids = {e["event_id"] for e in dec.telemetry_envelopes}
        assert "evt.os.task.routed" in event_ids
        assert "evt.os.worker.selected" in event_ids
        assert "evt.os.policy.gated" in event_ids

    def test_correlation_id_propagated_in_all_events(self):
        """correlation_id must appear in all telemetry events."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        corr = _corr()
        inp = _inp(env="dev", correlation_id=corr)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        for event in dec.telemetry_envelopes:
            assert event.get("correlation_id") == corr, (
                f"correlation_id missing from {event['event_id']}"
            )

    def test_telemetry_emitted_even_on_deny(self):
        """Denied decisions do not emit mandatory telemetry (no selected worker)."""
        # This verifies the deny path does not raise and returns a valid model
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = Registry()

        inp = _inp(env="dev")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is True
        # No exception — decision is always a valid RouteDecision


# ---------------------------------------------------------------------------
# WCP Correlation ID Enforcement
# ---------------------------------------------------------------------------

class TestCorrelationIdEnforcement:
    def test_empty_correlation_id_denies(self):
        """Empty correlation_id must be denied per preconditions."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="dev", correlation_id="   ")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_MISSING_CORRELATION_ID"


# ---------------------------------------------------------------------------
# Blast Radius Gating
# ---------------------------------------------------------------------------

class TestBlastRadius:
    def test_high_blast_score_in_prod_denies(self):
        """blast_score >= 85 in prod must require human review."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.blast_radius_scoring",
        ])
        gate = PolicyGate()

        # Use data_label="PUBLIC" so the request matches rr_hello_prod_001
        # which requires ctrl.blast_radius_scoring.v1, triggering the blast gate.
        inp = _inp(
            env="prod",
            data_label="PUBLIC",
            blast_score=90,  # pre-computed high score — above the 85 threshold
        )
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            policy_gate_eval=gate.evaluate,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_REQUIRES_HUMAN"

    def test_low_blast_score_in_prod_allows(self):
        """Low blast_score in prod must pass the blast gate."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.blast_radius_scoring",
        ])
        gate = PolicyGate()

        inp = _inp(
            env="prod",
            data_label="PUBLIC",
            blast_score=10,
        )
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            policy_gate_eval=gate.evaluate,
        )
        assert dec.denied is False
        assert dec.selected_worker_species_id == "wrk.hello.greeter"


# ---------------------------------------------------------------------------
# Policy Gate
# ---------------------------------------------------------------------------

class TestPolicyGate:
    def test_policy_gate_deny_blocks_dispatch(self):
        """A DENY from policy gate must produce a denied decision."""

        class DenyGate(PolicyGate):
            def evaluate(self, context):
                return ("DENY", "policy.v1", "test_always_deny")

        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.blast_radius_scoring",
        ])

        inp = _inp(env="prod", data_label="PUBLIC")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            policy_gate_eval=DenyGate().evaluate,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_POLICY_GATE"

    def test_policy_gate_required_but_not_provided_raises(self):
        """If policy_gate is required but no evaluator provided, must deny (fail closed, not raise)."""
        # F11 fix: make_decision() now fails closed with DENY_POLICY_GATE_UNCONFIGURED
        # instead of raising RuntimeError, preserving the "never raises" contract.
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.blast_radius_scoring",
        ])

        inp = _inp(env="prod", data_label="PUBLIC")
        dec = make_decision(
            inp=inp, rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_POLICY_GATE_UNCONFIGURED"
        assert len(dec.telemetry_envelopes) > 0  # telemetry emitted even on this deny


# ---------------------------------------------------------------------------
# No Available Worker
# ---------------------------------------------------------------------------

class TestNoAvailableWorker:
    def test_no_available_worker_denies(self):
        """When all worker candidates are unavailable, must deny."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = Registry()
        # Controls present but no workers enrolled
        registry.set_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="dev")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_NO_AVAILABLE_WORKER"


# ---------------------------------------------------------------------------
# Conformance spec
# ---------------------------------------------------------------------------

class TestConformance:
    def test_successful_decision_passes_default_spec(self):
        """A successful routing decision must pass WCP default conformance."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])
        spec = default_conformance_spec()

        inp = _inp(env="dev")
        # Should not raise
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            conformance_spec=spec,
        )
        assert dec.denied is False


# ---------------------------------------------------------------------------
# Registry enrollment
# ---------------------------------------------------------------------------

class TestRegistryEnrollment:
    def test_enroll_worker_makes_it_available(self):
        """Enrolling a worker record makes its species available."""
        registry = Registry()
        registry.enroll({
            "worker_id": "org.test.my-worker",
            "worker_species_id": "wrk.test.doer",
            "capabilities": ["cap.test.do"],
            "currently_implements": ["ctrl.obs.audit-log-append-only"],
        })
        assert registry.worker_available("wrk.test.doer")
        assert "cap.test.do" in registry.summary()["capabilities_mapped"]
        assert "ctrl.obs.audit-log-append-only" in registry.controls_present()

    def test_workers_for_capability(self):
        """Registry returns correct workers for a capability."""
        registry = Registry()
        registry.enroll({
            "worker_id": "org.test.w1",
            "worker_species_id": "wrk.doc.summarizer",
            "capabilities": ["cap.doc.summarize"],
            "currently_implements": [],
        })
        workers = registry.workers_for_capability("cap.doc.summarize")
        assert "wrk.doc.summarizer" in workers


# ---------------------------------------------------------------------------
# Rules engine
# ---------------------------------------------------------------------------

class TestRulesEngine:
    def test_membership_match(self):
        """{'in': [...]} match syntax works."""
        rule = Rule(
            rule_id="rr_test",
            match={"capability_id": "cap.x", "env": {"in": ["dev", "stage"]}},
            decision={},
        )
        assert route_first_match([rule], {"capability_id": "cap.x", "env": "dev"}) is rule
        assert route_first_match([rule], {"capability_id": "cap.x", "env": "prod"}) is None

    def test_wildcard_match(self):
        """{'any': true} matches any value."""
        rule = Rule(
            rule_id="rr_catch_all",
            match={"capability_id": {"any": True}},
            decision={},
        )
        for cap in ["cap.doc.summarize", "cap.mem.retrieve", "anything"]:
            assert route_first_match([rule], {"capability_id": cap}) is rule

    def test_first_match_wins(self):
        """First matching rule wins; later rules are not evaluated."""
        rules = [
            Rule("rr_first", match={"capability_id": "cap.x"}, decision={}),
            Rule("rr_second", match={"capability_id": "cap.x"}, decision={}),
        ]
        matched = route_first_match(rules, {"capability_id": "cap.x"})
        assert matched is not None
        assert matched.rule_id == "rr_first"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

class TestProvenance:
    def test_artifact_hash_present_on_approved_decision(self):
        """Every approved decision must include artifact_hash (SHA-256 of RouteInput)."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="dev")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is False
        assert dec.artifact_hash is not None
        assert len(dec.artifact_hash) == 64, "SHA-256 hex digest must be 64 characters"
        assert all(c in "0123456789abcdef" for c in dec.artifact_hash), (
            "artifact_hash must be a lowercase hex string"
        )

    def test_artifact_hash_is_deterministic(self):
        """Same RouteInput must produce the same artifact_hash every time."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        corr = _corr()
        hashes = []
        for _ in range(5):
            inp = RouteInput(
                capability_id="cap.hello.greet",
                env="dev",
                data_label="PUBLIC",
                tenant_risk="low",
                qos_class="P2",
                tenant_id="test-tenant",
                correlation_id=corr,
            )
            dec = make_decision(
                inp=inp,
                rules=rules,
                registry_controls_present=registry.controls_present(),
                registry_worker_available=registry.worker_available,
            )
            hashes.append(dec.artifact_hash)

        assert len(set(hashes)) == 1, "artifact_hash must be deterministic for identical inputs"


# ---------------------------------------------------------------------------
# Signatory Tenant (WCP §5.9)
# ---------------------------------------------------------------------------

class TestSignatoryTenant:
    """HallConfig.require_signatory enforcement tests."""

    def _make_decision_with_config(self, tenant_id: str, allowed: list[str], require: bool):
        from pyhall import HallConfig
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])
        inp = RouteInput(
            capability_id="cap.hello.greet",
            env="dev",
            data_label="PUBLIC",
            tenant_risk="low",
            qos_class="P2",
            tenant_id=tenant_id,
            correlation_id=_corr(),
        )
        cfg = HallConfig(require_signatory=require, allowed_tenants=allowed)
        return make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
        )

    def test_require_signatory_false_allows_any_tenant(self):
        """When require_signatory is False, any tenant_id is accepted."""
        dec = self._make_decision_with_config("unknown-tenant", allowed=[], require=False)
        assert dec.denied is False

    def test_require_signatory_true_allows_registered_tenant(self):
        """Registered tenant passes when require_signatory is True."""
        dec = self._make_decision_with_config(
            "mcp.my-app", allowed=["mcp.my-app", "agent.orch"], require=True
        )
        assert dec.denied is False

    def test_require_signatory_true_denies_unknown_tenant(self):
        """Unknown tenant is denied with DENY_UNKNOWN_TENANT when require_signatory is True."""
        dec = self._make_decision_with_config(
            "rogue.agent", allowed=["mcp.my-app"], require=True
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_UNKNOWN_TENANT"
        assert dec.deny_reason_if_denied["tenant_id"] == "rogue.agent"

    def test_no_hall_config_allows_any_tenant(self):
        """When hall_config is None (default), any tenant is accepted."""
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])
        inp = RouteInput(
            capability_id="cap.hello.greet",
            env="dev",
            data_label="PUBLIC",
            tenant_risk="low",
            qos_class="P2",
            tenant_id="whoever",
            correlation_id=_corr(),
        )
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )
        assert dec.denied is False


# ---------------------------------------------------------------------------
# Worker Code Attestation (WCP §5.10)
# ---------------------------------------------------------------------------

class TestWorkerCodeAttestation:
    """HallConfig.require_worker_attestation enforcement tests."""

    GOOD_HASH = "a3f9c2" * 10 + "a3f9"  # 64-char hex stand-in
    BAD_HASH  = "7b2c91" * 10 + "7b2c"

    def _base(self):
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])
        inp = RouteInput(
            capability_id="cap.hello.greet",
            env="dev",
            data_label="PUBLIC",
            tenant_risk="low",
            qos_class="P2",
            tenant_id="test-tenant",
            correlation_id=_corr(),
        )
        return rules, registry, inp

    def test_attestation_disabled_passes_with_no_hash(self):
        """When require_worker_attestation is False, no hash check occurs."""
        from pyhall import HallConfig
        rules, registry, inp = self._base()
        cfg = HallConfig(require_worker_attestation=False)
        dec = make_decision(
            inp=inp, rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
        )
        assert dec.denied is False
        assert dec.worker_attestation_checked is False

    def test_attestation_enabled_matching_hash_passes(self):
        """Matching registered hash → attestation_valid True, dispatch proceeds."""
        from pyhall import HallConfig
        rules, registry, inp = self._base()
        cfg = HallConfig(require_worker_attestation=True)
        dec = make_decision(
            inp=inp, rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
            registry_get_worker_hash=lambda wid: self.GOOD_HASH,
            get_current_worker_hash=lambda wid: self.GOOD_HASH,
        )
        assert dec.denied is False
        assert dec.worker_attestation_checked is True
        assert dec.worker_attestation_valid is True

    def test_attestation_enabled_mismatched_hash_denied(self):
        """Mismatched hash → DENY_WORKER_TAMPERED."""
        from pyhall import HallConfig
        rules, registry, inp = self._base()
        cfg = HallConfig(require_worker_attestation=True)
        dec = make_decision(
            inp=inp, rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
            registry_get_worker_hash=lambda wid: self.GOOD_HASH,
            get_current_worker_hash=lambda wid: self.BAD_HASH,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_WORKER_TAMPERED"
        assert dec.worker_attestation_checked is True
        assert dec.worker_attestation_valid is False

    def test_attestation_no_registered_hash_denied(self):
        """Worker with no registered hash → DENY_WORKER_ATTESTATION_MISSING."""
        from pyhall import HallConfig
        rules, registry, inp = self._base()
        cfg = HallConfig(require_worker_attestation=True)
        dec = make_decision(
            inp=inp, rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
            registry_get_worker_hash=lambda wid: None,
            get_current_worker_hash=lambda wid: self.GOOD_HASH,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_WORKER_ATTESTATION_MISSING"

    def test_attestation_required_both_callables_none_denied(self):
        """R5: require_worker_attestation=True with both callables omitted → DENY_ATTESTATION_UNCONFIGURED.

        Previously silently passed because the None guard only fired at Step 6.5,
        which was entered only when selected is not None — but the guard itself
        must still fire when the callables are absent (the callable parameter is None,
        not a callable that returns None).
        """
        from pyhall import HallConfig
        rules, registry, inp = self._base()
        cfg = HallConfig(require_worker_attestation=True)
        dec = make_decision(
            inp=inp, rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
            # registry_get_worker_hash omitted → defaults to None
            # get_current_worker_hash omitted → defaults to None
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_ATTESTATION_UNCONFIGURED"

    def test_attestation_required_only_registry_callable_none_denied(self):
        """R5 partial: registry callable None, current callable provided → DENY_ATTESTATION_UNCONFIGURED."""
        from pyhall import HallConfig
        rules, registry, inp = self._base()
        cfg = HallConfig(require_worker_attestation=True)
        dec = make_decision(
            inp=inp, rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
            # registry_get_worker_hash omitted → None
            get_current_worker_hash=lambda wid: self.GOOD_HASH,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_ATTESTATION_UNCONFIGURED"

    def test_attestation_required_only_current_callable_none_denied(self):
        """R5 partial: current callable None, registry callable provided → DENY_ATTESTATION_UNCONFIGURED."""
        from pyhall import HallConfig
        rules, registry, inp = self._base()
        cfg = HallConfig(require_worker_attestation=True)
        dec = make_decision(
            inp=inp, rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
            registry_get_worker_hash=lambda wid: self.GOOD_HASH,
            # get_current_worker_hash omitted → None
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_ATTESTATION_UNCONFIGURED"


# ---------------------------------------------------------------------------
# Registry attestation methods (WCP §5.10)
# ---------------------------------------------------------------------------

class TestRegistryAttestation:
    """Unit tests for Registry's native worker code attestation support."""

    def test_register_attestation_returns_sha256_hex(self, tmp_path):
        """register_attestation() hashes the file and stores the result."""
        worker_file = tmp_path / "my_worker.py"
        worker_file.write_text("def run(): pass\n")

        registry = Registry()
        digest = registry.register_attestation("wrk.test.worker", str(worker_file))

        assert len(digest) == 64
        assert digest == digest.lower()
        assert all(c in "0123456789abcdef" for c in digest)
        assert registry.get_worker_hash("wrk.test.worker") == digest

    def test_register_attestation_raises_on_missing_file(self):
        """register_attestation() raises FileNotFoundError for missing files."""
        registry = Registry()
        with pytest.raises(FileNotFoundError):
            registry.register_attestation("wrk.test.missing", "/nonexistent/path/worker.py")

    def test_get_worker_hash_returns_none_for_unknown_species(self):
        """get_worker_hash() returns None when species has no registered hash."""
        registry = Registry()
        assert registry.get_worker_hash("wrk.unknown.species") is None

    def test_compute_current_hash_returns_live_digest(self, tmp_path):
        """compute_current_hash() reads the file from disk and returns its SHA-256."""
        worker_file = tmp_path / "worker.py"
        worker_file.write_bytes(b"original content")

        registry = Registry()
        registry.register_attestation("wrk.test.live", str(worker_file))
        initial = registry.get_worker_hash("wrk.test.live")

        # File unchanged — live hash must match registered hash
        current = registry.compute_current_hash("wrk.test.live")
        assert current == initial

    def test_compute_current_hash_detects_file_modification(self, tmp_path):
        """compute_current_hash() reflects runtime file changes (bypasses import cache)."""
        worker_file = tmp_path / "worker.py"
        worker_file.write_bytes(b"original content")

        registry = Registry()
        registry.register_attestation("wrk.test.tamper", str(worker_file))
        registered = registry.get_worker_hash("wrk.test.tamper")

        # Simulate attacker modifying the worker after enrollment
        worker_file.write_bytes(b"TAMPERED content - exfil data here")

        current = registry.compute_current_hash("wrk.test.tamper")
        assert current != registered

    def test_compute_current_hash_returns_none_for_unknown_species(self):
        """compute_current_hash() returns None when species has no registered file path."""
        registry = Registry()
        assert registry.compute_current_hash("wrk.unknown.species") is None

    def test_attestation_callables_returns_correct_pair(self, tmp_path):
        """attestation_callables() returns (get_worker_hash, compute_current_hash) tuple."""
        worker_file = tmp_path / "worker.py"
        worker_file.write_bytes(b"def run(): return 42")

        registry = Registry()
        registry.register_attestation("wrk.test.callable", str(worker_file))

        reg_hash_fn, cur_hash_fn = registry.attestation_callables()

        registered = reg_hash_fn("wrk.test.callable")
        current = cur_hash_fn("wrk.test.callable")

        assert registered is not None
        assert len(registered) == 64
        assert registered == current  # file not modified

    def test_enroll_parses_attestation_block(self, tmp_path):
        """enroll() reads code_hash and source_file from the attestation block."""
        worker_file = tmp_path / "enrolled_worker.py"
        worker_file.write_bytes(b"def run(): pass")

        import hashlib
        expected_hash = hashlib.sha256(b"def run(): pass").hexdigest()

        registry = Registry()
        registry.enroll({
            "worker_id": "org.test.enrolled",
            "worker_species_id": "wrk.test.enrolled",
            "capabilities": ["cap.test.enrolled"],
            "currently_implements": [],
            "attestation": {
                "code_hash": expected_hash,
                "hash_method": "sha256",
                "source_file": str(worker_file),
            },
        })

        assert registry.get_worker_hash("wrk.test.enrolled") == expected_hash
        assert registry.compute_current_hash("wrk.test.enrolled") == expected_hash


# ---------------------------------------------------------------------------
# Round 3 Security Fixes — F18 through F29
# ---------------------------------------------------------------------------

class TestRound3Fixes:
    """Tests covering F18–F29 security fixes."""

    # --- F18: Blast gate Hall-level floor ---

    def test_f18_blast_gate_enforced_even_without_control_in_rule(self):
        """
        F18: When enforce_blast_scoring_in_prod=True (default), a prod request
        with a high blast score must be denied even if the matched rule does NOT
        include ctrl.blast_radius_scoring in required_controls.
        """
        from pyhall import HallConfig
        # Rule with NO blast control in required_controls
        rules_doc = {
            "rules": [
                {
                    "rule_id": "rr_no_blast_control",
                    "match": {"capability_id": "cap.hello.greet"},
                    "decision": {
                        "candidate_workers_ranked": [
                            {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0}
                        ],
                        "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                        "escalation": {"policy_gate": False},
                        "preconditions": {},
                    },
                }
            ]
        }
        rules = load_rules_from_dict(rules_doc)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        # enforce_blast_scoring_in_prod=True is the default — Hall enforces blast in prod
        cfg = HallConfig(enforce_blast_scoring_in_prod=True)
        inp = _inp(env="prod", data_label="RESTRICTED", blast_score=90)

        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_REQUIRES_HUMAN"

    def test_f18_blast_gate_floor_can_be_disabled_for_testing(self):
        """
        F18: Setting enforce_blast_scoring_in_prod=False disables the Hall-level
        floor so rules without the blast control bypass the gate (test-only).
        """
        from pyhall import HallConfig
        rules_doc = {
            "rules": [
                {
                    "rule_id": "rr_no_blast_control",
                    "match": {"capability_id": "cap.hello.greet"},
                    "decision": {
                        "candidate_workers_ranked": [
                            {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0}
                        ],
                        "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                        "escalation": {"policy_gate": False},
                        "preconditions": {},
                    },
                }
            ]
        }
        rules = load_rules_from_dict(rules_doc)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        # Floor disabled — high blast score does NOT trigger denial
        cfg = HallConfig(enforce_blast_scoring_in_prod=False)
        inp = _inp(env="prod", data_label="RESTRICTED", blast_score=90)

        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
        )
        assert dec.denied is False

    # --- F19: Privilege envelope Hall-level floor ---

    def test_f19_privilege_envelope_enforced_without_control_in_rule(self):
        """
        F19: When enforce_privilege_envelopes=True, privilege envelope check
        is applied even if the matched rule does not include
        ctrl.privilege_envelopes_required.
        """
        from pyhall import HallConfig
        rules_doc = {
            "rules": [
                {
                    "rule_id": "rr_no_priv_control",
                    "match": {"capability_id": "cap.hello.greet"},
                    "decision": {
                        "candidate_workers_ranked": [
                            {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0}
                        ],
                        "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                        "escalation": {"policy_gate": False},
                        "preconditions": {},
                    },
                }
            ]
        }
        rules = load_rules_from_dict(rules_doc)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        cfg = HallConfig(enforce_privilege_envelopes=True)
        inp = _inp(env="dev")

        # No privilege callables provided — must deny (same as unconfigured path)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=cfg,
        )
        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_PRIVILEGE_ENVELOPE_UNCONFIGURED"

    # --- F21: require_credential warning ---

    def test_f21_require_credential_emits_warning(self):
        """
        F21: HallConfig(require_credential=True) must emit a UserWarning because
        the flag has no enforcement effect in v0.1.
        """
        from pyhall import HallConfig
        import warnings
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        cfg = HallConfig(require_credential=True)
        inp = _inp(env="dev")

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            dec = make_decision(
                inp=inp,
                rules=rules,
                registry_controls_present=registry.controls_present(),
                registry_worker_available=registry.worker_available,
                hall_config=cfg,
            )

        assert dec.denied is False  # request still proceeds
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) >= 1
        assert "require_credential" in str(user_warnings[0].message)
        assert "v0.1" in str(user_warnings[0].message)

    # --- F22: skip_reason misattribution ---

    def test_f22_second_available_worker_skip_reason_is_already_selected(self):
        """
        F22: When a second available worker is skipped because the first was
        already selected, its skip_reason must be 'already_selected', not 'unavailable'.
        """
        rules_doc = {
            "rules": [
                {
                    "rule_id": "rr_two_candidates",
                    "match": {"capability_id": "cap.hello.greet"},
                    "decision": {
                        "candidate_workers_ranked": [
                            {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0},
                            {"worker_species_id": "wrk.hello.backup", "score_hint": 0.5},
                        ],
                        "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                        "escalation": {"policy_gate": False},
                        "preconditions": {},
                    },
                }
            ]
        }
        rules = load_rules_from_dict(rules_doc)
        registry = Registry()
        # Both workers are available
        registry.set_workers_available(["wrk.hello.greeter", "wrk.hello.backup"])
        registry.set_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="dev")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            hall_config=None,
        )

        assert dec.denied is False
        assert dec.selected_worker_species_id == "wrk.hello.greeter"

        # The second candidate was available but not selected
        candidates = dec.candidate_workers_ranked
        backup = next(c for c in candidates if c.worker_species_id == "wrk.hello.backup")
        assert backup.skip_reason == "already_selected", (
            f"Expected 'already_selected', got {backup.skip_reason!r}"
        )

    # --- F23: Policy gate exception leaks class name ---

    def test_f23_policy_gate_exception_message_has_no_class_name(self):
        """
        F23: When policy_gate_eval raises, the deny message must NOT contain
        the exception class name (information leakage).
        """
        def leaky_gate(ctx):
            raise ValueError("internal detail that should not escape")

        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.blast_radius_scoring",
        ])

        inp = _inp(env="prod", data_label="PUBLIC", blast_score=10)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            policy_gate_eval=leaky_gate,
        )

        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_INTERNAL_ERROR"
        deny_msg = dec.deny_reason_if_denied["message"]
        assert "ValueError" not in deny_msg, (
            f"Exception class name leaked into deny message: {deny_msg!r}"
        )

    # --- F25: bool rejected for blast_score ---

    def test_f25_bool_blast_score_raises_validation_error(self):
        """
        F25: Passing blast_score=True or blast_score=False must raise a
        Pydantic ValidationError at model construction time, not silently
        accept True as 1 or False as 0.
        """
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="blast_score"):
            RouteInput(
                capability_id="cap.hello.greet",
                env="dev",
                data_label="PUBLIC",
                tenant_risk="low",
                qos_class="P2",
                tenant_id="test",
                correlation_id=_corr(),
                blast_score=True,  # bool is NOT a valid blast_score
            )

    # --- F26: Log injection via control characters ---

    def test_f26_control_characters_stripped_from_telemetry_correlation_id(self):
        """
        F26: A correlation_id containing newline/control characters must be
        sanitized before appearing in telemetry envelopes.
        """
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        # Inject a newline into correlation_id — the \n is the log injection vector.
        # _sanitize_id strips the control character (the newline), which is the defense.
        # The remaining text is concatenated without the separator as an artifact of stripping.
        malicious_corr = "tenant-id\nINJECTED_LOG_LINE"
        inp = _inp(env="dev", correlation_id=malicious_corr)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is False
        for event in dec.telemetry_envelopes:
            corr_in_event = event.get("correlation_id", "")
            # The newline (the log injection vector) must be stripped
            assert "\n" not in corr_in_event, (
                f"Newline found in telemetry correlation_id: {corr_in_event!r}"
            )
            # No other control characters present
            import re as _re
            assert not _re.search(r'[\x00-\x1f\x7f]', corr_in_event), (
                f"Control characters found in telemetry correlation_id: {corr_in_event!r}"
            )

    # --- F27: startswith prefix collision in registry ---

    def test_f27_path_prefix_collision_rejected(self):
        """
        F27: /tmp/workers_evil/ must NOT be allowed when the allowlist contains
        /tmp/workers — the old startswith() check would incorrectly allow this.
        """
        registry = Registry()
        registry.set_allowed_worker_dirs(["/tmp/workers"])

        from pathlib import Path
        evil_path = Path("/tmp/workers_evil/bad_worker.py")
        assert not registry._is_path_allowed(evil_path), (
            "Path /tmp/workers_evil/bad_worker.py should NOT be allowed by /tmp/workers allowlist"
        )

    def test_f27_exact_dir_and_subdirs_allowed(self):
        """
        F27: Paths directly in or under /tmp/workers must still be allowed
        after the prefix collision fix.
        """
        registry = Registry()
        registry.set_allowed_worker_dirs(["/tmp/workers"])

        from pathlib import Path
        # Direct child
        assert registry._is_path_allowed(Path("/tmp/workers/my_worker.py")), (
            "/tmp/workers/my_worker.py should be allowed"
        )
        # Nested subdirectory
        assert registry._is_path_allowed(Path("/tmp/workers/sub/deep_worker.py")), (
            "/tmp/workers/sub/deep_worker.py should be allowed"
        )

    # --- F28: Dry-run telemetry pollution ---

    def test_f28_dry_run_telemetry_has_dry_run_marker(self):
        """
        F28: When dry_run=True, every telemetry envelope in the decision must
        contain 'dry_run': True so audit consumers can distinguish probes.
        """
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="dev", dry_run=True)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is False
        assert dec.dry_run is True
        assert len(dec.telemetry_envelopes) > 0
        for event in dec.telemetry_envelopes:
            assert event.get("dry_run") is True, (
                f"Telemetry event missing dry_run=True: {event.get('event_id', event.get('event'))!r}"
            )

    # --- F29: detect_shadow_rules utility ---

    def test_f29_detect_shadow_rules_broad_before_specific(self):
        """
        F29: detect_shadow_rules() must detect a broad rule that shadows a
        more specific rule appearing later in the list.
        """
        from pyhall import detect_shadow_rules
        from pyhall.rules import Rule

        # broad_rule matches cap.hello.greet for any env
        broad_rule = Rule(
            rule_id="rr_broad",
            match={"capability_id": "cap.hello.greet"},
            decision={},
        )
        # specific_rule has the same capability_id PLUS env=prod — more specific
        # but broad_rule appears first and will always match first
        specific_rule = Rule(
            rule_id="rr_specific",
            match={"capability_id": "cap.hello.greet", "env": "prod"},
            decision={},
        )

        warnings_found = detect_shadow_rules([broad_rule, specific_rule])
        assert len(warnings_found) >= 1
        shadowers = [w["shadower"] for w in warnings_found]
        assert "rr_broad" in shadowers, (
            f"Expected rr_broad to be flagged as shadower, got: {warnings_found}"
        )


# ---------------------------------------------------------------------------
# Security vulnerability fixes (VULN-PY-1 through VULN-PY-5)
# ---------------------------------------------------------------------------

class TestSecurityVulnFixes:

    # --- VULN-PY-1/PY-2: capability_id sanitized in telemetry ---

    def test_vuln_py1_capability_id_newline_sanitized_in_allow_telemetry(self):
        """
        VULN-PY-1/PY-2: A capability_id containing newline/control characters
        must be sanitized before appearing in allow-path telemetry envelopes.

        Uses a wildcard rule (any: true) so the malicious capability_id still
        routes to an allow decision, exercising the allow-path telemetry sanitization.
        """
        import re as _re

        # Wildcard rule — matches any capability_id including malicious ones
        wildcard_rules_doc = {
            "rules": [
                {
                    "rule_id": "rr_wildcard_any",
                    "match": {"capability_id": {"any": True}},
                    "decision": {
                        "candidate_workers_ranked": [
                            {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0}
                        ],
                        "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                        "escalation": {"policy_gate": False, "human_required_default": False},
                        "preconditions": {},
                    },
                }
            ]
        }

        rules = load_rules_from_dict(wildcard_rules_doc)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        malicious_cap = "cap.ok\nFAKE_EVENT: injected"
        inp = _inp(env="dev", capability_id=malicious_cap)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is False, (
            f"Expected allow decision, got deny: {dec.deny_reason_if_denied}"
        )
        for event in dec.telemetry_envelopes:
            cap_in_event = event.get("capability_id", "")
            if not cap_in_event:
                continue
            assert "\n" not in cap_in_event, (
                f"Newline found in telemetry capability_id: {cap_in_event!r}"
            )
            assert not _re.search(r'[\x00-\x1f\x7f]', cap_in_event), (
                f"Control characters found in telemetry capability_id: {cap_in_event!r}"
            )

    def test_vuln_py2_capability_id_newline_sanitized_in_deny_telemetry(self):
        """
        VULN-PY-2: A capability_id containing newline/control characters must
        be sanitized in deny-path telemetry (os_task_denied envelope).
        """
        import re as _re
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = Registry()  # no workers enrolled → DENY_NO_AVAILABLE_WORKER
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        malicious_cap = "cap.hello.greet\nFAKE_EVENT: injected"
        inp = _inp(env="dev", capability_id=malicious_cap)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is True
        for event in dec.telemetry_envelopes:
            cap_in_event = event.get("capability_id", "")
            if not cap_in_event:
                continue
            assert "\n" not in cap_in_event, (
                f"Newline found in deny telemetry capability_id: {cap_in_event!r}"
            )
            assert not _re.search(r'[\x00-\x1f\x7f]', cap_in_event), (
                f"Control characters found in deny telemetry capability_id: {cap_in_event!r}"
            )

    # --- VULN-PY-3: Privilege envelope exception returns generic message ---

    def test_vuln_py3_privilege_envelope_exception_no_class_name(self):
        """
        VULN-PY-3: When registry_policy_allows_privilege raises an exception,
        the deny message must NOT contain the exception class name.
        """
        from pyhall.models import HallConfig

        rules_doc = {
            "rules": [
                {
                    "rule_id": "rr_priv_test",
                    "match": {"capability_id": "cap.hello.greet", "env": "dev"},
                    "decision": {
                        "candidate_workers_ranked": [
                            {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0}
                        ],
                        "required_controls_suggested": [
                            "ctrl.obs.audit-log-append-only",
                            "ctrl.privilege_envelopes_required",
                        ],
                        "escalation": {},
                        "preconditions": {},
                    },
                }
            ]
        }

        rules = load_rules_from_dict(rules_doc)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.privilege_envelopes_required",
        ])

        def raising_policy(env, data_label, envelope):
            raise RuntimeError("internal detail that should not escape")

        inp = _inp(env="dev")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            registry_get_privilege_envelope=registry.get_privilege_envelope,
            registry_policy_allows_privilege=raising_policy,
        )

        assert dec.denied is True
        assert dec.deny_reason_if_denied["code"] == "DENY_INTERNAL_ERROR"
        deny_msg = dec.deny_reason_if_denied["message"]
        # Must not reveal the exception class name
        assert "RuntimeError" not in deny_msg, (
            f"Exception class name leaked into deny message: {deny_msg!r}"
        )
        # Must be the generic message
        assert "Privilege envelope check raised an exception." in deny_msg, (
            f"Expected generic exception message, got: {deny_msg!r}"
        )

    # --- VULN-PY-4: attestation_skipped uses event_id key ---

    def test_vuln_py4_attestation_skipped_uses_event_id_key(self):
        """
        VULN-PY-4: The attestation_skipped telemetry envelope must use
        'event_id' as the key (not 'event') to match all other envelopes.
        SIEM pipelines keyed on 'event_id' will silently miss this signal
        if the wrong key is used.
        """
        rules = load_rules_from_dict(HELLO_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.blast_radius_scoring",
        ])

        from pyhall.models import HallConfig
        # No require_worker_attestation → triggers attestation_skipped in prod
        hall_cfg = HallConfig(
            require_signatory=False,
            require_worker_attestation=False,
        )
        gate = PolicyGate()

        inp = _inp(env="prod", data_label="PUBLIC", blast_score=10)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
            policy_gate_eval=gate.evaluate,
            hall_config=hall_cfg,
        )

        assert dec.denied is False
        # Find the attestation_skipped event
        attestation_events = [
            ev for ev in dec.telemetry_envelopes
            if ev.get("event_id") == "evt.os.worker.attestation_skipped"
        ]
        assert len(attestation_events) == 1, (
            "Expected exactly one attestation_skipped event in telemetry. "
            f"All events: {[ev.get('event_id', ev.get('event')) for ev in dec.telemetry_envelopes]}"
        )
        skipped_event = attestation_events[0]
        # Must have 'event_id', must NOT have a bare 'event' key for the event name
        assert "event_id" in skipped_event, (
            f"attestation_skipped envelope missing 'event_id' key: {skipped_event!r}"
        )
        # Verify the old wrong key is not present with the event name value
        assert skipped_event.get("event") != "evt.os.worker.attestation_skipped", (
            "attestation_skipped envelope uses 'event' key instead of 'event_id'"
        )

    # --- VULN-PY-5: set_controls_present rejects invalid IDs ---

    def test_vuln_py5_set_controls_present_rejects_invalid_ids(self):
        """
        VULN-PY-5: set_controls_present() must reject control IDs that do not
        match the ctrl.<namespace>.<name> format, same as enroll().
        """
        registry = Registry()
        registry.set_controls_present([
            "ctrl.obs.audit-log-append-only",   # valid
            "INVALID_CONTROL",                   # invalid — no ctrl. prefix
            "ctrl.",                             # invalid — incomplete
            "ctrl.obs.audit-log-append-only",   # valid (duplicate, deduped)
        ])

        present = registry.controls_present()
        assert "ctrl.obs.audit-log-append-only" in present, (
            "Valid control ID should be present"
        )
        assert "INVALID_CONTROL" not in present, (
            "Invalid control ID must be rejected by set_controls_present()"
        )
        assert "ctrl." not in present, (
            "Incomplete control ID must be rejected by set_controls_present()"
        )

    def test_vuln_py5_add_controls_present_rejects_invalid_ids(self):
        """
        VULN-PY-5: add_controls_present() must reject control IDs that do not
        match the ctrl.<namespace>.<name> format, same as enroll().
        """
        registry = Registry()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",   # valid
            "not-a-ctrl-id",                    # invalid
            "ctrl..double-dot",                 # invalid — double dot after ctrl.
        ])

        present = registry.controls_present()
        assert "ctrl.obs.audit-log-append-only" in present, (
            "Valid control ID should be present"
        )
        assert "not-a-ctrl-id" not in present, (
            "Invalid control ID must be rejected by add_controls_present()"
        )
        assert "ctrl..double-dot" not in present, (
            "Invalid control ID with double-dot must be rejected by add_controls_present()"
        )


# ---------------------------------------------------------------------------
# PATCH-PY-005 — Shadow rule detection enforced at rule load in prod/edge
# ---------------------------------------------------------------------------

class TestPatchPy005ShadowRuleDetection:
    """
    PATCH-PY-005: make_decision() must detect shadow rules and fail-closed
    in prod/edge environments. In dev/stage, shadow detection is skipped and
    routing proceeds normally.
    """

    # Shared rule set: rule 1 is broad (matches any capability_id), rule 2 is
    # specific (matches any capability_id AND env=prod). In prod, rule 1 always
    # fires first and rule 2 is unreachable — a governance bypass via ordering.
    _SHADOW_RULES_DOC = {
        "rules": [
            {
                "rule_id": "rr_broad_any",
                "match": {"capability_id": {"any": True}},
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
                "rule_id": "rr_specific_prod",
                "match": {"capability_id": {"any": True}, "env": "prod"},
                "decision": {
                    "candidate_workers_ranked": [
                        {"worker_species_id": "wrk.hello.greeter", "score_hint": 1.0}
                    ],
                    "required_controls_suggested": [
                        "ctrl.obs.audit-log-append-only",
                        "ctrl.blast_radius_scoring",
                    ],
                    "escalation": {"policy_gate": False, "human_required_default": False},
                    "preconditions": {},
                },
            },
        ]
    }

    def test_shadow_rules_in_prod_denies_with_shadow_code(self):
        """
        PATCH-PY-005: When a broad rule appears before a specific rule in a
        prod-env request, make_decision() must return DENY_SHADOW_RULES_DETECTED
        before any rule matching occurs.
        """
        rules = load_rules_from_dict(self._SHADOW_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present([
            "ctrl.obs.audit-log-append-only",
            "ctrl.blast_radius_scoring",
        ])

        inp = _inp(env="prod", data_label="PUBLIC")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is True, "Expected decision to be denied"
        assert dec.deny_reason_if_denied["code"] == "DENY_SHADOW_RULES_DETECTED", (
            f"Expected DENY_SHADOW_RULES_DETECTED, got: {dec.deny_reason_if_denied['code']!r}"
        )
        assert "shadowed_rule_ids" in dec.deny_reason_if_denied, (
            "deny_reason must include 'shadowed_rule_ids'"
        )
        assert "rr_specific_prod" in dec.deny_reason_if_denied["shadowed_rule_ids"], (
            "rr_specific_prod must be listed as a shadowed rule"
        )
        assert dec.deny_reason_if_denied["shadow_count"] >= 1, (
            "shadow_count must be at least 1"
        )

    def test_shadow_rules_in_edge_denies_with_shadow_code(self):
        """
        PATCH-PY-005: Shadow rule detection must also fire for edge environment,
        not just prod.
        """
        rules = load_rules_from_dict(self._SHADOW_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="edge", data_label="PUBLIC")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is True, "Expected decision to be denied in edge env"
        assert dec.deny_reason_if_denied["code"] == "DENY_SHADOW_RULES_DETECTED", (
            f"Expected DENY_SHADOW_RULES_DETECTED in edge, got: {dec.deny_reason_if_denied['code']!r}"
        )

    def test_shadow_rules_in_dev_routes_normally(self):
        """
        PATCH-PY-005: In dev environment, shadow rule detection is NOT enforced.
        The same broad+specific rule set must route normally through the broad rule.
        """
        rules = load_rules_from_dict(self._SHADOW_RULES_DOC)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="dev", data_label="PUBLIC")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is False, (
            f"Expected allowed in dev, got denied: {dec.deny_reason_if_denied}"
        )
        assert dec.matched_rule_id == "rr_broad_any", (
            f"Expected broad rule to match in dev, got: {dec.matched_rule_id!r}"
        )

    def test_no_shadow_rules_in_prod_routes_normally(self):
        """
        PATCH-PY-005: A rule set with no shadow rules in prod must route normally
        — the detection must not fire false positives.
        """
        # Two rules with no overlap: first matches dev/stage, second matches prod
        clean_rules_doc = {
            "rules": [
                {
                    "rule_id": "rr_dev_stage",
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
                    "rule_id": "rr_prod_only",
                    "match": {
                        "capability_id": "cap.hello.greet",
                        "env": "prod",
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
            ]
        }
        rules = load_rules_from_dict(clean_rules_doc)
        registry = _registry_with_worker()
        registry.add_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(env="prod", data_label="PUBLIC")
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is False, (
            f"Expected allowed for clean rule set in prod, got denied: {dec.deny_reason_if_denied}"
        )
        assert dec.matched_rule_id == "rr_prod_only"


# ---------------------------------------------------------------------------
# PATCH-XSDK-SHADOW-003 — Shadow rule semantic wildcard detection
# PATCH-XSDK-TENANT-004 — Empty tenant_id enforcement
# PATCH-PY-DRYRUN-005   — dry_run propagated on deny paths
# ---------------------------------------------------------------------------

class TestPatchXsdkShadow003SemanticWildcard:
    """
    PATCH-XSDK-SHADOW-003: detect_shadow_rules() must detect semantic wildcards.

    A rule with {"any": True} on any match field semantically matches everything
    that any more-specific rule would match. The original dict-subset check missed
    this because {"any": True} is not a dict-subset of {"eq": "cap.secret.delete"}.
    """

    # Rule set used by both prod and dev tests:
    # allow-any uses capability_id={"any": True} (wildcard — matches all caps)
    # deny-secret uses capability_id={"eq": "cap.secret.delete"} (specific)
    # When allow-any appears first, deny-secret never fires → governance bypass.
    _SEMANTIC_SHADOW_RULES_DOC = {
        "rules": [
            {
                "rule_id": "allow-any",
                "match": {
                    "capability_id": {"any": True},
                    "env": {"in": ["dev", "stage", "prod", "edge"]},
                },
                "decision": {
                    "candidate_workers_ranked": [
                        {"worker_species_id": "wrk.test", "score_hint": 1.0}
                    ],
                    "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                    "escalation": {"policy_gate": False, "human_required_default": False},
                    "preconditions": {},
                },
            },
            {
                "rule_id": "deny-secret",
                "match": {
                    "capability_id": {"eq": "cap.secret.delete"},
                    "env": "prod",
                },
                "decision": {
                    "candidate_workers_ranked": [],
                    "required_controls_suggested": [
                        "ctrl.obs.audit-log-append-only",
                        "ctrl.blast_radius_scoring",
                    ],
                    "escalation": {"policy_gate": True, "human_required_default": True},
                    "preconditions": {},
                },
            },
        ]
    }

    def test_shadow_rule_semantic_wildcard_blocked_in_prod(self):
        """
        PATCH-XSDK-SHADOW-003: A broad rule with capability_id={"any": True}
        placed before a specific rule must be detected as a shadow and cause
        DENY_SHADOW_RULES_DETECTED in prod.

        This is the confirmed exploit: without semantic wildcard detection,
        make_decision() returns denied=False matched=allow-any even for
        capability_id="cap.secret.delete", bypassing the specific deny rule.
        """
        rules = load_rules_from_dict(self._SEMANTIC_SHADOW_RULES_DOC)
        registry = Registry()
        registry.set_workers_available(["wrk.test"])
        registry.set_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(
            capability_id="cap.secret.delete",
            env="prod",
            data_label="RESTRICTED",
            tenant_risk="high",
        )
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is True, (
            "Expected DENY_SHADOW_RULES_DETECTED in prod — semantic wildcard "
            f"shadow not detected. Got: denied={dec.denied}, "
            f"matched={dec.matched_rule_id}, reason={dec.deny_reason_if_denied}"
        )
        assert dec.deny_reason_if_denied["code"] == "DENY_SHADOW_RULES_DETECTED", (
            f"Expected DENY_SHADOW_RULES_DETECTED, got: {dec.deny_reason_if_denied['code']!r}"
        )
        assert "deny-secret" in dec.deny_reason_if_denied.get("shadowed_rule_ids", []), (
            "deny-secret must be listed as a shadowed rule. "
            f"Got: {dec.deny_reason_if_denied.get('shadowed_rule_ids')}"
        )

    def test_shadow_rule_semantic_wildcard_allowed_in_dev(self):
        """
        PATCH-XSDK-SHADOW-003: In dev environment, shadow rule detection is NOT
        enforced (same as existing PATCH-PY-005 behavior). The broad wildcard
        rule fires and the request is allowed — no DENY_SHADOW_RULES_DETECTED.
        """
        rules = load_rules_from_dict(self._SEMANTIC_SHADOW_RULES_DOC)
        registry = Registry()
        registry.set_workers_available(["wrk.test"])
        registry.set_controls_present(["ctrl.obs.audit-log-append-only"])

        inp = _inp(
            capability_id="cap.secret.delete",
            env="dev",
            data_label="INTERNAL",
            tenant_risk="low",
        )
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        # In dev: shadow detection disabled — broad rule fires, request allowed
        assert dec.denied is False, (
            f"Expected allowed in dev, got denied: {dec.deny_reason_if_denied}"
        )
        assert dec.matched_rule_id == "allow-any", (
            f"Expected allow-any to match in dev, got: {dec.matched_rule_id!r}"
        )


class TestPatchXsdkTenant004EmptyTenantId:
    """
    PATCH-XSDK-TENANT-004: Empty or whitespace tenant_id must be denied before
    routing. An empty tenant_id breaks telemetry attribution, policy gates, and
    audit log chain of custody.
    """

    _SIMPLE_RULES_DOC = {
        "rules": [
            {
                "rule_id": "rr_catch_all",
                "match": {"capability_id": {"any": True}},
                "decision": {
                    "candidate_workers_ranked": [
                        {"worker_species_id": "wrk.test", "score_hint": 1.0}
                    ],
                    "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                    "escalation": {"policy_gate": False, "human_required_default": False},
                    "preconditions": {},
                },
            }
        ]
    }

    def test_empty_tenant_id_denied(self):
        """
        PATCH-XSDK-TENANT-004: tenant_id="" must produce DENY_MISSING_TENANT_ID.

        Confirmed exploit: make_decision() with tenant_id="" previously returned
        denied=False, allowing anonymous routing with no tenant attribution.
        """
        rules = load_rules_from_dict(self._SIMPLE_RULES_DOC)
        registry = Registry()
        registry.set_workers_available(["wrk.test"])
        registry.set_controls_present(["ctrl.obs.audit-log-append-only"])

        # RouteInput with empty tenant_id — must be rejected at model or router level
        # NOTE: The Pydantic validator now rejects empty strings at construction.
        # We test the router-level check by bypassing the validator via object.__setattr__
        # (or constructing with a valid id then patching — either approach validates the router check).
        # Since the validator now fires first, verify the model-level rejection path:
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="tenant_id"):
            RouteInput(
                capability_id="cap.hello.greet",
                env="dev",
                data_label="PUBLIC",
                tenant_risk="low",
                qos_class="P2",
                tenant_id="",
                correlation_id=_corr(),
            )

    def test_whitespace_tenant_id_denied(self):
        """
        PATCH-XSDK-TENANT-004: tenant_id="   " (whitespace only) must produce
        DENY_MISSING_TENANT_ID. Whitespace-only IDs are functionally empty and
        break telemetry attribution.
        """
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="tenant_id"):
            RouteInput(
                capability_id="cap.hello.greet",
                env="dev",
                data_label="PUBLIC",
                tenant_risk="low",
                qos_class="P2",
                tenant_id="   ",
                correlation_id=_corr(),
            )

    def test_router_level_empty_tenant_id_denied(self):
        """
        PATCH-XSDK-TENANT-004: The router-level check catches empty tenant_id
        even when the model-level validator is bypassed (defense-in-depth).

        Uses object.__setattr__ to patch a constructed RouteInput so the
        router check is exercised independently of the Pydantic validator.
        """
        rules = load_rules_from_dict(self._SIMPLE_RULES_DOC)
        registry = Registry()
        registry.set_workers_available(["wrk.test"])
        registry.set_controls_present(["ctrl.obs.audit-log-append-only"])

        # Construct valid input, then forcibly blank tenant_id to test router check
        inp = _inp(env="dev", tenant_id="valid-tenant")
        object.__setattr__(inp, "tenant_id", "")  # bypass Pydantic frozen model

        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is True, (
            f"Expected DENY_MISSING_TENANT_ID, got denied={dec.denied}, "
            f"reason={dec.deny_reason_if_denied}"
        )
        assert dec.deny_reason_if_denied["code"] == "DENY_MISSING_TENANT_ID", (
            f"Expected DENY_MISSING_TENANT_ID, got: {dec.deny_reason_if_denied['code']!r}"
        )


class TestPatchPyDryrun005DryRunPreservedOnDeny:
    """
    PATCH-PY-DRYRUN-005: dry_run=True must be preserved on all deny paths.

    Confirmed exploit: make_decision() with dry_run=True and no matching rule
    previously returned decision.dry_run=False — the flag was silently dropped
    on deny paths. Audit consumers could not distinguish dry-run probes from
    real denials.
    """

    _SIMPLE_RULES_DOC = {
        "rules": [
            {
                "rule_id": "rr_catch_all_dev",
                "match": {"capability_id": {"any": True}, "env": "dev"},
                "decision": {
                    "candidate_workers_ranked": [
                        {"worker_species_id": "wrk.test", "score_hint": 1.0}
                    ],
                    "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                    "escalation": {"policy_gate": False, "human_required_default": False},
                    "preconditions": {},
                },
            }
        ]
    }

    def test_dry_run_preserved_on_deny(self):
        """
        PATCH-PY-DRYRUN-005: dry_run=True with no matching rule must return
        decision.dry_run=True — the flag must not be dropped on the deny path.
        """
        rules = load_rules_from_dict(self._SIMPLE_RULES_DOC)
        registry = Registry()
        registry.set_workers_available(["wrk.test"])
        registry.set_controls_present(["ctrl.obs.audit-log-append-only"])

        # No rule matches prod — produces DENY_NO_MATCHING_RULE on deny path
        inp = _inp(env="prod", dry_run=True)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is True, "Expected deny (no rule matches prod)"
        assert dec.dry_run is True, (
            f"dry_run must be True on deny path — got dec.dry_run={dec.dry_run!r}. "
            "PATCH-PY-DRYRUN-005: dry_run was silently dropped on deny paths."
        )

    def test_dry_run_telemetry_tagged(self):
        """
        PATCH-PY-DRYRUN-005: When dry_run=True and the decision is denied,
        every telemetry envelope in the deny path must include dry_run=True.

        Audit consumers that filter on dry_run=True in telemetry to exclude
        probes from dashboards would silently include dry-run denials as real
        events if this flag is not propagated.
        """
        rules = load_rules_from_dict(self._SIMPLE_RULES_DOC)
        registry = Registry()
        registry.set_workers_available(["wrk.test"])
        registry.set_controls_present(["ctrl.obs.audit-log-append-only"])

        # No rule matches prod — produces DENY_NO_MATCHING_RULE deny telemetry
        inp = _inp(env="prod", dry_run=True)
        dec = make_decision(
            inp=inp,
            rules=rules,
            registry_controls_present=registry.controls_present(),
            registry_worker_available=registry.worker_available,
        )

        assert dec.denied is True
        assert len(dec.telemetry_envelopes) > 0, "Expected at least one telemetry envelope on deny path"
        for event in dec.telemetry_envelopes:
            assert event.get("dry_run") is True, (
                f"Deny-path telemetry envelope missing dry_run=True: "
                f"event_id={event.get('event_id', event.get('event'))!r}, "
                f"envelope={event!r}"
            )
