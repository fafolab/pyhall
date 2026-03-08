"""
pyhall/router.py — WCP core routing engine.

make_decision() is the single entry point. It takes a RouteInput and
returns a RouteDecision. It never raises — all failures are expressed
as denied decisions.

Routing pipeline (WCP-Full):
  1. Match first routing rule (fail-closed if no match)
  2. Verify preconditions (correlation_id, etc.)
  3. Verify required controls against registry
  4. Blast radius scoring and gating (if ctrl.blast_radius_scoring present)
  5. Policy gate evaluation (if escalation.policy_gate is true)
  6. Select first available worker candidate
  7. Emit mandatory telemetry
  8. Optional conformance check (CI/test mode)
  9. Return RouteDecision
"""

from __future__ import annotations

import json
import re
import re as _re
from typing import Any, Callable, Dict, List, Optional

# F26: Control character sanitizer — strips \x00-\x1f and DEL from ID strings
# before writing them to telemetry or audit log entries.
_CTRL_CHARS_RE = _re.compile(r'[\x00-\x1f\x7f]')


def _sanitize_id(s: str) -> str:
    """Strip control characters from ID strings before writing to telemetry/audit log."""
    return _CTRL_CHARS_RE.sub("", s) if isinstance(s, str) else s

from .common import sha256
from .models import (
    CandidateWorker,
    Escalation,
    HallConfig,
    PreconditionsChecked,
    RouteDecision,
    RouteInput,
)
from .rules import Rule, route_first_match
from .telemetry import (
    new_decision_id,
    now_iso,
    os_policy_gated,
    os_task_denied,
    os_task_routed,
    os_worker_selected,
    gov_blast_scored,
    gov_privilege_envelope_checked,
)
from .conformance import validate_required_fields, validate_required_telemetry

DEFAULT_POLICY_VERSION = "policy.v0"


# ---------------------------------------------------------------------------
# Blast radius scoring helpers
# ---------------------------------------------------------------------------

def _compute_blast_score(inp: RouteInput) -> int:
    """
    Heuristic blast radius scorer.

    Computes a 0–100 score based on RouteInput fields. Higher = more dangerous.
    Replace with your domain-specific model for production use.

    Scoring factors:
      - data_label INTERNAL: +20
      - data_label RESTRICTED: +40
      - env prod/edge: +15
      - qos_class P0: +10
      - egress or external_call in request: +15
      - writes or mutates_state in request: +15
    """
    score = 10  # baseline
    if inp.data_label == "INTERNAL":
        score += 20
    elif inp.data_label == "RESTRICTED":
        score += 40
    if inp.env in ("prod", "edge"):
        score += 15
    if inp.qos_class == "P0":
        score += 10
    req = inp.request or {}
    if req.get("egress") or req.get("external_call"):
        score += 15
    if req.get("writes") or req.get("mutates_state"):
        score += 15
    return min(100, score)


def _blast_gate(score: int, inp: RouteInput) -> tuple[bool, str]:
    """
    Gate a blast score.

    Returns (allowed: bool, reason: str).
    Denies scores >= 85 in prod/edge — requires human review.
    """
    if inp.env in ("prod", "edge") and score >= 85:
        return (False, "REQUIRE_HUMAN_HIGH_BLAST")
    return (True, "blast_ok")


# ---------------------------------------------------------------------------
# Precondition helpers
# ---------------------------------------------------------------------------

def _ensure_correlation_id(inp: RouteInput) -> bool:
    return bool(inp.correlation_id and inp.correlation_id.strip())


# ---------------------------------------------------------------------------
# Deny helper — reduces repetition in make_decision
# ---------------------------------------------------------------------------

def _deny(
    inp: RouteInput,
    matched_rule_id: str,
    code: str,
    message: str,
    extra: Optional[Dict[str, Any]] = None,
    pre_checked: Optional[PreconditionsChecked] = None,
    required_controls: Optional[List[str]] = None,
    escalation: Optional[Escalation] = None,
    worker_attestation_checked: bool = False,
    worker_attestation_valid: Optional[bool] = None,
    candidate_workers: Optional[List[CandidateWorker]] = None,
) -> RouteDecision:
    reason: Dict[str, Any] = {"code": code, "message": message}
    if extra:
        reason.update(extra)
    # F6: Always emit deny telemetry — every denial is forensically recorded
    # F26: Sanitize IDs before writing to telemetry (log injection defense).
    telemetry_event = os_task_denied(
        correlation_id=_sanitize_id(inp.correlation_id),
        tenant_id=_sanitize_id(inp.tenant_id),
        capability_id=_sanitize_id(inp.capability_id),
        deny_code=code,
        deny_message=message,
        matched_rule_id=matched_rule_id,
    )
    # PATCH-PY-DRYRUN-005: Propagate dry_run into deny-path telemetry so audit
    # consumers can distinguish dry-run probes from real denials.
    if inp.dry_run:
        telemetry_event = {**telemetry_event, "dry_run": True}
    telemetry = [telemetry_event]
    return RouteDecision(
        decision_id=new_decision_id(),
        timestamp=now_iso(),
        correlation_id=inp.correlation_id,
        tenant_id=inp.tenant_id,
        capability_id=inp.capability_id,
        matched_rule_id=matched_rule_id,
        env=inp.env,
        data_label=inp.data_label,
        tenant_risk=inp.tenant_risk,
        qos_class=inp.qos_class,
        denied=True,
        deny_reason_if_denied=reason,
        required_controls_effective=sorted(required_controls) if required_controls else [],
        preconditions_checked=pre_checked or PreconditionsChecked(),
        escalation_effective=escalation or Escalation(),
        # PATCH-PY-DRYRUN-005: Propagate dry_run flag on all deny paths so the
        # caller can distinguish a dry-run probe denial from a real denial.
        dry_run=inp.dry_run,
        telemetry_envelopes=telemetry,
        worker_attestation_checked=worker_attestation_checked,
        worker_attestation_valid=worker_attestation_valid,
        candidate_workers_ranked=candidate_workers or [],
    )


# ---------------------------------------------------------------------------
# make_decision — the Hall's core dispatch function
# ---------------------------------------------------------------------------

def make_decision(
    inp: RouteInput,
    rules: List[Rule],
    registry_controls_present: set[str],
    registry_worker_available: Callable[[str], bool],
    registry_get_privilege_envelope: Optional[Callable[[str], Optional[dict]]] = None,
    registry_policy_allows_privilege: Optional[Callable[[str, str, dict], tuple[bool, str]]] = None,
    policy_gate_eval: Optional[Callable[[dict], tuple[str, str, str]]] = None,
    conformance_spec: Optional[Dict[str, Any]] = None,
    task_id: str = "task_default",
    hall_config: Optional[HallConfig] = None,
    registry_get_worker_hash: Optional[Callable[[str], Optional[str]]] = None,
    get_current_worker_hash: Optional[Callable[[str], Optional[str]]] = None,
    registry_client: Optional["RegistryClient"] = None,
) -> RouteDecision:
    """
    Make a WCP routing decision.

    This is the Hall's core function. Call it with a RouteInput and the
    active rules + registry state to get a RouteDecision.

    Args:
        inp:
            The capability request.

        rules:
            Ordered list of routing rules (loaded via load_rules()).

        registry_controls_present:
            Set of control IDs currently declared present in the registry.
            Obtain from Registry.controls_present().

        registry_worker_available:
            Callable(worker_species_id: str) -> bool.
            Returns True if the species is enrolled and available.

        registry_get_privilege_envelope:
            Optional callable(worker_species_id: str) -> dict | None.
            Returns the privilege envelope for a species.

        registry_policy_allows_privilege:
            Optional callable(env, data_label, envelope) -> (bool, str).
            Returns (allowed, reason) for privilege enforcement.

        policy_gate_eval:
            Optional callable(context: dict) -> (decision, policy_version, reason).
            Required when any matching rule has escalation.policy_gate = True.
            Must return decision as "ALLOW", "DENY", or "REQUIRE_HUMAN".

        conformance_spec:
            Optional conformance spec dict (from load_conformance_spec()).
            When provided, a conformance failure raises RuntimeError.
            Use in CI/test mode only — do not pass in production routing.

        task_id:
            Identifier for this routing task. Included in telemetry.

        hall_config:
            Optional Hall-level configuration. When provided and
            hall_config.require_signatory is True, any RouteInput whose
            tenant_id is not in hall_config.allowed_tenants is denied with
            DENY_UNKNOWN_TENANT before rule matching. See WCP spec §5.9.
            When hall_config.require_worker_attestation is True, the selected
            worker's current code hash is verified against its registered
            attestation hash. See WCP spec §5.10.

        registry_get_worker_hash:
            Optional callable(worker_species_id: str) -> str | None.
            Returns the registered (known-good) SHA-256 code hash for a
            worker species. Required when hall_config.require_worker_attestation
            is True.

        get_current_worker_hash:
            Optional callable(worker_species_id: str) -> str | None.
            Returns the current (live) SHA-256 code hash for a worker species
            at dispatch time. Required when hall_config.require_worker_attestation
            is True. Implementations compute this from the worker's file path,
            container image digest, or module source.

        registry_client:
            Optional RegistryClient instance. When provided:
            - Automatically wires registry_get_worker_hash via the client's
              get_worker_hash() method (uses the prefetch cache if populated).
            - Forces hall_config.require_worker_attestation = True, so every
              routing decision issues a standing receipt. This is the primary
              integration path for Hall binaries — the registry client is
              compiled in, making the attestation check non-bypassable without
              changing the binary hash (which breaks the PackageAttestationVerifier
              startup check).
            Call registry_client.prefetch(worker_ids) before make_decision() to
            populate the cache and avoid synchronous HTTP on the hot path.

    Returns:
        RouteDecision — never raises in normal operation.
            Exception: raises RuntimeError only when conformance_spec is provided
            and the decision fails conformance checks (CI/test-only mode).
            Do not pass conformance_spec in production code.
    """

    # -----------------------------------------------------------------------
    # registry_client auto-wiring: if provided, use it as the worker hash
    # source and enable attestation enforcement. This is the primary path
    # for Hall binaries — the registry client is baked in, so every decision
    # issues a standing receipt.
    # -----------------------------------------------------------------------
    if registry_client is not None:
        if registry_get_worker_hash is None:
            registry_get_worker_hash = registry_client.get_worker_hash
        if hall_config is None:
            hall_config = HallConfig(require_worker_attestation=True)
        elif not hall_config.require_worker_attestation:
            # Create a new HallConfig with attestation enabled, preserving other fields
            hall_config = HallConfig(
                require_signatory=hall_config.require_signatory,
                allowed_tenants=hall_config.allowed_tenants,
                require_worker_attestation=True,
            )

    # -----------------------------------------------------------------------
    # Step 0: Signatory tenant validation (WCP §5.9)
    # -----------------------------------------------------------------------
    if hall_config is not None and hall_config.require_signatory:
        if inp.tenant_id not in hall_config.allowed_tenants:
            return _deny(
                inp,
                matched_rule_id="PRE_ROUTING",
                code="DENY_UNKNOWN_TENANT",
                message=(
                    "Tenant is not registered as a signatory. "
                    "Register via the Hall configuration before dispatching workers."
                ),
                extra={"tenant_id": inp.tenant_id},
            )

    # F21: require_credential declared but not yet enforced — warn so operators
    # are not silently misled into believing credential validation is active.
    if hall_config is not None and hall_config.require_credential:
        import warnings
        warnings.warn(
            "HallConfig.require_credential=True has no effect in v0.1. "
            "Credential validation is planned for v0.2. "
            "Do not rely on this flag for security enforcement.",
            stacklevel=2,
        )

    # -----------------------------------------------------------------------
    # Step 0.1: Tenant ID presence check (PATCH-XSDK-TENANT-004)
    # -----------------------------------------------------------------------
    # An empty or whitespace-only tenant_id is a governance gap: telemetry,
    # audit logs, and policy gates all depend on a meaningful tenant identity.
    # Fail-closed before any rule matching so no rule can accidentally allow
    # anonymous routing.
    if not inp.tenant_id or not inp.tenant_id.strip():
        return _deny(
            inp,
            matched_rule_id="PRE_ROUTING",
            code="DENY_MISSING_TENANT_ID",
            message="tenant_id is required and must not be empty or whitespace.",
        )

    # -----------------------------------------------------------------------
    # Step 0.25: blast_score range validation — reject out-of-range values early
    # -----------------------------------------------------------------------
    # TypeScript validates this in validateRouteInput(); Go validates in router.
    # Python parity: blast_score must be in [0, 100] when provided.
    # blast_score=None is valid (means caller did not provide a score).
    if inp.blast_score is not None and (inp.blast_score < 0 or inp.blast_score > 100):
        return _deny(
            inp,
            matched_rule_id="PRE_ROUTING",
            code="DENY_INVALID_INPUT",
            message="blast_score must be in [0, 100]",
            extra={"blast_score": inp.blast_score},
        )

    # -----------------------------------------------------------------------
    # Step 0.5: Shadow rule detection — fail-closed in prod/edge (PATCH-PY-005)
    # -----------------------------------------------------------------------
    # A broad rule placed before a stricter rule silently shadows it — the
    # stricter rule never fires. In production this allows governance to be
    # bypassed entirely by rule ordering. Fail closed: deny the request and
    # require the operator to fix rule ordering before deploying to production.
    if inp.env in ("prod", "edge"):
        shadow_warnings = detect_shadow_rules(rules)
        if shadow_warnings:
            shadowed_ids = [w["shadowed"] for w in shadow_warnings]
            return _deny(
                inp,
                "NO_MATCH",
                "DENY_SHADOW_RULES_DETECTED",
                "Rule set contains shadow rules in prod/edge environment. "
                "Fix rule ordering before deploying to production.",
                extra={
                    "shadowed_rule_ids": shadowed_ids,
                    "shadow_count": len(shadow_warnings),
                },
            )

    # -----------------------------------------------------------------------
    # Step 1: Rule matching (fail-closed)
    # -----------------------------------------------------------------------
    matched = route_first_match(rules, inp.model_dump())
    if matched is None:
        return _deny(
            inp,
            "NO_MATCH",
            "DENY_NO_MATCHING_RULE",
            "No routing rule matched. Fail-closed per WCP spec section 5.1.",
        )

    d = matched.decision or {}
    candidates = d.get("candidate_workers_ranked", [])
    required_controls = set(d.get("required_controls_suggested", []))
    escalation_raw = d.get("escalation", {})
    pre_raw = d.get("preconditions", {})

    # -----------------------------------------------------------------------
    # Step 2: Preconditions
    # -----------------------------------------------------------------------
    _pre_defaults = PreconditionsChecked()
    pre_checked = PreconditionsChecked(
        **{
            k: pre_raw.get(k, getattr(_pre_defaults, k))
            for k in PreconditionsChecked.model_fields.keys()
        }
    )

    # F12: Apply Hall-level precondition floor — rules cannot lower below hall_config minimum.
    hall_enforce_corr_id = hall_config.enforce_correlation_id if hall_config is not None else True
    hall_enforce_controls = hall_config.enforce_required_controls if hall_config is not None else True

    if (pre_checked.must_have_correlation_id or hall_enforce_corr_id) and not _ensure_correlation_id(inp):
        return _deny(
            inp,
            matched.rule_id,
            "DENY_MISSING_CORRELATION_ID",
            "correlation_id is required but absent or empty.",
            pre_checked=pre_checked,
            required_controls=list(required_controls),
        )

    # -----------------------------------------------------------------------
    # Step 3: Controls check
    # -----------------------------------------------------------------------
    missing_controls = sorted(list(required_controls - registry_controls_present))
    if (pre_checked.deny_if_missing_required_controls or hall_enforce_controls) and missing_controls:
        return _deny(
            inp,
            matched.rule_id,
            "DENY_MISSING_REQUIRED_CONTROLS",
            "Required controls not present in registry.",
            extra={"missing": missing_controls},
            pre_checked=pre_checked,
            required_controls=list(required_controls),
        )

    # -----------------------------------------------------------------------
    # Step 4: Blast radius gating (WCP-Full)
    # -----------------------------------------------------------------------
    # F15: Compute score once here and reuse in Step 7 telemetry so the audit
    # log always records the gate-evaluated score, not the caller-provided value.
    blast_score_gated: Optional[int] = None

    # F18: Hall-level blast gate floor for prod/edge (cannot be bypassed by rule omission).
    # A rule that omits ctrl.blast_radius_scoring cannot escape blast gating in prod/edge
    # when enforce_blast_scoring_in_prod=True (the default).
    hall_enforce_blast = (
        hall_config.enforce_blast_scoring_in_prod
        if hall_config is not None
        else True
    )
    blast_in_prod = inp.env in ("prod", "edge") and hall_enforce_blast

    if "ctrl.blast_radius_scoring" in required_controls or blast_in_prod:
        # F3: Always compute — caller may augment (raise) the score but never lower it.
        computed_score = _compute_blast_score(inp)
        blast_score_gated = max(computed_score, inp.blast_score) if inp.blast_score is not None else computed_score
        blast_ok, blast_reason = _blast_gate(blast_score_gated, inp)
        if not blast_ok:
            # F16: Route through _deny() so telemetry is emitted on this deny path.
            return _deny(
                inp,
                matched.rule_id,
                "DENY_REQUIRES_HUMAN",
                "Blast radius too high for autonomous execution.",
                extra={"blast_score": blast_score_gated, "reason": blast_reason},
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=Escalation(
                    **{**escalation_raw, "human_required_default": True, "rationale": blast_reason}
                ),
            )

    # -----------------------------------------------------------------------
    # Step 5: Policy gate evaluation (WCP-Full)
    # -----------------------------------------------------------------------
    policy_version = DEFAULT_POLICY_VERSION
    escalation_obj = Escalation(**escalation_raw) if escalation_raw else Escalation()

    if escalation_obj.policy_gate:
        # F11: Fail closed — deny instead of raise so make_decision() never raises.
        if policy_gate_eval is None:
            return _deny(
                inp,
                matched.rule_id,
                "DENY_POLICY_GATE_UNCONFIGURED",
                "policy_gate_eval is required when escalation.policy_gate is True. "
                "Pass a PolicyGate instance's .evaluate method.",
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )
        # F11: Wrap callback — a throwing gate never escapes make_decision().
        try:
            gate_decision, policy_version, gate_reason = policy_gate_eval(
                {
                    "capability_id": inp.capability_id,
                    "tenant_id": inp.tenant_id,
                    "env": inp.env,
                    "data_label": inp.data_label,
                    "tenant_risk": inp.tenant_risk,
                    "qos_class": inp.qos_class,
                    "policy_version": DEFAULT_POLICY_VERSION,
                }
            )
        except Exception:
            # F23: Do not leak the exception class name into the deny message —
            # the type name can reveal internal implementation details.
            # Log the full exception server-side; return a generic message to the caller.
            return _deny(
                inp,
                matched.rule_id,
                "DENY_INTERNAL_ERROR",
                "policy_gate_eval raised an exception. See server logs for details.",
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )

        if gate_decision == "DENY":
            return _deny(
                inp,
                matched.rule_id,
                "DENY_POLICY_GATE",
                "Policy gate denied.",
                extra={"reason": gate_reason, "policy_version": policy_version},
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=Escalation(**{**escalation_raw, "rationale": gate_reason}),
            )

        # F1: REQUIRE_HUMAN must halt autonomous dispatch — never silently approve.
        # WCP §5.8: Hall MUST NOT silently approve or deny when REQUIRE_HUMAN is returned.
        if gate_decision == "REQUIRE_HUMAN":
            return _deny(
                inp,
                matched.rule_id,
                "DENY_REQUIRES_HUMAN_APPROVAL",
                (
                    "Policy gate requires human approval before this worker can be dispatched. "
                    "Submit the pending approval via wcp.approval.resolve."
                ),
                extra={
                    "reason": gate_reason,
                    "policy_version": policy_version,
                    "supervisor_required": True,
                },
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=Escalation(
                    **{**escalation_raw, "human_required_default": True, "rationale": gate_reason}
                ),
            )

        # F8: Strict allowlist — any unrecognized decision string fails closed.
        # Prevents buggy/tampered gates from silently approving via non-standard strings.
        if gate_decision != "ALLOW":
            return _deny(
                inp,
                matched.rule_id,
                "DENY_POLICY_GATE_INVALID_RESPONSE",
                f"policy_gate_eval returned unrecognized decision: {gate_decision!r}. "
                "Expected 'ALLOW', 'DENY', or 'REQUIRE_HUMAN'. Failing closed.",
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=Escalation(**{**escalation_raw, "rationale": "invalid_gate_response"}),
            )

    # -----------------------------------------------------------------------
    # Step 6: Select first available worker candidate
    # -----------------------------------------------------------------------
    cand_models: List[CandidateWorker] = []
    selected: Optional[str] = None

    for c in candidates:
        wid = c.get("worker_species_id")
        cm = CandidateWorker(
            worker_species_id=wid or "__missing__",
            score_hint=c.get("score_hint"),
        )
        # F11: Wrap callback — a throwing registry never escapes make_decision().
        try:
            _avail = bool(wid and registry_worker_available(wid))
        except Exception:
            _avail = False
        if selected is None and _avail:
            selected = wid
        elif not _avail:
            # F22: Only mark as "unavailable" when the worker is actually unavailable.
            # Previously this branch also fired for already-selected workers.
            cm.skip_reason = "unavailable"
        elif not wid:
            cm.skip_reason = "missing_id"
        else:
            # F22: Worker was available but an earlier candidate was already selected.
            cm.skip_reason = "already_selected"
        cand_models.append(cm)

    if selected is None:
        # F16: Route through _deny() so telemetry is emitted on this deny path.
        return _deny(
            inp,
            matched.rule_id,
            "DENY_NO_AVAILABLE_WORKER",
            "No available worker candidates. Route to review queue.",
            pre_checked=pre_checked,
            required_controls=list(required_controls),
            escalation=escalation_obj,
            candidate_workers=cand_models,
        )

    # -----------------------------------------------------------------------
    # Step 6.5: Worker Code Attestation (WCP §5.10)
    # -----------------------------------------------------------------------
    attestation_checked = False
    attestation_valid: Optional[bool] = None
    worker_attestation_checked = False  # F24: tracks whether attestation was performed

    _VALID_HASH = re.compile(r'^[0-9a-f]{64}$')

    if hall_config is not None and hall_config.require_worker_attestation and selected is not None:
        worker_attestation_checked = True  # F24: attestation was attempted
        # F2: When attestation is required, missing callables are a deny, not a skip.
        if registry_get_worker_hash is None or get_current_worker_hash is None:
            return _deny(
                inp,
                matched.rule_id,
                "DENY_ATTESTATION_UNCONFIGURED",
                (
                    "require_worker_attestation is True but hash callables were not provided. "
                    "Pass registry_get_worker_hash and get_current_worker_hash to make_decision()."
                ),
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )

        attestation_checked = True
        # F11: Wrap hash callables — exceptions become hash-unavailable denials.
        try:
            registered_hash = registry_get_worker_hash(selected)
        except Exception:
            registered_hash = None
        try:
            current_hash = get_current_worker_hash(selected)
        except Exception:
            current_hash = None

        if registered_hash is None:
            return _deny(
                inp,
                matched.rule_id,
                "DENY_WORKER_ATTESTATION_MISSING",
                (
                    f"Worker '{selected}' has no registered code hash. "
                    "Register the worker with an attestation hash before enabling "
                    "require_worker_attestation."
                ),
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )

        # F5: Validate hash format — must be SHA-256 (64 lowercase hex chars)
        if not _VALID_HASH.match(registered_hash):
            return _deny(
                inp,
                matched.rule_id,
                "DENY_WORKER_ATTESTATION_INVALID_HASH",
                (
                    f"Worker '{selected}' registered hash is not a valid SHA-256 digest. "
                    "Re-register with a 64-character lowercase hex SHA-256 hash."
                ),
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )

        if current_hash is None or not _VALID_HASH.match(current_hash):
            # Hash unavailable or malformed — treat as unverifiable, deny
            return _deny(
                inp,
                matched.rule_id,
                "DENY_WORKER_HASH_UNAVAILABLE",
                (
                    f"Worker '{selected}' current code hash could not be retrieved or is invalid. "
                    "Verify the get_current_worker_hash implementation."
                ),
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )

        if current_hash != registered_hash:
            attestation_valid = False
            # F4: Do NOT return hash values to caller — log internally only.
            # Returning registered_hash tells the attacker their target.
            return _deny(
                inp,
                matched.rule_id,
                "DENY_WORKER_TAMPERED",
                (
                    f"Worker '{selected}' code hash mismatch. "
                    "Worker may have been modified after attestation. "
                    "Re-attest the worker or investigate for tampering."
                ),
                extra={"worker_species_id": selected},
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
                worker_attestation_checked=True,
                worker_attestation_valid=False,
            )

        attestation_valid = True

    # -----------------------------------------------------------------------
    # Step 6.7: Privilege envelope enforcement (WCP-Full)
    # -----------------------------------------------------------------------
    # F9: Actually call the privilege callables — previously a stub that always
    # emitted "ALLOW" telemetry without performing any check (security theater).
    # F19: Hall-level floor — enforce privilege envelopes even when the rule omits
    # ctrl.privilege_envelopes_required, when enforce_privilege_envelopes=True.
    hall_enforce_priv = (
        hall_config.enforce_privilege_envelopes
        if hall_config is not None
        else False
    )
    if "ctrl.privilege_envelopes_required" in required_controls or hall_enforce_priv:
        if registry_get_privilege_envelope is None or registry_policy_allows_privilege is None:
            return _deny(
                inp,
                matched.rule_id,
                "DENY_PRIVILEGE_ENVELOPE_UNCONFIGURED",
                "ctrl.privilege_envelopes_required is set but privilege envelope callables "
                "were not provided. Pass registry_get_privilege_envelope and "
                "registry_policy_allows_privilege to make_decision().",
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )
        try:
            envelope = registry_get_privilege_envelope(selected)
            priv_allowed, priv_reason = registry_policy_allows_privilege(
                inp.env, inp.data_label, envelope
            )
        except Exception:
            # F26/VULN-PY-3: Do not leak the exception class name into the deny message —
            # the type name can reveal internal implementation details.
            # Log the full exception server-side; return a generic message to the caller.
            return _deny(
                inp,
                matched.rule_id,
                "DENY_INTERNAL_ERROR",
                "Privilege envelope check raised an exception.",
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )
        if not priv_allowed:
            return _deny(
                inp,
                matched.rule_id,
                "DENY_PRIVILEGE_ENVELOPE_VIOLATED",
                f"Worker privilege envelope denied for {inp.env}/{inp.data_label}: {priv_reason}",
                extra={"reason": priv_reason, "worker_species_id": selected},
                pre_checked=pre_checked,
                required_controls=list(required_controls),
                escalation=escalation_obj,
            )

    # -----------------------------------------------------------------------
    # Step 7: Build mandatory telemetry
    # -----------------------------------------------------------------------
    # F26: Sanitize IDs used in telemetry to strip control characters (log injection defense).
    safe_corr_id = _sanitize_id(inp.correlation_id)
    safe_tenant_id = _sanitize_id(inp.tenant_id)
    safe_capability_id = _sanitize_id(inp.capability_id)

    telemetry: List[Dict[str, Any]] = []

    # Governance events (WCP-Full — only if controls required them or Hall floor fired)
    if "ctrl.blast_radius_scoring" in required_controls or blast_in_prod:
        # F15: Use blast_score_gated (computed in Step 4 with max semantics) so
        # the audit log records the score the gate actually evaluated, not the
        # caller-provided value which may be lower.
        telemetry.append(
            gov_blast_scored(
                safe_corr_id,
                safe_tenant_id,
                inp.env,
                inp.data_label,
                policy_version,
                blast_score_gated,
                "ALLOW",
            )
        )

    if "ctrl.privilege_envelopes_required" in required_controls or hall_enforce_priv:
        telemetry.append(
            gov_privilege_envelope_checked(
                safe_corr_id,
                safe_tenant_id,
                inp.env,
                inp.data_label,
                policy_version,
                selected,
                "ALLOW",
            )
        )

    # F24: Emit telemetry when attestation was not performed in prod/edge —
    # so operators know the gate was skipped, not just absent from the audit log.
    if not worker_attestation_checked and inp.env in ("prod", "edge"):
        telemetry.append({
            "event_id": "evt.os.worker.attestation_skipped",
            "correlation_id": safe_corr_id,
            "worker_species_id": selected,
            "env": inp.env,
            "reason": "require_worker_attestation=False or hall_config=None",
            "severity": "warn",
        })

    # Mandatory WCP telemetry (required for WCP-Standard and above)
    telemetry.append(
        os_task_routed(
            safe_corr_id,
            safe_tenant_id,
            task_id,
            safe_capability_id,
            matched.rule_id,
            selected,
            policy_version,
            inp.qos_class,
        )
    )
    telemetry.append(
        os_worker_selected(
            safe_corr_id,
            safe_tenant_id,
            safe_capability_id,
            selected,
            "first_available_candidate",
        )
    )
    telemetry.append(
        os_policy_gated(
            safe_corr_id,
            safe_tenant_id,
            safe_capability_id,
            "ALLOW",
            policy_version,
            "policy_gate_allow" if escalation_obj.policy_gate else "no_gate_required",
        )
    )

    # F28: Mark all telemetry envelopes with dry_run=True when in dry-run mode,
    # so audit consumers can distinguish probes from real dispatches.
    if inp.dry_run:
        telemetry = [{**ev, "dry_run": True} for ev in telemetry]

    # -----------------------------------------------------------------------
    # Step 8: Assemble decision
    # -----------------------------------------------------------------------
    out = RouteDecision(
        decision_id=new_decision_id(),
        timestamp=now_iso(),
        correlation_id=inp.correlation_id,
        tenant_id=inp.tenant_id,
        capability_id=inp.capability_id,
        matched_rule_id=matched.rule_id,
        env=inp.env,
        data_label=inp.data_label,
        tenant_risk=inp.tenant_risk,
        qos_class=inp.qos_class,
        selected_worker_species_id=selected,
        candidate_workers_ranked=cand_models,
        required_controls_effective=sorted(required_controls),
        recommended_profiles_effective=d.get("recommended_profiles", []),
        escalation_effective=escalation_obj,
        preconditions_checked=pre_checked,
        denied=False,
        telemetry_envelopes=telemetry,
        worker_attestation_checked=attestation_checked,
        worker_attestation_valid=attestation_valid,
    )

    # -----------------------------------------------------------------------
    # Step 9: Provenance hash — SHA-256 of the RouteInput that produced this decision
    # -----------------------------------------------------------------------
    out.artifact_hash = sha256(json.dumps(inp.model_dump(), sort_keys=True, default=str))

    # -----------------------------------------------------------------------
    # Step 9.5: Dry-run mode (WCP §5.5)
    # -----------------------------------------------------------------------
    # F7: If dry_run=True, the full routing decision was made but the worker
    # MUST NOT be dispatched. Mark the decision so callers and audit consumers
    # can distinguish a probe from a real dispatch.
    if inp.dry_run:
        out.dry_run = True

    # -----------------------------------------------------------------------
    # Step 9.8: Decision count telemetry (fire-and-forget via registry_client)
    # -----------------------------------------------------------------------
    if registry_client is not None and selected is not None:
        registry_client.record_decision(selected)

    # -----------------------------------------------------------------------
    # Step 10: Optional conformance check (CI only)
    # -----------------------------------------------------------------------
    if conformance_spec is not None:
        missing = validate_required_fields(out.model_dump(), conformance_spec)
        tel_errs = validate_required_telemetry(telemetry, conformance_spec)
        if missing or tel_errs:
            # F20: intentional raise — conformance_spec is CI-only, not production
            raise RuntimeError(
                f"WCP conformance failure. "
                f"missing_fields={missing} "
                f"telemetry_errors={tel_errs}"
            )

    return out


# ---------------------------------------------------------------------------
# F29: detect_shadow_rules — rule misconfiguration utility
# ---------------------------------------------------------------------------

def _condition_covers(early_cond: Any, late_cond: Any) -> bool:
    """
    Return True if early_cond semantically covers (matches a superset of) late_cond.

    This is used by detect_shadow_rules() to understand operator semantics:
      - {"any": True}   covers anything — broadest possible match
      - {"in": [...]}   covers exact values in the list
      - "exact_value"   covers only that exact value
      - None (absent)   means the early rule has no constraint on this field,
                        which is equivalent to {"any": True} for that field

    Two conditions are compared to determine if early always matches when late would:
      - early={"any": True}    covers late=anything  → True (wildcard beats all)
      - early={"in": [a,b,c]} covers late={"eq": a} → True (superset)
      - early={"in": [a,b]}   covers late={"in": [a,b,c]} → False (not superset)
      - early="a"             covers late="a"        → True (identical)
      - early="a"             covers late="b"        → False
    """
    # Normalize: absent condition (None) on the early side means "any" — it
    # always matches, so it always covers whatever late_cond is.
    if early_cond is None:
        return True

    # Explicit {"any": True} is the wildcard — covers everything
    if isinstance(early_cond, dict) and early_cond.get("any") is True:
        return True

    # Identical conditions cover each other
    if early_cond == late_cond:
        return True

    # early={"in": [a, b, c]}, late={"eq": x} → covers if x in early list
    if isinstance(early_cond, dict) and "in" in early_cond:
        early_set = set(early_cond["in"])
        # late is a single exact value (string)
        if isinstance(late_cond, str) and late_cond in early_set:
            return True
        # late is also an {"in": [...]} — covers if early is a superset
        if isinstance(late_cond, dict) and "in" in late_cond:
            if early_set.issuperset(set(late_cond["in"])):
                return True
        # late is {"any": True} — early {"in": [...]} does NOT cover {"any": True}
        # because early is more restrictive
        return False

    # early is an exact string value — only covers the identical late value
    if isinstance(early_cond, str):
        return early_cond == late_cond

    return False


def _rule_semantically_shadows(early_match: Dict[str, Any], late_match: Dict[str, Any]) -> bool:
    """
    Return True if early_match semantically shadows late_match.

    Rule A (early) shadows rule B (late) when every input that matches B also
    matches A — i.e., A is at least as broad as B on every match dimension.

    For each field that late_match constrains, early_match must cover it.
    For fields that early_match constrains but late_match does not, those
    additional constraints make early MORE specific (not broader), so they do
    NOT cause early to shadow late.

    Special case: if both rules are identical they are duplicate shadows, not
    semantic shadows — handled separately in detect_shadow_rules().
    """
    if early_match == late_match:
        return False  # identical — handled separately

    # For each field late constrains, check that early covers it
    # Fields that late does NOT constrain are irrelevant — late matches
    # any value for those fields, and a missing early constraint (None → any)
    # also covers any value.
    all_fields = set(list(early_match.keys()) + list(late_match.keys()))

    for field in all_fields:
        early_cond = early_match.get(field)   # None if early has no constraint
        late_cond = late_match.get(field)     # None if late has no constraint

        if late_cond is None:
            # Late has no constraint on this field — it matches any value.
            # Early having a constraint here would make early MORE restrictive,
            # so early does NOT shadow late on this dimension.
            # But: if early also has no constraint (or {"any": True}), that's fine —
            # early is at least as broad as late here.
            if early_cond is not None and not (isinstance(early_cond, dict) and early_cond.get("any") is True):
                # Early is more restrictive than late on this field — early cannot
                # shadow late (late matches more inputs on this field than early does).
                return False
            # else: early is None or {"any": True} — both sides are unconstrained → OK
        else:
            # Late has a constraint — early must cover it (be at least as broad)
            if not _condition_covers(early_cond, late_cond):
                return False

    return True


def detect_shadow_rules(rules: List[Rule]) -> List[dict]:
    """
    Detect rules that may shadow later, more specific rules.

    A rule A shadows rule B if A appears before B in the list and A's match
    conditions are semantically a superset of B's — meaning every input that
    would match B also matches A, so B never fires.

    This function understands WCP match operator semantics:
      - {"any": True}   matches any value (wildcard — broadest)
      - {"in": [...]}   matches values in the list
      - "exact_value"   matches only that exact string
      - absent key      treated as unconstrained (same as wildcard for that field)

    PATCH-XSDK-SHADOW-003: Semantic wildcard awareness added.
    A rule with capability_id={"any": True} placed before a rule with
    capability_id={"eq": "cap.secret.delete"} is detected as a shadow
    even though {"any": True} is not a dict-subset of {"eq": "cap.secret.delete"}.

    Returns a list of shadow warnings (dicts with 'shadower', 'shadowed', 'reason').
    Call this at rule-load time to detect misconfiguration.

    Example:
        warnings = detect_shadow_rules(rules)
        for w in warnings:
            print(f"WARNING: rule {w['shadower']} shadows {w['shadowed']}: {w['reason']}")
    """
    warnings_list = []
    for i, early_rule in enumerate(rules):
        for late_rule in rules[i + 1:]:
            early_match = early_rule.match or {}
            late_match = late_rule.match or {}

            # Exact same match conditions = definite duplicate shadow
            if early_match == late_match and early_rule.rule_id != late_rule.rule_id:
                warnings_list.append({
                    "shadower": early_rule.rule_id,
                    "shadowed": late_rule.rule_id,
                    "reason": (
                        f"identical match conditions — rule '{late_rule.rule_id}' "
                        "will never be reached"
                    ),
                })
                continue

            # PATCH-XSDK-SHADOW-003: Semantic shadow detection.
            # Check if early rule's conditions semantically cover (subsume) the
            # late rule's conditions — making the late rule unreachable.
            if _rule_semantically_shadows(early_match, late_match):
                warnings_list.append({
                    "shadower": early_rule.rule_id,
                    "shadowed": late_rule.rule_id,
                    "reason": (
                        f"rule '{early_rule.rule_id}' match={early_match} "
                        f"semantically subsumes '{late_rule.rule_id}' match={late_match} "
                        "(early rule matches a superset of inputs — late rule unreachable)"
                    ),
                })
                continue

            # Legacy structural subset check (dict-level, non-semantic).
            # Catches cases where early_match is a literal dict-subset of late_match
            # that _rule_semantically_shadows() may not handle (defensive redundancy).
            if (
                all(late_match.get(k) == v for k, v in early_match.items())
                and early_match != late_match
                and early_match  # non-empty
            ):
                warnings_list.append({
                    "shadower": early_rule.rule_id,
                    "shadowed": late_rule.rule_id,
                    "reason": (
                        f"rule '{early_rule.rule_id}' match={early_match} "
                        f"subsumes '{late_rule.rule_id}' match={late_match}"
                    ),
                })

    return warnings_list
