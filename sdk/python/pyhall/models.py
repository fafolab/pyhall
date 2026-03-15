"""
pyhall/models.py — WCP routing envelope models.

RouteInput  — what the agent sends to the Hall.
RouteDecision — what the Hall returns.

These are the core data contracts of the Worker Class Protocol.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Enum-style type aliases (Pydantic Literal)
# ---------------------------------------------------------------------------

Env = Literal["dev", "stage", "prod", "edge"]
DataLabel = Literal["PUBLIC", "INTERNAL", "RESTRICTED"]
QoSClass = Literal["P0", "P1", "P2", "P3"]
TenantRisk = Literal["low", "medium", "high"]


# ---------------------------------------------------------------------------
# RouteInput
# ---------------------------------------------------------------------------

class RouteInput(BaseModel):
    """
    The capability request envelope sent to the Hall.

    Required fields follow the WCP spec section 4.1.
    """

    capability_id: str
    """The WCP capability being requested, e.g. 'cap.doc.summarize'."""

    env: Env
    """Deployment environment: dev | stage | prod | edge."""

    data_label: DataLabel
    """Data sensitivity label: PUBLIC | INTERNAL | RESTRICTED."""

    tenant_risk: TenantRisk
    """Risk tier of the requesting tenant: low | medium | high."""

    qos_class: QoSClass
    """Quality of Service priority: P0 (highest) through P3 (background)."""

    tenant_id: str
    """Identifier of the requesting tenant or system."""

    @field_validator("tenant_id", mode="before")
    @classmethod
    def reject_empty_tenant_id(cls, v):
        # PATCH-XSDK-TENANT-004: Reject blank strings at model construction time.
        # The router enforces the same check to catch cases where tenant_id is
        # set after construction or comes through a path that bypasses the validator.
        # Both layers are needed for defense-in-depth.
        if isinstance(v, str) and not v.strip():
            raise ValueError("tenant_id must not be empty or whitespace")
        return v

    correlation_id: str
    """UUID v4 correlation ID. Must be propagated through all downstream calls."""

    request: Dict[str, Any] = Field(default_factory=dict)
    """Arbitrary payload for the target worker."""

    # Governance preflight inputs (WCP-Full — blast radius + privilege)
    blast_radius: Optional[Dict[str, Any]] = None
    """Pre-computed blast radius dimensions if available."""

    blast_score: Optional[int] = None
    """Pre-computed blast score (0–100). Router computes it if None."""

    @field_validator("blast_score", mode="before")
    @classmethod
    def reject_bool_blast_score(cls, v):
        # F25: bool is a subclass of int in Python — reject it explicitly to prevent
        # True/False silently being treated as 1/0 blast scores.
        if isinstance(v, bool):
            raise ValueError("blast_score must be an int or None, not bool")
        return v

    privilege_context: Optional[Dict[str, Any]] = None
    """Privilege context for envelope enforcement."""

    dry_run: bool = False
    """If True, the full routing decision is made but no worker is executed."""

    tenant_credential: Optional[str] = None
    """
    Signed WCP credential issued by pyhall.dev.
    Optional in v0.1 (allowlist-only signatory enforcement).
    Required when HallConfig.require_credential is True (v0.2+).
    Format: signed JSON token (JWT-style) issued at tenant registration.
    """


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------

class CandidateWorker(BaseModel):
    """A worker species candidate considered during routing."""

    worker_species_id: str
    """WCP worker species ID, e.g. 'wrk.doc.summarizer'."""

    score_hint: Optional[float] = None
    """Optional pre-ranked score from the rules engine."""

    requires_controls_minimum: Optional[List[str]] = None
    """Minimum controls this candidate requires."""

    skip_reason: Optional[str] = None
    """Populated when this candidate was considered but not selected."""


class Escalation(BaseModel):
    """Escalation policy from the matched routing rule."""

    policy_gate: bool = False
    """Whether the policy gate must be evaluated."""

    msavx_step_up: bool = False
    """Whether MSAVX step-up approval is required."""

    human_required_default: bool = False
    """Whether human review is required by default."""

    human_required_if: List[Dict[str, Any]] = Field(default_factory=list)
    """Conditional human review triggers."""

    rationale: Optional[str] = None
    """Reason for escalation requirement."""


class HallConfig(BaseModel):
    """
    Hall-level configuration.

    Passed to make_decision() to apply Hall-wide policy independent
    of individual routing rules.

    See WCP spec §5.9 Signatory Tenant Validation.
    """

    require_signatory: bool = False
    """
    When True, deny any RouteInput whose tenant_id is not in allowed_tenants.
    Default: False (dev mode — any tenant accepted).
    WCP-Full compliance requires this set to True in production.
    """

    allowed_tenants: List[str] = Field(default_factory=list)
    """
    List of registered signatory tenant IDs.
    Only enforced when require_signatory is True.
    Example: ["mcp.my-app", "agent.orchestrator", "x.acme.deploy-bot"]
    """

    require_credential: bool = False
    """
    NOT YET ENFORCED in v0.1 — credential validation is planned for v0.2.
    Setting this to True currently emits a runtime warning but does NOT deny requests.
    WCP-Full compliance requires this set to True in production (v0.2+).
    """

    require_worker_attestation: bool = False
    """
    When True, the Hall verifies each candidate worker's code hash against
    the registered attestation hash before dispatch.
    A hash mismatch → DENY_WORKER_TAMPERED and the worker is flagged.
    WCP-Full compliance requires this set to True in production.
    See WCP spec §5.10.
    """

    enforce_correlation_id: bool = True
    """
    When True, the Hall requires a valid correlation_id on every request
    regardless of what individual routing rules declare in their preconditions.
    Rules cannot lower this below the Hall's floor.
    Default: True. Set to False only for testing.
    """

    enforce_required_controls: bool = True
    """
    When True, the Hall enforces required controls check regardless of what
    individual routing rules declare in their preconditions.
    Rules cannot lower this below the Hall's floor.
    Default: True. Set to False only for testing.
    """

    enforce_blast_scoring_in_prod: bool = True
    """
    F18: When True and env is 'prod' or 'edge', blast scoring gate is enforced
    regardless of whether the matched rule includes 'ctrl.blast_radius_scoring'
    in required_controls. Rules cannot lower this floor.
    Default: True. Set to False only for testing.
    """

    enforce_privilege_envelopes: bool = False
    """
    F19: When True, privilege envelope enforcement is applied regardless of
    whether the matched rule includes 'ctrl.privilege_envelopes_required' in
    required_controls.
    Default: False (privilege enforcement is opt-in per rule in v0.1).
    """


class PreconditionsChecked(BaseModel):
    """Precondition flags applied during routing."""

    must_have_correlation_id: bool = True
    """Deny if correlation_id is absent or empty."""

    must_attach_policy_version: bool = True
    """Policy version must be propagated."""

    must_record_artifact_hash_if_executes: bool = True
    """SHA-256 of request payload must be recorded on execution."""

    deny_if_missing_required_controls: bool = True
    """Deny dispatch if declared required controls are not present in registry."""

    deny_if_unsigned_artifact_in_prod: bool = False
    """Deny unsigned artifacts in production (WCP-Full)."""

    deny_if_no_attestation_in_prod: bool = False
    """Deny workers without attestation records in production."""


# ---------------------------------------------------------------------------
# RouteDecision
# ---------------------------------------------------------------------------

class RouteDecision(BaseModel):
    """
    The routing decision returned by the Hall.

    On success: denied=False, selected_worker_species_id is set.
    On denial:  denied=True,  deny_reason_if_denied is set.

    All decisions — allowed or denied — include telemetry_envelopes.
    """

    decision_id: str
    """UUID v4 identifying this specific routing decision."""

    timestamp: str
    """ISO 8601 UTC timestamp of the decision."""

    correlation_id: str
    """Propagated from RouteInput.correlation_id."""

    tenant_id: str
    """Propagated from RouteInput.tenant_id."""

    capability_id: str
    """The capability that was requested."""

    matched_rule_id: str
    """The routing rule that matched. 'NO_MATCH' if none matched."""

    env: Env
    data_label: DataLabel
    tenant_risk: TenantRisk
    qos_class: QoSClass

    # Decision outcome
    denied: bool = False
    deny_reason_if_denied: Optional[Dict[str, Any]] = None

    # Selected worker
    selected_worker_species_id: Optional[str] = None
    candidate_workers_ranked: List[CandidateWorker] = Field(default_factory=list)

    # Governance state
    required_controls_effective: List[str] = Field(default_factory=list)
    recommended_profiles_effective: List[Dict[str, Any]] = Field(default_factory=list)
    escalation_effective: Escalation = Field(default_factory=Escalation)
    preconditions_checked: PreconditionsChecked = Field(default_factory=PreconditionsChecked)

    # Provenance (WCP governance spine)
    artifact_hash: Optional[str] = None
    """SHA-256 of the serialized RouteInput (sort_keys=True). Proves what was routed."""

    # Worker Code Attestation (WCP §5.10)
    worker_attestation_checked: bool = False
    """True when Hall verified worker code hash against registered attestation."""

    worker_attestation_valid: Optional[bool] = None
    """True = hash matched. False = TAMPERED. None = attestation not checked."""

    # Dry-run flag (WCP §5.5)
    dry_run: bool = False
    """True when this decision was made in dry-run mode — no worker was dispatched."""

    # Mandatory telemetry (WCP section 5.4)
    telemetry_envelopes: List[Dict[str, Any]] = Field(default_factory=list)
