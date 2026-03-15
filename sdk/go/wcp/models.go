package wcp

// ---------------------------------------------------------------------------
// Enum-style string types
// Mirrors pyhall/models.py Literal types and src/models.ts union types.
// ---------------------------------------------------------------------------

// Env is the deployment environment.
type Env string

const (
	EnvDev   Env = "dev"
	EnvStage Env = "stage"
	EnvProd  Env = "prod"
	EnvEdge  Env = "edge"
)

// DataLabel is the data sensitivity classification.
type DataLabel string

const (
	DataLabelPublic     DataLabel = "PUBLIC"
	DataLabelInternal   DataLabel = "INTERNAL"
	DataLabelRestricted DataLabel = "RESTRICTED"
)

// QoSClass is the Quality of Service priority class.
// P0 = critical (highest), P3 = background (lowest).
type QoSClass string

const (
	QoSP0 QoSClass = "P0"
	QoSP1 QoSClass = "P1"
	QoSP2 QoSClass = "P2"
	QoSP3 QoSClass = "P3"
)

// TenantRisk is the risk tier of the requesting tenant.
type TenantRisk string

const (
	TenantRiskLow    TenantRisk = "low"
	TenantRiskMedium TenantRisk = "medium"
	TenantRiskHigh   TenantRisk = "high"
)

// ---------------------------------------------------------------------------
// RouteInput — the capability request envelope (WCP spec section 4.1)
// ---------------------------------------------------------------------------

// RouteInput is what the agent sends to the Hall.
// All fields tagged json match the canonical WCP wire format.
type RouteInput struct {
	// CapabilityID is the WCP capability being requested, e.g. "cap.doc.summarize".
	// Must be a registered WCP capability — unknown capabilities are denied.
	CapabilityID string `json:"capability_id"`

	// Env is the deployment environment: dev | stage | prod | edge.
	Env Env `json:"env"`

	// DataLabel is the data sensitivity label: PUBLIC | INTERNAL | RESTRICTED.
	DataLabel DataLabel `json:"data_label"`

	// TenantRisk is the risk tier of the requesting tenant: low | medium | high.
	TenantRisk TenantRisk `json:"tenant_risk"`

	// QoSClass is the Quality of Service priority: P0 (highest) through P3 (background).
	QoSClass QoSClass `json:"qos_class"`

	// TenantID identifies the requesting tenant or system.
	TenantID string `json:"tenant_id"`

	// CorrelationID is a UUID v4 that MUST be propagated through all downstream calls.
	CorrelationID string `json:"correlation_id"`

	// Request is the arbitrary payload for the target worker.
	Request map[string]any `json:"request,omitempty"`

	// BlastRadius is the pre-computed blast radius dimensions, if available.
	// The router computes blast score from this if BlastScore is nil.
	BlastRadius map[string]any `json:"blast_radius,omitempty"`

	// BlastScore is the pre-computed blast score (0–100).
	// Router computes it from BlastRadius if nil.
	BlastScore *int `json:"blast_score,omitempty"`

	// PrivilegeContext holds privilege context for envelope enforcement.
	PrivilegeContext map[string]any `json:"privilege_context,omitempty"`

	// DryRun: if true, the full routing decision is made but no worker is executed.
	// Every WCP router MUST support dry-run (WCP section 5.5).
	DryRun bool `json:"dry_run"`
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

// CandidateWorker is a worker species candidate considered during routing.
type CandidateWorker struct {
	// WorkerSpeciesID is the WCP worker species ID, e.g. "wrk.doc.summarizer".
	WorkerSpeciesID string `json:"worker_species_id"`

	// ScoreHint is an optional pre-ranked score from the rules engine.
	ScoreHint *float64 `json:"score_hint,omitempty"`

	// RequiresControlsMinimum lists the minimum controls this candidate requires.
	RequiresControlsMinimum []string `json:"requires_controls_minimum,omitempty"`

	// SkipReason is populated when this candidate was considered but not selected.
	SkipReason *string `json:"skip_reason,omitempty"`
}

// Escalation is the escalation policy from the matched routing rule.
type Escalation struct {
	// PolicyGate: whether the policy gate must be evaluated.
	PolicyGate bool `json:"policy_gate"`

	// MSAVXStepUp: whether MSAVX step-up approval is required.
	MSAVXStepUp bool `json:"msavx_step_up"`

	// HumanRequiredDefault: whether human review is required by default.
	HumanRequiredDefault bool `json:"human_required_default"`

	// HumanRequiredIf holds conditional human review triggers.
	HumanRequiredIf []map[string]any `json:"human_required_if,omitempty"`

	// Rationale is the reason for the escalation requirement.
	Rationale *string `json:"rationale,omitempty"`
}

// PreconditionsChecked records the precondition flags applied during routing.
type PreconditionsChecked struct {
	// MustHaveCorrelationID: deny if correlation_id is absent or empty.
	MustHaveCorrelationID bool `json:"must_have_correlation_id"`

	// MustAttachPolicyVersion: policy version must be propagated.
	MustAttachPolicyVersion bool `json:"must_attach_policy_version"`

	// MustRecordArtifactHashIfExecutes: SHA-256 of request payload must be recorded.
	MustRecordArtifactHashIfExecutes bool `json:"must_record_artifact_hash_if_executes"`

	// DenyIfMissingRequiredControls: deny dispatch if required controls absent.
	DenyIfMissingRequiredControls bool `json:"deny_if_missing_required_controls"`

	// DenyIfUnsignedArtifactInProd: deny unsigned artifacts in production (WCP-Full).
	DenyIfUnsignedArtifactInProd bool `json:"deny_if_unsigned_artifact_in_prod"`

	// DenyIfNoAttestationInProd: deny workers without attestation in production.
	DenyIfNoAttestationInProd bool `json:"deny_if_no_attestation_in_prod"`
}

// ---------------------------------------------------------------------------
// RouteDecision — the routing decision returned by the Hall (WCP section 4.2)
// ---------------------------------------------------------------------------

// RouteDecision is what the Hall returns after evaluating a RouteInput.
//
// On allow: Denied=false, SelectedWorkerSpeciesID is set.
// On deny:  Denied=true,  DenyReasonIfDenied is set.
//
// All decisions — allowed or denied — include TelemetryEnvelopes.
type RouteDecision struct {
	// DecisionID is a UUID v4 identifying this specific routing decision.
	DecisionID string `json:"decision_id"`

	// Timestamp is the ISO 8601 UTC timestamp of the decision.
	Timestamp string `json:"timestamp"`

	// CorrelationID is propagated from RouteInput.CorrelationID.
	CorrelationID string `json:"correlation_id"`

	// TenantID is propagated from RouteInput.TenantID.
	TenantID string `json:"tenant_id"`

	// CapabilityID is the capability that was requested.
	CapabilityID string `json:"capability_id"`

	// MatchedRuleID is the routing rule that matched.
	// Set to "NO_MATCH" if no rule matched (which always means denied=true).
	MatchedRuleID string `json:"matched_rule_id"`

	Env        Env        `json:"env"`
	DataLabel  DataLabel  `json:"data_label"`
	TenantRisk TenantRisk `json:"tenant_risk"`
	QoSClass   QoSClass   `json:"qos_class"`

	// Decision outcome
	Denied              bool           `json:"denied"`
	DenyReasonIfDenied  map[string]any `json:"deny_reason_if_denied,omitempty"`

	// Selected worker
	SelectedWorkerSpeciesID  *string           `json:"selected_worker_species_id,omitempty"`
	CandidateWorkersRanked   []CandidateWorker `json:"candidate_workers_ranked"`

	// Governance state
	RequiredControlsEffective    []string         `json:"required_controls_effective"`
	RecommendedProfilesEffective []map[string]any `json:"recommended_profiles_effective"`
	EscalationEffective          Escalation       `json:"escalation_effective"`
	PreconditionsChecked         PreconditionsChecked `json:"preconditions_checked"`

	// ArtifactHash is the SHA-256 of the serialized RouteInput.
	// Proves what was routed. Required for WCP evidence receipts (section 5.7).
	ArtifactHash *string `json:"artifact_hash,omitempty"`

	// DryRun mirrors RouteInput.DryRun. When true, this decision was produced by a
	// dry-run probe — no worker was dispatched. Callers and audit consumers MUST use
	// this field to distinguish probes from real dispatches (WCP section 5.5).
	// GO-F5 fix: field was missing; dry_run was never propagated.
	DryRun bool `json:"dry_run"`

	// WorkerAttestationChecked is true when the Hall verified the worker code hash
	// during this routing decision. False means attestation was not configured or
	// was not required — not necessarily a problem in dev/stage environments.
	// WCP §5.10.
	WorkerAttestationChecked bool `json:"worker_attestation_checked"`

	// WorkerAttestationValid is nil when attestation was not checked, true when the
	// current on-disk hash matched the registered hash, and false when a mismatch
	// was detected (TAMPERED). Consumers MUST treat false as a security signal.
	// WCP §5.10.
	WorkerAttestationValid *bool `json:"worker_attestation_valid,omitempty"`

	// TelemetryEnvelopes contains the mandatory telemetry events (WCP section 5.4).
	// Every decision must emit: evt.os.task.routed, evt.os.worker.selected, evt.os.policy.gated.
	TelemetryEnvelopes []map[string]any `json:"telemetry_envelopes"`
}

// ---------------------------------------------------------------------------
// Worker registry record (WCP spec section 6)
// ---------------------------------------------------------------------------

// WorkerRegistryRecord is the enrollment record a worker submits to the Hall.
type WorkerRegistryRecord struct {
	// WorkerID is the unique instance ID for this worker deployment.
	// Convention: "org.<name>.<descriptor>", e.g. "org.fafolab.doc-summarizer"
	WorkerID string `json:"worker_id"`

	// WorkerSpeciesID is the WCP worker class, e.g. "wrk.doc.summarizer".
	WorkerSpeciesID string `json:"worker_species_id"`

	// Capabilities lists all WCP capability IDs this worker can fulfill.
	Capabilities []string `json:"capabilities"`

	// RiskTier is the worker's self-declared risk level: low | medium | high.
	RiskTier string `json:"risk_tier,omitempty"`

	// RequiredControls lists controls the router must verify before dispatch.
	RequiredControls []string `json:"required_controls,omitempty"`

	// CurrentlyImplements lists controls this worker actually implements.
	CurrentlyImplements []string `json:"currently_implements,omitempty"`

	// AllowedEnvironments restricts which envs this worker may run in.
	AllowedEnvironments []string `json:"allowed_environments,omitempty"`

	// BlastRadius is the pre-declared blast radius dimensions (WCP section 7).
	BlastRadius map[string]any `json:"blast_radius,omitempty"`

	// PrivilegeEnvelope declares secrets, network, filesystem, and tool access.
	PrivilegeEnvelope *PrivilegeEnvelope `json:"privilege_envelope,omitempty"`

	// Owner is the org/team responsible for this worker.
	Owner string `json:"owner,omitempty"`

	// Contact is the owner's contact information.
	Contact string `json:"contact,omitempty"`

	// Notes are free-form notes about this worker.
	Notes string `json:"notes,omitempty"`

	// CatalogVersionMin is the minimum WCP catalog version this worker supports.
	CatalogVersionMin string `json:"catalog_version_min,omitempty"`

	// ArtifactHash is the SHA-256 of this registry record at enrollment time.
	ArtifactHash string `json:"artifact_hash,omitempty"`
}

// PrivilegeEnvelope declares the privilege boundaries for a worker.
type PrivilegeEnvelope struct {
	// SecretsAccess lists secret names the worker may access. Empty = none.
	SecretsAccess []string `json:"secrets_access,omitempty"`

	// NetworkEgress describes the egress policy: "none", "allowlisted", "unrestricted".
	NetworkEgress string `json:"network_egress,omitempty"`

	// FilesystemWrites lists paths the worker may write to. Empty = no writes.
	FilesystemWrites []string `json:"filesystem_writes,omitempty"`

	// Tools lists external tools the worker may invoke, e.g. "ollama-embed".
	Tools []string `json:"tools,omitempty"`

	// Egress holds additional egress configuration.
	Egress map[string]any `json:"egress,omitempty"`
}
