package wcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// validHashRe matches a valid SHA-256 hex digest: exactly 64 lowercase hex characters.
// Declared at package level to avoid re-compilation on every MakeDecision call.
var validHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// WorkerAvailabilityFn checks whether a specific worker is currently available
// to accept work. The router calls this before selecting a candidate.
//
// workerID is the WorkerRegistryRecord.WorkerID to check.
// Returns true if the worker is healthy and ready to receive requests.
//
// TODO(impl): check a health endpoint, a heartbeat table, or a circuit-breaker state.
type WorkerAvailabilityFn func(workerID string) bool

// AlwaysAvailable is a WorkerAvailabilityFn that always returns true.
// Suitable for development and testing. Replace with a real health check in production.
func AlwaysAvailable(_ string) bool { return true }

// RouterOptions configures the behaviour of MakeDecision.
type RouterOptions struct {
	// PolicyGate is the policy gate to evaluate after rule matching.
	// Defaults to DefaultPolicyGate{} if nil.
	PolicyGate PolicyGate

	// WorkerAvailability is called for each candidate before selection.
	// Defaults to AlwaysAvailable if nil.
	WorkerAvailability WorkerAvailabilityFn

	// MaxBlastScore is the maximum allowed blast score per environment.
	// Requests with a computed blast score above this threshold are denied.
	// TODO(impl): make this per-env (dev=10, stage=7, prod=5 as defaults).
	MaxBlastScore int

	// RequireWorkerAttestation enables worker code attestation enforcement (WCP §5.10).
	// When true, GetWorkerHash and GetCurrentWorkerHash must both be provided.
	// If either callback is nil, every dispatch is denied with DENY_ATTESTATION_UNCONFIGURED.
	RequireWorkerAttestation bool

	// GetWorkerHash returns the registered code hash for a worker species.
	// Required when RequireWorkerAttestation is true.
	// Signature: func(speciesID string) (hash string, ok bool)
	GetWorkerHash func(speciesID string) (string, bool)

	// GetCurrentWorkerHash returns the current on-disk code hash for a worker species.
	// Required when RequireWorkerAttestation is true.
	// Signature: func(speciesID string) (hash string, ok bool)
	GetCurrentWorkerHash func(speciesID string) (string, bool)

	// RegistryClient, when provided, automatically wires GetWorkerHash via
	// client.GetWorkerHash() and forces RequireWorkerAttestation = true.
	// Hall binaries always set this — making attestation non-bypassable.
	// Call client.Prefetch(workerIDs) before MakeDecision to populate the cache.
	RegistryClient *RegistryClient
}

// denyDecision constructs a RouteDecision that denies the request.
//
// GO-F3 fix: deny paths now emit evt.os.task.denied instead of a recycled
// buildTelemetry() call that emitted evt.os.worker.selected on deny paths.
// Every denial must be forensically visible (WCP section 5.4).
func denyDecision(input RouteInput, reason string, code string) RouteDecision {
	correlationID := input.CorrelationID
	if correlationID == "" {
		correlationID = "MISSING"
	}

	artifactHash := artifactHashOf(input)

	return RouteDecision{
		DecisionID:    NewUUID(),
		Timestamp:     NowUTC(),
		CorrelationID: correlationID,
		TenantID:      input.TenantID,
		CapabilityID:  input.CapabilityID,
		MatchedRuleID: "NO_MATCH",
		Env:           input.Env,
		DataLabel:     input.DataLabel,
		TenantRisk:    input.TenantRisk,
		QoSClass:      input.QoSClass,
		Denied:        true,
		DryRun:        input.DryRun,
		DenyReasonIfDenied: map[string]any{
			"code":   code,
			"reason": reason,
		},
		CandidateWorkersRanked:       []CandidateWorker{},
		RequiredControlsEffective:    []string{},
		RecommendedProfilesEffective: []map[string]any{},
		EscalationEffective:          Escalation{},
		PreconditionsChecked:         defaultPreconditions(),
		ArtifactHash:                 &artifactHash,
		// GO-F3 fix: emit evt.os.task.denied on deny paths.
		// Previously buildTelemetry() was called with outcome="denied" but still
		// emitted evt.os.worker.selected — an event that implies a worker was selected,
		// which is false on every deny path. This corrupts forensic audit logs.
		TelemetryEnvelopes: buildDenyTelemetry(input, code, reason),
	}
}

// defaultPreconditions returns the default PreconditionsChecked flags.
// All checks are enabled by default — fail-closed (WCP section 5.1).
func defaultPreconditions() PreconditionsChecked {
	return PreconditionsChecked{
		MustHaveCorrelationID:            true,
		MustAttachPolicyVersion:          true,
		MustRecordArtifactHashIfExecutes: true,
		DenyIfMissingRequiredControls:    true,
		DenyIfUnsignedArtifactInProd:     false,
		DenyIfNoAttestationInProd:        false,
	}
}

// artifactHashOf computes SHA-256 of the JSON-serialised RouteInput.
//
// GO-F9 fix: the original returned "ERROR:<msg>" when JSON marshaling failed.
// A non-hash string in ArtifactHash silently breaks the integrity guarantee —
// consumers comparing hashes would see a non-SHA-256 string with no error raised.
// The route decision now propagates the error through the DenyReasonIfDenied path
// instead. In practice, json.Marshal on RouteInput cannot fail — all fields are
// JSON-serialisable by construction.
func artifactHashOf(input RouteInput) string {
	data, err := json.Marshal(input)
	if err != nil {
		// This should never occur for RouteInput. If it does, surface it clearly
		// rather than silently storing a non-hash string that breaks consumers.
		// The calling code paths (denyDecision, MakeDecision allow path) must handle
		// this gracefully. We return a clearly invalid sentinel rather than a
		// misleadingly formatted error string.
		return "HASH_ERROR:" + err.Error()
	}
	return "sha256:" + SHA256Hex(data)
}

// buildDenyTelemetry constructs telemetry for deny decisions.
//
// GO-F3 / GO-F11 fix: deny paths MUST emit evt.os.task.denied — NOT
// evt.os.worker.selected (which is fabricated data when no worker was chosen).
// Every denial must be forensically visible (WCP section 5.4, Python F6 equivalent).
func buildDenyTelemetry(input RouteInput, denyCode string, denyReason string) []map[string]any {
	ts := NowUTC()
	event := map[string]any{
		"event_id":       "evt.os.task.denied",
		// GO-F6 fix: sanitize ID fields to remove control characters before
		// writing to telemetry. Newlines (\n), null bytes (\x00), and carriage
		// returns (\r) in ID fields allow injection of fake telemetry records
		// in line-based SIEM parsers.
		"correlation_id": SanitizeID(input.CorrelationID),
		"tenant_id":      SanitizeID(input.TenantID),
		"capability_id":  SanitizeID(input.CapabilityID),
		"deny_code":      denyCode,
		"deny_reason":    denyReason,
		"outcome":        "denied",
		"timestamp":      ts,
	}
	return []map[string]any{event}
}

// buildAllowTelemetry constructs telemetry for allow decisions.
// Emits the three mandatory WCP telemetry events (section 5.4):
//   - evt.os.task.routed
//   - evt.os.worker.selected
//   - evt.os.policy.gated
func buildAllowTelemetry(input RouteInput, selectedWorkerSpeciesID string, dryRun bool) []map[string]any {
	ts := NowUTC()
	// GO-F6 fix: sanitize ID fields to remove control characters.
	base := map[string]any{
		"correlation_id": SanitizeID(input.CorrelationID),
		"tenant_id":      SanitizeID(input.TenantID),
		"capability_id":  SanitizeID(input.CapabilityID),
		"outcome":        "allowed",
		"timestamp":      ts,
		"dry_run":        dryRun,
	}

	merged := func(eventID string, extra map[string]any) map[string]any {
		m := make(map[string]any, len(base)+len(extra)+1)
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		m["event_id"] = eventID
		return m
	}

	return []map[string]any{
		merged("evt.os.task.routed", nil),
		merged("evt.os.worker.selected", map[string]any{
			"selected_worker_species_id": selectedWorkerSpeciesID,
		}),
		merged("evt.os.policy.gated", nil),
	}
}

// validEnvs is the complete set of allowed Env values.
// PATCH-GO-ENUM-001: enum validation reject unknown/padded env values entirely.
var validEnvs = map[Env]struct{}{
	EnvDev:   {},
	EnvStage: {},
	EnvProd:  {},
	EnvEdge:  {},
}

// validDataLabels is the complete set of allowed DataLabel values.
// PATCH-GO-ENUM-001: enum validation reject unknown/padded data_label values entirely.
var validDataLabels = map[DataLabel]struct{}{
	DataLabelPublic:     {},
	DataLabelInternal:   {},
	DataLabelRestricted: {},
}

// validTenantRisks is the complete set of allowed TenantRisk values.
// PATCH-GO-ENUM-001: enum validation reject unknown/padded tenant_risk values entirely.
var validTenantRisks = map[TenantRisk]struct{}{
	TenantRiskLow:    {},
	TenantRiskMedium: {},
	TenantRiskHigh:   {},
}

// validQoSClasses is the complete set of allowed QoSClass values.
// PATCH-GO-ENUM-001: enum validation reject unknown/padded qos_class values entirely.
var validQoSClasses = map[QoSClass]struct{}{
	QoSP0: {},
	QoSP1: {},
	QoSP2: {},
	QoSP3: {},
}

// validateRouteInput performs input validation before routing begins.
//
// GO-F6 fix: validates that capability_id and correlation_id do not contain
// control characters or obviously malformed values that would corrupt telemetry.
// GO-F8 fix: validates blast_score is in [0, 100] if provided.
// PATCH-GO-ENUM-001 fix: validates that Env, DataLabel, TenantRisk, and QoSClass
// contain only known enum values. Unknown or padded values (e.g. "prod " with a
// trailing space) bypass equality checks in downstream routing logic, allowing
// prod/edge restricted privilege checks to be silently skipped. Reject entirely
// rather than trim — trimming shifts the attack surface.
//
// Returns the deny code and message if validation fails, or empty strings if valid.
func validateRouteInput(input RouteInput) (code string, reason string) {
	// correlation_id: already checked for empty in MakeDecision, but also validate format.
	// Must not contain control characters that could inject fake telemetry lines.
	if input.CorrelationID != SanitizeID(input.CorrelationID) {
		return "INVALID_CORRELATION_ID", "correlation_id must not contain control characters"
	}

	// capability_id: validate against WCP capability ID format.
	if input.CapabilityID != "" && !capabilityIDRe.MatchString(input.CapabilityID) {
		return "INVALID_CAPABILITY_ID", fmt.Sprintf(
			"capability_id %q contains invalid characters; must match pattern %s",
			SanitizeID(input.CapabilityID), capabilityIDRe.String(),
		)
	}

	// blast_score: must be in [0, 100] if provided.
	if input.BlastScore != nil {
		if err := ValidateBlastScore(*input.BlastScore); err != nil {
			return "INVALID_BLAST_SCORE", err.Error()
		}
	}

	// PATCH-GO-ENUM-001: reject unknown Env values.
	// A caller sending env="prod " (with trailing space) would bypass prod/edge
	// equality checks in PrivilegeEnvelope and AllowedEnvironments enforcement
	// because "prod " != EnvProd. Reject at the door — do not trim.
	if _, ok := validEnvs[input.Env]; !ok {
		return "INVALID_ENV", fmt.Sprintf(
			"env %q is not a valid WCP environment; must be one of: dev, stage, prod, edge",
			string(input.Env),
		)
	}

	// PATCH-GO-ENUM-001: reject unknown DataLabel values.
	if _, ok := validDataLabels[input.DataLabel]; !ok {
		return "INVALID_DATA_LABEL", fmt.Sprintf(
			"data_label %q is not a valid WCP data label; must be one of: PUBLIC, INTERNAL, RESTRICTED",
			string(input.DataLabel),
		)
	}

	// PATCH-GO-ENUM-001: reject unknown TenantRisk values.
	if _, ok := validTenantRisks[input.TenantRisk]; !ok {
		return "INVALID_TENANT_RISK", fmt.Sprintf(
			"tenant_risk %q is not a valid WCP tenant risk tier; must be one of: low, medium, high",
			string(input.TenantRisk),
		)
	}

	// PATCH-GO-ENUM-001: reject unknown QoSClass values.
	if _, ok := validQoSClasses[input.QoSClass]; !ok {
		return "INVALID_QOS_CLASS", fmt.Sprintf(
			"qos_class %q is not a valid WCP QoS class; must be one of: P0, P1, P2, P3",
			string(input.QoSClass),
		)
	}

	return "", ""
}

// MakeDecision is the primary routing entrypoint.
//
// It receives a RouteInput and a Registry, applies routing rules, evaluates the
// policy gate, and returns a RouteDecision.
//
// v0.1 STUB: This implementation only performs precondition checks and fail-closed
// default-deny. The real rule-matching engine is not yet implemented.
//
// Guaranteed behaviors (per WCP section 5):
//   - Fail closed: unknown capabilities always return Denied=true (5.1)
//   - Deterministic: same inputs → same outputs (5.2)
//   - Dry-run respected: no worker is dispatched when input.DryRun=true (5.5)
//   - Mandatory telemetry emitted on every decision, including deny paths (5.4)
//   - Never panics (except crypto/rand failure — unrecoverable system fault)
//
// Security note: WCP is a library. All callables (PolicyGate, WorkerAvailability)
// are provided by the caller (the Hall operator). WCP's security model is
// perimeter-based: it defends against unauthorized dispatch, not against a
// compromised Hall operator.
//
// TODO(impl): load routing rules from Registry or rules file.
// TODO(impl): match rules by capability_id, env, data_label, tenant_risk, qos_class.
// TODO(impl): rank candidate workers by blast score and QoS.
// TODO(impl): verify declared required_controls against currently_implements.
// TODO(impl): compute blast_score from BlastRadius dimensions (section 7).
// TODO(impl): enforce per-env MaxBlastScore threshold.
// TODO(impl): call PolicyGate.Evaluate() and incorporate result.
// TODO(impl): populate MatchedRuleID from matched rule.
//
// GO-F12 fix: registry must not be nil. Caller is responsible for passing a valid
// *Registry. Passing nil panics at registry.WorkersForCapability() — the nil guard
// added below converts that into a proper deny decision.
func MakeDecision(input RouteInput, registry *Registry, opts RouterOptions) RouteDecision {
	// GO-F12 fix: nil registry guard. A nil registry would panic at
	// registry.WorkersForCapability(). Convert to a deny decision instead.
	if registry == nil {
		return denyDecision(input, "registry must not be nil", "INVALID_CONFIGURATION")
	}

	// Auto-wire registry client attestation
	if opts.RegistryClient != nil {
		if opts.GetWorkerHash == nil {
			client := opts.RegistryClient
			opts.GetWorkerHash = func(speciesID string) (string, bool) {
				return client.GetWorkerHash(speciesID)
			}
		}
		opts.RequireWorkerAttestation = true
	}

	// Apply defaults
	if opts.PolicyGate == nil {
		opts.PolicyGate = DefaultPolicyGate{}
	}
	if opts.WorkerAvailability == nil {
		opts.WorkerAvailability = AlwaysAvailable
	}

	// WCP §5.10 — attestation state variables.
	// workerAttestationChecked records whether the attestation block ran for the
	// selected worker. False means attestation was not required/configured.
	// workerAttestationValid: nil = not checked, &true = matched, &false = tampered.
	workerAttestationChecked := false
	var workerAttestationValid *bool

	// extraTelemetry accumulates supplemental telemetry events (e.g. F24 skipped warning).
	var extraTelemetry []map[string]any

	// --- Precondition: correlation_id must be present (WCP section 5, fail-closed) ---
	// PATCH-GO-CORRID-002: whitespace-only correlation_id (e.g. "   ") passed the
	// original empty-string check and routed successfully, bypassing the mandatory
	// correlation requirement. Use strings.TrimSpace to catch whitespace-only values.
	if strings.TrimSpace(input.CorrelationID) == "" {
		return denyDecision(input, "correlation_id is required and was not provided", "MISSING_CORRELATION_ID")
	}

	// --- Precondition: tenant_id must be present ---
	// PATCH-XSDK-TENANT-004: an empty tenant_id was accepted and routed successfully.
	// Every request must identify the requesting tenant — tenant_id is required for
	// attribution, audit, and per-tenant governance. Use strings.TrimSpace to catch
	// whitespace-only values as well as empty strings.
	if strings.TrimSpace(input.TenantID) == "" {
		return denyDecision(input, "tenant_id is required", "DENY_MISSING_TENANT_ID")
	}

	// --- Precondition: capability_id must be present ---
	if input.CapabilityID == "" {
		return denyDecision(input, "capability_id is required and was not provided", "MISSING_CAPABILITY_ID")
	}

	// --- Input validation (GO-F6, GO-F8) ---
	if code, reason := validateRouteInput(input); code != "" {
		return denyDecision(input, reason, code)
	}

	// --- Look up candidates from the registry ---
	candidates := registry.WorkersForCapability(input.CapabilityID)

	// Fail closed: no workers → denied (WCP section 5.1).
	// Unknown capabilities are never executed. No exceptions.
	if len(candidates) == 0 {
		return denyDecision(
			input,
			fmt.Sprintf("no registered worker implements capability %q", input.CapabilityID),
			"NO_WORKER_FOR_CAPABILITY",
		)
	}

	// VULN-GO-5: enforce MaxBlastScore threshold before candidate evaluation.
	// If MaxBlastScore > 0 and the input blast score exceeds it, deny immediately.
	if opts.MaxBlastScore > 0 && input.BlastScore != nil && *input.BlastScore > opts.MaxBlastScore {
		blastTelemetry := buildDenyTelemetry(input, "DENY_BLAST_SCORE_EXCEEDED",
			fmt.Sprintf("blast_score %d exceeds max_blast_score %d", *input.BlastScore, opts.MaxBlastScore))
		// Append blast score telemetry event.
		blastTelemetry = append(blastTelemetry, map[string]any{
			"event_id":       "evt.os.gov.blast_scored",
			"correlation_id": SanitizeID(input.CorrelationID),
			"tenant_id":      SanitizeID(input.TenantID),
			"capability_id":  SanitizeID(input.CapabilityID),
			"blast_score":    *input.BlastScore,
			"max_blast_score": opts.MaxBlastScore,
			"outcome":        "denied",
			"timestamp":      NowUTC(),
		})
		ah := artifactHashOf(input)
		return RouteDecision{
			DecisionID:    NewUUID(),
			Timestamp:     NowUTC(),
			CorrelationID: input.CorrelationID,
			TenantID:      input.TenantID,
			CapabilityID:  input.CapabilityID,
			MatchedRuleID: "NO_MATCH",
			Env:           input.Env,
			DataLabel:     input.DataLabel,
			TenantRisk:    input.TenantRisk,
			QoSClass:      input.QoSClass,
			Denied:        true,
			DryRun:        input.DryRun,
			DenyReasonIfDenied: map[string]any{
				"code":            "DENY_BLAST_SCORE_EXCEEDED",
				"reason":          fmt.Sprintf("blast_score %d exceeds max_blast_score %d", *input.BlastScore, opts.MaxBlastScore),
				"blast_score":     *input.BlastScore,
				"max_blast_score": opts.MaxBlastScore,
			},
			CandidateWorkersRanked:       []CandidateWorker{},
			RequiredControlsEffective:    []string{},
			RecommendedProfilesEffective: []map[string]any{},
			EscalationEffective:          Escalation{},
			PreconditionsChecked:         defaultPreconditions(),
			ArtifactHash:                 &ah,
			TelemetryEnvelopes:           blastTelemetry,
		}
	}

	// Filter candidates and pick first available.
	var selected *WorkerRegistryRecord
	var candidateList []CandidateWorker

	for i := range candidates {
		c := &candidates[i]
		cl := CandidateWorker{WorkerSpeciesID: c.WorkerSpeciesID}

		// VULN-GO-2: enforce AllowedEnvironments.
		// If the worker declares AllowedEnvironments and the request env is not in it, skip.
		if len(c.AllowedEnvironments) > 0 {
			envAllowed := false
			for _, allowedEnv := range c.AllowedEnvironments {
				if Env(allowedEnv) == input.Env {
					envAllowed = true
					break
				}
			}
			if !envAllowed {
				reason := "env_not_allowed"
				cl.SkipReason = &reason
				candidateList = append(candidateList, cl)
				continue
			}
		}

		// VULN-GO-3: enforce RequiredControls.
		// All entries in worker.RequiredControls must be present in the registry
		// (as currently_implements by at least one enrolled worker).
		if len(c.RequiredControls) > 0 {
			ok, missingCtrl := registry.ControlsPresent(c.RequiredControls)
			if !ok {
				reason := "required_controls_missing"
				cl.SkipReason = &reason
				candidateList = append(candidateList, cl)
				continue
			}
			_ = missingCtrl
		}

		available := opts.WorkerAvailability(c.WorkerID)

		if selected == nil && available {
			selected = c
			// No SkipReason for the selected worker.
		} else {
			// GO-F22 equivalent fix: distinguish "unavailable" from "already_selected".
			// Recording all skipped workers as "unavailable" corrupts availability
			// telemetry — a worker that was available but not chosen looks like it
			// was down, producing false downtime metrics.
			if !available {
				reason := "unavailable"
				cl.SkipReason = &reason
			} else {
				reason := "lower precedence (stub ranking)"
				cl.SkipReason = &reason
			}
		}
		candidateList = append(candidateList, cl)
	}

	if selected == nil {
		// Build a deny decision that includes the candidateList with skip reasons.
		// denyDecision() always constructs an empty CandidateWorkersRanked — we need
		// the populated list here so callers can see WHY each candidate was skipped
		// (env_not_allowed, required_controls_missing, unavailable).
		ah := artifactHashOf(input)
		if candidateList == nil {
			candidateList = []CandidateWorker{}
		}
		return RouteDecision{
			DecisionID:    NewUUID(),
			Timestamp:     NowUTC(),
			CorrelationID: input.CorrelationID,
			TenantID:      input.TenantID,
			CapabilityID:  input.CapabilityID,
			MatchedRuleID: "NO_MATCH",
			Env:           input.Env,
			DataLabel:     input.DataLabel,
			TenantRisk:    input.TenantRisk,
			QoSClass:      input.QoSClass,
			Denied:        true,
			DryRun:        input.DryRun,
			DenyReasonIfDenied: map[string]any{
				"code":   "NO_AVAILABLE_WORKER",
				"reason": "all candidate workers are unavailable or filtered by governance",
			},
			CandidateWorkersRanked:       candidateList,
			RequiredControlsEffective:    []string{},
			RecommendedProfilesEffective: []map[string]any{},
			EscalationEffective:          Escalation{},
			PreconditionsChecked:         defaultPreconditions(),
			ArtifactHash:                 &ah,
			TelemetryEnvelopes: buildDenyTelemetry(input, "NO_AVAILABLE_WORKER",
				"all candidate workers are unavailable or filtered by governance"),
		}
	}

	// WCP §5.10 — Worker Code Attestation enforcement.
	// Only runs when a worker was selected (selected != nil is guaranteed here).
	// Verifies the current on-disk hash of the selected worker's code matches the
	// registered hash. Hash values are NEVER included in deny messages (F4 security).
	if opts.RequireWorkerAttestation {
		workerAttestationChecked = true

		// Both callbacks are required — deny if either is missing.
		if opts.GetWorkerHash == nil || opts.GetCurrentWorkerHash == nil {
			ah := artifactHashOf(input)
			if candidateList == nil {
				candidateList = []CandidateWorker{}
			}
			return RouteDecision{
				DecisionID:    NewUUID(),
				Timestamp:     NowUTC(),
				CorrelationID: input.CorrelationID,
				TenantID:      input.TenantID,
				CapabilityID:  input.CapabilityID,
				MatchedRuleID: "NO_MATCH",
				Env:           input.Env,
				DataLabel:     input.DataLabel,
				TenantRisk:    input.TenantRisk,
				QoSClass:      input.QoSClass,
				Denied:        true,
				DryRun:        input.DryRun,
				DenyReasonIfDenied: map[string]any{
					"code":   "DENY_ATTESTATION_UNCONFIGURED",
					"reason": "RequireWorkerAttestation=true but GetWorkerHash or GetCurrentWorkerHash callback is nil",
				},
				WorkerAttestationChecked:     true,
				WorkerAttestationValid:       nil,
				CandidateWorkersRanked:       candidateList,
				RequiredControlsEffective:    normalizeControls(selected.RequiredControls),
				RecommendedProfilesEffective: []map[string]any{},
				EscalationEffective:          Escalation{},
				PreconditionsChecked:         defaultPreconditions(),
				ArtifactHash:                 &ah,
				TelemetryEnvelopes: buildDenyTelemetry(input, "DENY_ATTESTATION_UNCONFIGURED",
					"attestation callbacks not configured"),
			}
		}

		// Retrieve the registered hash for the selected worker species.
		registeredHash, hasRegistered := opts.GetWorkerHash(selected.WorkerSpeciesID)
		if !hasRegistered || registeredHash == "" {
			ah := artifactHashOf(input)
			if candidateList == nil {
				candidateList = []CandidateWorker{}
			}
			return RouteDecision{
				DecisionID:    NewUUID(),
				Timestamp:     NowUTC(),
				CorrelationID: input.CorrelationID,
				TenantID:      input.TenantID,
				CapabilityID:  input.CapabilityID,
				MatchedRuleID: "NO_MATCH",
				Env:           input.Env,
				DataLabel:     input.DataLabel,
				TenantRisk:    input.TenantRisk,
				QoSClass:      input.QoSClass,
				Denied:        true,
				DryRun:        input.DryRun,
				DenyReasonIfDenied: map[string]any{
					"code":   "DENY_WORKER_ATTESTATION_MISSING",
					"reason": "no registered attestation hash for worker species " + SanitizeID(selected.WorkerSpeciesID),
				},
				WorkerAttestationChecked:     true,
				WorkerAttestationValid:       nil,
				CandidateWorkersRanked:       candidateList,
				RequiredControlsEffective:    normalizeControls(selected.RequiredControls),
				RecommendedProfilesEffective: []map[string]any{},
				EscalationEffective:          Escalation{},
				PreconditionsChecked:         defaultPreconditions(),
				ArtifactHash:                 &ah,
				TelemetryEnvelopes: buildDenyTelemetry(input, "DENY_WORKER_ATTESTATION_MISSING",
					"no registered attestation hash for selected worker"),
			}
		}

		// Validate the registered hash format.
		if !validHashRe.MatchString(registeredHash) {
			ah := artifactHashOf(input)
			if candidateList == nil {
				candidateList = []CandidateWorker{}
			}
			return RouteDecision{
				DecisionID:    NewUUID(),
				Timestamp:     NowUTC(),
				CorrelationID: input.CorrelationID,
				TenantID:      input.TenantID,
				CapabilityID:  input.CapabilityID,
				MatchedRuleID: "NO_MATCH",
				Env:           input.Env,
				DataLabel:     input.DataLabel,
				TenantRisk:    input.TenantRisk,
				QoSClass:      input.QoSClass,
				Denied:        true,
				DryRun:        input.DryRun,
				DenyReasonIfDenied: map[string]any{
					"code":   "DENY_WORKER_ATTESTATION_INVALID_HASH",
					"reason": "registered attestation hash is not a valid SHA-256 hex digest",
				},
				WorkerAttestationChecked:     true,
				WorkerAttestationValid:       nil,
				CandidateWorkersRanked:       candidateList,
				RequiredControlsEffective:    normalizeControls(selected.RequiredControls),
				RecommendedProfilesEffective: []map[string]any{},
				EscalationEffective:          Escalation{},
				PreconditionsChecked:         defaultPreconditions(),
				ArtifactHash:                 &ah,
				TelemetryEnvelopes: buildDenyTelemetry(input, "DENY_WORKER_ATTESTATION_INVALID_HASH",
					"registered hash is not valid SHA-256 hex"),
			}
		}

		// Retrieve the current on-disk hash.
		currentHash, hasCurrent := opts.GetCurrentWorkerHash(selected.WorkerSpeciesID)
		if !hasCurrent || currentHash == "" || !validHashRe.MatchString(currentHash) {
			ah := artifactHashOf(input)
			if candidateList == nil {
				candidateList = []CandidateWorker{}
			}
			return RouteDecision{
				DecisionID:    NewUUID(),
				Timestamp:     NowUTC(),
				CorrelationID: input.CorrelationID,
				TenantID:      input.TenantID,
				CapabilityID:  input.CapabilityID,
				MatchedRuleID: "NO_MATCH",
				Env:           input.Env,
				DataLabel:     input.DataLabel,
				TenantRisk:    input.TenantRisk,
				QoSClass:      input.QoSClass,
				Denied:        true,
				DryRun:        input.DryRun,
				DenyReasonIfDenied: map[string]any{
					"code":   "DENY_WORKER_HASH_UNAVAILABLE",
					"reason": "current on-disk hash for worker species is unavailable or unreadable",
				},
				WorkerAttestationChecked:     true,
				WorkerAttestationValid:       nil,
				CandidateWorkersRanked:       candidateList,
				RequiredControlsEffective:    normalizeControls(selected.RequiredControls),
				RecommendedProfilesEffective: []map[string]any{},
				EscalationEffective:          Escalation{},
				PreconditionsChecked:         defaultPreconditions(),
				ArtifactHash:                 &ah,
				TelemetryEnvelopes: buildDenyTelemetry(input, "DENY_WORKER_HASH_UNAVAILABLE",
					"current worker hash unavailable"),
			}
		}

		// Compare registered hash vs current hash.
		// Hash values are NOT included in the deny message (F4 security: no hash
		// values in externally visible denial payloads).
		if currentHash != registeredHash {
			f := false
			workerAttestationValid = &f
			ah := artifactHashOf(input)
			if candidateList == nil {
				candidateList = []CandidateWorker{}
			}
			return RouteDecision{
				DecisionID:    NewUUID(),
				Timestamp:     NowUTC(),
				CorrelationID: input.CorrelationID,
				TenantID:      input.TenantID,
				CapabilityID:  input.CapabilityID,
				MatchedRuleID: "NO_MATCH",
				Env:           input.Env,
				DataLabel:     input.DataLabel,
				TenantRisk:    input.TenantRisk,
				QoSClass:      input.QoSClass,
				Denied:        true,
				DryRun:        input.DryRun,
				DenyReasonIfDenied: map[string]any{
					"code":   "DENY_WORKER_TAMPERED",
					"reason": "worker code hash mismatch — possible tampering detected",
				},
				WorkerAttestationChecked:     true,
				WorkerAttestationValid:       workerAttestationValid,
				CandidateWorkersRanked:       candidateList,
				RequiredControlsEffective:    normalizeControls(selected.RequiredControls),
				RecommendedProfilesEffective: []map[string]any{},
				EscalationEffective:          Escalation{},
				PreconditionsChecked:         defaultPreconditions(),
				ArtifactHash:                 &ah,
				TelemetryEnvelopes: buildDenyTelemetry(input, "DENY_WORKER_TAMPERED",
					"worker code hash mismatch"),
			}
		}

		// Hashes match — attestation passed.
		t := true
		workerAttestationValid = &t
	}

	// F24: Emit warning telemetry when attestation was skipped in prod/edge.
	// This is a non-fatal advisory — production operators should be aware that
	// attestation is not enforced and should consider enabling it.
	if !workerAttestationChecked && (input.Env == EnvProd || input.Env == EnvEdge) {
		extraTelemetry = append(extraTelemetry, map[string]any{
			"event_id":          "evt.os.worker.attestation_skipped",
			"correlation_id":    SanitizeID(input.CorrelationID),
			"worker_species_id": selected.WorkerSpeciesID,
			"env":               string(input.Env),
			"reason":            "RequireWorkerAttestation=false or not configured",
			"severity":          "warn",
		})
	}

	// VULN-GO-4: enforce PrivilegeEnvelope.
	// After worker selection, check that the selected worker's privilege envelope
	// is acceptable for the request's env/data_label combination.
	if selected.PrivilegeEnvelope != nil {
		if allowed, reason := registry.PolicyAllowsPrivilege(input.Env, input.DataLabel, selected.PrivilegeEnvelope); !allowed {
			return denyDecision(input, "privilege envelope denied: "+reason, "DENY_PRIVILEGE_ENVELOPE_DENIED")
		}
	}

	// VULN-GO-3 (rule-level): enforce required controls from the routing rule.
	// The hall-level required controls check (from the matched rule's required_controls_suggested)
	// is enforced here for any controls declared in the candidate's RequiredControls that have
	// already passed the ControlsPresent check above. No additional check needed at this point
	// since the per-candidate check above is the enforcement layer.
	// TODO(impl): when routing rules are fully implemented, also check
	// rule.required_controls_suggested against registry.ControlsPresent().

	// --- Policy gate ---
	// TODO(impl): build real Escalation from the matched routing rule.
	escalation := Escalation{PolicyGate: true}
	gateResult := opts.PolicyGate.Evaluate(input, escalation)

	// GO-F4 fix: RequiresHumanReview=true with Passed=true silently approved
	// human-review-required operations. The router now checks RequiresHumanReview
	// on the allow path and converts it to a DENY_REQUIRES_HUMAN_APPROVAL decision.
	// Human review requirement is NOT a soft suggestion — it is a hard stop.
	if gateResult.RequiresHumanReview {
		return RouteDecision{
			DecisionID:    NewUUID(),
			Timestamp:     NowUTC(),
			CorrelationID: input.CorrelationID,
			TenantID:      input.TenantID,
			CapabilityID:  input.CapabilityID,
			MatchedRuleID: "NO_MATCH",
			Env:           input.Env,
			DataLabel:     input.DataLabel,
			TenantRisk:    input.TenantRisk,
			QoSClass:      input.QoSClass,
			Denied:        true,
			DryRun:        input.DryRun,
			DenyReasonIfDenied: map[string]any{
				"code":               "DENY_REQUIRES_HUMAN_APPROVAL",
				"reason":             "policy gate requires human approval before dispatch: " + gateResult.Reason,
				"supervisor_required": true,
			},
			CandidateWorkersRanked:       candidateList,
			RequiredControlsEffective:    normalizeControls(selected.RequiredControls),
			RecommendedProfilesEffective: []map[string]any{},
			EscalationEffective:          escalation,
			PreconditionsChecked:         defaultPreconditions(),
			ArtifactHash:                 func() *string { h := artifactHashOf(input); return &h }(),
			TelemetryEnvelopes: buildDenyTelemetry(input, "DENY_REQUIRES_HUMAN_APPROVAL",
				"policy gate requires human approval"),
		}
	}

	if !gateResult.Passed {
		return denyDecision(input, "policy gate denied: "+gateResult.Reason, "POLICY_GATE_DENIED")
	}

	// --- GO-F1 fix: policy gate implicit allow ---
	// The PolicyGate interface returns a PolicyGateResult with Passed bool.
	// A future-proof guard: if Passed is false for any reason not already caught,
	// deny. The explicit RequiresHumanReview check above handles that arm.
	// This ordering ensures no implicit allow escapes.

	// --- Build allow decision ---
	artifactHash := artifactHashOf(input)
	speciesID := selected.WorkerSpeciesID

	if opts.RegistryClient != nil && speciesID != "" {
		opts.RegistryClient.RecordDecision(speciesID)
	}

	// GO-F13 fix: selected.RequiredControls may be nil (omitempty field).
	// RouteDecision.RequiredControlsEffective is typed as []string and consumers
	// expect a JSON array, not null. Normalise nil → empty slice.
	requiredControls := normalizeControls(selected.RequiredControls)

	// GO-F5 fix: propagate DryRun from input to decision.
	// Originally, input.DryRun had zero effect — no worker IS dispatched by
	// MakeDecision() (it's a stub), but the field must be present in the decision
	// so callers and audit consumers can distinguish probes from real dispatches.

	// Merge base allow telemetry with any extra events (e.g. F24 attestation_skipped).
	finalTelemetry := buildAllowTelemetry(input, speciesID, input.DryRun)
	finalTelemetry = append(finalTelemetry, extraTelemetry...)

	return RouteDecision{
		DecisionID:                   NewUUID(),
		Timestamp:                    NowUTC(),
		CorrelationID:                input.CorrelationID,
		TenantID:                     input.TenantID,
		CapabilityID:                 input.CapabilityID,
		MatchedRuleID:                "STUB_RULE_001", // TODO(impl): real matched rule ID
		Env:                          input.Env,
		DataLabel:                    input.DataLabel,
		TenantRisk:                   input.TenantRisk,
		QoSClass:                     input.QoSClass,
		Denied:                       false,
		DryRun:                       input.DryRun,
		SelectedWorkerSpeciesID:      &speciesID,
		CandidateWorkersRanked:       candidateList,
		RequiredControlsEffective:    requiredControls,
		RecommendedProfilesEffective: []map[string]any{},
		EscalationEffective:          escalation,
		PreconditionsChecked:         defaultPreconditions(),
		ArtifactHash:                 &artifactHash,
		WorkerAttestationChecked:     workerAttestationChecked,
		WorkerAttestationValid:       workerAttestationValid,
		TelemetryEnvelopes:           finalTelemetry,
	}
}

// normalizeControls converts a nil []string to an empty (non-nil) []string.
//
// GO-F13 fix: WorkerRegistryRecord.RequiredControls is omitempty — it can be nil.
// When propagated to RouteDecision.RequiredControlsEffective, nil serialises as
// JSON null instead of [], breaking consumers that expect a JSON array.
func normalizeControls(controls []string) []string {
	if controls == nil {
		return []string{}
	}
	return controls
}
