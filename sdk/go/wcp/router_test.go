package wcp

// WCP Go SDK Security Test Suite
//
// Round 1 audit — GO-F1 through GO-F15.
// Round 2 — WCP §5.10 Worker Code Attestation.
// All tests verify the security fixes implemented in this audit round.
// Run with: go test ./... -v
//
// Test count: 35 + 10 attestation router tests
// Coverage: GO-F1, GO-F2, GO-F3, GO-F4, GO-F5, GO-F6, GO-F7, GO-F8,
//           GO-F9, GO-F10, GO-F11, GO-F12, GO-F13, GO-F14, GO-F15
//           + valid path smoke tests
//           + WCP §5.10 attestation enforcement

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// minimalValidInput returns a RouteInput that passes all precondition checks.
func minimalValidInput() RouteInput {
	return RouteInput{
		CorrelationID: "test-correlation-id-1234",
		CapabilityID:  "cap.doc.summarize",
		Env:           EnvDev,
		DataLabel:     DataLabelInternal,
		TenantRisk:    TenantRiskLow,
		QoSClass:      QoSP2,
		TenantID:      "tenant-001",
	}
}

// enrolledRegistry returns a registry with one worker enrolled for cap.doc.summarize.
func enrolledRegistry() *Registry {
	r := NewRegistry()
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.doc-summarizer",
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc.summarize"},
	})
	return r
}

// defaultOpts returns RouterOptions with defaults applied.
func defaultOpts() RouterOptions {
	return RouterOptions{}
}

// ---------------------------------------------------------------------------
// Smoke tests — valid path must still work after all fixes
// ---------------------------------------------------------------------------

func TestValidDispatchAllowed(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())

	if dec.Denied {
		t.Fatalf("expected Denied=false for valid input, got denied with reason %v", dec.DenyReasonIfDenied)
	}
	if dec.SelectedWorkerSpeciesID == nil {
		t.Fatal("expected SelectedWorkerSpeciesID to be set on allow decision")
	}
	if *dec.SelectedWorkerSpeciesID != "wrk.doc.summarizer" {
		t.Errorf("expected wrk.doc.summarizer, got %s", *dec.SelectedWorkerSpeciesID)
	}
	if dec.CorrelationID != inp.CorrelationID {
		t.Errorf("CorrelationID not propagated: got %q", dec.CorrelationID)
	}
	if dec.ArtifactHash == nil || !strings.HasPrefix(*dec.ArtifactHash, "sha256:") {
		t.Errorf("expected ArtifactHash with sha256: prefix, got %v", dec.ArtifactHash)
	}
}

func TestDecisionIDIsNonEmpty(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if dec.DecisionID == "" {
		t.Error("DecisionID must be non-empty")
	}
	if dec.Timestamp == "" {
		t.Error("Timestamp must be non-empty")
	}
}

func TestTwoDecisionsHaveDistinctIDs(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	d1 := MakeDecision(inp, reg, defaultOpts())
	d2 := MakeDecision(inp, reg, defaultOpts())
	if d1.DecisionID == d2.DecisionID {
		t.Error("expected distinct DecisionIDs for two separate calls")
	}
}

// ---------------------------------------------------------------------------
// GO-F1: Policy gate implicit allow — unrecognized / non-canonical gate values
// ---------------------------------------------------------------------------
// The DefaultPolicyGate stub always returns Passed=true.
// A custom gate returning Passed=false must still deny.
// A gate returning RequiresHumanReview=true must deny even when Passed=true.
// (RequiresHumanReview behavior is GO-F4 — tested there.)

func TestPolicyGateDenyIsHonored(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	opts := RouterOptions{
		PolicyGate: denyGate{},
	}
	dec := MakeDecision(inp, reg, opts)
	if !dec.Denied {
		t.Fatal("expected Denied=true when policy gate returns Passed=false")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "POLICY_GATE_DENIED" {
		t.Errorf("expected POLICY_GATE_DENIED, got %v", code)
	}
}

// denyGate always denies.
type denyGate struct{}

func (denyGate) Evaluate(_ RouteInput, _ Escalation) PolicyGateResult {
	return PolicyGateResult{Passed: false, Reason: "test: always deny"}
}

// ---------------------------------------------------------------------------
// GO-F4: RequiresHumanReview=true silently approved
// ---------------------------------------------------------------------------

func TestRequiresHumanReviewDenies(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	opts := RouterOptions{
		PolicyGate: humanReviewGate{},
	}
	dec := MakeDecision(inp, reg, opts)
	if !dec.Denied {
		t.Fatal("GO-F4: expected Denied=true when PolicyGateResult.RequiresHumanReview=true")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "DENY_REQUIRES_HUMAN_APPROVAL" {
		t.Errorf("GO-F4: expected DENY_REQUIRES_HUMAN_APPROVAL, got %v", code)
	}
	sv, ok := dec.DenyReasonIfDenied["supervisor_required"]
	if !ok || sv != true {
		t.Errorf("GO-F4: expected supervisor_required=true in deny payload, got %v", dec.DenyReasonIfDenied)
	}
}

func TestP0ProdDeniedByDefaultGateNoRules(t *testing.T) {
	// VULN-GO-1 fix: DefaultPolicyGate{} (no Rules) fails-closed for prod.
	// P0 in prod with no configured rules must be denied (no_policy_configured).
	inp := minimalValidInput()
	inp.QoSClass = QoSP0
	inp.Env = EnvProd
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("VULN-GO-1: P0 in prod with no policy rules must be denied (fail-closed)")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "POLICY_GATE_DENIED" {
		t.Errorf("expected POLICY_GATE_DENIED for P0/prod with no rules, got %v", code)
	}
}

func TestP0ProdRequiresHumanViaDefaultGateWithRules(t *testing.T) {
	// With explicit rules that allow P0 in prod, RequiresHumanReview is still set.
	inp := minimalValidInput()
	inp.QoSClass = QoSP0
	inp.Env = EnvProd
	reg := enrolledRegistry()
	opts := RouterOptions{
		PolicyGate: DefaultPolicyGate{
			Rules: []PolicyRule{
				{Passed: true, Reason: "test: allow all"},
			},
		},
	}
	dec := MakeDecision(inp, reg, opts)
	if !dec.Denied {
		t.Fatal("VULN-GO-1: P0 in prod with rules that pass must still be denied with DENY_REQUIRES_HUMAN_APPROVAL")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "DENY_REQUIRES_HUMAN_APPROVAL" {
		t.Errorf("expected DENY_REQUIRES_HUMAN_APPROVAL for P0/prod with passing rules, got %v", code)
	}
}

// humanReviewGate returns Passed=true but RequiresHumanReview=true.
// GO-F4 exploit: before the fix this was silently approved.
type humanReviewGate struct{}

func (humanReviewGate) Evaluate(_ RouteInput, _ Escalation) PolicyGateResult {
	return PolicyGateResult{Passed: true, RequiresHumanReview: true, Reason: "test: requires human"}
}

// ---------------------------------------------------------------------------
// GO-F5: DryRun not propagated to RouteDecision
// ---------------------------------------------------------------------------

func TestDryRunPropagatedOnAllow(t *testing.T) {
	inp := minimalValidInput()
	inp.DryRun = true
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if dec.Denied {
		t.Fatalf("unexpected deny for valid dry-run input: %v", dec.DenyReasonIfDenied)
	}
	if !dec.DryRun {
		t.Error("GO-F5: DryRun=true in input must be propagated to RouteDecision.DryRun")
	}
}

func TestDryRunPropagatedOnDeny(t *testing.T) {
	// Dry-run on a missing correlation_id — should still propagate DryRun.
	inp := minimalValidInput()
	inp.DryRun = true
	inp.CorrelationID = ""
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("expected Denied=true for missing correlation_id")
	}
	if !dec.DryRun {
		t.Error("GO-F5: DryRun=true must be propagated even on deny decisions")
	}
}

func TestDryRunFalseByDefault(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if dec.DryRun {
		t.Error("GO-F5: DryRun should default to false when input.DryRun=false")
	}
}

// ---------------------------------------------------------------------------
// GO-F6: Control character injection in ID fields (log injection)
// ---------------------------------------------------------------------------

func TestCapabilityIDWithNewlineIsRejected(t *testing.T) {
	inp := minimalValidInput()
	inp.CapabilityID = "cap.doc.summarize\nevt.os.task.routed fake-event"
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("GO-F6: capability_id containing \\n must be rejected to prevent log injection")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "INVALID_CAPABILITY_ID" {
		t.Errorf("expected INVALID_CAPABILITY_ID, got %v", code)
	}
}

func TestCapabilityIDWithNullByteIsRejected(t *testing.T) {
	inp := minimalValidInput()
	inp.CapabilityID = "cap.doc.summarize\x00"
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("GO-F6: capability_id containing null byte must be rejected")
	}
}

func TestCorrelationIDWithNewlineIsRejected(t *testing.T) {
	inp := minimalValidInput()
	inp.CorrelationID = "corr-123\nevt.os.task.routed injected-event"
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("GO-F6: correlation_id containing \\n must be rejected to prevent log injection")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "INVALID_CORRELATION_ID" {
		t.Errorf("expected INVALID_CORRELATION_ID, got %v", code)
	}
}

func TestSanitizeIDStripsControlChars(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"hello\nworld", "helloworld"},
		{"test\x00null", "testnull"},
		{"cr\rtest", "crtest"},
		{"tab\there", "tabhere"},
		{"clean-id-123", "clean-id-123"},
		{"", ""},
	}
	for _, tc := range cases {
		got := SanitizeID(tc.input)
		if got != tc.expected {
			t.Errorf("SanitizeID(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// GO-F7: WorkerID and capability ID not validated at enrollment
// ---------------------------------------------------------------------------

func TestEnrollRejectsWorkerIDWithControlChars(t *testing.T) {
	r := NewRegistry()
	err := r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.worker\nmalicious",
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc.summarize"},
	})
	if err == nil {
		t.Fatal("GO-F7: enrollment must reject worker_id containing control characters")
	}
}

func TestEnrollRejectsCapabilityIDWithControlChars(t *testing.T) {
	r := NewRegistry()
	err := r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.worker",
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc.summarize\nevt.fake"},
	})
	if err == nil {
		t.Fatal("GO-F7: enrollment must reject capability_id containing control characters")
	}
}

func TestEnrollRejectsCapabilityIDWithSpaces(t *testing.T) {
	r := NewRegistry()
	err := r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.worker",
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc INJECT"},
	})
	if err == nil {
		t.Fatal("GO-F7: enrollment must reject capability_id containing spaces")
	}
}

func TestEnrollRejectsControlIDWithControlChars(t *testing.T) {
	r := NewRegistry()
	err := r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.worker",
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc.summarize"},
		RequiredControls: []string{"ctrl.obs.audit\x00inject"},
	})
	if err == nil {
		t.Fatal("GO-F7: enrollment must reject control IDs containing null bytes")
	}
}

func TestEnrollAcceptsValidWorker(t *testing.T) {
	r := NewRegistry()
	err := r.Enroll(WorkerRegistryRecord{
		WorkerID:         "org.fafolab.doc-summarizer",
		WorkerSpeciesID:  "wrk.doc.summarizer",
		Capabilities:     []string{"cap.doc.summarize", "cap.doc.translate"},
		RequiredControls: []string{"ctrl.obs.audit-log-append-only"},
	})
	if err != nil {
		t.Fatalf("GO-F7: valid worker enrollment failed unexpectedly: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GO-F8: BlastScore accepts negative values and values > 100
// ---------------------------------------------------------------------------

func TestValidateBlastScoreRejectsNegative(t *testing.T) {
	if err := ValidateBlastScore(-1); err == nil {
		t.Fatal("GO-F8: ValidateBlastScore(-1) must return error")
	}
}

func TestValidateBlastScoreRejectsOver100(t *testing.T) {
	if err := ValidateBlastScore(101); err == nil {
		t.Fatal("GO-F8: ValidateBlastScore(101) must return error")
	}
}

func TestValidateBlastScoreAcceptsBoundaries(t *testing.T) {
	if err := ValidateBlastScore(0); err != nil {
		t.Errorf("GO-F8: ValidateBlastScore(0) must not return error, got %v", err)
	}
	if err := ValidateBlastScore(100); err != nil {
		t.Errorf("GO-F8: ValidateBlastScore(100) must not return error, got %v", err)
	}
	if err := ValidateBlastScore(50); err != nil {
		t.Errorf("GO-F8: ValidateBlastScore(50) must not return error, got %v", err)
	}
}

func TestRouteInputNegativeBlastScoreDenied(t *testing.T) {
	inp := minimalValidInput()
	score := -5
	inp.BlastScore = &score
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("GO-F8: negative blast_score must be rejected")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "INVALID_BLAST_SCORE" {
		t.Errorf("expected INVALID_BLAST_SCORE, got %v", code)
	}
}

func TestRouteInputBlastScoreOver100Denied(t *testing.T) {
	inp := minimalValidInput()
	score := 150
	inp.BlastScore = &score
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("GO-F8: blast_score > 100 must be rejected")
	}
}

// ---------------------------------------------------------------------------
// GO-F3 / GO-F11: Deny paths emit correct telemetry events
// ---------------------------------------------------------------------------

func TestDenyTelemetryEmitsTaskDenied(t *testing.T) {
	// Missing correlation_id — most primitive deny path.
	inp := minimalValidInput()
	inp.CorrelationID = ""
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())

	if !dec.Denied {
		t.Fatal("expected Denied=true")
	}
	if len(dec.TelemetryEnvelopes) == 0 {
		t.Fatal("GO-F3: TelemetryEnvelopes must not be empty on deny decisions")
	}
	evt := dec.TelemetryEnvelopes[0]
	eventID, _ := evt["event_id"].(string)
	if eventID != "evt.os.task.denied" {
		t.Errorf("GO-F3: expected evt.os.task.denied on deny path, got %q", eventID)
	}
	// Must not contain evt.os.worker.selected (no worker was selected).
	for _, e := range dec.TelemetryEnvelopes {
		if e["event_id"] == "evt.os.worker.selected" {
			t.Error("GO-F11: deny telemetry must NOT contain evt.os.worker.selected")
		}
	}
}

func TestDenyTelemetryContainsDenyCode(t *testing.T) {
	inp := minimalValidInput()
	inp.CapabilityID = ""
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())

	evt := dec.TelemetryEnvelopes[0]
	denyCode, _ := evt["deny_code"].(string)
	if denyCode != "MISSING_CAPABILITY_ID" {
		t.Errorf("GO-F3: expected deny_code=MISSING_CAPABILITY_ID in telemetry, got %q", denyCode)
	}
}

func TestAllowTelemetryEmitsThreeEvents(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())

	if dec.Denied {
		t.Fatalf("expected allow decision, got denied: %v", dec.DenyReasonIfDenied)
	}
	if len(dec.TelemetryEnvelopes) != 3 {
		t.Errorf("expected 3 telemetry events on allow, got %d", len(dec.TelemetryEnvelopes))
	}
	wantEvents := map[string]bool{
		"evt.os.task.routed":    false,
		"evt.os.worker.selected": false,
		"evt.os.policy.gated":   false,
	}
	for _, e := range dec.TelemetryEnvelopes {
		id, _ := e["event_id"].(string)
		wantEvents[id] = true
	}
	for ev, found := range wantEvents {
		if !found {
			t.Errorf("GO-F11: expected telemetry event %q on allow path", ev)
		}
	}
}

func TestAllowTelemetryContainsWorkerSpeciesID(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())

	var workerSelectedEvt map[string]any
	for _, e := range dec.TelemetryEnvelopes {
		if e["event_id"] == "evt.os.worker.selected" {
			workerSelectedEvt = e
		}
	}
	if workerSelectedEvt == nil {
		t.Fatal("expected evt.os.worker.selected event")
	}
	sid, _ := workerSelectedEvt["selected_worker_species_id"].(string)
	if sid != "wrk.doc.summarizer" {
		t.Errorf("expected wrk.doc.summarizer in worker.selected event, got %q", sid)
	}
}

// ---------------------------------------------------------------------------
// GO-F12: Nil registry must not panic
// ---------------------------------------------------------------------------

func TestNilRegistryReturnsdeny(t *testing.T) {
	inp := minimalValidInput()
	// Must not panic.
	dec := MakeDecision(inp, nil, defaultOpts())
	if !dec.Denied {
		t.Fatal("GO-F12: nil registry must produce a deny decision, not panic")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "INVALID_CONFIGURATION" {
		t.Errorf("expected INVALID_CONFIGURATION, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// GO-F13: nil RequiredControls normalised to empty slice
// ---------------------------------------------------------------------------

func TestRequiredControlsNilNormalisedToEmptySlice(t *testing.T) {
	r := NewRegistry()
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.no-controls",
		WorkerSpeciesID: "wrk.doc.minimal",
		Capabilities:    []string{"cap.doc.minimal"},
		// RequiredControls intentionally omitted — will be nil.
	})
	inp := minimalValidInput()
	inp.CapabilityID = "cap.doc.minimal"
	dec := MakeDecision(inp, r, defaultOpts())

	if dec.Denied {
		t.Fatalf("unexpected deny: %v", dec.DenyReasonIfDenied)
	}
	if dec.RequiredControlsEffective == nil {
		t.Error("GO-F13: RequiredControlsEffective must not be nil — must be empty slice for JSON []")
	}
	if len(dec.RequiredControlsEffective) != 0 {
		t.Errorf("expected empty slice, got %v", dec.RequiredControlsEffective)
	}
}

// ---------------------------------------------------------------------------
// Precondition: missing correlation_id
// ---------------------------------------------------------------------------

func TestMissingCorrelationIDDenied(t *testing.T) {
	inp := minimalValidInput()
	inp.CorrelationID = ""
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("expected Denied=true for missing correlation_id")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "MISSING_CORRELATION_ID" {
		t.Errorf("expected MISSING_CORRELATION_ID, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// Precondition: missing capability_id
// ---------------------------------------------------------------------------

func TestMissingCapabilityIDDenied(t *testing.T) {
	inp := minimalValidInput()
	inp.CapabilityID = ""
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("expected Denied=true for missing capability_id")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "MISSING_CAPABILITY_ID" {
		t.Errorf("expected MISSING_CAPABILITY_ID, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed: no worker registered
// ---------------------------------------------------------------------------

func TestNoWorkerForCapabilityDenied(t *testing.T) {
	inp := minimalValidInput()
	inp.CapabilityID = "cap.unknown.capability"
	reg := NewRegistry() // empty registry
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("expected Denied=true for unknown capability")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "NO_WORKER_FOR_CAPABILITY" {
		t.Errorf("expected NO_WORKER_FOR_CAPABILITY, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// Worker availability: all workers unavailable
// ---------------------------------------------------------------------------

func TestAllWorkersUnavailableDenied(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	opts := RouterOptions{
		WorkerAvailability: func(_ string) bool { return false },
	}
	dec := MakeDecision(inp, reg, opts)
	if !dec.Denied {
		t.Fatal("expected Denied=true when all workers unavailable")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "NO_AVAILABLE_WORKER" {
		t.Errorf("expected NO_AVAILABLE_WORKER, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// Worker candidate skip_reason accuracy (GO-F22 equivalent)
// ---------------------------------------------------------------------------

func TestSkipReasonDistinguishesUnavailableFromNotChosen(t *testing.T) {
	r := NewRegistry()
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.worker-a",
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc.multi"},
	})
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.worker-b",
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc.multi"},
	})
	inp := minimalValidInput()
	inp.CapabilityID = "cap.doc.multi"
	dec := MakeDecision(inp, r, defaultOpts()) // AlwaysAvailable

	if dec.Denied {
		t.Fatalf("unexpected deny: %v", dec.DenyReasonIfDenied)
	}
	// One candidate should be selected (no SkipReason), the other skipped with
	// "lower precedence" (not "unavailable") since AlwaysAvailable returns true.
	skippedReasons := map[string]int{}
	for _, c := range dec.CandidateWorkersRanked {
		if c.SkipReason != nil {
			skippedReasons[*c.SkipReason]++
		}
	}
	if count := skippedReasons["unavailable"]; count > 0 {
		t.Errorf("GO-F22: available worker marked as 'unavailable' — should be 'lower precedence'")
	}
}

// ---------------------------------------------------------------------------
// ArtifactHash prefix validation
// ---------------------------------------------------------------------------

func TestArtifactHashHasSha256Prefix(t *testing.T) {
	inp := minimalValidInput()
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if dec.ArtifactHash == nil {
		t.Fatal("ArtifactHash must be set on allow decisions")
	}
	if !strings.HasPrefix(*dec.ArtifactHash, "sha256:") {
		t.Errorf("expected ArtifactHash to start with sha256:, got %q", *dec.ArtifactHash)
	}
}

func TestDenyArtifactHashHasSha256Prefix(t *testing.T) {
	inp := minimalValidInput()
	inp.CorrelationID = ""
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if dec.ArtifactHash == nil {
		t.Fatal("ArtifactHash must be set on deny decisions")
	}
	if !strings.HasPrefix(*dec.ArtifactHash, "sha256:") {
		t.Errorf("expected deny ArtifactHash to start with sha256:, got %q", *dec.ArtifactHash)
	}
}

// ---------------------------------------------------------------------------
// Registry basic operations
// ---------------------------------------------------------------------------

func TestEnrollDuplicateRejected(t *testing.T) {
	r := NewRegistry()
	rec := WorkerRegistryRecord{
		WorkerID:        "org.fafolab.doc-summarizer",
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc.summarize"},
	}
	if err := r.Enroll(rec); err != nil {
		t.Fatalf("first enroll failed: %v", err)
	}
	if err := r.Enroll(rec); err == nil {
		t.Fatal("expected error on duplicate enrollment")
	}
}

func TestEnrollRequiresWorkerID(t *testing.T) {
	r := NewRegistry()
	err := r.Enroll(WorkerRegistryRecord{
		WorkerSpeciesID: "wrk.doc.summarizer",
		Capabilities:    []string{"cap.doc.summarize"},
	})
	if err == nil {
		t.Fatal("expected error when worker_id is empty")
	}
}

func TestEnrollRequiresAtLeastOneCapability(t *testing.T) {
	r := NewRegistry()
	err := r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.worker",
		WorkerSpeciesID: "wrk.doc.summarizer",
	})
	if err == nil {
		t.Fatal("expected error when capabilities list is empty")
	}
}

func TestWorkersForCapabilityReturnsEmpty(t *testing.T) {
	r := NewRegistry()
	workers := r.WorkersForCapability("cap.nonexistent")
	if workers == nil {
		t.Error("WorkersForCapability must return non-nil empty slice")
	}
	if len(workers) != 0 {
		t.Errorf("expected empty slice, got %d workers", len(workers))
	}
}

// ---------------------------------------------------------------------------
// VULN-GO-2: AllowedEnvironments enforcement
// ---------------------------------------------------------------------------

func TestAllowedEnvironmentsDevWorkerDeniedInProd(t *testing.T) {
	// VULN-GO-2: worker with AllowedEnvironments=["dev"] must not dispatch in prod.
	r := NewRegistry()
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:            "org.fafolab.dev-only-worker",
		WorkerSpeciesID:     "wrk.dev.only",
		Capabilities:        []string{"cap.dev.only"},
		AllowedEnvironments: []string{"dev"},
	})

	inp := minimalValidInput()
	inp.CapabilityID = "cap.dev.only"
	inp.Env = EnvProd

	// Use DefaultPolicyGate with rules so the gate doesn't deny first.
	opts := RouterOptions{
		PolicyGate: DefaultPolicyGate{
			Rules: []PolicyRule{{Passed: true, Reason: "test: allow"}},
		},
	}
	dec := MakeDecision(inp, r, opts)

	if !dec.Denied {
		t.Fatal("VULN-GO-2: worker with AllowedEnvironments=[dev] must be denied in prod")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "NO_AVAILABLE_WORKER" {
		t.Errorf("VULN-GO-2: expected NO_AVAILABLE_WORKER, got %v", code)
	}
	// Verify the candidate was skipped with env_not_allowed reason.
	found := false
	for _, c := range dec.CandidateWorkersRanked {
		if c.SkipReason != nil && *c.SkipReason == "env_not_allowed" {
			found = true
		}
	}
	if !found {
		t.Errorf("VULN-GO-2: expected candidate with skip_reason=env_not_allowed in CandidateWorkersRanked, got %v", dec.CandidateWorkersRanked)
	}
}

func TestAllowedEnvironmentsDevWorkerAllowedInDev(t *testing.T) {
	// VULN-GO-2: worker with AllowedEnvironments=["dev"] must dispatch normally in dev.
	r := NewRegistry()
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:            "org.fafolab.dev-only-worker2",
		WorkerSpeciesID:     "wrk.dev.only",
		Capabilities:        []string{"cap.dev.only2"},
		AllowedEnvironments: []string{"dev"},
	})

	inp := minimalValidInput()
	inp.CapabilityID = "cap.dev.only2"
	inp.Env = EnvDev

	dec := MakeDecision(inp, r, defaultOpts())
	if dec.Denied {
		t.Fatalf("VULN-GO-2: worker with AllowedEnvironments=[dev] must be allowed in dev, got: %v", dec.DenyReasonIfDenied)
	}
}

// ---------------------------------------------------------------------------
// VULN-GO-3: RequiredControls enforcement
// ---------------------------------------------------------------------------

func enrolledRegistryWithControl(capability string, requiredCtrl string, implementedCtrl string) *Registry {
	r := NewRegistry()
	rec := WorkerRegistryRecord{
		WorkerID:        "org.fafolab.ctrl-worker",
		WorkerSpeciesID: "wrk.ctrl.worker",
		Capabilities:    []string{capability},
	}
	if requiredCtrl != "" {
		rec.RequiredControls = []string{requiredCtrl}
	}
	if implementedCtrl != "" {
		rec.CurrentlyImplements = []string{implementedCtrl}
	}
	_ = r.Enroll(rec)
	return r
}

func TestRequiredControlsPresentAllowsDispatch(t *testing.T) {
	// VULN-GO-3: worker with RequiredControls=["ctrl.present"] where control IS
	// implemented by an enrolled worker → dispatch allowed.
	r := NewRegistry()
	// Worker that provides the control.
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:            "org.fafolab.control-provider",
		WorkerSpeciesID:     "wrk.ctrl.provider",
		Capabilities:        []string{"cap.ctrl.provider"},
		CurrentlyImplements: []string{"ctrl.present"},
	})
	// Worker that requires the control.
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:         "org.fafolab.ctrl-consumer",
		WorkerSpeciesID:  "wrk.ctrl.consumer",
		Capabilities:     []string{"cap.ctrl.consumer"},
		RequiredControls: []string{"ctrl.present"},
	})

	inp := minimalValidInput()
	inp.CapabilityID = "cap.ctrl.consumer"

	dec := MakeDecision(inp, r, defaultOpts())
	if dec.Denied {
		t.Fatalf("VULN-GO-3: required control is present; dispatch must be allowed, got: %v", dec.DenyReasonIfDenied)
	}
}

func TestRequiredControlsMissingDeniesDispatch(t *testing.T) {
	// VULN-GO-3: worker with RequiredControls=["ctrl.missing"] where no enrolled
	// worker implements it → dispatch denied (required_controls_missing skip).
	r := NewRegistry()
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:         "org.fafolab.needs-missing-ctrl",
		WorkerSpeciesID:  "wrk.ctrl.needy",
		Capabilities:     []string{"cap.ctrl.needy"},
		RequiredControls: []string{"ctrl.missing"},
		// CurrentlyImplements is empty — ctrl.missing is not present in the registry.
	})

	inp := minimalValidInput()
	inp.CapabilityID = "cap.ctrl.needy"

	dec := MakeDecision(inp, r, defaultOpts())
	if !dec.Denied {
		t.Fatal("VULN-GO-3: required control is absent; dispatch must be denied")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "NO_AVAILABLE_WORKER" {
		t.Errorf("VULN-GO-3: expected NO_AVAILABLE_WORKER, got %v", code)
	}
	// Verify the candidate was skipped with required_controls_missing reason.
	found := false
	for _, c := range dec.CandidateWorkersRanked {
		if c.SkipReason != nil && *c.SkipReason == "required_controls_missing" {
			found = true
		}
	}
	if !found {
		t.Errorf("VULN-GO-3: expected candidate with skip_reason=required_controls_missing, got %v", dec.CandidateWorkersRanked)
	}
}

// ---------------------------------------------------------------------------
// VULN-GO-1: DefaultPolicyGate fail-closed behavior
// ---------------------------------------------------------------------------

func TestDefaultPolicyGateEmptyRulesInProdDenies(t *testing.T) {
	// VULN-GO-1: DefaultPolicyGate{} with no Rules must deny in prod (fail-closed).
	inp := minimalValidInput()
	inp.Env = EnvProd
	inp.QoSClass = QoSP2 // Non-P0 to avoid the human-review path.
	reg := enrolledRegistry()

	dec := MakeDecision(inp, reg, defaultOpts()) // defaultOpts uses DefaultPolicyGate{}
	if !dec.Denied {
		t.Fatal("VULN-GO-1: DefaultPolicyGate with no rules must deny in prod (fail-closed)")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "POLICY_GATE_DENIED" {
		t.Errorf("VULN-GO-1: expected POLICY_GATE_DENIED for no-rules in prod, got %v", code)
	}
}

func TestDefaultPolicyGateEmptyRulesInDevAllows(t *testing.T) {
	// VULN-GO-1: DefaultPolicyGate{} with no Rules must pass in dev.
	inp := minimalValidInput()
	inp.Env = EnvDev
	inp.QoSClass = QoSP2
	reg := enrolledRegistry()

	dec := MakeDecision(inp, reg, defaultOpts())
	if dec.Denied {
		t.Fatalf("VULN-GO-1: DefaultPolicyGate with no rules must allow in dev, got: %v", dec.DenyReasonIfDenied)
	}
}

// ---------------------------------------------------------------------------
// VULN-GO-4: PrivilegeEnvelope enforcement
// ---------------------------------------------------------------------------

// restrictedPrivilegeRegistry is a registry whose enrolled worker has an unrestricted
// network egress privilege envelope — dangerous for RESTRICTED data in prod/edge.
func restrictedPrivilegeRegistry() *Registry {
	r := NewRegistry()
	_ = r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.fafolab.privileged-worker",
		WorkerSpeciesID: "wrk.privileged",
		Capabilities:    []string{"cap.privileged"},
		PrivilegeEnvelope: &PrivilegeEnvelope{
			NetworkEgress: "unrestricted",
		},
	})
	return r
}

func TestPrivilegeEnvelopeDeniedForRestrictedDataInProd(t *testing.T) {
	// VULN-GO-4: a worker with NetworkEgress=unrestricted must be denied
	// when dispatching RESTRICTED data in prod.
	r := restrictedPrivilegeRegistry()

	inp := minimalValidInput()
	inp.CapabilityID = "cap.privileged"
	inp.Env = EnvProd
	inp.DataLabel = DataLabelRestricted

	// Use DefaultPolicyGate with rules so the gate doesn't deny first.
	opts := RouterOptions{
		PolicyGate: DefaultPolicyGate{
			Rules: []PolicyRule{{Passed: true, Reason: "test: allow"}},
		},
	}
	dec := MakeDecision(inp, r, opts)

	if !dec.Denied {
		t.Fatal("VULN-GO-4: worker with unrestricted network egress must be denied for RESTRICTED data in prod")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "DENY_PRIVILEGE_ENVELOPE_DENIED" {
		t.Errorf("VULN-GO-4: expected DENY_PRIVILEGE_ENVELOPE_DENIED, got %v", code)
	}
}

func TestPrivilegeEnvelopeAllowedForPublicDataInDev(t *testing.T) {
	// VULN-GO-4: the same unrestricted worker is allowed for PUBLIC data in dev.
	r := restrictedPrivilegeRegistry()

	inp := minimalValidInput()
	inp.CapabilityID = "cap.privileged"
	inp.Env = EnvDev
	inp.DataLabel = DataLabelPublic

	dec := MakeDecision(inp, r, defaultOpts())
	if dec.Denied {
		t.Fatalf("VULN-GO-4: privileged worker must be allowed for PUBLIC data in dev, got: %v", dec.DenyReasonIfDenied)
	}
}

// ---------------------------------------------------------------------------
// VULN-GO-5: BlastScore threshold enforcement
// ---------------------------------------------------------------------------

func TestBlastScoreExceedsMaxDenied(t *testing.T) {
	// VULN-GO-5: blast_score > MaxBlastScore must be denied.
	inp := minimalValidInput()
	score := 80
	inp.BlastScore = &score
	reg := enrolledRegistry()
	opts := RouterOptions{MaxBlastScore: 50}

	dec := MakeDecision(inp, reg, opts)
	if !dec.Denied {
		t.Fatal("VULN-GO-5: blast_score > MaxBlastScore must be denied")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "DENY_BLAST_SCORE_EXCEEDED" {
		t.Errorf("VULN-GO-5: expected DENY_BLAST_SCORE_EXCEEDED, got %v", code)
	}
}

func TestBlastScoreAtMaxAllowed(t *testing.T) {
	// VULN-GO-5: blast_score == MaxBlastScore must be allowed (not exceeded).
	inp := minimalValidInput()
	score := 50
	inp.BlastScore = &score
	reg := enrolledRegistry()
	opts := RouterOptions{MaxBlastScore: 50}

	dec := MakeDecision(inp, reg, opts)
	if dec.Denied {
		t.Fatalf("VULN-GO-5: blast_score == MaxBlastScore must be allowed, got: %v", dec.DenyReasonIfDenied)
	}
}

func TestBlastScoreDisabledWhenMaxIsZero(t *testing.T) {
	// VULN-GO-5: MaxBlastScore=0 means disabled — any valid blast_score is allowed.
	inp := minimalValidInput()
	score := 99
	inp.BlastScore = &score
	reg := enrolledRegistry()
	opts := RouterOptions{MaxBlastScore: 0}

	dec := MakeDecision(inp, reg, opts)
	if dec.Denied {
		t.Fatalf("VULN-GO-5: MaxBlastScore=0 must not enforce blast score limit, got: %v", dec.DenyReasonIfDenied)
	}
}

func TestBlastScoreExceedsMaxEmitsBlastScoredTelemetry(t *testing.T) {
	// VULN-GO-5: deny due to blast score must emit evt.os.gov.blast_scored telemetry.
	inp := minimalValidInput()
	score := 75
	inp.BlastScore = &score
	reg := enrolledRegistry()
	opts := RouterOptions{MaxBlastScore: 40}

	dec := MakeDecision(inp, reg, opts)
	if !dec.Denied {
		t.Fatal("VULN-GO-5: expected denied decision for blast_score > MaxBlastScore")
	}
	found := false
	for _, e := range dec.TelemetryEnvelopes {
		if e["event_id"] == "evt.os.gov.blast_scored" {
			found = true
			if e["blast_score"] != score {
				t.Errorf("VULN-GO-5: expected blast_score=%d in telemetry, got %v", score, e["blast_score"])
			}
			if e["max_blast_score"] != opts.MaxBlastScore {
				t.Errorf("VULN-GO-5: expected max_blast_score=%d in telemetry, got %v", opts.MaxBlastScore, e["max_blast_score"])
			}
		}
	}
	if !found {
		t.Error("VULN-GO-5: expected evt.os.gov.blast_scored event in TelemetryEnvelopes")
	}
}

// ---------------------------------------------------------------------------
// PATCH-GO-ENUM-001: Runtime enum validation
// ---------------------------------------------------------------------------

func TestEnumValidation_InvalidEnv(t *testing.T) {
	// PATCH-GO-ENUM-001: env="prod " (trailing space) must be denied with INVALID_ENV.
	// Before the fix, "prod " != EnvProd so prod/edge privilege checks were bypassed
	// entirely, allowing restricted-data requests to route without enforcement.
	inp := minimalValidInput()
	inp.Env = Env("prod ")
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("PATCH-GO-ENUM-001: env with trailing space must be denied (not bypass prod checks)")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "INVALID_ENV" {
		t.Errorf("PATCH-GO-ENUM-001: expected INVALID_ENV, got %v", code)
	}
}

func TestEnumValidation_InvalidDataLabel(t *testing.T) {
	// PATCH-GO-ENUM-001: data_label="RESTRICTED " (trailing space) must be denied with INVALID_DATA_LABEL.
	// Before the fix, "RESTRICTED " != DataLabelRestricted so privilege checks for
	// RESTRICTED data in prod/edge were silently bypassed.
	inp := minimalValidInput()
	inp.DataLabel = DataLabel("RESTRICTED ")
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("PATCH-GO-ENUM-001: data_label with trailing space must be denied (not bypass RESTRICTED checks)")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "INVALID_DATA_LABEL" {
		t.Errorf("PATCH-GO-ENUM-001: expected INVALID_DATA_LABEL, got %v", code)
	}
}

func TestEnumValidation_UnknownEnv(t *testing.T) {
	// PATCH-GO-ENUM-001: env="production" (unknown value) must be denied with INVALID_ENV.
	// Only the four canonical WCP env values are accepted.
	inp := minimalValidInput()
	inp.Env = Env("production")
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("PATCH-GO-ENUM-001: unknown env value must be denied")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "INVALID_ENV" {
		t.Errorf("PATCH-GO-ENUM-001: expected INVALID_ENV for unknown env, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// PATCH-GO-CORRID-002: Whitespace-only correlation_id bypass
// ---------------------------------------------------------------------------

func TestCorrelationIDWhitespaceOnly(t *testing.T) {
	// PATCH-GO-CORRID-002: correlation_id="   " (whitespace only) must be denied
	// with MISSING_CORRELATION_ID. The original check used == "" which allowed
	// whitespace-only values through, bypassing the mandatory correlation requirement.
	inp := minimalValidInput()
	inp.CorrelationID = "   "
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("PATCH-GO-CORRID-002: whitespace-only correlation_id must be denied")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "MISSING_CORRELATION_ID" {
		t.Errorf("PATCH-GO-CORRID-002: expected MISSING_CORRELATION_ID, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// PATCH-XSDK-TENANT-004 (Go): Empty tenant_id accepted
// ---------------------------------------------------------------------------

func TestMissingTenantID(t *testing.T) {
	// PATCH-XSDK-TENANT-004: tenant_id="" must be denied with DENY_MISSING_TENANT_ID.
	// Before the fix, an empty tenant_id was accepted and routed successfully,
	// bypassing per-tenant governance, attribution, and audit requirements.
	inp := minimalValidInput()
	inp.TenantID = ""
	reg := enrolledRegistry()
	dec := MakeDecision(inp, reg, defaultOpts())
	if !dec.Denied {
		t.Fatal("PATCH-XSDK-TENANT-004: empty tenant_id must be denied")
	}
	code := dec.DenyReasonIfDenied["code"]
	if code != "DENY_MISSING_TENANT_ID" {
		t.Errorf("PATCH-XSDK-TENANT-004: expected DENY_MISSING_TENANT_ID, got %v", code)
	}
}

// ---------------------------------------------------------------------------
// WCP §5.10 — Worker Code Attestation enforcement
// ---------------------------------------------------------------------------

// attestationOpts builds RouterOptions with attestation enabled and the provided
// hash callbacks. Pass nil for either to test the missing-callback path.
func attestationOpts(getHash func(string) (string, bool), getCurrent func(string) (string, bool)) RouterOptions {
	return RouterOptions{
		RequireWorkerAttestation: true,
		GetWorkerHash:            getHash,
		GetCurrentWorkerHash:     getCurrent,
	}
}

// validSHA256 is a syntactically valid 64-char lowercase hex string used in tests.
var validSHA256 = strings.Repeat("a", 64) //nolint:unused

// prodPolicyOpts returns RouterOptions that pass the policy gate in prod
// (so attestation tests are not blocked by the prod fail-closed gate).
func prodPolicyOpts(getHash func(string) (string, bool), getCurrent func(string) (string, bool)) RouterOptions {
	return RouterOptions{
		PolicyGate: DefaultPolicyGate{
			Rules: []PolicyRule{{Passed: true, Reason: "test: allow"}},
		},
		RequireWorkerAttestation: true,
		GetWorkerHash:            getHash,
		GetCurrentWorkerHash:     getCurrent,
	}
}

func TestAttestationEnforcement(t *testing.T) {
	const speciesID = "wrk.doc.summarizer"

	t.Run("RequireWorkerAttestation=false (default) — no attestation performed", func(t *testing.T) {
		inp := minimalValidInput()
		reg := enrolledRegistry()
		dec := MakeDecision(inp, reg, defaultOpts())

		if dec.Denied {
			t.Fatalf("expected allow, got denied: %v", dec.DenyReasonIfDenied)
		}
		if dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=false when RequireWorkerAttestation=false")
		}
		if dec.WorkerAttestationValid != nil {
			t.Errorf("expected WorkerAttestationValid=nil, got %v", dec.WorkerAttestationValid)
		}
	})

	t.Run("matching hashes — DISPATCHED with attestation checked", func(t *testing.T) {
		inp := minimalValidInput()
		reg := enrolledRegistry()

		hash := strings.Repeat("c", 64)
		opts := attestationOpts(
			func(_ string) (string, bool) { return hash, true },
			func(_ string) (string, bool) { return hash, true },
		)
		dec := MakeDecision(inp, reg, opts)

		if dec.Denied {
			t.Fatalf("expected allow when hashes match, got denied: %v", dec.DenyReasonIfDenied)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true on matching hash path")
		}
		if dec.WorkerAttestationValid == nil {
			t.Fatal("expected WorkerAttestationValid to be non-nil on matching hash path")
		}
		if !*dec.WorkerAttestationValid {
			t.Error("expected WorkerAttestationValid=true when hashes match")
		}
	})

	t.Run("hash mismatch — DENY_WORKER_TAMPERED", func(t *testing.T) {
		inp := minimalValidInput()
		reg := enrolledRegistry()

		registeredHash := strings.Repeat("d", 64)
		currentHash := strings.Repeat("e", 64)
		opts := attestationOpts(
			func(_ string) (string, bool) { return registeredHash, true },
			func(_ string) (string, bool) { return currentHash, true },
		)
		dec := MakeDecision(inp, reg, opts)

		if !dec.Denied {
			t.Fatal("expected DENY_WORKER_TAMPERED when hashes differ")
		}
		code := dec.DenyReasonIfDenied["code"]
		if code != "DENY_WORKER_TAMPERED" {
			t.Errorf("expected DENY_WORKER_TAMPERED, got %v", code)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true on tampered path")
		}
		if dec.WorkerAttestationValid == nil {
			t.Fatal("expected WorkerAttestationValid to be non-nil on tampered path")
		}
		if *dec.WorkerAttestationValid {
			t.Error("expected WorkerAttestationValid=false when hashes differ")
		}
		// F4 security: hash values must NOT appear in the deny reason message.
		reason, _ := dec.DenyReasonIfDenied["reason"].(string)
		if strings.Contains(reason, registeredHash) || strings.Contains(reason, currentHash) {
			t.Error("F4 security violation: deny reason must not contain hash values")
		}
	})

	t.Run("missing callbacks — DENY_ATTESTATION_UNCONFIGURED", func(t *testing.T) {
		inp := minimalValidInput()
		reg := enrolledRegistry()
		opts := RouterOptions{
			RequireWorkerAttestation: true,
			// GetWorkerHash and GetCurrentWorkerHash intentionally nil.
		}
		dec := MakeDecision(inp, reg, opts)

		if !dec.Denied {
			t.Fatal("expected DENY_ATTESTATION_UNCONFIGURED when callbacks are nil")
		}
		code := dec.DenyReasonIfDenied["code"]
		if code != "DENY_ATTESTATION_UNCONFIGURED" {
			t.Errorf("expected DENY_ATTESTATION_UNCONFIGURED, got %v", code)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true in attestation deny paths")
		}
	})

	t.Run("no registered hash — DENY_WORKER_ATTESTATION_MISSING", func(t *testing.T) {
		inp := minimalValidInput()
		reg := enrolledRegistry()
		opts := attestationOpts(
			func(_ string) (string, bool) { return "", false },
			func(_ string) (string, bool) { return strings.Repeat("f", 64), true },
		)
		dec := MakeDecision(inp, reg, opts)

		if !dec.Denied {
			t.Fatal("expected DENY_WORKER_ATTESTATION_MISSING")
		}
		code := dec.DenyReasonIfDenied["code"]
		if code != "DENY_WORKER_ATTESTATION_MISSING" {
			t.Errorf("expected DENY_WORKER_ATTESTATION_MISSING, got %v", code)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true in attestation deny paths")
		}
	})

	t.Run("registered hash is empty string with ok=true — DENY_WORKER_ATTESTATION_MISSING", func(t *testing.T) {
		// GetWorkerHash returns ("", true): worker is registered but the stored
		// hash value is an empty string. The router treats registeredHash == ""
		// as missing regardless of the ok flag — not as a valid hash to compare.
		inp := minimalValidInput()
		reg := enrolledRegistry()
		opts := attestationOpts(
			func(_ string) (string, bool) { return "", true },
			func(_ string) (string, bool) { return strings.Repeat("f", 64), true },
		)
		dec := MakeDecision(inp, reg, opts)

		if !dec.Denied {
			t.Fatal("expected DENY_WORKER_ATTESTATION_MISSING when registered hash is empty string with ok=true")
		}
		code := dec.DenyReasonIfDenied["code"]
		if code != "DENY_WORKER_ATTESTATION_MISSING" {
			t.Errorf("expected DENY_WORKER_ATTESTATION_MISSING, got %v", code)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true in attestation deny paths")
		}
	})

	t.Run("current hash unavailable — DENY_WORKER_HASH_UNAVAILABLE", func(t *testing.T) {
		inp := minimalValidInput()
		reg := enrolledRegistry()
		opts := attestationOpts(
			func(_ string) (string, bool) { return strings.Repeat("a", 64), true },
			func(_ string) (string, bool) { return "", false },
		)
		dec := MakeDecision(inp, reg, opts)

		if !dec.Denied {
			t.Fatal("expected DENY_WORKER_HASH_UNAVAILABLE")
		}
		code := dec.DenyReasonIfDenied["code"]
		if code != "DENY_WORKER_HASH_UNAVAILABLE" {
			t.Errorf("expected DENY_WORKER_HASH_UNAVAILABLE, got %v", code)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true in attestation deny paths")
		}
	})

	t.Run("malformed registered hash — DENY_WORKER_ATTESTATION_INVALID_HASH", func(t *testing.T) {
		inp := minimalValidInput()
		reg := enrolledRegistry()
		opts := attestationOpts(
			// Not a valid SHA-256 hex digest.
			func(_ string) (string, bool) { return "not-a-valid-hash", true },
			func(_ string) (string, bool) { return strings.Repeat("b", 64), true },
		)
		dec := MakeDecision(inp, reg, opts)

		if !dec.Denied {
			t.Fatal("expected DENY_WORKER_ATTESTATION_INVALID_HASH for malformed hash")
		}
		code := dec.DenyReasonIfDenied["code"]
		if code != "DENY_WORKER_ATTESTATION_INVALID_HASH" {
			t.Errorf("expected DENY_WORKER_ATTESTATION_INVALID_HASH, got %v", code)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true in attestation deny paths")
		}
	})

	t.Run("no worker selected — attestation block skipped", func(t *testing.T) {
		// No workers enrolled → NO_WORKER_FOR_CAPABILITY deny.
		// The attestation block must not run (no worker was selected).
		inp := minimalValidInput()
		inp.CapabilityID = "cap.no.worker.registered"
		reg := NewRegistry() // empty
		opts := RouterOptions{
			RequireWorkerAttestation: true,
			GetWorkerHash:            func(_ string) (string, bool) { return strings.Repeat("a", 64), true },
			GetCurrentWorkerHash:     func(_ string) (string, bool) { return strings.Repeat("a", 64), true },
		}
		dec := MakeDecision(inp, reg, opts)

		if !dec.Denied {
			t.Fatal("expected Denied=true when no workers are registered")
		}
		code := dec.DenyReasonIfDenied["code"]
		if code != "NO_WORKER_FOR_CAPABILITY" {
			t.Errorf("expected NO_WORKER_FOR_CAPABILITY (not an attestation code), got %v", code)
		}
		if dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=false when no worker was selected")
		}
	})

	t.Run("F24 — attestation_skipped telemetry in prod when not required", func(t *testing.T) {
		// In prod with RequireWorkerAttestation=false, the router should emit
		// evt.os.worker.attestation_skipped as a warning telemetry event.
		inp := minimalValidInput()
		inp.Env = EnvProd
		reg := enrolledRegistry()
		// Use a policy gate that passes in prod (otherwise denied before attestation).
		opts := RouterOptions{
			PolicyGate: DefaultPolicyGate{
				Rules: []PolicyRule{{Passed: true, Reason: "test: allow"}},
			},
			RequireWorkerAttestation: false, // attestation not required
		}
		dec := MakeDecision(inp, reg, opts)

		if dec.Denied {
			t.Fatalf("expected allow decision, got denied: %v", dec.DenyReasonIfDenied)
		}

		found := false
		for _, e := range dec.TelemetryEnvelopes {
			if e["event_id"] == "evt.os.worker.attestation_skipped" {
				found = true
				if e["env"] != string(EnvProd) {
					t.Errorf("expected env=prod in attestation_skipped event, got %v", e["env"])
				}
				if e["severity"] != "warn" {
					t.Errorf("expected severity=warn in attestation_skipped event, got %v", e["severity"])
				}
			}
		}
		if !found {
			t.Error("F24: expected evt.os.worker.attestation_skipped event in TelemetryEnvelopes for prod without attestation")
		}
	})
}

// ---------------------------------------------------------------------------
// RegistryClient auto-wire: RouterOptions.RegistryClient forces attestation
// ---------------------------------------------------------------------------

func TestMakeDecision_AutoWiresRegistryClient(t *testing.T) {
	// Verify that setting RouterOptions.RegistryClient:
	//   1. Forces RequireWorkerAttestation=true without the caller setting it.
	//   2. Wires GetWorkerHash from the client cache.
	//   3. Still denies when GetCurrentWorkerHash is absent (DENY_ATTESTATION_UNCONFIGURED).
	//
	// We use a real RegistryClient pointed at a non-existent server but pre-populate
	// its cache directly via setCache so no network calls are made.

	reg := enrolledRegistry() // wrk.doc.summarizer / cap.doc.summarize
	inp := minimalValidInput()

	hash := strings.Repeat("b", 64)

	// Build a RegistryClient and seed its cache so GetWorkerHash returns the hash.
	client := NewRegistryClient(RegistryClientOptions{
		BaseURL: "http://127.0.0.1:0", // unreachable — cache must be hit instead
	})
	client.setCache("wrk.doc.summarizer", VerifyResponse{
		WorkerID:    "wrk.doc.summarizer",
		Status:      "active",
		CurrentHash: &hash,
	})

	t.Run("RegistryClient without GetCurrentWorkerHash → DENY_ATTESTATION_UNCONFIGURED", func(t *testing.T) {
		// RegistryClient is set; GetCurrentWorkerHash is not.
		// The router must auto-enable RequireWorkerAttestation and then deny
		// because GetCurrentWorkerHash is still nil.
		opts := RouterOptions{
			RegistryClient: client,
			// GetCurrentWorkerHash intentionally omitted.
		}
		dec := MakeDecision(inp, reg, opts)

		if !dec.Denied {
			t.Fatal("expected DENY_ATTESTATION_UNCONFIGURED when RegistryClient is set but GetCurrentWorkerHash is nil")
		}
		code := dec.DenyReasonIfDenied["code"]
		if code != "DENY_ATTESTATION_UNCONFIGURED" {
			t.Errorf("expected DENY_ATTESTATION_UNCONFIGURED, got %v", code)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true — RequireWorkerAttestation must have been forced on by RegistryClient")
		}
	})

	t.Run("RegistryClient with matching GetCurrentWorkerHash → allowed", func(t *testing.T) {
		// RegistryClient provides the registered hash via cache.
		// GetCurrentWorkerHash returns the same hash → attestation passes.
		opts := RouterOptions{
			RegistryClient: client,
			GetCurrentWorkerHash: func(_ string) (string, bool) {
				return hash, true
			},
		}
		dec := MakeDecision(inp, reg, opts)

		if dec.Denied {
			t.Fatalf("expected allow when RegistryClient hash matches current hash, got denied: %v", dec.DenyReasonIfDenied)
		}
		if !dec.WorkerAttestationChecked {
			t.Error("expected WorkerAttestationChecked=true when RegistryClient is set")
		}
		if dec.WorkerAttestationValid == nil || !*dec.WorkerAttestationValid {
			t.Error("expected WorkerAttestationValid=true when hashes match via RegistryClient")
		}
	})

	t.Run("RegistryClient does not override caller-supplied GetWorkerHash", func(t *testing.T) {
		// If the caller already provides GetWorkerHash, RegistryClient must not
		// overwrite it (the auto-wire only sets GetWorkerHash when it is nil).
		callerHash := strings.Repeat("c", 64)
		callerHashCalled := false

		opts := RouterOptions{
			RegistryClient: client,
			GetWorkerHash: func(_ string) (string, bool) {
				callerHashCalled = true
				return callerHash, true
			},
			GetCurrentWorkerHash: func(_ string) (string, bool) {
				return callerHash, true // match caller-supplied hash
			},
		}
		dec := MakeDecision(inp, reg, opts)

		if dec.Denied {
			t.Fatalf("expected allow when caller-supplied GetWorkerHash matches current hash, got denied: %v", dec.DenyReasonIfDenied)
		}
		if !callerHashCalled {
			t.Error("expected caller-supplied GetWorkerHash to be called (not overridden by RegistryClient)")
		}
	})
}
