package wcp

// PATCH-XSDK-001: Cross-SDK Governance Conformance Tests
//
// Loads shared test vectors from docs/conformance/wcp_conformance_vectors.json
// and verifies that the Go SDK produces the declared `denied` outcome (and
// deny_code where applicable) for each vector not listed in skip_sdks.
//
// Purpose: detect governance regressions that survive per-SDK tests because
// they only manifest as cross-SDK divergence. When this test passes alongside
// Python and TypeScript conformance tests, all three SDKs agree on governance
// outcomes for every shared vector.
//
// Run:
//   go test ./wcp/ -run Conformance -v

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ---------------------------------------------------------------------------
// Vector file schema (mirrors docs/conformance/wcp_conformance_vectors.json)
// ---------------------------------------------------------------------------

type conformanceExpect struct {
	Denied             bool    `json:"denied"`
	DenyCode           *string `json:"deny_code"`
	DenyCodeGo         *string `json:"deny_code_go"`
	DenyCodePython     *string `json:"deny_code_python"`
	TelemetryInvariant *string `json:"telemetry_invariant"`
}

type conformanceSetup struct {
	NoWorkers         bool     `json:"no_workers"`
	RequiredControl   *string  `json:"required_control"`
	ControlPresent    *bool    `json:"control_present"`
	WorkerAllowedEnvs []string `json:"worker_allowed_envs"`
	WorkerSpeciesID   *string  `json:"worker_species_id"`
	WorkerCapability  *string  `json:"worker_capability"`
}

type ruleDecision struct {
	CandidateWorkersRanked   []map[string]interface{} `json:"candidate_workers_ranked"`
	RequiredControlsSuggested []string                 `json:"required_controls_suggested"`
	Escalation                map[string]interface{}   `json:"escalation"`
	Preconditions             map[string]interface{}   `json:"preconditions"`
}

type conformanceRule struct {
	RuleID   string                 `json:"rule_id"`
	Match    map[string]interface{} `json:"match"`
	Decision ruleDecision           `json:"decision"`
}

type conformanceInput struct {
	CapabilityID string      `json:"capability_id"`
	Env          string      `json:"env"`
	DataLabel    string      `json:"data_label"`
	TenantRisk   string      `json:"tenant_risk"`
	QoSClass     string      `json:"qos_class"`
	TenantID     string      `json:"tenant_id"`
	CorrelationID string     `json:"correlation_id"`
	BlastScore   *int        `json:"blast_score"`
	Request      interface{} `json:"request"`
}

type conformanceVector struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	SkipSDKs    []string          `json:"skip_sdks"`
	SkipReason  string            `json:"skip_reason"`
	Notes       string            `json:"notes"`
	Input       conformanceInput  `json:"input"`
	Rule        *conformanceRule  `json:"rule"`
	Setup       *conformanceSetup `json:"setup"`
	Expect      conformanceExpect `json:"expect"`
}

type vectorFile struct {
	Vectors []conformanceVector `json:"vectors"`
}

const sdkName = "go"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// vectorsPath returns the absolute path to the conformance vectors JSON file.
// It uses the current file's location to locate the repo root.
func vectorsPath() string {
	_, filename, _, _ := runtime.Caller(0)
	// conformance_test.go is at: git/sdk/go/wcp/conformance_test.go
	// so: wcp/ -> go/ -> sdk/ -> git/ -> docs/conformance/
	wcpDir := filepath.Dir(filename)     // sdk/go/wcp
	gitRoot := filepath.Join(wcpDir, "..", "..", "..") // sdk/go/wcp -> sdk/go -> sdk -> git
	return filepath.Join(gitRoot, "docs", "conformance", "wcp_conformance_vectors.json")
}

// loadVectors reads and parses the conformance vectors file.
func loadVectors(t *testing.T) []conformanceVector {
	t.Helper()
	data, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Fatalf("conformance: failed to read vectors file %s: %v", vectorsPath(), err)
	}
	var doc vectorFile
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("conformance: failed to parse vectors file: %v", err)
	}
	return doc.Vectors
}

// isSkipped returns true if the vector should be skipped for this SDK.
// Vectors with skip_sdks=["all"] are procedural multi-step tests implemented
// as standalone test functions — they are excluded from the parametric loop.
func isSkipped(v conformanceVector) bool {
	for _, sdk := range v.SkipSDKs {
		if sdk == sdkName || sdk == "all" {
			return true
		}
	}
	return false
}

// buildRouteInput constructs a RouteInput from the vector's input spec.
func buildRouteInput(inp conformanceInput) RouteInput {
	return RouteInput{
		CapabilityID:  inp.CapabilityID,
		Env:           Env(inp.Env),
		DataLabel:     DataLabel(inp.DataLabel),
		TenantRisk:    TenantRisk(inp.TenantRisk),
		QoSClass:      QoSClass(inp.QoSClass),
		TenantID:      inp.TenantID,
		CorrelationID: inp.CorrelationID,
		BlastScore:    inp.BlastScore,
	}
}

// buildRegistry constructs a Registry for the vector.
//
// Setup rules:
//   - no_workers=true → empty registry
//   - worker_allowed_envs set → enroll worker with AllowedEnvironments constraint
//   - required_control + control_present → enroll an implementing worker if present=true
//   - default → enroll wrk.test.worker for cap.doc.summarize (the standard test worker)
func buildRegistry(t *testing.T, vector conformanceVector) *Registry {
	t.Helper()
	r := NewRegistry()
	setup := vector.Setup

	if setup != nil && setup.NoWorkers {
		return r
	}

	// AllowedEnvironments vector (CV-009, CV-010)
	if setup != nil && len(setup.WorkerAllowedEnvs) > 0 {
		speciesID := "wrk.test.devonly"
		if setup.WorkerSpeciesID != nil {
			speciesID = *setup.WorkerSpeciesID
		}
		capability := "cap.doc.devonly"
		if setup.WorkerCapability != nil {
			capability = *setup.WorkerCapability
		}
		err := r.Enroll(WorkerRegistryRecord{
			WorkerID:            "org.conformance.devonly-worker",
			WorkerSpeciesID:     speciesID,
			Capabilities:        []string{capability},
			AllowedEnvironments: setup.WorkerAllowedEnvs,
		})
		if err != nil {
			t.Fatalf("%s: failed to enroll dev-only worker: %v", vector.ID, err)
		}
		return r
	}

	// Required control vector (CV-007, CV-008)
	// Enroll the primary worker that needs the control.
	var requiredControls []string
	if setup != nil && setup.RequiredControl != nil {
		requiredControls = []string{*setup.RequiredControl}
	}
	err := r.Enroll(WorkerRegistryRecord{
		WorkerID:        "org.conformance.test-worker",
		WorkerSpeciesID: "wrk.test.worker",
		Capabilities:    []string{"cap.doc.summarize"},
		RequiredControls: requiredControls,
	})
	if err != nil {
		t.Fatalf("%s: failed to enroll test worker: %v", vector.ID, err)
	}

	// If control_present=true, enroll a second worker that implements it
	if setup != nil && setup.RequiredControl != nil && setup.ControlPresent != nil && *setup.ControlPresent {
		err2 := r.Enroll(WorkerRegistryRecord{
			WorkerID:            "org.conformance.control-provider",
			WorkerSpeciesID:     "wrk.ctrl.provider",
			Capabilities:        []string{"cap.ctrl.provider"},
			CurrentlyImplements: []string{*setup.RequiredControl},
		})
		if err2 != nil {
			t.Fatalf("%s: failed to enroll control-provider worker: %v", vector.ID, err2)
		}
	}

	return r
}

// resolveExpectedCode returns the Go-specific deny code from the vector.
// Falls back to the generic deny_code if no Go-specific code is declared.
func resolveExpectedCode(vector conformanceVector) *string {
	if vector.Expect.DenyCodeGo != nil {
		return vector.Expect.DenyCodeGo
	}
	return vector.Expect.DenyCode
}

// buildRouterOpts returns RouterOptions appropriate for this vector.
// For CV-009 (prod env with AllowedEnvironments restriction), we need the policy
// gate to pass so the env restriction is actually reached. Use a permissive gate.
func buildRouterOpts(vector conformanceVector) RouterOptions {
	// Vectors with prod env need a policy gate that allows (otherwise gate denies first).
	if vector.Input.Env == "prod" || vector.Input.Env == "edge" {
		return RouterOptions{
			PolicyGate: DefaultPolicyGate{
				Rules: []PolicyRule{
					{Passed: true, Reason: "conformance: allow for env-restriction test"},
				},
			},
		}
	}
	return RouterOptions{}
}

// ---------------------------------------------------------------------------
// Conformance test entry point
// ---------------------------------------------------------------------------

func TestConformanceVectors(t *testing.T) {
	vectors := loadVectors(t)

	// Sanity: all 13 required IDs must be present
	t.Run("vector_file_has_required_ids", func(t *testing.T) {
		ids := make(map[string]bool)
		for _, v := range vectors {
			ids[v.ID] = true
		}
		for i := 1; i <= 13; i++ {
			id := cvID(i)
			if !ids[id] {
				t.Errorf("required conformance vector %s is missing from vectors file", id)
			}
		}
	})

	// Sanity: every vector has required fields
	t.Run("vector_file_schema_valid", func(t *testing.T) {
		for _, v := range vectors {
			if v.ID == "" {
				t.Errorf("vector missing 'id': %+v", v)
			}
			if v.Description == "" {
				t.Errorf("vector %s missing 'description'", v.ID)
			}
			// Procedural vectors (skip_sdks=["all"]) have no input/expect block.
			// All others must have a non-empty capability_id.
			if v.Input.CapabilityID == "" && !isSkipped(v) {
				t.Errorf("vector %s missing capability_id in input", v.ID)
			}
		}
	})

	// Run each non-skipped vector as a subtest
	for _, vec := range vectors {
		vec := vec // capture loop variable
		if isSkipped(vec) {
			t.Run(vec.ID, func(t *testing.T) {
				t.Skipf("vector %s skipped for SDK %q: %s", vec.ID, sdkName, vec.SkipReason)
			})
			continue
		}

		t.Run(vec.ID, func(t *testing.T) {
			inp := buildRouteInput(vec.Input)
			registry := buildRegistry(t, vec)
			opts := buildRouterOpts(vec)

			dec := MakeDecision(inp, registry, opts)

			expectedDenied := vec.Expect.Denied
			if dec.Denied != expectedDenied {
				t.Errorf(
					"%s (%s): expected Denied=%v, got Denied=%v. DenyReasonIfDenied=%v",
					vec.ID, vec.Description, expectedDenied, dec.Denied, dec.DenyReasonIfDenied,
				)
			}

			// Assert deny code when denied and expected code is declared
			expectedCode := resolveExpectedCode(vec)
			if vec.Expect.Denied && expectedCode != nil {
				actualCode, _ := dec.DenyReasonIfDenied["code"].(string)
				if actualCode != *expectedCode {
					t.Errorf(
						"%s (%s): expected deny_code=%q, got %q. Full reason: %v",
						vec.ID, vec.Description, *expectedCode, actualCode, dec.DenyReasonIfDenied,
					)
				}
			}

			// Telemetry invariant: no raw control characters in capability_id field
			if vec.Expect.TelemetryInvariant != nil &&
				*vec.Expect.TelemetryInvariant == "no_control_chars_in_capability_id_field_in_telemetry" {
				for _, envelope := range dec.TelemetryEnvelopes {
					rawCap, _ := envelope["capability_id"].(string)
					for _, ch := range rawCap {
						if ch == '\n' || ch == '\x00' || ch == '\r' || (ch >= 0x00 && ch <= 0x1f) {
							t.Errorf(
								"%s: telemetry capability_id contains control char U+%04X: %q",
								vec.ID, ch, rawCap,
							)
							break
						}
					}
				}
			}
		})
	}

	// Skipped vectors must be documented
	t.Run("skipped_vectors_documented", func(t *testing.T) {
		for _, v := range vectors {
			if isSkipped(v) {
				if v.SkipReason == "" && v.Notes == "" {
					t.Errorf("vector %s is skipped for %q but has no skip_reason or notes", v.ID, sdkName)
				}
			}
		}
	})
}

// cvID formats a conformance vector ID like "CV-001".
func cvID(n int) string {
	switch {
	case n < 10:
		return "CV-00" + string(rune('0'+n))
	case n < 100:
		return "CV-0" + string(rune('0'+n/10)) + string(rune('0'+n%10))
	default:
		return "CV-???"
	}
}

// ---------------------------------------------------------------------------
// CV-013: Worker attestation — standalone procedural test (WCP §5.10)
// ---------------------------------------------------------------------------

// TestCV013WorkerAttestation is the Go implementation of CV-013.
//
// Release-blocking cross-SDK conformance vector. Tests the tamper detection
// path mandated by WCP §5.10:
//
//  1. Enroll worker with attestation registered (SHA-256 of source file).
//  2. Dispatch capability → verify WorkerAttestationValid=true, Denied=false.
//  3. Mutate the worker source file (change content).
//  4. Dispatch again → verify Denied=true, code=DENY_WORKER_TAMPERED.
//  5. Verify evidence receipt: WorkerAttestationChecked=true, Valid=false.
//  6. F4: hash values must NOT appear in the deny payload.
func TestCV013WorkerAttestation(t *testing.T) {
	// Step 1: create a temp worker file.
	tmpDir := t.TempDir()
	workerFile := filepath.Join(tmpDir, "worker.py")
	if err := os.WriteFile(workerFile, []byte("def run(): pass\n"), 0644); err != nil {
		t.Fatalf("CV-013: failed to create worker file: %v", err)
	}

	reg := NewRegistry()
	if err := reg.Enroll(WorkerRegistryRecord{
		WorkerID:            "org.test.cv013",
		WorkerSpeciesID:     "wrk.test.cv013",
		Capabilities:        []string{"cap.test.cv013"},
		RequiredControls:    []string{"ctrl.obs.audit-log-append-only"},
		CurrentlyImplements: []string{"ctrl.obs.audit-log-append-only"},
		AllowedEnvironments: []string{"dev"},
	}); err != nil {
		t.Fatalf("CV-013: enroll failed: %v", err)
	}

	if _, err := reg.RegisterAttestation("wrk.test.cv013", workerFile); err != nil {
		t.Fatalf("CV-013: RegisterAttestation failed: %v", err)
	}

	inp := RouteInput{
		CapabilityID:  "cap.test.cv013",
		Env:           EnvDev,
		DataLabel:     DataLabelPublic,
		TenantRisk:    TenantRiskLow,
		QoSClass:      QoSP2,
		TenantID:      "test.tenant",
		CorrelationID: "cv013",
	}

	opts := RouterOptions{
		RequireWorkerAttestation: true,
		GetWorkerHash:            reg.GetWorkerHash,
		GetCurrentWorkerHash:     reg.ComputeCurrentHash,
		WorkerAvailability:       AlwaysAvailable,
	}

	// Step 2: intact file → DISPATCHED
	dec1 := MakeDecision(inp, reg, opts)
	if dec1.Denied {
		t.Fatalf("CV-013 Step 2: expected DISPATCHED, got Denied with reason: %v", dec1.DenyReasonIfDenied)
	}
	if !dec1.WorkerAttestationChecked {
		t.Error("CV-013 Step 2: expected WorkerAttestationChecked=true")
	}
	if dec1.WorkerAttestationValid == nil || !*dec1.WorkerAttestationValid {
		t.Error("CV-013 Step 2: expected WorkerAttestationValid=true")
	}

	// Step 3: tamper — overwrite worker file content.
	if err := os.WriteFile(workerFile, []byte("def run(): exfiltrate()\n"), 0644); err != nil {
		t.Fatalf("CV-013: failed to tamper worker file: %v", err)
	}

	// Step 4: tampered file → DENY_WORKER_TAMPERED
	dec2 := MakeDecision(inp, reg, opts)
	if !dec2.Denied {
		t.Fatal("CV-013 Step 4: expected DENY_WORKER_TAMPERED after file mutation, got DISPATCHED")
	}
	code, _ := dec2.DenyReasonIfDenied["code"].(string)
	if code != "DENY_WORKER_TAMPERED" {
		t.Errorf("CV-013 Step 4: expected deny code DENY_WORKER_TAMPERED, got %q (full reason: %v)",
			code, dec2.DenyReasonIfDenied)
	}
	// Step 5: verify evidence receipt fields
	if !dec2.WorkerAttestationChecked {
		t.Error("CV-013 Step 5: expected WorkerAttestationChecked=true")
	}
	if dec2.WorkerAttestationValid == nil {
		t.Error("CV-013 Step 4: WorkerAttestationValid is nil — router did not set it on DENY_WORKER_TAMPERED path")
	} else if *dec2.WorkerAttestationValid {
		t.Error("CV-013 Step 4: expected WorkerAttestationValid=false, got true")
	}
	// Step 6 / F4: hash values must NOT appear in the deny payload
	if _, ok := dec2.DenyReasonIfDenied["registered_hash"]; ok {
		t.Error("CV-013 F4 violation: registered_hash must not appear in deny payload")
	}
	if _, ok := dec2.DenyReasonIfDenied["current_hash"]; ok {
		t.Error("CV-013 F4 violation: current_hash must not appear in deny payload")
	}
}
