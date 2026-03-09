// Package hello_worker is the canonical minimal WCP worker example.
//
// This worker demonstrates the three-step WCP worker contract:
//  1. Receive a RouteDecision from the Hall.
//  2. Execute the work (here: just return a greeting).
//  3. Return an evidence receipt with artifact_hash and controls_verified.
//
// Every real WCP worker follows this same pattern regardless of what it does.
// The governance contract is identical whether the worker summarizes a document,
// fetches a URL, or runs an ML inference job.
//
// To enroll this worker in a Hall, use the registry_record.json alongside it.
package hello_worker

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pyhall/pyhall-go/wcp"
)

// HelloWorker implements the "cap.example.greet" capability.
// Worker species: wrk.example.greeter
type HelloWorker struct{}

// WorkerResult is the structured output returned by this worker.
type WorkerResult struct {
	// Message is the greeting produced by the worker.
	Message string `json:"message"`

	// EvidenceReceipt is the WCP evidence receipt proving governance was honored.
	// Required by WCP section 5.7 for all executed dispatches.
	EvidenceReceipt EvidenceReceipt `json:"evidence_receipt"`
}

// EvidenceReceipt is the mandatory WCP evidence receipt (spec section 5.7).
// The Hall or worker MUST produce this for every executed dispatch.
type EvidenceReceipt struct {
	// CorrelationID is propagated from the RouteDecision.
	CorrelationID string `json:"correlation_id"`

	// DispatchedAt is the ISO 8601 UTC timestamp when the worker was dispatched.
	DispatchedAt string `json:"dispatched_at"`

	// WorkerID identifies the specific worker instance.
	WorkerID string `json:"worker_id"`

	// CapabilityID identifies the capability that was executed.
	CapabilityID string `json:"capability_id"`

	// PolicyDecision summarizes the policy gate outcome.
	PolicyDecision string `json:"policy_decision"`

	// ControlsVerified lists the controls that were verified before dispatch.
	ControlsVerified []string `json:"controls_verified"`

	// ArtifactHash is the SHA-256 of the serialised request payload.
	// Proves exactly what was sent to the worker.
	ArtifactHash string `json:"artifact_hash"`
}

// Run executes the hello worker.
//
// Parameters:
//   - decision: the RouteDecision produced by the Hall. Must not be denied.
//   - request: the raw request payload from RouteInput.Request.
//
// The worker's job is:
//  1. Validate preconditions (decision must be allowed, correlation_id present).
//  2. Execute the capability (produce the greeting).
//  3. Return a WorkerResult including the evidence receipt.
func (w HelloWorker) Run(decision wcp.RouteDecision, request map[string]any) (*WorkerResult, error) {
	// --- Precondition: must not be a denied decision ---
	if decision.Denied {
		return nil, fmt.Errorf("hello_worker: received denied RouteDecision — refusing execution")
	}

	// --- Precondition: correlation_id must be present ---
	if decision.CorrelationID == "" {
		return nil, fmt.Errorf("hello_worker: correlation_id is missing — cannot produce auditable evidence")
	}

	// --- Execute the capability ---
	// In a real worker this is where the actual work happens.
	// This worker just builds a greeting.
	name, _ := request["name"].(string)
	if name == "" {
		name = "World"
	}
	message := fmt.Sprintf("Hello from WCP, %s! correlation_id=%s", name, decision.CorrelationID)

	// --- Compute artifact_hash of the request payload ---
	// Required by WCP section 5.7. Proves what was sent to the worker.
	payloadBytes, _ := json.Marshal(request)
	artifactHash := "sha256:" + wcp.SHA256Hex(payloadBytes)

	// --- Build evidence receipt ---
	controlsVerified := decision.RequiredControlsEffective
	if controlsVerified == nil {
		controlsVerified = []string{}
	}

	receipt := EvidenceReceipt{
		CorrelationID:    decision.CorrelationID,
		DispatchedAt:     time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		WorkerID:         "org.fafolab.hello-worker",
		CapabilityID:     decision.CapabilityID,
		PolicyDecision:   "allowed",
		ControlsVerified: controlsVerified,
		ArtifactHash:     artifactHash,
	}

	return &WorkerResult{
		Message:         message,
		EvidenceReceipt: receipt,
	}, nil
}
