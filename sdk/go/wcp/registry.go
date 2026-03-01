package wcp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// RegistryError is returned when a registry operation fails.
type RegistryError struct {
	Op  string // operation that failed
	Msg string
}

func (e RegistryError) Error() string {
	return fmt.Sprintf("registry %s: %s", e.Op, e.Msg)
}

// Registry stores the enrolled workers and routing rules.
//
// v0.1: in-memory only. Workers are enrolled via Enroll() and looked up
// by capability ID during routing.
//
// TODO(impl): persist to SQLite / JSON on disk so workers survive restarts.
// TODO(impl): support loading from a seed file (routing_rules.seed.json).
// TODO(impl): expose GET /wcp/workers and GET /wcp/capabilities HTTP handlers.
type Registry struct {
	mu      sync.RWMutex
	workers map[string]WorkerRegistryRecord // keyed by WorkerID

	// WCP §5.10 — Worker Code Attestation state.
	// Keyed by WorkerSpeciesID (not WorkerID) so attestation is per-species.
	attestationHashes map[string]string // speciesID → registered SHA-256 hex
	attestationFiles  map[string]string // speciesID → resolved absolute file path
	attestationMu     sync.RWMutex     // separate lock to avoid deadlock with mu
}

// NewRegistry creates an empty in-memory registry.
func NewRegistry() *Registry {
	return &Registry{
		workers:           make(map[string]WorkerRegistryRecord),
		attestationHashes: make(map[string]string),
		attestationFiles:  make(map[string]string),
	}
}

// RegisterAttestation records the SHA-256 hash of a worker's source file for a
// given speciesID. Implements WCP §5.10 worker code attestation.
//
// sourceFile is resolved to an absolute path. If the file does not exist,
// a RegistryError is returned. The computed SHA-256 hex digest is stored and
// returned for caller confirmation.
//
// Thread-safe — uses attestationMu independently from the worker enrollment lock
// to avoid deadlock.
func (r *Registry) RegisterAttestation(speciesID, sourceFile string) (string, error) {
	resolved, err := filepath.Abs(sourceFile)
	if err != nil {
		return "", RegistryError{Op: "register_attestation", Msg: "cannot resolve path: " + err.Error()}
	}

	f, err := os.Open(resolved)
	if err != nil {
		return "", RegistryError{Op: "register_attestation", Msg: "file not found: " + resolved}
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", RegistryError{Op: "register_attestation", Msg: "cannot read file: " + err.Error()}
	}
	digest := hex.EncodeToString(h.Sum(nil))

	r.attestationMu.Lock()
	r.attestationHashes[speciesID] = digest
	r.attestationFiles[speciesID] = resolved
	r.attestationMu.Unlock()

	return digest, nil
}

// GetWorkerHash returns the registered code hash for a worker species.
// Returns the hash and true if registered, or "", false if not registered.
//
// Thread-safe.
func (r *Registry) GetWorkerHash(speciesID string) (string, bool) {
	r.attestationMu.RLock()
	defer r.attestationMu.RUnlock()
	h, ok := r.attestationHashes[speciesID]
	return h, ok
}

// ComputeCurrentHash reads the file that was registered for speciesID and
// returns its current SHA-256 hex digest. Returns "", false if speciesID has
// no registered file, or if the file cannot be read (deleted, permission error, etc.).
//
// Thread-safe.
func (r *Registry) ComputeCurrentHash(speciesID string) (string, bool) {
	r.attestationMu.RLock()
	path, ok := r.attestationFiles[speciesID]
	r.attestationMu.RUnlock()

	if !ok {
		return "", false
	}

	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// Enroll adds a worker record to the registry.
// Returns RegistryError if the record is invalid or already enrolled.
//
// GO-F7 fix: ID fields are now validated against WCP format rules. WorkerID,
// WorkerSpeciesID, capability IDs, and control IDs must not contain control
// characters, path separators, or other characters that could corrupt telemetry
// or enable log injection. Empty or malformed IDs are rejected at enrollment.
//
// TODO(impl): verify declared controls match currently_implements.
// TODO(impl): compute and store ArtifactHash of the record on enrollment.
func (r *Registry) Enroll(rec WorkerRegistryRecord) error {
	// --- Required field checks ---
	if rec.WorkerID == "" {
		return RegistryError{Op: "enroll", Msg: "worker_id is required"}
	}
	if rec.WorkerSpeciesID == "" {
		return RegistryError{Op: "enroll", Msg: "worker_species_id is required"}
	}
	if len(rec.Capabilities) == 0 {
		return RegistryError{Op: "enroll", Msg: "at least one capability is required"}
	}

	// --- GO-F7 fix: format validation for ID fields ---
	// WorkerID must match the safe ID pattern (no control chars, path separators, etc.)
	if !workerIDRe.MatchString(rec.WorkerID) {
		return RegistryError{Op: "enroll", Msg: fmt.Sprintf(
			"worker_id %q contains invalid characters; must match pattern %s",
			SanitizeID(rec.WorkerID), workerIDRe.String(),
		)}
	}
	// WorkerSpeciesID must match the capability ID pattern (dot-separated lowercase).
	if !capabilityIDRe.MatchString(rec.WorkerSpeciesID) {
		return RegistryError{Op: "enroll", Msg: fmt.Sprintf(
			"worker_species_id %q contains invalid characters; must match pattern %s",
			SanitizeID(rec.WorkerSpeciesID), capabilityIDRe.String(),
		)}
	}
	// Each capability ID must be valid.
	for i, cap := range rec.Capabilities {
		if !capabilityIDRe.MatchString(cap) {
			return RegistryError{Op: "enroll", Msg: fmt.Sprintf(
				"capabilities[%d] %q contains invalid characters; must match pattern %s",
				i, SanitizeID(cap), capabilityIDRe.String(),
			)}
		}
	}
	// Each required control ID must be valid.
	for i, ctrl := range rec.RequiredControls {
		if !controlIDRe.MatchString(ctrl) {
			return RegistryError{Op: "enroll", Msg: fmt.Sprintf(
				"required_controls[%d] %q contains invalid characters; must match pattern %s",
				i, SanitizeID(ctrl), controlIDRe.String(),
			)}
		}
	}
	// Each currently_implements control ID must be valid.
	for i, ctrl := range rec.CurrentlyImplements {
		if !controlIDRe.MatchString(ctrl) {
			return RegistryError{Op: "enroll", Msg: fmt.Sprintf(
				"currently_implements[%d] %q contains invalid characters; must match pattern %s",
				i, SanitizeID(ctrl), controlIDRe.String(),
			)}
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.workers[rec.WorkerID]; exists {
		return RegistryError{Op: "enroll", Msg: fmt.Sprintf("worker %q already enrolled", rec.WorkerID)}
	}

	r.workers[rec.WorkerID] = rec
	return nil
}

// WorkersForCapability returns all enrolled workers that declare the given capability ID.
// Returns an empty (non-nil) slice if no workers match — never returns nil.
//
// GO-F13 adjacent: the original implementation used `var matches []WorkerRegistryRecord`
// (nil slice) and returned it when no workers matched. A nil []WorkerRegistryRecord
// serialises to JSON null instead of [], breaking consumers that expect an array.
// Initialised as a non-nil empty slice to guarantee consistent serialisation.
//
// TODO(impl): filter by env, data_label, risk_tier before returning candidates.
// TODO(impl): rank by blast score, QoS, and tenant risk.
func (r *Registry) WorkersForCapability(capabilityID string) []WorkerRegistryRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	matches := make([]WorkerRegistryRecord, 0)
	for _, w := range r.workers {
		for _, cap := range w.Capabilities {
			if cap == capabilityID {
				matches = append(matches, w)
				break
			}
		}
	}
	return matches
}

// Get returns a single worker record by worker ID.
// Returns false if not found.
func (r *Registry) Get(workerID string) (WorkerRegistryRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	w, ok := r.workers[workerID]
	return w, ok
}

// AllWorkers returns all enrolled worker records.
// Used by the GET /wcp/workers discovery endpoint.
func (r *Registry) AllWorkers() []WorkerRegistryRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]WorkerRegistryRecord, 0, len(r.workers))
	for _, w := range r.workers {
		out = append(out, w)
	}
	return out
}

// ControlsPresent returns true if ALL of the given control IDs are declared as
// currently_implements by at least one enrolled worker, false otherwise.
//
// This is the registry-level control presence check used by the router to enforce
// RequiredControls before dispatch. A required control must be satisfied by the
// currently enrolled fleet — if no enrolled worker implements it, the control is absent.
//
// VULN-GO-3: this method is called by MakeDecision to enforce worker.RequiredControls.
func (r *Registry) ControlsPresent(controlIDs []string) (bool, string) {
	if len(controlIDs) == 0 {
		return true, ""
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Build the set of all controls currently implemented by any enrolled worker.
	implemented := make(map[string]struct{})
	for _, w := range r.workers {
		for _, ctrl := range w.CurrentlyImplements {
			implemented[ctrl] = struct{}{}
		}
	}

	for _, required := range controlIDs {
		if _, ok := implemented[required]; !ok {
			return false, required
		}
	}
	return true, ""
}

// PolicyAllowsPrivilege returns (true, "") when the given privilege envelope is
// acceptable for the env + data_label combination, or (false, reason) when it is not.
//
// VULN-GO-4: called by MakeDecision after worker selection to enforce privilege
// envelope constraints before dispatch is allowed.
//
// Current rules (v0.1):
//   - In prod or edge, NetworkEgress="unrestricted" is denied for RESTRICTED data.
//   - In prod or edge, any SecretsAccess entries are denied for RESTRICTED data
//     unless the data label is INTERNAL or lower.
//   - dev/stage: no restrictions (operators must configure real policy for prod).
func (r *Registry) PolicyAllowsPrivilege(env Env, dataLabel DataLabel, envelope *PrivilegeEnvelope) (bool, string) {
	if envelope == nil {
		return true, ""
	}

	isProdOrEdge := env == EnvProd || env == EnvEdge
	if !isProdOrEdge {
		return true, ""
	}

	// In prod/edge: unrestricted network egress is denied for RESTRICTED data.
	if dataLabel == DataLabelRestricted && envelope.NetworkEgress == "unrestricted" {
		return false, "network_egress=unrestricted is not allowed for RESTRICTED data in prod/edge"
	}

	// In prod/edge: secrets access is denied for RESTRICTED data.
	if dataLabel == DataLabelRestricted && len(envelope.SecretsAccess) > 0 {
		return false, "secrets_access is not permitted for RESTRICTED data in prod/edge without explicit policy"
	}

	return true, ""
}

// AllCapabilities returns the deduplicated list of all registered capability IDs.
// Used by the GET /wcp/capabilities discovery endpoint (WCP section 5.6).
func (r *Registry) AllCapabilities() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]struct{})
	for _, w := range r.workers {
		for _, cap := range w.Capabilities {
			seen[cap] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for cap := range seen {
		out = append(out, cap)
	}
	return out
}
