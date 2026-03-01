// Package wcp implements the Worker Class Protocol (WCP) in Go.
//
// This is a v0.1 scaffolding — stubs and interfaces only.
// For the production-ready reference implementation use PyHall:
//
//	pip install pyhall
//
// WCP Spec: https://github.com/fafolab/wcp/blob/main/WCP_SPEC.md
package wcp

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"regexp"
	"time"
)

// idSanitizer strips ASCII control characters (U+0000–U+001F, U+007F) from
// ID fields before they are written into telemetry payloads.
//
// GO-F6 fix: correlation_id, tenant_id, and capability_id accepted newlines (\n),
// null bytes (\x00), carriage returns (\r), and other control characters that
// propagate into telemetry. Line-based SIEM parsers treat \n as a record boundary,
// enabling fake audit-entry injection. Strip at telemetry construction, not at
// routing, to preserve original values for routing logic.
var controlCharRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// SanitizeID strips control characters from an ID field for safe use in telemetry.
func SanitizeID(s string) string {
	return controlCharRe.ReplaceAllString(s, "")
}

// capabilityIDRe is the compiled regex for WCP capability ID format validation.
// Valid format: one or more dot-separated lowercase alphanumeric segments, e.g.
// "cap.doc.summarize", "cap.infra.deploy", "x.custom.worker".
//
// GO-F6 fix: capability IDs and control IDs were accepted without format validation,
// allowing injection of control characters, path separators, and other malformed values.
// Compile once at package init — never per-call (avoids redundant compilation overhead).
var capabilityIDRe = regexp.MustCompile(`^[a-z0-9_\-]+(\.[a-z0-9_\-\*]+)*$`)

// controlIDRe is the compiled regex for WCP control ID format validation.
// Valid format: must start with "ctrl." followed by a lowercase alphanumeric
// character, then any combination of lowercase alphanumeric, dots, underscores,
// and hyphens. e.g. "ctrl.obs.audit-log-append-only", "ctrl.blast_radius_scoring".
//
// VULN-GO-6 fix: the previous pattern accepted any namespace (e.g. "foo.bar"),
// allowing non-control IDs to be enrolled as controls. The ctrl. prefix is
// mandatory per WCP namespace rules — cap/wrk/ctrl/pol/prof/evt are reserved.
// Non-ctrl. namespaces (x.*, org.<name>.*) must not appear in required_controls.
var controlIDRe = regexp.MustCompile(`^ctrl\.[a-z0-9][a-z0-9._\-]*$`)

// workerIDRe is the compiled regex for WCP worker ID format validation.
// Convention: "org.<name>.<descriptor>", e.g. "org.fafolab.doc-summarizer".
// Must not contain control characters, path separators, or whitespace.
var workerIDRe = regexp.MustCompile(`^[a-zA-Z0-9_\.\-]+$`)

// NowUTC returns the current time in UTC, formatted as ISO 8601 with a Z suffix.
// All WCP timestamps use UTC. Store UTC; display in the operator's local timezone.
func NowUTC() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

// NewUUID generates a random UUID v4 string (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx).
// This avoids an external dependency on github.com/google/uuid for the scaffold.
// Replace with a battle-tested library in production.
//
// GO-F10 fix: the original fallback used time.Now().UnixNano() — a predictable,
// non-random value. crypto/rand.Read() failure is now treated as an unrecoverable
// error: the function panics rather than silently emitting a guessable decision ID.
// Decision IDs and correlation IDs must be unguessable; predictable IDs enable
// replay attacks and audit log manipulation.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is not recoverable — a deterministic UUID would be
		// guessable, enabling decision-ID replay. Panic to surface the system fault.
		// In practice, crypto/rand.Read only fails if the OS entropy pool is
		// completely unavailable, which indicates a critically broken environment.
		panic(fmt.Sprintf("wcp: crypto/rand.Read failed — cannot generate safe UUID: %v", err))
	}
	// Set version 4 bits
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ValidateBlastScore validates a blast score value is in the range [0, 100].
// Returns an error if the value is out of range.
//
// GO-F8 fix: RouteInput.BlastScore accepted negative values and values > 100
// without validation. Blast scores outside [0, 100] produce undefined behavior
// in the blast gate and could cause integer overflow in gate comparisons.
func ValidateBlastScore(score int) error {
	if score < 0 || score > 100 {
		return fmt.Errorf("blast_score must be in [0, 100], got %d", score)
	}
	return nil
}

// SHA256Hex computes the hex-encoded SHA-256 hash of data.
// Used for artifact hashing per WCP section 5.7:
//
//	artifact_hash = sha256(serialized RouteInput, sort_keys=True)
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// OK wraps a value and a nil error — convenience return helper.
func OK[T any](v T) (T, error) {
	return v, nil
}

// Err wraps a zero value and an error — convenience return helper.
func Err[T any](format string, args ...any) (T, error) {
	var zero T
	return zero, fmt.Errorf(format, args...)
}
