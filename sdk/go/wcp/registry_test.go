package wcp

// Registry attestation tests — WCP §5.10
//
// Tests for RegisterAttestation(), GetWorkerHash(), and ComputeCurrentHash().
// These tests use real temp files to verify the hash pipeline end-to-end.

import (
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// RegisterAttestation
// ---------------------------------------------------------------------------

func TestRegisterAttestationReturns64HexChars(t *testing.T) {
	r := NewRegistry()

	// Create a temp file with known content.
	f, err := os.CreateTemp("", "wcp-attest-*.go")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString("package test\n// worker code\n")
	f.Close()

	hash, err := r.RegisterAttestation("wrk.test.worker", f.Name())
	if err != nil {
		t.Fatalf("RegisterAttestation returned unexpected error: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %q", len(hash), hash)
	}
	if !validHashRe.MatchString(hash) {
		t.Errorf("hash %q does not match SHA-256 hex pattern", hash)
	}
}

func TestRegisterAttestationErrorWhenFileNotFound(t *testing.T) {
	r := NewRegistry()
	_, err := r.RegisterAttestation("wrk.test.missing", "/tmp/wcp-nonexistent-file-that-does-not-exist-xyz.go")
	if err == nil {
		t.Fatal("expected error when registering attestation for non-existent file")
	}
	regErr, ok := err.(RegistryError)
	if !ok {
		t.Fatalf("expected RegistryError, got %T: %v", err, err)
	}
	if regErr.Op != "register_attestation" {
		t.Errorf("expected Op=register_attestation, got %q", regErr.Op)
	}
	if !strings.Contains(regErr.Msg, "file not found") {
		t.Errorf("expected 'file not found' in error message, got %q", regErr.Msg)
	}
}

// ---------------------------------------------------------------------------
// GetWorkerHash
// ---------------------------------------------------------------------------

func TestGetWorkerHashReturnsRegisteredHash(t *testing.T) {
	r := NewRegistry()

	f, err := os.CreateTemp("", "wcp-attest-*.go")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString("package test\n")
	f.Close()

	registered, err := r.RegisterAttestation("wrk.hash.test", f.Name())
	if err != nil {
		t.Fatalf("RegisterAttestation failed: %v", err)
	}

	got, ok := r.GetWorkerHash("wrk.hash.test")
	if !ok {
		t.Fatal("GetWorkerHash returned ok=false for registered species")
	}
	if got != registered {
		t.Errorf("GetWorkerHash returned %q, want %q", got, registered)
	}
}

func TestGetWorkerHashReturnsFalseForUnknownSpecies(t *testing.T) {
	r := NewRegistry()
	hash, ok := r.GetWorkerHash("wrk.not.registered")
	if ok {
		t.Errorf("expected ok=false for unregistered species, got ok=true, hash=%q", hash)
	}
	if hash != "" {
		t.Errorf("expected empty hash for unregistered species, got %q", hash)
	}
}

// ---------------------------------------------------------------------------
// ComputeCurrentHash
// ---------------------------------------------------------------------------

func TestComputeCurrentHashMatchesRegistered(t *testing.T) {
	r := NewRegistry()

	f, err := os.CreateTemp("", "wcp-attest-*.go")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	content := "package test\nfunc Work() {}\n"
	_, _ = f.WriteString(content)
	f.Close()

	registered, err := r.RegisterAttestation("wrk.current.test", f.Name())
	if err != nil {
		t.Fatalf("RegisterAttestation failed: %v", err)
	}

	current, ok := r.ComputeCurrentHash("wrk.current.test")
	if !ok {
		t.Fatal("ComputeCurrentHash returned ok=false when file is unchanged")
	}
	if current != registered {
		t.Errorf("current hash %q != registered hash %q (file unchanged)", current, registered)
	}
}

func TestComputeCurrentHashDiffersAfterFileMutation(t *testing.T) {
	r := NewRegistry()

	f, err := os.CreateTemp("", "wcp-attest-*.go")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString("package test\nfunc Original() {}\n")
	f.Close()

	registered, err := r.RegisterAttestation("wrk.mutated.test", f.Name())
	if err != nil {
		t.Fatalf("RegisterAttestation failed: %v", err)
	}

	// Mutate the file after registration — simulates tampered worker code.
	if err := os.WriteFile(f.Name(), []byte("package test\nfunc TAMPERED() {}\n"), 0o644); err != nil {
		t.Fatalf("failed to mutate temp file: %v", err)
	}

	current, ok := r.ComputeCurrentHash("wrk.mutated.test")
	if !ok {
		t.Fatal("ComputeCurrentHash returned ok=false after mutation (file still exists)")
	}
	if current == registered {
		t.Error("expected current hash to differ from registered hash after file mutation")
	}
}

func TestComputeCurrentHashReturnsFalseForUnregisteredSpecies(t *testing.T) {
	r := NewRegistry()
	hash, ok := r.ComputeCurrentHash("wrk.never.registered")
	if ok {
		t.Errorf("expected ok=false for unregistered species, got ok=true, hash=%q", hash)
	}
	if hash != "" {
		t.Errorf("expected empty hash, got %q", hash)
	}
}

func TestComputeCurrentHashReturnsFalseWhenFileDeleted(t *testing.T) {
	r := NewRegistry()

	f, err := os.CreateTemp("", "wcp-attest-*.go")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	_, _ = f.WriteString("package test\n")
	f.Close()

	_, err = r.RegisterAttestation("wrk.deleted.test", f.Name())
	if err != nil {
		t.Fatalf("RegisterAttestation failed: %v", err)
	}

	// Delete the file after registration.
	if err := os.Remove(f.Name()); err != nil {
		t.Fatalf("failed to delete temp file: %v", err)
	}

	hash, ok := r.ComputeCurrentHash("wrk.deleted.test")
	if ok {
		t.Errorf("expected ok=false when registered file is deleted, got ok=true, hash=%q", hash)
	}
	if hash != "" {
		t.Errorf("expected empty hash when file deleted, got %q", hash)
	}
}
