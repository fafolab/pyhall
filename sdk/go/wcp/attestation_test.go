package wcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempFile creates a file at path (relative to dir) with the given content.
func writeTempFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// TestCanonicalPackageHash verifies the hash is deterministic and excludes
// excluded files.
func TestCanonicalPackageHash(t *testing.T) {
	dir := t.TempDir()

	writeTempFile(t, dir, "code/worker_logic.py", "def run(): pass\n")
	writeTempFile(t, dir, "code/bootstrap.py", "from worker_logic import run\n")
	writeTempFile(t, dir, "requirements.lock", "# deps\n")
	writeTempFile(t, dir, "config.schema.json", "{}\n")

	// Add files that must be excluded
	writeTempFile(t, dir, "manifest.json", `{"should": "be excluded"}`)
	writeTempFile(t, dir, "manifest.sig", "sig-data")
	writeTempFile(t, dir, "__pycache__/foo.pyc", "bytecode")
	writeTempFile(t, dir, "code/__pycache__/bar.pyc", "bytecode")
	writeTempFile(t, dir, ".DS_Store", "apple meta")

	h1, err := CanonicalPackageHash(dir)
	if err != nil {
		t.Fatalf("CanonicalPackageHash: %v", err)
	}

	if len(h1) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %s", len(h1), h1)
	}

	// Hash must be deterministic
	h2, err := CanonicalPackageHash(dir)
	if err != nil {
		t.Fatalf("CanonicalPackageHash (second call): %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic: %s != %s", h1, h2)
	}

	// Verify excluded files really are excluded: add content to manifest.json and
	// recompute — the hash must not change.
	writeTempFile(t, dir, "manifest.json", `{"changed": "content", "extra": 999}`)
	h3, err := CanonicalPackageHash(dir)
	if err != nil {
		t.Fatalf("CanonicalPackageHash after manifest change: %v", err)
	}
	if h1 != h3 {
		t.Errorf("manifest.json change affected hash (should be excluded): %s != %s", h1, h3)
	}
}

// TestVerify_ManifestMissing checks the ATTEST_MANIFEST_MISSING deny code when
// no manifest.json exists.
func TestVerify_ManifestMissing(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "code/worker_logic.py", "def run(): pass\n")

	v := &PackageAttestationVerifier{
		PackageRoot:     dir,
		ManifestPath:    filepath.Join(dir, "manifest.json"),
		WorkerID:        "org.example.worker-1",
		WorkerSpeciesID: "wrk.example.worker",
	}

	result := v.Verify()

	if result.OK {
		t.Error("expected OK=false, got OK=true")
	}
	if result.DenyCode != AttestManifestMissing {
		t.Errorf("expected DenyCode=%s, got %s", AttestManifestMissing, result.DenyCode)
	}
}

// TestVerify_HashMismatch checks ATTEST_HASH_MISMATCH when a file is modified
// after the manifest was built.
func TestVerify_HashMismatch(t *testing.T) {
	const secret = "test-secret-for-hash-mismatch"
	dir := t.TempDir()

	writeTempFile(t, dir, "code/worker_logic.py", "def run(): pass\n")
	writeTempFile(t, dir, "requirements.lock", "# empty\n")

	manifest, err := BuildManifest(BuildManifestOptions{
		PackageRoot:     dir,
		WorkerID:        "org.example.w1",
		WorkerSpeciesID: "wrk.example.worker",
		WorkerVersion:   "0.1.0",
		SigningSecret:   secret,
	})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	if err := WriteManifest(manifest, manifestPath); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	// Modify a file AFTER the manifest is written to cause a hash mismatch
	writeTempFile(t, dir, "code/worker_logic.py", "def run(): return 42  # modified\n")

	t.Setenv("WCP_ATTEST_HMAC_KEY", secret)

	v := &PackageAttestationVerifier{
		PackageRoot:     dir,
		ManifestPath:    manifestPath,
		WorkerID:        "org.example.w1",
		WorkerSpeciesID: "wrk.example.worker",
	}

	result := v.Verify()

	if result.OK {
		t.Error("expected OK=false after file modification, got OK=true")
	}
	if result.DenyCode != AttestHashMismatch {
		t.Errorf("expected DenyCode=%s, got %s", AttestHashMismatch, result.DenyCode)
	}
}

// TestVerify_HappyPath tests the full build → write → verify cycle.
func TestVerify_HappyPath(t *testing.T) {
	const secret = "super-secret-signing-key"
	dir := t.TempDir()

	writeTempFile(t, dir, "code/worker_logic.py", "def run(): pass\n")
	writeTempFile(t, dir, "code/bootstrap.py", "from worker_logic import run\nrun()\n")
	writeTempFile(t, dir, "requirements.lock", "requests==2.31.0\n")
	writeTempFile(t, dir, "config.schema.json", `{"type":"object"}`+"\n")

	manifest, err := BuildManifest(BuildManifestOptions{
		PackageRoot:     dir,
		WorkerID:        "org.fafolab.doc-summarizer",
		WorkerSpeciesID: "wrk.fafolab.doc-summarizer",
		WorkerVersion:   "1.0.0",
		SigningSecret:   secret,
		BuildSource:     "ci",
	})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	// Validate manifest fields
	if manifest["schema_version"] != "awp.v1" {
		t.Errorf("schema_version: expected awp.v1, got %v", manifest["schema_version"])
	}
	if manifest["worker_id"] != "org.fafolab.doc-summarizer" {
		t.Errorf("worker_id mismatch: %v", manifest["worker_id"])
	}
	if manifest["build_source"] != "ci" {
		t.Errorf("build_source: expected ci, got %v", manifest["build_source"])
	}
	sig, ok := manifest["signature_hmac_sha256"].(string)
	if !ok || len(sig) != 64 {
		t.Errorf("signature_hmac_sha256: expected 64-char hex, got %v", manifest["signature_hmac_sha256"])
	}
	ts, ok := manifest["trust_statement"].(string)
	if !ok || !strings.Contains(ts, "namespace org.fafolab") {
		t.Errorf("trust_statement unexpected: %v", ts)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	if err := WriteManifest(manifest, manifestPath); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	// Verify the manifest file is valid JSON with a trailing newline
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile manifest: %v", err)
	}
	if raw[len(raw)-1] != '\n' {
		t.Error("manifest file does not end with trailing newline")
	}

	// Set the env var and verify
	t.Setenv("WCP_ATTEST_HMAC_KEY", secret)

	v := &PackageAttestationVerifier{
		PackageRoot:     dir,
		ManifestPath:    manifestPath,
		WorkerID:        "org.fafolab.doc-summarizer",
		WorkerSpeciesID: "wrk.fafolab.doc-summarizer",
	}

	result := v.Verify()

	if !result.OK {
		t.Errorf("expected OK=true, got OK=false (DenyCode=%s, meta=%v)", result.DenyCode, result.Meta)
	}
	if result.DenyCode != "" {
		t.Errorf("expected empty DenyCode, got %s", result.DenyCode)
	}

	// Check meta fields
	for _, key := range []string{"package_hash", "manifest_schema", "attested_at_utc", "verified_at_utc", "trust_statement"} {
		if _, ok := result.Meta[key]; !ok {
			t.Errorf("missing meta key: %s", key)
		}
	}
	if result.Meta["manifest_schema"] != "awp.v1" {
		t.Errorf("manifest_schema: expected awp.v1, got %v", result.Meta["manifest_schema"])
	}
}

// TestVerify_SignatureMissing checks ATTEST_SIGNATURE_MISSING when env var is unset.
func TestVerify_SignatureMissing(t *testing.T) {
	const secret = "sig-missing-test-secret"
	dir := t.TempDir()
	writeTempFile(t, dir, "code/worker_logic.py", "def run(): pass\n")

	manifest, err := BuildManifest(BuildManifestOptions{
		PackageRoot:     dir,
		WorkerID:        "org.example.w2",
		WorkerSpeciesID: "wrk.example.worker",
		WorkerVersion:   "0.1.0",
		SigningSecret:   secret,
	})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	if err := WriteManifest(manifest, manifestPath); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	// Ensure the env var is NOT set
	os.Unsetenv("WCP_ATTEST_HMAC_KEY")

	v := &PackageAttestationVerifier{
		PackageRoot:     dir,
		ManifestPath:    manifestPath,
		WorkerID:        "org.example.w2",
		WorkerSpeciesID: "wrk.example.worker",
	}

	result := v.Verify()

	if result.OK {
		t.Error("expected OK=false with missing secret env, got OK=true")
	}
	if result.DenyCode != AttestSignatureMissing {
		t.Errorf("expected DenyCode=%s, got %s", AttestSignatureMissing, result.DenyCode)
	}
}

// TestVerify_IDMismatch checks ATTEST_MANIFEST_ID_MISMATCH.
func TestVerify_IDMismatch(t *testing.T) {
	const secret = "id-mismatch-secret"
	dir := t.TempDir()
	writeTempFile(t, dir, "code/worker_logic.py", "def run(): pass\n")

	manifest, err := BuildManifest(BuildManifestOptions{
		PackageRoot:     dir,
		WorkerID:        "org.example.real-worker",
		WorkerSpeciesID: "wrk.example.worker",
		WorkerVersion:   "0.1.0",
		SigningSecret:   secret,
	})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	if err := WriteManifest(manifest, manifestPath); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	t.Setenv("WCP_ATTEST_HMAC_KEY", secret)

	// Verify with a DIFFERENT worker ID
	v := &PackageAttestationVerifier{
		PackageRoot:     dir,
		ManifestPath:    manifestPath,
		WorkerID:        "org.example.impersonator",
		WorkerSpeciesID: "wrk.example.worker",
	}

	result := v.Verify()

	if result.OK {
		t.Error("expected OK=false for ID mismatch, got OK=true")
	}
	if result.DenyCode != AttestManifestIDMismatch {
		t.Errorf("expected DenyCode=%s, got %s", AttestManifestIDMismatch, result.DenyCode)
	}
}

// TestBuildManifest_DefaultBuildSource checks that omitting BuildSource defaults to "local".
func TestBuildManifest_DefaultBuildSource(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "code/worker_logic.py", "pass\n")

	manifest, err := BuildManifest(BuildManifestOptions{
		PackageRoot:     dir,
		WorkerID:        "org.example.w3",
		WorkerSpeciesID: "wrk.example.worker",
		WorkerVersion:   "0.1.0",
		SigningSecret:   "any-secret",
		// BuildSource intentionally omitted
	})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	if manifest["build_source"] != "local" {
		t.Errorf("expected build_source=local, got %v", manifest["build_source"])
	}
}
