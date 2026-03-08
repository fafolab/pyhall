// Package wcp — attestation.go
//
// Full-package attestation for WCP workers.
//
// The unit of attestation is the complete worker package:
//
//	worker-package/
//	  code/
//	    worker_logic.py
//	    bootstrap.py
//	  requirements.lock
//	  config.schema.json
//	  manifest.json         ← signed manifest (excluded from hash input)
//
// Trust semantics: attestation is bound to namespace-key authorization
// (x.* or org.*), not to personal authorship.
//
// Deny codes (fail-closed — no silent fallback):
//
//	ATTEST_MANIFEST_MISSING      manifest.json does not exist or is unreadable
//	ATTEST_MANIFEST_ID_MISMATCH  manifest worker_id/worker_species_id != declared
//	ATTEST_HASH_MISMATCH         recomputed package hash != manifest package_hash
//	ATTEST_SIGNATURE_MISSING     no signature in manifest or no signing secret set
//	ATTEST_SIG_INVALID           HMAC-SHA256 signature does not match
//
// Signing model: HMAC-SHA256 for portability and self-contained operation.
// For production deployments, replace with Ed25519 asymmetric signing and
// store the public key in the pyhall.dev registry.
package wcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Deny codes
// ---------------------------------------------------------------------------

const (
	AttestManifestMissing    = "ATTEST_MANIFEST_MISSING"
	AttestManifestIDMismatch = "ATTEST_MANIFEST_ID_MISMATCH"
	AttestHashMismatch       = "ATTEST_HASH_MISMATCH"
	AttestSignatureMissing   = "ATTEST_SIGNATURE_MISSING"
	AttestSigInvalid         = "ATTEST_SIG_INVALID"
)

// manifestSchemaVersion is the schema version embedded in every manifest.
const manifestSchemaVersion = "awp.v1"

// defaultSecretEnv is the default environment variable name for the HMAC signing secret.
const defaultSecretEnv = "WCP_ATTEST_HMAC_KEY"

// hashExcludes is the set of file/directory names excluded from the canonical
// package hash. manifest.json is excluded because it CONTAINS the hash — including
// it would require iterative hashing. manifest.sig and manifest.tmp are transient
// signing artefacts.
var hashExcludes = map[string]bool{
	".git":         true,
	"__pycache__":  true,
	".DS_Store":    true,
	"manifest.json": true,
	"manifest.sig": true,
	"manifest.tmp": true,
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func utcNowISO() string {
	return time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func namespaceFromSpecies(workerSpeciesID string) string {
	if idx := strings.Index(workerSpeciesID, "."); idx >= 0 {
		return workerSpeciesID[:idx]
	}
	return workerSpeciesID
}

// ---------------------------------------------------------------------------
// Canonical package hash
// ---------------------------------------------------------------------------

// CanonicalPackageHash computes a deterministic SHA-256 hash over the full
// worker package content.
//
// Hash input format — one record per file, sorted lexicographically by
// relative POSIX path:
//
//	<relative_posix_path>\n<size_bytes>\n<sha256_hex(file_content)>\n
//
// Excluded from the hash: manifest.json, manifest.sig, manifest.tmp,
// .git/, __pycache__/, .DS_Store, and *.pyc files.
//
// Returns a 64-character lowercase hex SHA-256 digest.
func CanonicalPackageHash(packageRoot string) (string, error) {
	type fileRecord struct {
		relPosix string
		content  []byte
	}

	var records []fileRecord

	err := filepath.WalkDir(packageRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip excluded directories
			if hashExcludes[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if any path component is in the exclude set
		rel, err := filepath.Rel(packageRoot, path)
		if err != nil {
			return err
		}
		relPosix := filepath.ToSlash(rel)

		// Check each path component
		parts := strings.Split(relPosix, "/")
		for _, part := range parts {
			if hashExcludes[part] {
				return nil
			}
		}

		// Exclude *.pyc files
		if strings.HasSuffix(relPosix, ".pyc") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("attestation: reading %s: %w", path, err)
		}

		records = append(records, fileRecord{relPosix: relPosix, content: content})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("attestation: walking package root: %w", err)
	}

	// Sort lexicographically by relative POSIX path
	sort.Slice(records, func(i, j int) bool {
		return records[i].relPosix < records[j].relPosix
	})

	// Build the hash input
	var sb strings.Builder
	for _, r := range records {
		fmt.Fprintf(&sb, "%s\n%d\n%s\n", r.relPosix, len(r.content), sha256Hex(r.content))
	}

	return sha256Hex([]byte(sb.String())), nil
}

// ---------------------------------------------------------------------------
// Manifest signing payload
// ---------------------------------------------------------------------------

// canonicalManifestPayload returns the canonical bytes used as the HMAC signing input.
// Only a fixed subset of manifest fields are signed — this makes the signature stable
// even if the manifest gains optional fields later.
func canonicalManifestPayload(manifest map[string]any) ([]byte, error) {
	keys := []string{
		"schema_version",
		"worker_id",
		"worker_species_id",
		"worker_version",
		"package_hash",
		"built_at_utc",
		"build_source",
	}
	// Build an ordered struct for deterministic JSON serialization.
	// encoding/json marshals map[string]any keys in sorted order (Go 1.12+),
	// but we only include the 7 signed keys to match Python's sort_keys behavior.
	payload := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := manifest[k]; ok {
			payload[k] = v
		} else {
			payload[k] = nil
		}
	}
	// Marshal with no spaces (separators=(",", ":") in Python)
	b, err := marshalCompactSorted(payload)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// marshalCompactSorted marshals a map[string]any with sorted keys and no spaces.
// Go's encoding/json sorts map keys alphabetically when marshaling (Go 1.12+),
// so json.Marshal on map[string]any already produces sorted output.
func marshalCompactSorted(v map[string]any) ([]byte, error) {
	return json.Marshal(v)
}

func signHMAC(manifest map[string]any, secret string) (string, error) {
	payload, err := canonicalManifestPayload(manifest)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ---------------------------------------------------------------------------
// Build + write manifest
// ---------------------------------------------------------------------------

// BuildManifestOptions configures BuildManifest.
type BuildManifestOptions struct {
	PackageRoot     string
	WorkerID        string
	WorkerSpeciesID string
	WorkerVersion   string
	SigningSecret   string
	BuildSource     string // default "local"
}

// BuildManifest builds and signs a worker package manifest.
//
// Computes the canonical package hash, assembles the manifest dict, and
// signs it with HMAC-SHA256. The manifest is NOT written to disk — call
// WriteManifest after reviewing.
//
// Returns the signed manifest as a map[string]any ready to pass to WriteManifest.
func BuildManifest(opts BuildManifestOptions) (map[string]any, error) {
	buildSource := opts.BuildSource
	if buildSource == "" {
		buildSource = "local"
	}

	now := utcNowISO()
	ns := namespaceFromSpecies(opts.WorkerSpeciesID)

	pkgHash, err := CanonicalPackageHash(opts.PackageRoot)
	if err != nil {
		return nil, fmt.Errorf("attestation: computing package hash: %w", err)
	}

	manifest := map[string]any{
		"schema_version":    manifestSchemaVersion,
		"worker_id":         opts.WorkerID,
		"worker_species_id": opts.WorkerSpeciesID,
		"worker_version":    opts.WorkerVersion,
		"package_hash":      pkgHash,
		"built_at_utc":      now,
		"attested_at_utc":   now,
		"build_source":      buildSource,
		"trust_statement": fmt.Sprintf(
			"Package attested by namespace %s at %s; package hash sha256:%s.",
			ns, now, pkgHash,
		),
	}

	sig, err := signHMAC(manifest, opts.SigningSecret)
	if err != nil {
		return nil, fmt.Errorf("attestation: signing manifest: %w", err)
	}
	manifest["signature_hmac_sha256"] = sig

	return manifest, nil
}

// WriteManifest writes a signed manifest map to disk as formatted JSON.
//
// Output is indented with 2 spaces, keys are sorted, and a trailing newline
// is appended — matching the Python reference implementation.
func WriteManifest(manifest map[string]any, manifestPath string) error {
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		return fmt.Errorf("attestation: creating manifest parent dirs: %w", err)
	}

	b, err := marshalIndentedSorted(manifest)
	if err != nil {
		return fmt.Errorf("attestation: marshaling manifest: %w", err)
	}

	// Append trailing newline to match Python's behavior
	b = append(b, '\n')

	if err := os.WriteFile(manifestPath, b, 0o644); err != nil {
		return fmt.Errorf("attestation: writing manifest: %w", err)
	}
	return nil
}

// marshalIndentedSorted produces JSON with 2-space indentation and sorted keys.
// encoding/json sorts map[string]any keys alphabetically.
func marshalIndentedSorted(v map[string]any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// ---------------------------------------------------------------------------
// PackageAttestationVerifier
// ---------------------------------------------------------------------------

// PackageAttestationVerifier verifies that a worker package is attested and
// unchanged at runtime.
//
// Fail-closed: any mismatch returns a deny code and OK=false.
// No silent fallback execution.
type PackageAttestationVerifier struct {
	PackageRoot     string
	ManifestPath    string
	WorkerID        string
	WorkerSpeciesID string
	// SecretEnv is the environment variable name for the HMAC signing secret.
	// Defaults to "WCP_ATTEST_HMAC_KEY" if empty.
	SecretEnv string
}

// AttestResult is the result of a package attestation verification.
type AttestResult struct {
	OK       bool
	DenyCode string
	Meta     map[string]any
}

// Verify checks the worker package against the signed manifest.
//
// Returns an AttestResult where:
//   - OK=true means all checks passed.
//   - DenyCode is empty when OK=true; one of the ATTEST_* constants otherwise.
//   - Meta contains diagnostic data. When OK=true it includes:
//     package_hash, manifest_schema, attested_at_utc, verified_at_utc, trust_statement.
func (v *PackageAttestationVerifier) Verify() AttestResult {
	secretEnv := v.SecretEnv
	if secretEnv == "" {
		secretEnv = defaultSecretEnv
	}

	// 1. Manifest must exist and be parseable
	f, err := os.Open(v.ManifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return AttestResult{OK: false, DenyCode: AttestManifestMissing, Meta: map[string]any{}}
		}
		return AttestResult{OK: false, DenyCode: AttestManifestMissing, Meta: map[string]any{
			"error": err.Error(),
		}}
	}
	defer f.Close()

	manifestBytes, err := io.ReadAll(f)
	if err != nil {
		return AttestResult{OK: false, DenyCode: AttestManifestMissing, Meta: map[string]any{
			"error": err.Error(),
		}}
	}

	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return AttestResult{OK: false, DenyCode: AttestManifestMissing, Meta: map[string]any{
			"error": err.Error(),
		}}
	}

	// 2. Identity check — manifest must declare the same worker
	manifestWorkerID, _ := manifest["worker_id"].(string)
	manifestSpeciesID, _ := manifest["worker_species_id"].(string)
	if manifestWorkerID != v.WorkerID || manifestSpeciesID != v.WorkerSpeciesID {
		return AttestResult{OK: false, DenyCode: AttestManifestIDMismatch, Meta: map[string]any{
			"manifest_worker_id":         manifestWorkerID,
			"expected_worker_id":         v.WorkerID,
			"manifest_worker_species_id": manifestSpeciesID,
			"expected_worker_species_id": v.WorkerSpeciesID,
		}}
	}

	// 3. Package hash must match
	expectedHash, _ := manifest["package_hash"].(string)
	computedHash, err := CanonicalPackageHash(v.PackageRoot)
	if err != nil {
		return AttestResult{OK: false, DenyCode: AttestHashMismatch, Meta: map[string]any{
			"error":         err.Error(),
			"expected_hash": expectedHash,
		}}
	}
	if expectedHash == "" || expectedHash != computedHash {
		return AttestResult{OK: false, DenyCode: AttestHashMismatch, Meta: map[string]any{
			"expected_hash": expectedHash,
			"computed_hash": computedHash,
		}}
	}

	// 4. Signature must be present and valid
	sig, _ := manifest["signature_hmac_sha256"].(string)
	secret := os.Getenv(secretEnv)
	if sig == "" || secret == "" {
		return AttestResult{OK: false, DenyCode: AttestSignatureMissing, Meta: map[string]any{
			"signature_present": sig != "",
			"secret_env_set":    secret != "",
			"secret_env":        secretEnv,
		}}
	}

	expectedSig, err := signHMAC(manifest, secret)
	if err != nil {
		return AttestResult{OK: false, DenyCode: AttestSigInvalid, Meta: map[string]any{
			"error": err.Error(),
		}}
	}
	// Constant-time compare
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return AttestResult{OK: false, DenyCode: AttestSigInvalid, Meta: map[string]any{}}
	}

	// All checks passed
	ns := namespaceFromSpecies(v.WorkerSpeciesID)
	verifiedAt := utcNowISO()
	attestedAt, _ := manifest["attested_at_utc"].(string)
	if attestedAt == "" {
		attestedAt = "unknown"
	}

	return AttestResult{OK: true, Meta: map[string]any{
		"package_hash":    computedHash,
		"manifest_schema": manifest["schema_version"],
		"attested_at_utc": attestedAt,
		"verified_at_utc": verifiedAt,
		"trust_statement": fmt.Sprintf(
			"Package attested by namespace %s at %s; package hash sha256:%s.",
			ns, attestedAt, computedHash,
		),
	}}
}
