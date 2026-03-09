/**
 * tests/attestation.test.ts — PackageAttestationVerifier + helpers
 *
 * Covers:
 *   - canonicalPackageHash: determinism, exclusions, sensitivity
 *   - scaffoldPackage: layout, overwrite guard
 *   - buildManifest + writeManifest: fields, round-trip
 *   - PackageAttestationVerifier: all deny codes + happy path
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";

import {
  ATTEST_MANIFEST_MISSING,
  ATTEST_MANIFEST_ID_MISMATCH,
  ATTEST_HASH_MISMATCH,
  ATTEST_SIGNATURE_MISSING,
  ATTEST_SIG_INVALID,
  canonicalPackageHash,
  buildManifest,
  writeManifest,
  scaffoldPackage,
  PackageAttestationVerifier,
} from "../src/attestation";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "pyhall-attest-test-"));
}

function writeFile(dir: string, relPath: string, content: string): void {
  const abs = path.join(dir, relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content, "utf-8");
}

const SECRET = "test-signing-secret-1234";
const WORKER_ID = "org.example.test-worker.instance-1";
const SPECIES_ID = "wrk.example.test-worker";
const VERSION = "1.0.0";

// ---------------------------------------------------------------------------
// canonicalPackageHash
// ---------------------------------------------------------------------------

describe("canonicalPackageHash", () => {
  it("is deterministic for the same directory contents", () => {
    const dir = makeTmpDir();
    writeFile(dir, "code/bootstrap.py", "# bootstrap\n");
    writeFile(dir, "requirements.lock", "# none\n");

    const h1 = canonicalPackageHash(dir);
    const h2 = canonicalPackageHash(dir);
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes when a file is added", () => {
    const dir = makeTmpDir();
    writeFile(dir, "code/bootstrap.py", "# bootstrap\n");

    const h1 = canonicalPackageHash(dir);
    writeFile(dir, "code/extra.py", "# extra\n");
    const h2 = canonicalPackageHash(dir);

    expect(h1).not.toBe(h2);
  });

  it("changes when file content changes", () => {
    const dir = makeTmpDir();
    writeFile(dir, "code/bootstrap.py", "# original\n");

    const h1 = canonicalPackageHash(dir);
    writeFile(dir, "code/bootstrap.py", "# modified\n");
    const h2 = canonicalPackageHash(dir);

    expect(h1).not.toBe(h2);
  });

  it("excludes manifest.json from the hash", () => {
    const dir = makeTmpDir();
    writeFile(dir, "code/bootstrap.py", "# bootstrap\n");
    const h1 = canonicalPackageHash(dir);

    writeFile(dir, "manifest.json", JSON.stringify({ package_hash: "anything" }));
    const h2 = canonicalPackageHash(dir);

    expect(h1).toBe(h2);
  });

  it("excludes manifest.sig and manifest.tmp", () => {
    const dir = makeTmpDir();
    writeFile(dir, "code/bootstrap.py", "# bootstrap\n");
    const h1 = canonicalPackageHash(dir);

    writeFile(dir, "manifest.sig", "sig-data");
    writeFile(dir, "manifest.tmp", "tmp-data");
    const h2 = canonicalPackageHash(dir);

    expect(h1).toBe(h2);
  });

  it("excludes .pyc files", () => {
    const dir = makeTmpDir();
    writeFile(dir, "code/bootstrap.py", "# bootstrap\n");
    const h1 = canonicalPackageHash(dir);

    writeFile(dir, "code/__pycache__/bootstrap.cpython-311.pyc", "\x00\x00bytecode");
    const h2 = canonicalPackageHash(dir);

    // __pycache__ dir is excluded, so hash should remain the same
    expect(h1).toBe(h2);
  });

  it("excludes .DS_Store", () => {
    const dir = makeTmpDir();
    writeFile(dir, "code/bootstrap.py", "# bootstrap\n");
    const h1 = canonicalPackageHash(dir);

    writeFile(dir, ".DS_Store", "mac-metadata");
    const h2 = canonicalPackageHash(dir);

    expect(h1).toBe(h2);
  });

  it("produces different hash for empty vs non-empty directory", () => {
    const emptyDir = makeTmpDir();
    const populatedDir = makeTmpDir();
    writeFile(populatedDir, "code/bootstrap.py", "# bootstrap\n");

    const h1 = canonicalPackageHash(emptyDir);
    const h2 = canonicalPackageHash(populatedDir);

    expect(h1).not.toBe(h2);
  });
});

// ---------------------------------------------------------------------------
// scaffoldPackage
// ---------------------------------------------------------------------------

describe("scaffoldPackage", () => {
  it("creates expected scaffold layout", () => {
    const dir = makeTmpDir();
    scaffoldPackage(dir);

    expect(fs.existsSync(path.join(dir, "code", "bootstrap.py"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "code", "worker_logic.py"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "requirements.lock"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "config.schema.json"))).toBe(true);
  });

  it("worker_logic.py contains stub raise NotImplementedError", () => {
    const dir = makeTmpDir();
    scaffoldPackage(dir);
    const content = fs.readFileSync(path.join(dir, "code", "worker_logic.py"), "utf-8");
    expect(content).toContain("NotImplementedError");
  });

  it("throws when worker_logic.py exists and overwrite=false", () => {
    const dir = makeTmpDir();
    scaffoldPackage(dir);
    expect(() => scaffoldPackage(dir, { overwrite: false })).toThrow();
  });

  it("overwrites when overwrite=true", () => {
    const dir = makeTmpDir();
    scaffoldPackage(dir);
    expect(() => scaffoldPackage(dir, { overwrite: true })).not.toThrow();
  });

  it("config.schema.json is valid JSON with $schema field", () => {
    const dir = makeTmpDir();
    scaffoldPackage(dir);
    const raw = fs.readFileSync(path.join(dir, "config.schema.json"), "utf-8");
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    expect(parsed["$schema"]).toContain("json-schema.org");
  });
});

// ---------------------------------------------------------------------------
// buildManifest + writeManifest
// ---------------------------------------------------------------------------

describe("buildManifest", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
    scaffoldPackage(dir);
  });

  it("returns manifest with all required fields", () => {
    const m = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: SECRET,
    });

    expect(m["schema_version"]).toBe("awp.v1");
    expect(m["worker_id"]).toBe(WORKER_ID);
    expect(m["worker_species_id"]).toBe(SPECIES_ID);
    expect(m["worker_version"]).toBe(VERSION);
    expect(typeof m["package_hash"]).toBe("string");
    expect((m["package_hash"] as string)).toHaveLength(64);
    expect(m["built_at_utc"]).toBeTruthy();
    expect(m["attested_at_utc"]).toBeTruthy();
    expect(m["build_source"]).toBe("local");
    expect(m["trust_statement"]).toContain("namespace org.example");
    expect(m["signature_hmac_sha256"]).toBeTruthy();
  });

  it("package_hash in manifest matches canonicalPackageHash", () => {
    const m = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: SECRET,
    });
    const expected = canonicalPackageHash(dir);
    expect(m["package_hash"]).toBe(expected);
  });

  it("trust_statement includes namespace attribution", () => {
    const m = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: SECRET,
    });
    expect(m["trust_statement"]).toContain("Package attested by namespace org.example");
    expect(m["trust_statement"]).toContain("sha256:");
  });

  it("built_at_utc is UTC ISO-8601 string", () => {
    const m = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: SECRET,
    });
    const ts = m["built_at_utc"] as string;
    expect(ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  it("different signing secrets produce different signatures", () => {
    const m1 = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: "secret-A",
    });
    const m2 = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: "secret-B",
    });
    expect(m1["signature_hmac_sha256"]).not.toBe(m2["signature_hmac_sha256"]);
  });

  it("buildSource defaults to 'local' but can be overridden", () => {
    const m = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: SECRET,
      buildSource: "ci",
    });
    expect(m["build_source"]).toBe("ci");
  });
});

describe("writeManifest", () => {
  it("round-trip: write then read back losslessly", () => {
    const dir = makeTmpDir();
    scaffoldPackage(dir);
    const m = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: SECRET,
    });

    const manifestPath = path.join(dir, "manifest.json");
    writeManifest(m, manifestPath);

    expect(fs.existsSync(manifestPath)).toBe(true);
    const raw = fs.readFileSync(manifestPath, "utf-8");
    expect(raw.endsWith("\n")).toBe(true);

    const parsed = JSON.parse(raw) as Record<string, unknown>;
    expect(parsed["worker_id"]).toBe(WORKER_ID);
    expect(parsed["package_hash"]).toBe(m["package_hash"]);
    expect(parsed["signature_hmac_sha256"]).toBe(m["signature_hmac_sha256"]);
  });

  it("creates parent directories if missing", () => {
    const dir = makeTmpDir();
    const nestedPath = path.join(dir, "subdir", "nested", "manifest.json");
    writeManifest({ test: "value" }, nestedPath);
    expect(fs.existsSync(nestedPath)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PackageAttestationVerifier — deny codes
// ---------------------------------------------------------------------------

describe("PackageAttestationVerifier", () => {
  let dir: string;
  let manifestPath: string;

  beforeEach(() => {
    dir = makeTmpDir();
    scaffoldPackage(dir);
    manifestPath = path.join(dir, "manifest.json");
  });

  const makeVerifier = (overrides: {
    workerId?: string;
    workerSpeciesId?: string;
    secretEnv?: string;
  } = {}) =>
    new PackageAttestationVerifier({
      packageRoot: dir,
      manifestPath,
      workerId: overrides.workerId ?? WORKER_ID,
      workerSpeciesId: overrides.workerSpeciesId ?? SPECIES_ID,
      secretEnv: overrides.secretEnv ?? "PYHALL_TEST_SECRET",
    });

  const buildAndWrite = () => {
    const m = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: SECRET,
    });
    writeManifest(m, manifestPath);
    return m;
  };

  // 1. ATTEST_MANIFEST_MISSING

  it("returns ATTEST_MANIFEST_MISSING when manifest absent", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    const result = makeVerifier().verify();
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_MANIFEST_MISSING);
    delete process.env["PYHALL_TEST_SECRET"];
  });

  it("returns ATTEST_MANIFEST_MISSING when manifest is not valid JSON", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    fs.writeFileSync(manifestPath, "not valid json", "utf-8");
    const result = makeVerifier().verify();
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_MANIFEST_MISSING);
    delete process.env["PYHALL_TEST_SECRET"];
  });

  // 2. ATTEST_MANIFEST_ID_MISMATCH

  it("returns ATTEST_MANIFEST_ID_MISMATCH when worker_id doesn't match", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    buildAndWrite();
    const result = makeVerifier({ workerId: "org.example.different.worker" }).verify();
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_MANIFEST_ID_MISMATCH);
    expect(result.meta["expected_worker_id"]).toBe("org.example.different.worker");
    delete process.env["PYHALL_TEST_SECRET"];
  });

  it("returns ATTEST_MANIFEST_ID_MISMATCH when worker_species_id doesn't match", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    buildAndWrite();
    const result = makeVerifier({ workerSpeciesId: "wrk.example.other-worker" }).verify();
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_MANIFEST_ID_MISMATCH);
    delete process.env["PYHALL_TEST_SECRET"];
  });

  // 3. ATTEST_HASH_MISMATCH

  it("returns ATTEST_HASH_MISMATCH when a file is modified after signing", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    buildAndWrite();

    // Modify a file after the manifest was written
    writeFile(dir, "code/worker_logic.py", "# tampered content\n");

    const result = makeVerifier().verify();
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_HASH_MISMATCH);
    delete process.env["PYHALL_TEST_SECRET"];
  });

  it("returns ATTEST_HASH_MISMATCH when a new file is added after signing", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    buildAndWrite();

    writeFile(dir, "code/extra.py", "# injected\n");

    const result = makeVerifier().verify();
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_HASH_MISMATCH);
    delete process.env["PYHALL_TEST_SECRET"];
  });

  it("manifest.json edits alone do not change hash (excluded from hash)", () => {
    // The hash should be stable across manifest.json changes — it's excluded
    // We verify this indirectly: build → write manifest → hash still matches
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    buildAndWrite();

    // Overwrite manifest.json with a slightly different formatted version
    // (still valid, just different whitespace) — hash should still match
    const raw = fs.readFileSync(manifestPath, "utf-8");
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    fs.writeFileSync(manifestPath, JSON.stringify(parsed), "utf-8"); // compact format

    // The hash check should still pass (package_hash in manifest is unchanged)
    // but since we also changed the manifest content, re-read
    // Actually the verifier reads the manifest.json — let's restore it correctly
    // This test verifies that adding/modifying manifest.json doesn't affect canonicalPackageHash
    const hashBefore = canonicalPackageHash(dir);
    writeFile(dir, "manifest.json", JSON.stringify({ some: "thing" }));
    const hashAfter = canonicalPackageHash(dir);
    expect(hashBefore).toBe(hashAfter);
    delete process.env["PYHALL_TEST_SECRET"];
  });

  // 4. ATTEST_SIGNATURE_MISSING

  it("returns ATTEST_SIGNATURE_MISSING when secret env is not set", () => {
    delete process.env["PYHALL_TEST_SECRET"];
    buildAndWrite();
    const result = makeVerifier().verify();
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_SIGNATURE_MISSING);
    expect(result.meta["secret_env_set"]).toBe(false);
  });

  it("returns ATTEST_SIGNATURE_MISSING when manifest has no signature field", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    const m = buildManifest({
      packageRoot: dir,
      workerId: WORKER_ID,
      workerSpeciesId: SPECIES_ID,
      workerVersion: VERSION,
      signingSecret: SECRET,
    });
    // Remove signature before writing
    delete (m as Record<string, unknown>)["signature_hmac_sha256"];
    writeManifest(m, manifestPath);

    const result = makeVerifier().verify();
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_SIGNATURE_MISSING);
    delete process.env["PYHALL_TEST_SECRET"];
  });

  // 5. ATTEST_SIG_INVALID

  it("returns ATTEST_SIG_INVALID when wrong signing secret is used", () => {
    // Build and write with SECRET
    process.env["PYHALL_TEST_SECRET"] = "wrong-secret-xyz";
    buildAndWrite(); // signed with SECRET
    const result = makeVerifier().verify(); // verifies with "wrong-secret-xyz"
    expect(result.ok).toBe(false);
    expect(result.denyCode).toBe(ATTEST_SIG_INVALID);
    delete process.env["PYHALL_TEST_SECRET"];
  });

  // 6. Happy path

  it("returns ok=true with full meta on valid attested package", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    buildAndWrite();
    const result = makeVerifier().verify();

    expect(result.ok).toBe(true);
    expect(result.denyCode).toBeNull();
    expect(result.meta["package_hash"]).toHaveLength(64);
    expect(result.meta["manifest_schema"]).toBe("awp.v1");
    expect(result.meta["trust_statement"]).toContain("namespace org.example");
    expect(result.meta["trust_statement"]).toContain("sha256:");
    expect(result.meta["verified_at_utc"]).toBeTruthy();
    expect(result.meta["attested_at_utc"]).toBeTruthy();
    delete process.env["PYHALL_TEST_SECRET"];
  });

  it("package_hash in meta matches canonicalPackageHash", () => {
    process.env["PYHALL_TEST_SECRET"] = SECRET;
    buildAndWrite();
    const result = makeVerifier().verify();
    expect(result.ok).toBe(true);
    expect(result.meta["package_hash"]).toBe(canonicalPackageHash(dir));
    delete process.env["PYHALL_TEST_SECRET"];
  });
});

// ---------------------------------------------------------------------------
// C4 parity stubs — now implemented above, log remaining edge cases
// ---------------------------------------------------------------------------

describe("Attestation parity stubs (C4) — remaining edge cases", () => {
  describe("canonical package hash parity", () => {
    test.todo("hash is identical to Python canonical_package_hash output for reference fixture");
  });

  describe("package scaffold parity", () => {
    test.todo("injects supplied worker logic file into scaffold (Python-specific path)");
  });

  describe("manifest build/write parity", () => {
    test.todo("manifest HMAC payload exactly matches Python _canonical_manifest_payload output for reference fixture");
  });
});
