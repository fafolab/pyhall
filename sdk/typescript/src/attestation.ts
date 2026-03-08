/**
 * src/attestation.ts — Full-package attestation for WCP workers.
 *
 * The unit of attestation is the complete worker package:
 *
 *     worker-package/
 *       code/
 *         worker_logic.py
 *         bootstrap.py
 *       requirements.lock
 *       config.schema.json
 *       manifest.json         ← signed manifest (excluded from hash input)
 *
 * Trust semantics: attestation is bound to namespace-key authorization
 * (x.* or org.*), not to personal authorship. The trust statement reads:
 *
 *     "Package attested by namespace <ns> at <UTC>; package hash sha256:<hash>."
 *
 * Deny codes (fail-closed — no silent fallback):
 *     ATTEST_MANIFEST_MISSING      manifest.json does not exist or is unreadable
 *     ATTEST_MANIFEST_ID_MISMATCH  manifest worker_id/worker_species_id != declared
 *     ATTEST_HASH_MISMATCH         recomputed package hash != manifest package_hash
 *     ATTEST_SIGNATURE_MISSING     no signature in manifest or no signing secret set
 *     ATTEST_SIG_INVALID           HMAC-SHA256 signature does not match
 *
 * Signing model: HMAC-SHA256 for portability and self-contained operation.
 * For production deployments, replace with Ed25519 asymmetric signing and
 * store the public key in the pyhall.dev registry.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Deny codes
// ---------------------------------------------------------------------------

export const ATTEST_MANIFEST_MISSING = "ATTEST_MANIFEST_MISSING";
export const ATTEST_MANIFEST_ID_MISMATCH = "ATTEST_MANIFEST_ID_MISMATCH";
export const ATTEST_HASH_MISMATCH = "ATTEST_HASH_MISMATCH";
export const ATTEST_SIGNATURE_MISSING = "ATTEST_SIGNATURE_MISSING";
export const ATTEST_SIG_INVALID = "ATTEST_SIG_INVALID";

// Manifest schema version
const MANIFEST_SCHEMA_VERSION = "awp.v1";

// Default env var name for the HMAC signing secret
const DEFAULT_SECRET_ENV = "WCP_ATTEST_HMAC_KEY";

// Files excluded from the canonical package hash.
// manifest.json is excluded because it CONTAINS the hash — including it
// would require iterative hashing. manifest.sig and manifest.tmp are
// transient signing artefacts.
const HASH_EXCLUDES = new Set([
  ".git",
  "__pycache__",
  ".DS_Store",
  "manifest.json",
  "manifest.sig",
  "manifest.tmp",
]);

// ---------------------------------------------------------------------------
// Options / result interfaces
// ---------------------------------------------------------------------------

export interface BuildManifestOptions {
  packageRoot: string;
  workerId: string;
  workerSpeciesId: string;
  workerVersion: string;
  signingSecret: string;
  /** default: 'local' */
  buildSource?: string;
}

export interface AttestResult {
  ok: boolean;
  denyCode: string | null;
  meta: Record<string, unknown>;
}

export interface VerifierOptions {
  packageRoot: string;
  manifestPath: string;
  workerId: string;
  workerSpeciesId: string;
  /** default: 'WCP_ATTEST_HMAC_KEY' */
  secretEnv?: string;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function _utcNowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function _sha256Hex(b: Buffer): string {
  return crypto.createHash("sha256").update(b).digest("hex");
}

function _namespaceFromSpecies(workerSpeciesId: string): string {
  const dot = workerSpeciesId.indexOf(".");
  return dot !== -1 ? workerSpeciesId.slice(0, dot) : workerSpeciesId;
}

// ---------------------------------------------------------------------------
// Canonical package hash
// ---------------------------------------------------------------------------

/**
 * Compute a deterministic SHA-256 hash over the full worker package content.
 *
 * Hash input format — one record per file, sorted lexicographically by
 * relative POSIX path:
 *
 *     <relative_posix_path>\n<size_bytes>\n<sha256_hex(file_content)>\n
 *
 * Excluded from the hash: manifest.json, manifest.sig, manifest.tmp,
 * .git/, __pycache__/, .DS_Store, and *.pyc files.
 *
 * Returns a 64-character lowercase hex SHA-256 digest.
 */
export function canonicalPackageHash(packageRoot: string): string {
  const allFiles = _walkDir(packageRoot);

  // Sort lexicographically by relative POSIX path
  allFiles.sort((a, b) => a.rel.localeCompare(b.rel));

  const records: string[] = [];
  for (const { abs, rel } of allFiles) {
    const content = fs.readFileSync(abs);
    records.push(`${rel}\n${content.length}\n${_sha256Hex(content)}\n`);
  }

  return _sha256Hex(Buffer.from(records.join(""), "utf-8"));
}

/**
 * Recursively walk a directory and return all non-excluded files with
 * their absolute path and relative POSIX path.
 */
function _walkDir(
  dir: string,
  packageRoot?: string,
): Array<{ abs: string; rel: string }> {
  const root = packageRoot ?? dir;
  const results: Array<{ abs: string; rel: string }> = [];

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    // Skip excluded names at any level
    if (HASH_EXCLUDES.has(entry.name)) continue;
    // Skip .pyc files
    if (entry.name.endsWith(".pyc")) continue;

    const abs = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      results.push(..._walkDir(abs, root));
    } else if (entry.isFile()) {
      // Convert to relative POSIX path
      const rel = path.relative(root, abs).split(path.sep).join("/");
      results.push({ abs, rel });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Manifest signing payload
// ---------------------------------------------------------------------------

/**
 * Return the canonical bytes used as the HMAC signing input.
 *
 * Only a fixed subset of manifest fields are signed — this makes the
 * signature stable even if the manifest gains optional fields later.
 */
function _canonicalManifestPayload(manifest: Record<string, unknown>): Buffer {
  const keys = [
    "schema_version",
    "worker_id",
    "worker_species_id",
    "worker_version",
    "package_hash",
    "built_at_utc",
    "build_source",
  ];
  const payload: Record<string, unknown> = {};
  for (const k of keys) {
    payload[k] = manifest[k] ?? null;
  }
  // Sort keys, no spaces — mirrors Python json.dumps(sort_keys=True, separators=(',', ':'))
  const sorted = Object.fromEntries(
    Object.entries(payload).sort(([a], [b]) => a.localeCompare(b))
  );
  return Buffer.from(JSON.stringify(sorted), "utf-8");
}

function _signHmac(manifest: Record<string, unknown>, secret: string): string {
  return crypto
    .createHmac("sha256", secret)
    .update(_canonicalManifestPayload(manifest))
    .digest("hex");
}

// ---------------------------------------------------------------------------
// Build + write manifest
// ---------------------------------------------------------------------------

/**
 * Build and sign a worker package manifest.
 *
 * Computes the canonical package hash, assembles the manifest dict, and
 * signs it with HMAC-SHA256. The manifest is NOT written to disk — call
 * writeManifest() after reviewing.
 *
 * Trust statement format (embedded in manifest):
 *     "Package attested by namespace <ns> at <UTC>; package hash sha256:<hash>."
 */
export function buildManifest(opts: BuildManifestOptions): Record<string, unknown> {
  const {
    packageRoot,
    workerId,
    workerSpeciesId,
    workerVersion,
    signingSecret,
    buildSource = "local",
  } = opts;

  const now = _utcNowIso();
  const ns = _namespaceFromSpecies(workerSpeciesId);
  const pkgHash = canonicalPackageHash(packageRoot);

  const manifest: Record<string, unknown> = {
    schema_version: MANIFEST_SCHEMA_VERSION,
    worker_id: workerId,
    worker_species_id: workerSpeciesId,
    worker_version: workerVersion,
    package_hash: pkgHash,
    built_at_utc: now,
    attested_at_utc: now,
    build_source: buildSource,
    trust_statement:
      `Package attested by namespace ${ns} at ${now}; ` +
      `package hash sha256:${pkgHash}.`,
  };

  manifest["signature_hmac_sha256"] = _signHmac(manifest, signingSecret);
  return manifest;
}

/**
 * Write a signed manifest dict to disk as formatted JSON.
 * Parent directories are created if needed.
 */
export function writeManifest(manifest: Record<string, unknown>, manifestPath: string): void {
  const dir = path.dirname(manifestPath);
  fs.mkdirSync(dir, { recursive: true });

  // Sort keys for deterministic output, 2-space indent, trailing newline
  const sortedManifest = Object.fromEntries(
    Object.entries(manifest).sort(([a], [b]) => a.localeCompare(b))
  );
  fs.writeFileSync(manifestPath, JSON.stringify(sortedManifest, null, 2) + "\n", "utf-8");
}

// ---------------------------------------------------------------------------
// Scaffold package
// ---------------------------------------------------------------------------

/**
 * Create a minimal worker package directory layout.
 *
 * Layout created:
 *     <packageRoot>/
 *       code/
 *         bootstrap.py
 *         worker_logic.py   ← stub
 *       requirements.lock
 *       config.schema.json
 *
 * Throws if worker_logic.py exists and overwrite is false.
 */
export function scaffoldPackage(
  packageRoot: string,
  opts: { overwrite?: boolean } = {},
): void {
  const { overwrite = false } = opts;

  fs.mkdirSync(packageRoot, { recursive: true });
  const codeDir = path.join(packageRoot, "code");
  fs.mkdirSync(codeDir, { recursive: true });

  const logicTarget = path.join(codeDir, "worker_logic.py");
  if (fs.existsSync(logicTarget) && !overwrite) {
    throw new Error(
      `${logicTarget} already exists. Pass overwrite: true to replace.`
    );
  }

  fs.writeFileSync(
    logicTarget,
    '"""Worker business logic — replace this stub with your implementation."""\n\n\ndef run():\n    raise NotImplementedError("Replace this stub with your worker logic.")\n',
    "utf-8",
  );

  const bootstrap = path.join(codeDir, "bootstrap.py");
  fs.writeFileSync(
    bootstrap,
    "#!/usr/bin/env python3\nfrom worker_logic import run\n\nif __name__ == '__main__':\n    run()\n",
    "utf-8",
  );

  const reqs = path.join(packageRoot, "requirements.lock");
  if (!fs.existsSync(reqs)) {
    fs.writeFileSync(
      reqs,
      "# Pin your dependencies here — one package==version per line\n",
      "utf-8",
    );
  }

  const schema = path.join(packageRoot, "config.schema.json");
  if (!fs.existsSync(schema)) {
    fs.writeFileSync(
      schema,
      JSON.stringify(
        {
          $schema: "https://json-schema.org/draft/2020-12/schema",
          type: "object",
          properties: {},
          additionalProperties: true,
        },
        null,
        2,
      ) + "\n",
      "utf-8",
    );
  }
}

// ---------------------------------------------------------------------------
// PackageAttestationVerifier
// ---------------------------------------------------------------------------

/**
 * Verifies that a worker package is attested and unchanged at runtime.
 *
 * Fail-closed: any mismatch returns a deny code and ok=false.
 * No silent fallback execution.
 *
 * Deny codes returned:
 *     ATTEST_MANIFEST_MISSING      manifest.json absent or unreadable
 *     ATTEST_MANIFEST_ID_MISMATCH  manifest identity != declared worker identity
 *     ATTEST_HASH_MISMATCH         recomputed hash != manifest package_hash
 *     ATTEST_SIGNATURE_MISSING     no signature or no signing secret
 *     ATTEST_SIG_INVALID           HMAC does not verify
 *
 * Usage:
 *
 *     const verifier = new PackageAttestationVerifier({
 *       packageRoot: '/opt/workers/my-worker',
 *       manifestPath: '/opt/workers/my-worker/manifest.json',
 *       workerId: 'org.example.my-worker.instance-1',
 *       workerSpeciesId: 'wrk.example.my-worker',
 *     });
 *     const result = verifier.verify();
 *     if (!result.ok) throw new Error(`Attestation denied: ${result.denyCode}`);
 *
 *     // result.meta.trust_statement — canonical namespace-key trust claim
 *     // result.meta.package_hash — verified hash for embedding in evidence receipts
 *     // result.meta.verified_at_utc — UTC ISO 8601
 */
export class PackageAttestationVerifier {
  private readonly packageRoot: string;
  private readonly manifestPath: string;
  private readonly workerId: string;
  private readonly workerSpeciesId: string;
  private readonly secretEnv: string;

  constructor(opts: VerifierOptions) {
    this.packageRoot = opts.packageRoot;
    this.manifestPath = opts.manifestPath;
    this.workerId = opts.workerId;
    this.workerSpeciesId = opts.workerSpeciesId;
    this.secretEnv = opts.secretEnv ?? DEFAULT_SECRET_ENV;
  }

  /**
   * Verify the worker package.
   *
   * Returns an AttestResult:
   *   ok:       true if the package passes all attestation checks.
   *   denyCode: null when ok=true; one of the ATTEST_* constants otherwise.
   *   meta:     Diagnostic dict. When ok=true includes:
   *               package_hash, manifest_schema, attested_at_utc,
   *               verified_at_utc, trust_statement.
   */
  verify(): AttestResult {
    // 1. Manifest must exist and be parseable
    if (!fs.existsSync(this.manifestPath)) {
      return { ok: false, denyCode: ATTEST_MANIFEST_MISSING, meta: {} };
    }

    let manifest: Record<string, unknown>;
    try {
      const raw = fs.readFileSync(this.manifestPath, "utf-8");
      manifest = JSON.parse(raw) as Record<string, unknown>;
    } catch (exc) {
      return {
        ok: false,
        denyCode: ATTEST_MANIFEST_MISSING,
        meta: { error: String(exc) },
      };
    }

    // 2. Identity check — manifest must declare the same worker
    if (
      manifest["worker_id"] !== this.workerId ||
      manifest["worker_species_id"] !== this.workerSpeciesId
    ) {
      return {
        ok: false,
        denyCode: ATTEST_MANIFEST_ID_MISMATCH,
        meta: {
          manifest_worker_id: manifest["worker_id"],
          expected_worker_id: this.workerId,
          manifest_worker_species_id: manifest["worker_species_id"],
          expected_worker_species_id: this.workerSpeciesId,
        },
      };
    }

    // 3. Package hash must match
    const expectedHash = (manifest["package_hash"] as string) ?? "";
    const computedHash = canonicalPackageHash(this.packageRoot);
    if (!expectedHash || expectedHash !== computedHash) {
      return {
        ok: false,
        denyCode: ATTEST_HASH_MISMATCH,
        meta: {
          expected_hash: expectedHash,
          computed_hash: computedHash,
        },
      };
    }

    // 4. Signature must be present and valid
    const sig = (manifest["signature_hmac_sha256"] as string) ?? "";
    const secret = process.env[this.secretEnv] ?? "";
    if (!sig || !secret) {
      return {
        ok: false,
        denyCode: ATTEST_SIGNATURE_MISSING,
        meta: {
          signature_present: Boolean(sig),
          secret_env_set: Boolean(secret),
          secret_env: this.secretEnv,
        },
      };
    }

    const expectedSig = _signHmac(manifest, secret);
    // Constant-time comparison
    let sigsMatch = false;
    try {
      sigsMatch = crypto.timingSafeEqual(
        Buffer.from(sig, "hex"),
        Buffer.from(expectedSig, "hex"),
      );
    } catch {
      // Length mismatch or invalid hex — definitely not equal
      sigsMatch = false;
    }

    if (!sigsMatch) {
      return { ok: false, denyCode: ATTEST_SIG_INVALID, meta: {} };
    }

    // All checks passed
    const ns = _namespaceFromSpecies(this.workerSpeciesId);
    const verifiedAt = _utcNowIso();
    const attestedAt = (manifest["attested_at_utc"] as string) ?? "unknown";
    return {
      ok: true,
      denyCode: null,
      meta: {
        package_hash: computedHash,
        manifest_schema: manifest["schema_version"],
        attested_at_utc: attestedAt,
        verified_at_utc: verifiedAt,
        trust_statement:
          `Package attested by namespace ${ns} at ${attestedAt}; ` +
          `package hash sha256:${computedHash}.`,
      },
    };
  }
}
