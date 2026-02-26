/**
 * src/registry.ts — WCP Worker Registry.
 *
 * The Registry is the Hall's source of truth for enrolled workers.
 *
 * Workers enroll by providing a JSON registry record. The Registry:
 *   - Tracks which worker species are available
 *   - Maps capabilities to species
 *   - Tracks which controls are present
 *   - Enforces privilege envelope policies
 *
 * Mirrors pyhall/registry.py exactly.
 *
 * Worker registry record format (WCP spec section 6):
 *   {
 *     "worker_id": "org.example.my-summarizer",
 *     "worker_species_id": "wrk.doc.summarizer",
 *     "capabilities": ["cap.doc.summarize"],
 *     "risk_tier": "low",
 *     "required_controls": ["ctrl.obs.audit-log-append-only"],
 *     "currently_implements": ["ctrl.obs.audit-log-append-only"],
 *     "allowed_environments": ["dev", "stage", "prod"],
 *     "blast_radius": {"data": 1, "network": 0, "financial": 0, "time": 1},
 *     "privilege_envelope": {
 *       "secrets_access": [],
 *       "network_egress": "none",
 *       "filesystem_writes": ["/tmp/"],
 *       "tools": []
 *     },
 *     "owner": "org.example",
 *     "contact": "team@example.com"
 *   }
 */

import { createHash } from "crypto";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import type { WorkerRegistryRecord, PrivilegeEnvelope } from "./models.js";

// TS-F8: Control ID format validation — reject poisoned IDs at enrollment time.
// Valid control IDs must start with "ctrl." followed by at least one valid segment character.
// Segments may contain lowercase letters, digits, hyphens, underscores, and dots.
const VALID_CTRL_RE = /^ctrl\.[a-z0-9][a-z0-9._\-]*$/;

export class Registry {
  private _controlsPresent: Set<string> = new Set();
  private _workersAvailable: Set<string> = new Set();
  private _privilegeEnvelopes: Map<string, PrivilegeEnvelope> = new Map();
  private _enrolled: Map<string, WorkerRegistryRecord> = new Map();
  private _capabilitiesMap: Map<string, string[]> = new Map();

  // Worker Code Attestation (WCP §5.10)
  private _attestationHashes: Map<string, string> = new Map(); // speciesId → registered SHA-256
  private _attestationFiles: Map<string, string> = new Map();  // speciesId → resolved file path

  // Per-env egress allowlists (stub). Replace with real policy.
  private _egressAllowlist: Map<string, string[]> = new Map([
    ["dev", []],
    ["stage", []],
    ["prod", []],
    ["edge", []],
  ]);

  // -----------------------------------------------------------------------
  // Enrollment
  // -----------------------------------------------------------------------

  /**
   * Enroll a single worker from a registry record.
   */
  enroll(record: WorkerRegistryRecord): void {
    const workerId =
      record.worker_id ?? `unknown-${this._enrolled.size}`;
    this._enrolled.set(workerId, record);

    const speciesId = record.worker_species_id;
    if (speciesId) {
      this._workersAvailable.add(speciesId);
    }

    for (const cap of record.capabilities ?? []) {
      if (!this._capabilitiesMap.has(cap)) {
        this._capabilitiesMap.set(cap, []);
      }
      const existing = this._capabilitiesMap.get(cap)!;
      if (speciesId && !existing.includes(speciesId)) {
        existing.push(speciesId);
      }
    }

    for (const ctrl of record.currently_implements ?? []) {
      // TS-F8: Validate control ID format before adding — reject path-traversal and injection attempts.
      if (!VALID_CTRL_RE.test(ctrl)) {
        console.warn(
          `[pyhall.registry] WARNING: invalid control ID rejected for worker '${record.worker_id}': ${JSON.stringify(ctrl)}`
        );
        continue;
      }
      this._controlsPresent.add(ctrl);
    }

    const envelope = record.privilege_envelope;
    if (envelope && speciesId) {
      this._privilegeEnvelopes.set(speciesId, envelope);
    }
  }

  // -----------------------------------------------------------------------
  // Controls
  // -----------------------------------------------------------------------

  /**
   * Override the full set of present controls (replaces existing set).
   * TS-F21: Applies the same control ID format validation as enroll() —
   * direct calls cannot bypass the TS-F8 injection guard.
   */
  setControlsPresent(controls: string[]): void {
    this._controlsPresent = new Set();
    for (const c of controls) {
      if (!VALID_CTRL_RE.test(c)) {
        console.warn(
          `[pyhall.registry] WARNING: invalid control ID rejected in setControlsPresent: ${JSON.stringify(c)}`
        );
        continue;
      }
      this._controlsPresent.add(c);
    }
  }

  /**
   * Add controls to the existing set (additive).
   * TS-F21: Applies the same control ID format validation as enroll() —
   * direct calls cannot bypass the TS-F8 injection guard.
   */
  addControlsPresent(controls: string[]): void {
    for (const c of controls) {
      if (!VALID_CTRL_RE.test(c)) {
        console.warn(
          `[pyhall.registry] WARNING: invalid control ID rejected in addControlsPresent: ${JSON.stringify(c)}`
        );
        continue;
      }
      this._controlsPresent.add(c);
    }
  }

  /** Return the set of currently declared controls. */
  controlsPresent(): Set<string> {
    return new Set(this._controlsPresent);
  }

  // -----------------------------------------------------------------------
  // Worker availability
  // -----------------------------------------------------------------------

  /**
   * Override the full set of available worker species.
   * VULN-TS-3: Only species that have been formally enrolled (via enroll()) are
   * accepted. Unenrolled species IDs are warned and silently dropped — they
   * cannot be made available without governance metadata.
   */
  setWorkersAvailable(workerSpeciesIds: string[]): void {
    this._workersAvailable = new Set();
    for (const id of workerSpeciesIds) {
      if (!this._isEnrolledSpecies(id)) {
        console.warn(
          `[pyhall.registry] WARNING: setWorkersAvailable skipping unenrolled species '${id}'. ` +
            `Enroll the worker first via enroll() before marking it available.`
        );
        continue;
      }
      this._workersAvailable.add(id);
    }
  }

  /**
   * Mark additional worker species as available.
   * VULN-TS-3: Only enrolled species are accepted (same guard as setWorkersAvailable).
   */
  addWorkersAvailable(workerSpeciesIds: string[]): void {
    for (const id of workerSpeciesIds) {
      if (!this._isEnrolledSpecies(id)) {
        console.warn(
          `[pyhall.registry] WARNING: addWorkersAvailable skipping unenrolled species '${id}'. ` +
            `Enroll the worker first via enroll() before marking it available.`
        );
        continue;
      }
      this._workersAvailable.add(id);
    }
  }

  /**
   * Return true if the species is enrolled and currently available.
   * VULN-TS-3: Both conditions must be true — the species must be formally
   * enrolled with governance metadata AND marked available. Availability alone
   * (via a direct setWorkersAvailable call) is no longer sufficient.
   */
  workerAvailable(workerSpeciesId: string): boolean {
    return this._isEnrolledSpecies(workerSpeciesId) && this._workersAvailable.has(workerSpeciesId);
  }

  /**
   * Return true if any enrolled worker record declares this species ID.
   * Used internally to guard setWorkersAvailable / addWorkersAvailable.
   */
  private _isEnrolledSpecies(speciesId: string): boolean {
    for (const record of this._enrolled.values()) {
      if (record.worker_species_id === speciesId) return true;
    }
    return false;
  }

  /** Return list of enrolled worker species that handle this capability. */
  workersForCapability(capabilityId: string): string[] {
    return [...(this._capabilitiesMap.get(capabilityId) ?? [])];
  }

  // -----------------------------------------------------------------------
  // Privilege envelopes
  // -----------------------------------------------------------------------

  /** Map worker_species_id -> privilege envelope. */
  setPrivilegeEnvelopes(envelopes: Record<string, PrivilegeEnvelope>): void {
    this._privilegeEnvelopes = new Map(Object.entries(envelopes));
  }

  /** Return the privilege envelope for a species, or undefined. */
  getPrivilegeEnvelope(workerSpeciesId: string): PrivilegeEnvelope | undefined {
    return this._privilegeEnvelopes.get(workerSpeciesId);
  }

  /** Configure the egress allowlist for an environment. */
  setEgressAllowlist(env: string, allowlist: string[]): void {
    this._egressAllowlist.set(env, [...allowlist]);
  }

  /**
   * Evaluate whether the privilege envelope is allowed for this
   * environment and data label.
   *
   * This is a stub implementation. In production, replace with your
   * organization's policy engine.
   *
   * Returns [allowed, reason].
   */
  policyAllowsPrivilege(
    env: string,
    dataLabel: string,
    envelope: PrivilegeEnvelope | undefined
  ): [boolean, string] {
    const egress = (envelope?.egress ?? {}) as { allowlist?: string[] };
    if ((env === "prod" || env === "edge") && dataLabel === "RESTRICTED") {
      const dests = egress.allowlist ?? [];
      if (dests.length > 0) {
        const allowedList = this._egressAllowlist.get(env) ?? [];
        if (allowedList.length === 0) {
          return [false, "egress_denied_no_allowlist_configured"];
        }
        for (const dest of dests) {
          if (!allowedList.includes(dest)) {
            return [false, `egress_not_allowlisted:${dest}`];
          }
        }
      }
    }
    return [true, "stub_allow"];
  }

  // -----------------------------------------------------------------------
  // Worker Code Attestation (WCP §5.10)
  // -----------------------------------------------------------------------

  /**
   * Register a worker's code hash by SHA-256 of its source file.
   * Call once at enrollment time to establish the known-good fingerprint.
   * Returns the hex digest. Throws if the file does not exist.
   * Mirrors pyhall/registry.py register_attestation().
   */
  registerAttestation(speciesId: string, sourceFile: string): string {
    const resolved = resolve(sourceFile);
    if (!existsSync(resolved)) {
      throw new Error(`Worker source file not found: ${sourceFile}`);
    }
    const content = readFileSync(resolved);
    const digest = createHash("sha256").update(content).digest("hex");
    this._attestationHashes.set(speciesId, digest);
    this._attestationFiles.set(speciesId, resolved);
    return digest;
  }

  /**
   * Return the registered code hash for a worker species.
   * Returns null if no attestation has been registered.
   * Mirrors pyhall/registry.py get_worker_hash().
   */
  getWorkerHash(speciesId: string): string | null {
    return this._attestationHashes.get(speciesId) ?? null;
  }

  /**
   * Recompute the current code hash from the worker source file.
   * Returns null if no source file was registered for this species.
   * Compare to getWorkerHash() at dispatch time to detect tampering.
   * Mirrors pyhall/registry.py compute_current_hash().
   *
   * TOCTOU safety: returns null on any read error (file deleted, permission
   * change, etc.) instead of throwing — mirrors Python's OSError → None
   * behaviour. The Hall dispatch loop must never throw from an attestation
   * check.
   */
  computeCurrentHash(speciesId: string): string | null {
    const path = this._attestationFiles.get(speciesId);
    if (path === undefined) return null;
    try {
      const content = readFileSync(path);
      return createHash("sha256").update(content).digest("hex");
    } catch {
      return null;
    }
  }

  // -----------------------------------------------------------------------
  // Introspection
  // -----------------------------------------------------------------------

  /** Return the number of enrolled workers. */
  enrolledCount(): number {
    return this._enrolled.size;
  }

  /** Return list of all enrolled worker records. */
  enrolledWorkers(): WorkerRegistryRecord[] {
    return [...this._enrolled.values()];
  }

  /** Return a status summary dict for display or health checks. */
  summary(): {
    enrolled_workers: number;
    available_species: string[];
    controls_present_count: number;
    controls_present: string[];
    capabilities_mapped: string[];
  } {
    return {
      enrolled_workers: this.enrolledCount(),
      available_species: [...this._workersAvailable].sort(),
      controls_present_count: this._controlsPresent.size,
      controls_present: [...this._controlsPresent].sort(),
      capabilities_mapped: [...this._capabilitiesMap.keys()].sort(),
    };
  }
}
