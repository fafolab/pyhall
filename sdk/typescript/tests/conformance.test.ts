/**
 * tests/conformance.test.ts — PATCH-XSDK-001: Cross-SDK Governance Conformance Tests
 *
 * Loads shared test vectors from docs/conformance/wcp_conformance_vectors.json and
 * verifies that this SDK produces the declared `denied` outcome (and `deny_code` where
 * applicable) for each vector not listed in skip_sdks.
 *
 * Purpose: catch governance regressions that survive per-SDK tests because they only
 * manifest as cross-SDK divergence. If this test passes and the Python/Go equivalents
 * also pass, all three SDKs agree on governance outcomes for every shared vector.
 *
 * Run:
 *   npm test -- --testPathPattern conformance
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { makeDecision } from "../src/router.js";
import { Registry } from "../src/registry.js";
import { loadRulesFromDoc } from "../src/rules.js";
import type { RouteInput } from "../src/models.js";
import type { Rule } from "../src/rules.js";

// ---------------------------------------------------------------------------
// Vector file location
// ---------------------------------------------------------------------------

// Path: tests/ -> typescript/ (../) -> sdk/ (../../) -> git/ (../../../) -> docs/conformance/
const VECTORS_PATH = path.resolve(
  __dirname,
  "../../../docs/conformance/wcp_conformance_vectors.json"
);

const SDK_NAME = "typescript";

// ---------------------------------------------------------------------------
// Types matching the vector file schema
// ---------------------------------------------------------------------------

interface VectorExpect {
  denied: boolean;
  deny_code?: string | null;
  deny_code_go?: string | null;
  deny_code_python?: string | null;
  telemetry_invariant?: string;
}

interface VectorSetup {
  no_workers?: boolean;
  required_control?: string;
  control_present?: boolean;
  worker_allowed_envs?: string[];
  worker_species_id?: string;
  worker_capability?: string;
}

interface ConformanceVector {
  id: string;
  description: string;
  skip_sdks?: string[];
  skip_reason?: string;
  notes?: string;
  // input and expect are optional: procedural vectors (skip_sdks=["all"]) omit them.
  input?: Record<string, unknown>;
  rule?: Record<string, unknown>;
  setup?: VectorSetup;
  expect?: VectorExpect;
}

interface VectorFile {
  _meta: Record<string, unknown>;
  vectors: ConformanceVector[];
}

// ---------------------------------------------------------------------------
// Load vectors
// ---------------------------------------------------------------------------

function loadVectors(): ConformanceVector[] {
  const raw = fs.readFileSync(VECTORS_PATH, "utf-8");
  const doc = JSON.parse(raw) as VectorFile;
  return doc.vectors;
}

const ALL_VECTORS = loadVectors();
const ACTIVE_VECTORS = ALL_VECTORS.filter(
  (v) => !(v.skip_sdks ?? []).includes(SDK_NAME) && !(v.skip_sdks ?? []).includes("all")
);

// ---------------------------------------------------------------------------
// Helper: build RouteInput from vector.input
// ---------------------------------------------------------------------------

function buildInput(raw: Record<string, unknown>): RouteInput {
  const inp: RouteInput = {
    capability_id: raw["capability_id"] as string,
    env: raw["env"] as RouteInput["env"],
    data_label: raw["data_label"] as RouteInput["data_label"],
    tenant_risk: raw["tenant_risk"] as RouteInput["tenant_risk"],
    qos_class: raw["qos_class"] as RouteInput["qos_class"],
    tenant_id: raw["tenant_id"] as string,
    correlation_id: raw["correlation_id"] as string,
    request: (raw["request"] as Record<string, unknown>) ?? {},
  };
  if (raw["blast_score"] !== undefined && raw["blast_score"] !== null) {
    inp.blast_score = raw["blast_score"] as number;
  }
  return inp;
}

// ---------------------------------------------------------------------------
// Helper: build rules list from vector.rule
// ---------------------------------------------------------------------------

function buildRules(vector: ConformanceVector): Rule[] {
  if (!vector.rule) {
    return [];
  }
  // loadRulesFromDoc expects { rules: [...] }
  const doc = { rules: [vector.rule] };
  return loadRulesFromDoc(doc as Parameters<typeof loadRulesFromDoc>[0]);
}

// ---------------------------------------------------------------------------
// Helper: build Registry for this vector
// ---------------------------------------------------------------------------

function buildRegistry(vector: ConformanceVector): Registry {
  const setup = vector.setup ?? {};
  const reg = new Registry();

  if (setup.no_workers) {
    // Empty registry — no workers enrolled
    return reg;
  }

  // Default: enroll wrk.test.worker (enroll() auto-marks it available)
  reg.enroll({
    worker_id: "org.conformance.test-worker",
    worker_species_id: "wrk.test.worker",
    capabilities: ["cap.doc.summarize", "cap.doc.devonly"],
    currently_implements: [],
  });

  // Control presence — add the required control if control_present=true
  const requiredCtrl = setup.required_control;
  if (requiredCtrl !== undefined) {
    if (setup.control_present === true) {
      reg.addControlsPresent([requiredCtrl]);
    }
    // else: control absent — do not add
  }

  return reg;
}

// ---------------------------------------------------------------------------
// Helper: resolve expected deny code for this SDK
// ---------------------------------------------------------------------------

function getExpectedDenyCode(vector: ConformanceVector): string | null | undefined {
  // TypeScript uses generic deny_code (no special override).
  // expect may be undefined for procedural vectors (skip_sdks=["all"]).
  return vector.expect?.deny_code ?? null;
}

// ---------------------------------------------------------------------------
// Conformance tests
// ---------------------------------------------------------------------------

describe("WCP Cross-SDK Conformance Vectors (PATCH-XSDK-001)", () => {
  // Sanity: vector file is loadable and complete
  test("vector file has all 13 required IDs", () => {
    const ids = new Set(ALL_VECTORS.map((v) => v.id));
    for (let i = 1; i <= 13; i++) {
      const expected = `CV-${String(i).padStart(3, "0")}`;
      expect(ids.has(expected)).toBe(true);
    }
  });

  test("vector file schema is valid (id, description, input, expect present)", () => {
    for (const v of ALL_VECTORS) {
      expect(v.id).toBeDefined();
      expect(v.description).toBeDefined();
      // Procedural vectors (skip_sdks=["all"]) are documentation-only records and
      // intentionally omit input/expect — they are implemented as standalone tests.
      if ((v.skip_sdks ?? []).includes("all")) {
        continue;
      }
      expect(v.input).toBeDefined();
      expect(v.expect).toBeDefined();
      expect(typeof v.expect!.denied).toBe("boolean");
    }
  });

  // Run active (non-skipped) vectors
  // ACTIVE_VECTORS excludes skip_sdks=["all"] procedural vectors, so input and
  // expect are always defined here — non-null assertions (!) are safe.
  test.each(ACTIVE_VECTORS.map((v) => [v.id, v] as [string, ConformanceVector]))(
    "%s: %s",
    (_id: string, vector: ConformanceVector) => {
      const expectedDenied = vector.expect!.denied;
      const expectedCode = getExpectedDenyCode(vector);

      const inp = buildInput(vector.input!);
      const rules = buildRules(vector);
      const registry = buildRegistry(vector);

      const dec = makeDecision({
        inp,
        rules,
        registryControlsPresent: registry.controlsPresent(),
        registryWorkerAvailable: (s: string) => registry.workerAvailable(s),
      });

      // Assert denied outcome
      expect(dec.denied).toBe(expectedDenied);

      // Assert deny code (when denied and a code is expected)
      if (expectedDenied && expectedCode != null) {
        const actualCode = (
          dec.deny_reason_if_denied as Record<string, unknown> | null
        )?.["code"];
        expect(actualCode).toBe(expectedCode);
      }

      // Telemetry invariant: no raw control characters in capability_id field
      const invariant = vector.expect!.telemetry_invariant;
      if (
        invariant === "no_control_chars_in_capability_id_field_in_telemetry"
      ) {
        for (const envelope of dec.telemetry_envelopes ?? []) {
          const rawCap = String((envelope as Record<string, unknown>)["capability_id"] ?? "");
          expect(rawCap).not.toMatch(/\n/);
          expect(rawCap).not.toMatch(/\x00/);
          expect(rawCap).not.toMatch(/\r/);
        }
      }
    }
  );

  // Report skipped vectors as a documentation check
  test("skipped vectors for this SDK are documented", () => {
    const skipped = ALL_VECTORS.filter((v) =>
      (v.skip_sdks ?? []).includes(SDK_NAME)
    );
    // Not a failure — just ensure skipped vectors have a skip_reason or notes
    for (const v of skipped) {
      const hasReason = v.skip_reason || v.notes;
      expect(hasReason).toBeTruthy();
    }
  });
});

// ---------------------------------------------------------------------------
// CV-013: Worker attestation — standalone procedural test (WCP §5.10)
// ---------------------------------------------------------------------------

describe("CV-013: Worker attestation (WCP §5.10)", () => {
  it("enroll → dispatch (pass) → tamper → dispatch (DENY_WORKER_TAMPERED)", () => {
    // Step 1: create a temp worker file (cleaned up unconditionally in finally)
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cv013-"));
    const workerFile = path.join(tmpDir, "worker.py");
    fs.writeFileSync(workerFile, "def run(): pass\n");
    try {

    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.cv013",
      worker_species_id: "wrk.test.cv013",
      capabilities: ["cap.test.cv013"],
      risk_tier: "low",
      required_controls: ["ctrl.obs.audit-log-append-only"],
      currently_implements: ["ctrl.obs.audit-log-append-only"],
      allowed_environments: ["dev"],
    });
    registry.registerAttestation("wrk.test.cv013", workerFile);

    const rules = loadRulesFromDoc({
      rules: [{
        rule_id: "rr_cv013",
        match: { capability_id: "cap.test.cv013" },
        decision: {
          candidate_workers_ranked: [{ worker_species_id: "wrk.test.cv013", score_hint: 1.0 }],
          required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
          escalation: {},
          preconditions: {},
        },
      }],
    });

    const base: RouteInput = {
      capability_id: "cap.test.cv013",
      env: "dev",
      data_label: "PUBLIC",
      tenant_risk: "low",
      qos_class: "P2",
      tenant_id: "test.tenant",
      correlation_id: "cv013",
    };

    // Step 2: intact file → DISPATCHED
    const dec1 = makeDecision({
      inp: base,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id: string) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      registryGetWorkerHash: (id: string) => registry.getWorkerHash(id),
      registryGetCurrentWorkerHash: (id: string) => registry.computeCurrentHash(id),
    });
    expect(dec1.denied).toBe(false);
    expect(dec1.worker_attestation_checked).toBe(true);
    expect(dec1.worker_attestation_valid).toBe(true);

    // Step 3: tamper — overwrite worker file content
    fs.writeFileSync(workerFile, "def run(): exfiltrate()\n");

    // Step 4: tampered file → DENY_WORKER_TAMPERED
    const dec2 = makeDecision({
      inp: base,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id: string) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      registryGetWorkerHash: (id: string) => registry.getWorkerHash(id),
      registryGetCurrentWorkerHash: (id: string) => registry.computeCurrentHash(id),
    });
    expect(dec2.denied).toBe(true);
    expect((dec2.deny_reason_if_denied as Record<string, unknown>)["code"]).toBe("DENY_WORKER_TAMPERED");
    // Step 5: verify evidence receipt fields
    expect(dec2.worker_attestation_checked).toBe(true);
    expect(dec2.worker_attestation_valid).toBe(false);
    // Step 6 / F4: no hash values in deny payload
    expect((dec2.deny_reason_if_denied as Record<string, unknown>)["registered_hash"]).toBeUndefined();
    expect((dec2.deny_reason_if_denied as Record<string, unknown>)["current_hash"]).toBeUndefined();
    } finally {
      try { fs.unlinkSync(workerFile); } catch { /* ignore */ }
      try { fs.rmdirSync(tmpDir); } catch { /* ignore */ }
    }
  });
});
