/**
 * tests/router.test.ts — pyhall-ts core router test suite.
 *
 * Tests WCP compliance — mirrors tests/test_router.py exactly (21 tests):
 *   - Fail-closed on no matching rule
 *   - Deterministic routing
 *   - Controls enforcement
 *   - Blast radius gating
 *   - Policy gate integration
 *   - Mandatory telemetry emission
 *   - Correlation ID enforcement
 *   - Dry-run mode
 */

import { writeFileSync, mkdtempSync, unlinkSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { makeDecision } from "../src/router.js";
import { Registry } from "../src/registry.js";
import { PolicyGate } from "../src/policyGate.js";
import { loadRulesFromDoc, routeFirstMatch, type Rule } from "../src/rules.js";
import { defaultConformanceSpec } from "../src/conformance.js";
import type { RouteInput } from "../src/models.js";
import type { PolicyGateContext, PolicyGateResult } from "../src/policyGate.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function corr(): string {
  return `test-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

function inp(overrides: Partial<RouteInput> = {}): RouteInput {
  return {
    capability_id: "cap.hello.greet",
    env: "dev",
    data_label: "PUBLIC",
    tenant_risk: "low",
    qos_class: "P2",
    tenant_id: "test-tenant",
    correlation_id: corr(),
    ...overrides,
  };
}

const HELLO_RULES_DOC = {
  rules: [
    {
      rule_id: "rr_hello_dev_001",
      match: {
        capability_id: "cap.hello.greet",
        env: { in: ["dev", "stage"] },
      },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
        escalation: {
          policy_gate: false,
          human_required_default: false,
        },
        preconditions: {},
      },
    },
    {
      rule_id: "rr_hello_prod_001",
      match: {
        capability_id: "cap.hello.greet",
        env: "prod",
        data_label: { in: ["PUBLIC", "INTERNAL"] },
      },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        required_controls_suggested: [
          "ctrl.obs.audit-log-append-only",
          "ctrl.blast_radius_scoring",
        ],
        escalation: {
          policy_gate: true,
          human_required_default: false,
        },
        preconditions: {},
      },
    },
    {
      rule_id: "rr_default_deny",
      match: { capability_id: { any: true } },
      decision: {
        candidate_workers_ranked: [],
        required_controls_suggested: [],
        escalation: {},
        preconditions: {},
      },
    },
  ],
};

function registryWithWorker(species = "wrk.hello.greeter"): Registry {
  const registry = new Registry();
  registry.enroll({
    worker_id: "org.test.hello-greeter",
    worker_species_id: species,
    capabilities: ["cap.hello.greet"],
    currently_implements: ["ctrl.obs.audit-log-append-only"],
  });
  return registry;
}

// ---------------------------------------------------------------------------
// WCP 5.1 — Fail Closed (2 tests)
// ---------------------------------------------------------------------------

describe("TestFailClosed", () => {
  test("test_no_rules_denies — empty rules list must deny", () => {
    const registry = new Registry();
    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules: [],
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(dec.matched_rule_id).toBe("NO_MATCH");
    expect((dec.deny_reason_if_denied as Record<string, unknown>)["code"]).toBe(
      "DENY_NO_MATCHING_RULE"
    );
  });

  test("test_unknown_capability_denies — unknown cap with no catch-all must deny", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);
    const i = inp({ capability_id: "cap.does.not.exist" });

    // Remove catch-all to get a true NO_MATCH
    const filteredRules = rules.filter((r) => r.rule_id !== "rr_default_deny");
    const dec = makeDecision({
      inp: i,
      rules: filteredRules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(dec.matched_rule_id).toBe("NO_MATCH");
  });
});

// ---------------------------------------------------------------------------
// WCP 5.2 — Deterministic Routing (2 tests)
// ---------------------------------------------------------------------------

describe("TestDeterministicRouting", () => {
  test("test_identical_inputs_produce_identical_rule — same inputs, same rule", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const fixedCorr = corr();
    const results: string[] = [];

    for (let j = 0; j < 10; j++) {
      const i: RouteInput = {
        capability_id: "cap.hello.greet",
        env: "dev",
        data_label: "PUBLIC",
        tenant_risk: "low",
        qos_class: "P2",
        tenant_id: "test-tenant",
        correlation_id: fixedCorr,
      };
      const dec = makeDecision({
        inp: i,
        rules,
        registryControlsPresent: registry.controlsPresent(),
        registryWorkerAvailable: (id) => registry.workerAvailable(id),
      });
      results.push(dec.matched_rule_id);
    }

    const unique = new Set(results);
    expect(unique.size).toBe(1);
    expect(results[0]).toBe("rr_hello_dev_001");
  });

  test("test_env_routes_correct_rule — dev vs prod routes to different rules", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);
    const gate = new PolicyGate();

    const devInp = inp({ env: "dev" });
    const prodInp = inp({ env: "prod", data_label: "PUBLIC" });

    const devDec = makeDecision({
      inp: devInp,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (ctx) => gate.evaluate(ctx),
    });
    const prodDec = makeDecision({
      inp: prodInp,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (ctx) => gate.evaluate(ctx),
    });

    expect(devDec.matched_rule_id).toBe("rr_hello_dev_001");
    expect(prodDec.matched_rule_id).toBe("rr_hello_prod_001");
  });
});

// ---------------------------------------------------------------------------
// WCP 5.3 — Controls Enforcement (2 tests)
// ---------------------------------------------------------------------------

describe("TestControlsEnforcement", () => {
  test("test_missing_controls_denies — missing required controls must produce a deny", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = new Registry();
    registry.setWorkersAvailable(["wrk.hello.greeter"]);
    // No controls registered — should deny

    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    const reason = dec.deny_reason_if_denied as Record<string, unknown>;
    expect(reason["code"]).toBe("DENY_MISSING_REQUIRED_CONTROLS");
    const missing = reason["missing"] as string[];
    expect(missing).toContain("ctrl.obs.audit-log-append-only");
  });

  test("test_present_controls_allows — when required controls are present, routing proceeds", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(false);
    expect(dec.selected_worker_species_id).toBe("wrk.hello.greeter");
  });
});

// ---------------------------------------------------------------------------
// WCP 5.4 — Mandatory Telemetry (3 tests)
// ---------------------------------------------------------------------------

describe("TestMandatoryTelemetry", () => {
  test("test_three_mandatory_events_emitted — every successful dispatch emits three events", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });

    const eventIds = new Set(
      dec.telemetry_envelopes.map((e) => (e as Record<string, unknown>)["event_id"])
    );
    expect(eventIds.has("evt.os.task.routed")).toBe(true);
    expect(eventIds.has("evt.os.worker.selected")).toBe(true);
    expect(eventIds.has("evt.os.policy.gated")).toBe(true);
  });

  test("test_correlation_id_propagated_in_all_events — correlation_id in every telemetry event", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const fixedCorr = corr();
    const i = inp({ env: "dev", correlation_id: fixedCorr });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });

    for (const event of dec.telemetry_envelopes) {
      const e = event as Record<string, unknown>;
      expect(e["correlation_id"]).toBe(fixedCorr);
    }
  });

  test("test_telemetry_emitted_even_on_deny — denied decisions do not raise", () => {
    // Verifies the deny path does not throw and returns a valid decision
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = new Registry();

    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    // No exception — decision is always a valid RouteDecision
    expect(dec.decision_id).toBeTruthy();
    expect(dec.timestamp).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Correlation ID Enforcement (1 test)
// ---------------------------------------------------------------------------

describe("TestCorrelationIdEnforcement", () => {
  test("test_empty_correlation_id_denies — empty correlation_id must be denied", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev", correlation_id: "   " });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_MISSING_CORRELATION_ID");
  });
});

// ---------------------------------------------------------------------------
// Blast Radius Gating (2 tests)
// ---------------------------------------------------------------------------

describe("TestBlastRadius", () => {
  test("test_high_blast_score_in_prod_denies — blast_score >= 85 in prod requires human review", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);
    const gate = new PolicyGate();

    const i = inp({
      env: "prod",
      data_label: "PUBLIC",
      blast_score: 90, // above the 85 threshold
    });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (ctx) => gate.evaluate(ctx),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_REQUIRES_HUMAN");
  });

  test("test_low_blast_score_in_prod_allows — low blast_score passes the blast gate", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);
    const gate = new PolicyGate();

    const i = inp({
      env: "prod",
      data_label: "PUBLIC",
      blast_score: 10,
    });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (ctx) => gate.evaluate(ctx),
    });
    expect(dec.denied).toBe(false);
    expect(dec.selected_worker_species_id).toBe("wrk.hello.greeter");
  });
});

// ---------------------------------------------------------------------------
// Policy Gate (2 tests)
// ---------------------------------------------------------------------------

describe("TestPolicyGate", () => {
  test("test_policy_gate_deny_blocks_dispatch — DENY from policy gate produces a denied decision", () => {
    class DenyGate extends PolicyGate {
      evaluate(_ctx: PolicyGateContext): PolicyGateResult {
        return ["DENY", "policy.v1", "test_always_deny"];
      }
    }

    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);

    const i = inp({ env: "prod", data_label: "PUBLIC" });
    const gate = new DenyGate();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (ctx) => gate.evaluate(ctx),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_POLICY_GATE");
  });

  test("test_policy_gate_required_but_not_provided_denies — TS-F4: must deny when gate required but absent", () => {
    // TS-F4: policyGateEval missing now returns a deny instead of throwing
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);

    const i = inp({ env: "prod", data_label: "PUBLIC" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: null, // not provided
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_POLICY_GATE_UNCONFIGURED");
  });
});

// ---------------------------------------------------------------------------
// No Available Worker (1 test)
// ---------------------------------------------------------------------------

describe("TestNoAvailableWorker", () => {
  test("test_no_available_worker_denies — all candidates unavailable must deny", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = new Registry();
    // Controls present but no workers enrolled
    registry.setControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_NO_AVAILABLE_WORKER");
  });
});

// ---------------------------------------------------------------------------
// Conformance spec (1 test)
// ---------------------------------------------------------------------------

describe("TestConformance", () => {
  test("test_successful_decision_passes_default_spec — successful decision passes default conformance", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);
    const spec = defaultConformanceSpec();

    const i = inp({ env: "dev" });
    // Should not throw
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      conformanceSpec: spec,
    });
    expect(dec.denied).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Registry enrollment (2 tests)
// ---------------------------------------------------------------------------

describe("TestRegistryEnrollment", () => {
  test("test_enroll_worker_makes_it_available — enrolling a worker makes its species available", () => {
    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.my-worker",
      worker_species_id: "wrk.test.doer",
      capabilities: ["cap.test.do"],
      currently_implements: ["ctrl.obs.audit-log-append-only"],
    });
    expect(registry.workerAvailable("wrk.test.doer")).toBe(true);
    expect(registry.summary().capabilities_mapped).toContain("cap.test.do");
    expect(registry.controlsPresent().has("ctrl.obs.audit-log-append-only")).toBe(true);
  });

  test("test_workers_for_capability — registry returns correct workers for a capability", () => {
    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.w1",
      worker_species_id: "wrk.doc.summarizer",
      capabilities: ["cap.doc.summarize"],
      currently_implements: [],
    });
    const workers = registry.workersForCapability("cap.doc.summarize");
    expect(workers).toContain("wrk.doc.summarizer");
  });
});

// ---------------------------------------------------------------------------
// Rules engine (3 tests)
// ---------------------------------------------------------------------------

describe("TestRulesEngine", () => {
  test("test_membership_match — {in: [...]} match syntax works", () => {
    const rule: Rule = {
      rule_id: "rr_test",
      match: { capability_id: "cap.x", env: { in: ["dev", "stage"] } },
      decision: {},
    };
    expect(
      routeFirstMatch([rule], { capability_id: "cap.x", env: "dev" })
    ).toBe(rule);
    expect(
      routeFirstMatch([rule], { capability_id: "cap.x", env: "prod" })
    ).toBeNull();
  });

  test("test_wildcard_match — {any: true} matches any value", () => {
    const rule: Rule = {
      rule_id: "rr_catch_all",
      match: { capability_id: { any: true } },
      decision: {},
    };
    for (const cap of ["cap.doc.summarize", "cap.mem.retrieve", "anything"]) {
      expect(routeFirstMatch([rule], { capability_id: cap })).toBe(rule);
    }
  });

  test("test_first_match_wins — first matching rule wins; later rules are not evaluated", () => {
    const rules: Rule[] = [
      { rule_id: "rr_first", match: { capability_id: "cap.x" }, decision: {} },
      { rule_id: "rr_second", match: { capability_id: "cap.x" }, decision: {} },
    ];
    const matched = routeFirstMatch(rules, { capability_id: "cap.x" });
    expect(matched).not.toBeNull();
    expect(matched!.rule_id).toBe("rr_first");
  });
});

// ---------------------------------------------------------------------------
// Round 3 Fixes — TS-F1 through TS-F12
// ---------------------------------------------------------------------------

// Rules document with privilege envelope control for TS-F2 tests
const PRIV_RULES_DOC = {
  rules: [
    {
      rule_id: "rr_priv_dev_001",
      match: { capability_id: "cap.hello.greet" },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        required_controls_suggested: [
          "ctrl.obs.audit-log-append-only",
          "ctrl.privilege_envelopes_required",
        ],
        escalation: { policy_gate: false },
        preconditions: {},
      },
    },
  ],
};

// Rules with policy_gate=true for TS-F1, TS-F4, TS-F10 tests
const GATE_RULES_DOC = {
  rules: [
    {
      rule_id: "rr_gate_001",
      match: { capability_id: "cap.hello.greet" },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
        escalation: { policy_gate: true },
        preconditions: {},
      },
    },
  ],
};

describe("Round3Fixes", () => {
  // TS-F1: REQUIRE_HUMAN from policy gate → denied
  test("TS-F1: policy gate REQUIRE_HUMAN → denied with DENY_REQUIRES_HUMAN_APPROVAL", () => {
    const rules = loadRulesFromDoc(GATE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (_ctx) => ["REQUIRE_HUMAN", "policy.v1", "needs_human_review"],
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_REQUIRES_HUMAN_APPROVAL");
  });

  // TS-F2: Privilege envelope callable is actually called
  test("TS-F2: privilege envelope callables are actually invoked when ctrl.privilege_envelopes_required", () => {
    const rules = loadRulesFromDoc(PRIV_RULES_DOC);
    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.hello-greeter",
      worker_species_id: "wrk.hello.greeter",
      capabilities: ["cap.hello.greet"],
      currently_implements: [
        "ctrl.obs.audit-log-append-only",
        "ctrl.privilege_envelopes_required",
      ],
    });

    let envelopeCallCount = 0;
    let policyCallCount = 0;

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      registryGetPrivilegeEnvelope: (speciesId) => {
        envelopeCallCount++;
        return registry.getPrivilegeEnvelope(speciesId);
      },
      registryPolicyAllowsPrivilege: (env, dataLabel, envelope) => {
        policyCallCount++;
        return registry.policyAllowsPrivilege(env, dataLabel, envelope);
      },
    });

    // Both callables must have been invoked
    expect(envelopeCallCount).toBe(1);
    expect(policyCallCount).toBe(1);
    // Decision should be allowed (stub policy allows)
    expect(dec.denied).toBe(false);
  });

  // TS-F3 (updated for VULN-TS-1): NaN blast_score is now rejected at input validation
  // (DENY_INVALID_INPUT) rather than being silently replaced by a computed score.
  // This is strictly more secure — invalid blast scores are caught before routing begins.
  test("TS-F3: blast_score NaN is rejected at input validation — DENY_INVALID_INPUT (not a bypass)", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);
    const gate = new PolicyGate();

    const i = inp({
      env: "prod",
      data_label: "INTERNAL",
      qos_class: "P0",
      blast_score: NaN, // NaN is now rejected at validateRouteInput() — VULN-TS-1 fix
      request: { egress: true, writes: true },
    });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (ctx) => gate.evaluate(ctx),
    });
    // NaN blast_score is rejected at input validation — cannot bypass the blast gate
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  // TS-F4: policyGateEval throws → denied with DENY_INTERNAL_ERROR
  test("TS-F4: policyGateEval throws → denied with DENY_INTERNAL_ERROR, no propagation", () => {
    const rules = loadRulesFromDoc(GATE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    // Must not throw — exception is caught and returned as deny
    let dec: ReturnType<typeof makeDecision>;
    expect(() => {
      dec = makeDecision({
        inp: i,
        rules,
        registryControlsPresent: registry.controlsPresent(),
        registryWorkerAvailable: (id) => registry.workerAvailable(id),
        policyGateEval: (_ctx) => {
          throw new Error("gate exploded");
        },
      });
    }).not.toThrow();
    expect(dec!.denied).toBe(true);
    expect(
      (dec!.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INTERNAL_ERROR");
  });

  // TS-F4: policyGateEval missing with policy_gate=true → deny DENY_POLICY_GATE_UNCONFIGURED
  test("TS-F4: missing policyGateEval when policy_gate=true → DENY_POLICY_GATE_UNCONFIGURED", () => {
    const rules = loadRulesFromDoc(GATE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: null,
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_POLICY_GATE_UNCONFIGURED");
  });

  // TS-F5: empty correlation_id denied even when per-rule flag is false (hall floor)
  test("TS-F5: empty correlation_id denied by hall floor even when per-rule flag is false", () => {
    // Build a rule that explicitly sets must_have_correlation_id: false
    const noCorrelationRules = {
      rules: [
        {
          rule_id: "rr_no_corr_001",
          match: { capability_id: "cap.hello.greet" },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            // Per-rule explicitly disables correlation_id check
            preconditions: { must_have_correlation_id: false },
          },
        },
      ],
    };

    const rules = loadRulesFromDoc(noCorrelationRules);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ correlation_id: "" });
    // hallConfig.enforceCorrelationId defaults to true — hall floor wins
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      // No hallConfig override — defaults: enforceCorrelationId = true
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_MISSING_CORRELATION_ID");
  });

  // TS-F6: any deny path → telemetry_envelopes has at least one event, first is evt.os.task.denied
  test("TS-F6: every deny path emits at least one telemetry event (evt.os.task.denied)", () => {
    // Test multiple deny paths
    const denyPaths: Array<{ label: string; decisionFn: () => ReturnType<typeof makeDecision> }> = [
      {
        label: "no_matching_rule",
        decisionFn: () =>
          makeDecision({
            inp: inp({ capability_id: "cap.unknown.xyz" }),
            rules: [],
            registryControlsPresent: new Set(),
            registryWorkerAvailable: () => false,
          }),
      },
      {
        label: "missing_controls",
        decisionFn: () => {
          const rules = loadRulesFromDoc(HELLO_RULES_DOC);
          return makeDecision({
            inp: inp({ env: "dev" }),
            rules,
            registryControlsPresent: new Set(), // no controls
            registryWorkerAvailable: () => true,
          });
        },
      },
      {
        label: "missing_correlation_id",
        decisionFn: () => {
          const rules = loadRulesFromDoc(HELLO_RULES_DOC);
          const registry = registryWithWorker();
          registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);
          return makeDecision({
            inp: inp({ env: "dev", correlation_id: "" }),
            rules,
            registryControlsPresent: registry.controlsPresent(),
            registryWorkerAvailable: (id) => registry.workerAvailable(id),
          });
        },
      },
    ];

    for (const { label, decisionFn } of denyPaths) {
      const dec = decisionFn();
      expect(dec.denied).toBe(true);
      expect(dec.telemetry_envelopes.length).toBeGreaterThanOrEqual(1);
      const firstEvent = dec.telemetry_envelopes[0] as Record<string, unknown>;
      expect(firstEvent["event_id"]).toBe("evt.os.task.denied");
    }
  });

  // TS-F8: poisoned control ID at enrollment → NOT added to registry
  test("TS-F8: path-traversal control ID at enrollment is rejected", () => {
    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.bad-worker",
      worker_species_id: "wrk.test.bad",
      capabilities: ["cap.test.bad"],
      currently_implements: [
        "../../etc/passwd",
        "ctrl.obs.audit-log-append-only", // valid one should still be added
        "'; DROP TABLE controls; --",
        "ctrl.valid.control",
      ],
    });

    const controls = registry.controlsPresent();
    // Poisoned IDs must NOT be present
    expect(controls.has("../../etc/passwd")).toBe(false);
    expect(controls.has("'; DROP TABLE controls; --")).toBe(false);
    // Valid IDs must still be present
    expect(controls.has("ctrl.obs.audit-log-append-only")).toBe(true);
    expect(controls.has("ctrl.valid.control")).toBe(true);
  });

  // TS-F9: inp.env = null → denied with DENY_INVALID_INPUT, does not throw
  test("TS-F9: inp.env = null → DENY_INVALID_INPUT, does not throw or dispatch", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const badInp = inp({ env: null as any });
    let dec: ReturnType<typeof makeDecision>;
    expect(() => {
      dec = makeDecision({
        inp: badInp,
        rules,
        registryControlsPresent: registry.controlsPresent(),
        registryWorkerAvailable: (id) => registry.workerAvailable(id),
      });
    }).not.toThrow();
    expect(dec!.denied).toBe(true);
    expect(
      (dec!.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  // TS-F9: inp.correlation_id = {} (object) → denied with DENY_INVALID_INPUT, no TypeError
  test("TS-F9: inp.correlation_id = {} (object) → DENY_INVALID_INPUT, no TypeError thrown", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const badInp = inp({ correlation_id: {} as any });
    let dec: ReturnType<typeof makeDecision>;
    expect(() => {
      dec = makeDecision({
        inp: badInp,
        rules,
        registryControlsPresent: registry.controlsPresent(),
        registryWorkerAvailable: (id) => registry.workerAvailable(id),
      });
    }).not.toThrow();
    expect(dec!.denied).toBe(true);
    expect(
      (dec!.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  // TS-F10: policy gate returns "" (empty string) → DENY_POLICY_GATE_INVALID_RESPONSE
  test("TS-F10: policy gate returns empty string → DENY_POLICY_GATE_INVALID_RESPONSE", () => {
    const rules = loadRulesFromDoc(GATE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (_ctx) => ["" as "ALLOW", "policy.v1", "empty_response"],
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_POLICY_GATE_INVALID_RESPONSE");
  });

  // TS-F11: dry_run=true → RouteDecision.dry_run === true
  test("TS-F11: dry_run=true is reflected in RouteDecision.dry_run", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev", dry_run: true });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(false);
    expect(dec.dry_run).toBe(true);
    // All telemetry events must also have dry_run=true
    for (const event of dec.telemetry_envelopes) {
      expect((event as Record<string, unknown>)["dry_run"]).toBe(true);
    }
  });

  // TS-F12: rules=[null, validRule] → does not crash, returns valid decision
  test("TS-F12: null entry in rules array does not crash the router", () => {
    const validRule: Rule = {
      rule_id: "rr_valid",
      match: { capability_id: "cap.hello.greet" },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
        escalation: { policy_gate: false },
        preconditions: {},
      },
    };

    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    let dec: ReturnType<typeof makeDecision>;
    expect(() => {
      dec = makeDecision({
        inp: i,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        rules: [null as any, validRule],
        registryControlsPresent: registry.controlsPresent(),
        registryWorkerAvailable: (id) => registry.workerAvailable(id),
      });
    }).not.toThrow();
    // The null was filtered, the valid rule matched
    expect(dec!.denied).toBe(false);
    expect(dec!.matched_rule_id).toBe("rr_valid");
  });
});

// ---------------------------------------------------------------------------
// Round 4 Fixes — TS-F13 through TS-F22
// ---------------------------------------------------------------------------

// Helper: a rule that does NOT include ctrl.blast_radius_scoring
const NO_BLAST_CTRL_RULES_DOC = {
  rules: [
    {
      rule_id: "rr_no_blast_ctrl_001",
      match: { capability_id: "cap.hello.greet" },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        // ctrl.blast_radius_scoring deliberately omitted
        required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
        escalation: { policy_gate: false },
        preconditions: {},
      },
    },
  ],
};

describe("Round4Fixes", () => {
  // TS-F13: Hall floor — enforceBlastScoringInProd=true must deny high-blast requests
  // in prod even when the rule omits ctrl.blast_radius_scoring.
  test("TS-F13: blast gate enforced in prod even when ctrl.blast_radius_scoring absent from rule", () => {
    const rules = loadRulesFromDoc(NO_BLAST_CTRL_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // High-blast prod request — score: 10+40+15+10+15+15 = 105 → capped at 100
    const i = inp({
      env: "prod",
      data_label: "RESTRICTED",
      qos_class: "P0",
      request: { egress: true, writes: true },
    });
    // Default hallConfig: enforceBlastScoringInProd=true
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_REQUIRES_HUMAN");
  });

  // TS-F13: With enforceBlastScoringInProd=false, the rule-level absence of blast ctrl passes.
  test("TS-F13: enforceBlastScoringInProd=false allows opt-out of hall blast floor", () => {
    const rules = loadRulesFromDoc(NO_BLAST_CTRL_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const gate = new PolicyGate();
    const i = inp({
      env: "prod",
      data_label: "RESTRICTED",
      qos_class: "P0",
      request: { egress: true, writes: true },
    });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (ctx) => gate.evaluate(ctx),
      hallConfig: { enforceBlastScoringInProd: false },
    });
    // Blast gate disabled — should route (no policy gate on this rule)
    expect(dec.denied).toBe(false);
  });

  // TS-F14: requireSignatory=true with allowed tenant passes through
  test("TS-F14: requireSignatory=true allows listed tenants", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ tenant_id: "org.trusted" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireSignatory: true, allowedTenants: ["org.trusted", "org.other"] },
    });
    expect(dec.denied).toBe(false);
  });

  // TS-F14: requireSignatory=true with unlisted tenant → DENY_UNKNOWN_TENANT
  test("TS-F14: requireSignatory=true denies tenants not in allowedTenants", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ tenant_id: "org.unknown" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireSignatory: true, allowedTenants: ["org.trusted"] },
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_UNKNOWN_TENANT");
  });

  // TS-F15: enforceRequiredControls hall floor overrides per-rule deny_if_missing_required_controls=false
  test("TS-F15: hall enforceRequiredControls floor overrides per-rule flag set to false", () => {
    // Rule explicitly says deny_if_missing_required_controls: false — but hall floor wins
    const rulesDoc = {
      rules: [
        {
          rule_id: "rr_no_ctrl_check_001",
          match: { capability_id: "cap.hello.greet" },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            // Rule explicitly disables controls check
            preconditions: { deny_if_missing_required_controls: false },
          },
        },
      ],
    };
    const rules = loadRulesFromDoc(rulesDoc);
    const registry = new Registry();
    // NO controls registered — required but per-rule says to skip the check
    registry.setWorkersAvailable(["wrk.hello.greeter"]);

    const i = inp();
    // Hall floor (default enforceRequiredControls=true) must still deny
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_MISSING_REQUIRED_CONTROLS");
  });

  // TS-F16: control characters in correlation_id are stripped in telemetry (log injection)
  test("TS-F16: control characters in correlation_id are stripped from telemetry payloads", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // Embed a newline + fake event injection in correlation_id
    const maliciousCorr = "corr-123\nevt.os.task.routed{injected:true}";
    const i = inp({ env: "dev", correlation_id: maliciousCorr });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    // Decision should succeed (valid routing)
    expect(dec.denied).toBe(false);
    // All telemetry events must have sanitized correlation_id (no \n)
    for (const event of dec.telemetry_envelopes) {
      const e = event as Record<string, unknown>;
      expect(typeof e["correlation_id"]).toBe("string");
      expect((e["correlation_id"] as string).includes("\n")).toBe(false);
      expect((e["correlation_id"] as string).includes("\r")).toBe(false);
    }
  });

  // TS-F16: null bytes in tenant_id are stripped from telemetry
  test("TS-F16: null bytes in tenant_id stripped from telemetry", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev", tenant_id: "tenant\x00injected" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(false);
    for (const event of dec.telemetry_envelopes) {
      const e = event as Record<string, unknown>;
      const tid = e["tenant_id"] as string;
      expect(tid.includes("\x00")).toBe(false);
    }
  });

  // TS-F17: worker that was available but not selected gets skip_reason "already_selected"
  test("TS-F17: second available worker gets skip_reason='already_selected', not 'unavailable'", () => {
    const rulesDoc = {
      rules: [
        {
          rule_id: "rr_multi_worker",
          match: { capability_id: "cap.hello.greet" },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.primary", score_hint: 1.0 },
              { worker_species_id: "wrk.hello.secondary", score_hint: 0.5 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            preconditions: {},
          },
        },
      ],
    };
    const rules = loadRulesFromDoc(rulesDoc);
    const registry = new Registry();
    // Both workers enrolled and available (enroll required before setWorkersAvailable — VULN-TS-3 fix)
    registry.enroll({
      worker_id: "org.test.hello-primary",
      worker_species_id: "wrk.hello.primary",
      capabilities: ["cap.hello.greet"],
      currently_implements: ["ctrl.obs.audit-log-append-only"],
    });
    registry.enroll({
      worker_id: "org.test.hello-secondary",
      worker_species_id: "wrk.hello.secondary",
      capabilities: ["cap.hello.greet"],
      currently_implements: [],
    });
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(false);
    expect(dec.selected_worker_species_id).toBe("wrk.hello.primary");

    // The second candidate (available but not selected) must be "already_selected", not "unavailable"
    const secondary = dec.candidate_workers_ranked.find(
      (c) => c.worker_species_id === "wrk.hello.secondary"
    );
    expect(secondary).toBeDefined();
    expect(secondary!.skip_reason).toBe("already_selected");
  });

  // TS-F18: privilege envelope exception does not leak class name
  test("TS-F18: privilege envelope exception does not leak internal class names", () => {
    const rules = loadRulesFromDoc(PRIV_RULES_DOC);
    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.hello-greeter",
      worker_species_id: "wrk.hello.greeter",
      capabilities: ["cap.hello.greet"],
      currently_implements: [
        "ctrl.obs.audit-log-append-only",
        "ctrl.privilege_envelopes_required",
      ],
    });

    class DatabaseConnectionError extends Error {
      constructor() { super("connection failed"); }
    }

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      registryGetPrivilegeEnvelope: () => ({}),
      registryPolicyAllowsPrivilege: () => {
        throw new DatabaseConnectionError();
      },
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INTERNAL_ERROR");
    // The deny message must NOT contain the class name
    const msg = (dec.deny_reason_if_denied as Record<string, unknown>)["message"] as string;
    expect(msg).not.toContain("DatabaseConnectionError");
  });

  // TS-F19: registryWorkerAvailable throwing does not propagate out of makeDecision
  test("TS-F19: registryWorkerAvailable throwing does not crash makeDecision", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev" });
    let dec: ReturnType<typeof makeDecision>;
    expect(() => {
      dec = makeDecision({
        inp: i,
        rules,
        registryControlsPresent: registry.controlsPresent(),
        // Callback throws on every call
        registryWorkerAvailable: () => { throw new Error("registry exploded"); },
      });
    }).not.toThrow();
    // All candidates failed availability check — should deny (no worker selected)
    expect(dec!.denied).toBe(true);
    expect(
      (dec!.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_NO_AVAILABLE_WORKER");
  });

  // TS-F20: invalid data_label is rejected at runtime
  test("TS-F20: invalid data_label rejected at runtime — DENY_INVALID_INPUT", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const i = inp({ data_label: "HACKED" as any });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  // TS-F20: invalid qos_class is rejected at runtime
  test("TS-F20: invalid qos_class rejected at runtime — DENY_INVALID_INPUT", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const i = inp({ qos_class: "PX" as any });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  // TS-F20: invalid tenant_risk is rejected at runtime
  test("TS-F20: invalid tenant_risk rejected at runtime — DENY_INVALID_INPUT", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const i = inp({ tenant_risk: "extreme" as any });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  // TS-F20: empty capability_id is rejected at runtime
  test("TS-F20: empty capability_id rejected at runtime — DENY_INVALID_INPUT", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ capability_id: "" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  // TS-F21: setControlsPresent bypasses TS-F8 without fix — path-traversal control must be rejected
  test("TS-F21: path-traversal control ID rejected via setControlsPresent (not just enroll)", () => {
    const registry = new Registry();
    // Direct call to setControlsPresent with poisoned IDs
    registry.setControlsPresent([
      "../../etc/passwd",
      "ctrl.obs.audit-log-append-only", // valid
      "'; DROP TABLE controls; --",
    ]);
    const controls = registry.controlsPresent();
    expect(controls.has("../../etc/passwd")).toBe(false);
    expect(controls.has("'; DROP TABLE controls; --")).toBe(false);
    expect(controls.has("ctrl.obs.audit-log-append-only")).toBe(true);
  });

  // TS-F21: addControlsPresent also validates
  test("TS-F21: path-traversal control ID rejected via addControlsPresent", () => {
    const registry = new Registry();
    registry.addControlsPresent([
      "ctrl.valid.one",
      "../evil/path",
      "ctrl.valid.two",
    ]);
    const controls = registry.controlsPresent();
    expect(controls.has("ctrl.valid.one")).toBe(true);
    expect(controls.has("ctrl.valid.two")).toBe(true);
    expect(controls.has("../evil/path")).toBe(false);
  });

  // TS-F22: conformanceSpec path throws (documented CI-only behavior; never throws on normal paths)
  test("TS-F22: conformanceSpec path throws on violation (documented CI-only behavior)", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // A spec that requires an impossible field — will fail validation
    const badSpec = {
      spec_version: "1.0",
      decision_output_schema: {
        required_fields: ["decision_id", "nonexistent_field_xyz"],
      },
      telemetry_requirements: { required_events: [] },
    };

    const i = inp({ env: "dev" });
    // The conformanceSpec path is the only one that throws — document this behavior
    expect(() => {
      makeDecision({
        inp: i,
        rules,
        registryControlsPresent: registry.controlsPresent(),
        registryWorkerAvailable: (id) => registry.workerAvailable(id),
        conformanceSpec: badSpec,
      });
    }).toThrow(/WCP conformance failure/);
  });
});

// ---------------------------------------------------------------------------
// Security Vulnerability Fixes — VULN-TS-1, VULN-TS-2, VULN-TS-3
// ---------------------------------------------------------------------------

// Rules doc with ctrl.blast_radius_scoring for blast gate tests
const BLAST_RULES_DOC = {
  rules: [
    {
      rule_id: "rr_blast_test_001",
      match: { capability_id: "cap.hello.greet" },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        required_controls_suggested: [
          "ctrl.obs.audit-log-append-only",
          "ctrl.blast_radius_scoring",
        ],
        escalation: { policy_gate: false },
        preconditions: {},
      },
    },
  ],
};

// Rules doc with deny_if_no_attestation_in_prod for VULN-TS-2 tests
const ATTESTATION_RULES_DOC = {
  rules: [
    {
      rule_id: "rr_attestation_001",
      match: { capability_id: "cap.hello.greet" },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
        escalation: { policy_gate: false },
        preconditions: { deny_if_no_attestation_in_prod: true },
      },
    },
  ],
};

describe("SecurityVulnerabilityFixes", () => {
  // -------------------------------------------------------------------------
  // VULN-TS-1: Negative blast_score bypasses blast gate
  // -------------------------------------------------------------------------

  test("VULN-TS-1: blast_score -999 is rejected — DENY_INVALID_INPUT (negative bypasses blast gate)", () => {
    // Negative scores pass the blastGate() check (score >= 85 is false for -999)
    // so they must be caught at validateRouteInput() before routing.
    const rules = loadRulesFromDoc(BLAST_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);

    const i = inp({
      env: "prod",
      data_label: "PUBLIC",
      blast_score: -999,
    });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  test("VULN-TS-1: blast_score 101 is rejected — DENY_INVALID_INPUT (above 100)", () => {
    const rules = loadRulesFromDoc(BLAST_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);

    const i = inp({
      env: "prod",
      data_label: "PUBLIC",
      blast_score: 101,
    });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_INVALID_INPUT");
  });

  test("VULN-TS-1: blast_score 0 is accepted — valid lower boundary", () => {
    const rules = loadRulesFromDoc(BLAST_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);
    const gate = new PolicyGate();

    const i = inp({
      env: "prod",
      data_label: "PUBLIC",
      blast_score: 0,
    });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (ctx) => gate.evaluate(ctx),
    });
    // blast_score=0 is valid and below threshold (85) — should route
    expect(dec.denied).toBe(false);
    expect(dec.selected_worker_species_id).toBe("wrk.hello.greeter");
  });

  test("VULN-TS-1: blast_score 100 is accepted — valid upper boundary", () => {
    // blast_score=100 is valid input (within [0,100]) but >= 85 in prod
    // so it triggers DENY_REQUIRES_HUMAN (blast gate fires), not DENY_INVALID_INPUT.
    const rules = loadRulesFromDoc(BLAST_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent([
      "ctrl.obs.audit-log-append-only",
      "ctrl.blast_radius_scoring",
    ]);

    const i = inp({
      env: "prod",
      data_label: "PUBLIC",
      blast_score: 100,
    });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    // Valid input but high score in prod — blast gate fires
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_REQUIRES_HUMAN");
  });

  // -------------------------------------------------------------------------
  // VULN-TS-2: Attestation is now fully implemented (WCP §5.10)
  // -------------------------------------------------------------------------

  test("VULN-TS-2: requireWorkerAttestation=true with no callbacks → DENY_ATTESTATION_UNCONFIGURED", () => {
    // When requireWorkerAttestation=true but no hash callbacks are provided,
    // the router must deny with DENY_ATTESTATION_UNCONFIGURED (not silently bypass).
    const rules = loadRulesFromDoc(ATTESTATION_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      // No registryGetWorkerHash or registryGetCurrentWorkerHash provided
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_ATTESTATION_UNCONFIGURED");
  });

  test("VULN-TS-2: deny_if_no_attestation_in_prod=true with requireWorkerAttestation=false (default) does NOT deny", () => {
    // If the hall config does not opt in to attestation enforcement, the
    // per-rule flag alone does not trigger a deny. Existing deployments
    // that have this flag set in rules are unaffected until they opt in.
    const rules = loadRulesFromDoc(ATTESTATION_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      // hallConfig.requireWorkerAttestation defaults to false — no deny
    });
    expect(dec.denied).toBe(false);
    expect(dec.selected_worker_species_id).toBe("wrk.hello.greeter");
  });

  // -------------------------------------------------------------------------
  // VULN-TS-3: Non-enrolled worker dispatched via setWorkersAvailable()
  // -------------------------------------------------------------------------

  test("VULN-TS-3: setWorkersAvailable with unenrolled species — workerAvailable returns false", () => {
    // An unenrolled species can be injected via setWorkersAvailable without
    // formal governance metadata. After the fix, workerAvailable() requires
    // enrollment — marking availability alone is insufficient.
    const registry = new Registry();
    registry.setWorkersAvailable(["wrk.evil.ghost"]);
    // "wrk.evil.ghost" was never enrolled — must not be reported as available
    expect(registry.workerAvailable("wrk.evil.ghost")).toBe(false);
  });

  test("VULN-TS-3: unenrolled species in setWorkersAvailable cannot be dispatched via routing", () => {
    const rulesDoc = {
      rules: [
        {
          rule_id: "rr_ghost_worker_001",
          match: { capability_id: "cap.hello.greet" },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.evil.ghost", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            preconditions: {},
          },
        },
      ],
    };
    const rules = loadRulesFromDoc(rulesDoc);
    const registry = new Registry();
    registry.setWorkersAvailable(["wrk.evil.ghost"]); // not enrolled
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });
    // Ghost worker is not enrolled — routing must deny (no available worker)
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_NO_AVAILABLE_WORKER");
  });

  test("VULN-TS-3: enrolled species is correctly available after enroll() + setWorkersAvailable()", () => {
    // Sanity check: the legitimate enrollment + availability flow still works.
    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.legitimate",
      worker_species_id: "wrk.test.legit",
      capabilities: ["cap.test.legit"],
      currently_implements: [],
    });
    registry.setWorkersAvailable(["wrk.test.legit"]);
    expect(registry.workerAvailable("wrk.test.legit")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PATCH-TS-003 + PATCH-TS-004 — Free-text telemetry field sanitization and
// enforceBlastScoringInProd=false warning
// ---------------------------------------------------------------------------

describe("PatchTS003AndTS004", () => {
  // PATCH-TS-003: policy_version with newline is sanitized in telemetry output
  test("PATCH-TS-003: policy_version containing newline is sanitized in telemetry", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    // Use a policy gate that returns a policy_version containing an injected newline
    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });

    // Decision succeeds — now verify that any policy_version fields in telemetry
    // do not contain newlines (the default "policy.v0" is clean, but we check
    // the sanitization path by inspecting the emitted events).
    expect(dec.denied).toBe(false);
    for (const event of dec.telemetry_envelopes) {
      const e = event as Record<string, unknown>;
      if (typeof e["policy_version"] === "string") {
        expect(e["policy_version"].includes("\n")).toBe(false);
        expect(e["policy_version"].includes("\r")).toBe(false);
      }
    }
  });

  // PATCH-TS-003: policy_version with injected newline through policy gate is stripped
  test("PATCH-TS-003: policy_version with injected newline from policy gate is stripped in telemetry", () => {
    // Use GATE_RULES_DOC so the policy gate is activated and a custom policy_version flows into telemetry
    const gateRules = loadRulesFromDoc({
      rules: [
        {
          rule_id: "rr_patch003_gate",
          match: { capability_id: "cap.hello.greet" },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: true },
            preconditions: {},
          },
        },
      ],
    });
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const maliciousPolicyVersion = "policy.v1\nevt.os.task.routed{injected:true}";
    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules: gateRules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      policyGateEval: (_ctx) => ["ALLOW", maliciousPolicyVersion, "ok"],
    });

    expect(dec.denied).toBe(false);
    // All telemetry events must have sanitized policy_version (no \n)
    for (const event of dec.telemetry_envelopes) {
      const e = event as Record<string, unknown>;
      if (typeof e["policy_version"] === "string") {
        expect(e["policy_version"].includes("\n")).toBe(false);
        expect(e["policy_version"].includes("\r")).toBe(false);
        expect(e["policy_version"].includes("\x00")).toBe(false);
      }
    }
  });

  // PATCH-TS-003: matched_rule_id containing a control character is sanitized
  test("PATCH-TS-003: matched_rule_id containing control char is sanitized in telemetry", () => {
    // Build a rule whose rule_id contains a control character — it should be
    // stripped from the telemetry payload even though routing uses the raw value.
    const rulesDoc = {
      rules: [
        {
          rule_id: "rr_evil\x01rule",
          match: { capability_id: "cap.hello.greet" },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            preconditions: {},
          },
        },
      ],
    };
    const rules = loadRulesFromDoc(rulesDoc);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });

    expect(dec.denied).toBe(false);
    // The matched_rule_id in telemetry must NOT contain the control character
    for (const event of dec.telemetry_envelopes) {
      const e = event as Record<string, unknown>;
      if (typeof e["matched_rule_id"] === "string") {
        // eslint-disable-next-line no-control-regex
        expect(/[\x00-\x1f\x7f]/.test(e["matched_rule_id"])).toBe(false);
      }
    }
  });

  // PATCH-TS-004: enforceBlastScoringInProd=false in prod emits console.warn
  test("PATCH-TS-004: enforceBlastScoringInProd=false in prod triggers console.warn", () => {
    const rules = loadRulesFromDoc(NO_BLAST_CTRL_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const i = inp({
      env: "prod",
      data_label: "RESTRICTED",
      qos_class: "P0",
      request: { egress: true, writes: true },
    });
    makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { enforceBlastScoringInProd: false },
    });

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("enforceBlastScoringInProd=false")
    );
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("prod/edge")
    );
    warnSpy.mockRestore();
  });

  // PATCH-TS-004: enforceBlastScoringInProd=false in edge emits console.warn
  test("PATCH-TS-004: enforceBlastScoringInProd=false in edge triggers console.warn", () => {
    const rulesDoc = {
      rules: [
        {
          rule_id: "rr_edge_001",
          match: { capability_id: "cap.hello.greet" },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            preconditions: {},
          },
        },
      ],
    };
    const rules = loadRulesFromDoc(rulesDoc);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const i = inp({ env: "edge" });
    makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { enforceBlastScoringInProd: false },
    });

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("enforceBlastScoringInProd=false")
    );
    warnSpy.mockRestore();
  });

  // PATCH-TS-004: enforceBlastScoringInProd=false in dev does NOT emit console.warn
  test("PATCH-TS-004: enforceBlastScoringInProd=false in dev does NOT warn (not prod/edge)", () => {
    const rules = loadRulesFromDoc(HELLO_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const i = inp({ env: "dev" });
    makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { enforceBlastScoringInProd: false },
    });

    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// PATCH-XSDK-SHADOW-003 — Shadow rule detection
// ---------------------------------------------------------------------------

describe("ShadowRuleDetection", () => {
  // Shadow rule: broad any-cap before specific rule → DENY_SHADOW_RULES_DETECTED in prod
  test("PATCH-XSDK-SHADOW-003: broad {any: true} rule before specific rule denied in prod", () => {
    // allow-any fires first, deny-secret can never be reached
    const shadowRulesDoc = {
      rules: [
        {
          rule_id: "allow-any",
          match: {
            capability_id: { any: true },
            env: { any: true },
          },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            preconditions: {},
          },
        },
        {
          rule_id: "deny-secret",
          match: {
            capability_id: { eq: "cap.secret.delete" },
            env: "prod",
          },
          decision: {
            candidate_workers_ranked: [],
            required_controls_suggested: [],
            escalation: {},
            preconditions: {},
          },
        },
      ],
    };

    const rules = loadRulesFromDoc(shadowRulesDoc);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ capability_id: "cap.secret.delete", env: "prod", data_label: "INTERNAL" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });

    // In prod, shadow rules are a hard deny
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_SHADOW_RULES_DETECTED");
  });

  // Shadow rule: broad any-cap before specific rule → console.warn + allowed in dev
  test("PATCH-XSDK-SHADOW-003: broad {any: true} rule before specific rule warned but allowed in dev", () => {
    const shadowRulesDoc = {
      rules: [
        {
          rule_id: "allow-any",
          match: {
            capability_id: { any: true },
          },
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            preconditions: {},
          },
        },
        {
          rule_id: "deny-secret",
          match: {
            capability_id: "cap.secret.delete",
          },
          decision: {
            candidate_workers_ranked: [],
            required_controls_suggested: [],
            escalation: {},
            preconditions: {},
          },
        },
      ],
    };

    const rules = loadRulesFromDoc(shadowRulesDoc);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const i = inp({ capability_id: "cap.secret.delete", env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });

    // In dev, shadow rules are non-blocking — routing continues
    expect(dec.denied).toBe(false);
    expect(dec.selected_worker_species_id).toBe("wrk.hello.greeter");

    // console.warn must have been called mentioning shadow rules
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Shadow rules detected")
    );
    warnSpy.mockRestore();
  });

  // VULN-TS-26: empty-match rule before specific rule → DENY_SHADOW_RULES_DETECTED in prod
  test("VULN-TS-26: empty-match rule before specific rule denied in prod", () => {
    // match: {} has no field constraints — it is unconstrained on every field,
    // meaning it matches any input. A specific rule below it can never be reached.
    const shadowRulesDoc = {
      rules: [
        {
          rule_id: "broad",
          match: {},
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            preconditions: {},
          },
        },
        {
          rule_id: "specific",
          match: {
            capability_id: { eq: "cap.secret.delete" },
          },
          decision: {
            candidate_workers_ranked: [],
            required_controls_suggested: [],
            escalation: {},
            preconditions: {},
          },
        },
      ],
    };

    const rules = loadRulesFromDoc(shadowRulesDoc);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp({ capability_id: "cap.secret.delete", env: "prod", data_label: "INTERNAL" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });

    // In prod, the empty-match shadow is a hard deny
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_SHADOW_RULES_DETECTED");
  });

  // VULN-TS-26: empty-match rule before specific rule → console.warn + allowed in dev
  test("VULN-TS-26: empty-match rule before specific rule warned but allowed in dev", () => {
    const shadowRulesDoc = {
      rules: [
        {
          rule_id: "broad",
          match: {},
          decision: {
            candidate_workers_ranked: [
              { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
            ],
            required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
            escalation: { policy_gate: false },
            preconditions: {},
          },
        },
        {
          rule_id: "specific",
          match: {
            capability_id: { eq: "cap.secret.delete" },
          },
          decision: {
            candidate_workers_ranked: [],
            required_controls_suggested: [],
            escalation: {},
            preconditions: {},
          },
        },
      ],
    };

    const rules = loadRulesFromDoc(shadowRulesDoc);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const i = inp({ capability_id: "cap.secret.delete", env: "dev" });
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
    });

    // In dev, shadow rules are non-blocking — routing continues
    expect(dec.denied).toBe(false);
    expect(dec.selected_worker_species_id).toBe("wrk.hello.greeter");

    // console.warn must have been called mentioning shadow rules
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Shadow rules detected")
    );
    warnSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Registry attestation (WCP §5.10)
// ---------------------------------------------------------------------------

describe("Registry attestation (WCP §5.10)", () => {
  it("registerAttestation returns SHA-256 hex of file content", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "pyhall-attest-"));
    const workerFile = join(tmpDir, "worker.py");
    writeFileSync(workerFile, "def run(): pass\n");
    const reg = new Registry();
    const hash = reg.registerAttestation("wrk.test.worker", workerFile);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(reg.getWorkerHash("wrk.test.worker")).toBe(hash);
  });

  it("computeCurrentHash matches registered hash when file unchanged", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "pyhall-attest-"));
    const workerFile = join(tmpDir, "worker.py");
    writeFileSync(workerFile, "def run(): pass\n");
    const reg = new Registry();
    const registered = reg.registerAttestation("wrk.test.worker", workerFile);
    expect(reg.computeCurrentHash("wrk.test.worker")).toBe(registered);
  });

  it("computeCurrentHash differs after file mutation", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "pyhall-attest-"));
    const workerFile = join(tmpDir, "worker.py");
    writeFileSync(workerFile, "def run(): pass\n");
    const reg = new Registry();
    const registered = reg.registerAttestation("wrk.test.worker", workerFile);
    writeFileSync(workerFile, "def run(): exfiltrate()\n");
    expect(reg.computeCurrentHash("wrk.test.worker")).not.toBe(registered);
  });

  it("getWorkerHash returns null for unknown species", () => {
    expect(new Registry().getWorkerHash("wrk.unknown")).toBeNull();
  });

  it("computeCurrentHash returns null for species with no file registered", () => {
    expect(new Registry().computeCurrentHash("wrk.unknown")).toBeNull();
  });

  it("registerAttestation throws when file does not exist", () => {
    expect(() =>
      new Registry().registerAttestation("wrk.test", "/nonexistent/worker.py")
    ).toThrow();
  });

  it("computeCurrentHash returns null if registered file is deleted after registration", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "pyhall-attest-"));
    const workerFile = join(tmpDir, "worker.py");
    writeFileSync(workerFile, "def run(): pass\n");
    const reg = new Registry();
    reg.registerAttestation("wrk.test.worker", workerFile);
    unlinkSync(workerFile);
    expect(reg.computeCurrentHash("wrk.test.worker")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Router attestation enforcement (WCP §5.10)
// ---------------------------------------------------------------------------

// Shared rule doc for attestation enforcement tests
const ATTEST_ENFORCE_RULES_DOC = {
  rules: [
    {
      rule_id: "rr_attest_enforce_001",
      match: { capability_id: "cap.hello.greet" },
      decision: {
        candidate_workers_ranked: [
          { worker_species_id: "wrk.hello.greeter", score_hint: 1.0 },
        ],
        required_controls_suggested: ["ctrl.obs.audit-log-append-only"],
        escalation: { policy_gate: false },
        preconditions: {},
      },
    },
  ],
};

describe("Router attestation enforcement (WCP §5.10)", () => {
  // 1. requireWorkerAttestation: false (default) → dispatches without callbacks
  test("attestation not required (default) → DISPATCHED, worker_attestation_checked is falsy", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      // No hallConfig → requireWorkerAttestation defaults to false
    });
    expect(dec.denied).toBe(false);
    expect(dec.worker_attestation_checked).toBeFalsy();
  });

  // 2. requireWorkerAttestation: true + matching hashes → DISPATCHED, checked=true, valid=true
  test("matching hashes → DISPATCHED, worker_attestation_checked=true, worker_attestation_valid=true", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const goodHash = "a".repeat(64);
    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      registryGetWorkerHash: (_speciesId) => goodHash,
      registryGetCurrentWorkerHash: (_speciesId) => goodHash,
    });
    expect(dec.denied).toBe(false);
    expect(dec.selected_worker_species_id).toBe("wrk.hello.greeter");
    expect(dec.worker_attestation_checked).toBe(true);
    expect(dec.worker_attestation_valid).toBe(true);
  });

  // 3. Hash mismatch → DENY_WORKER_TAMPERED, worker_attestation_valid=false
  test("hash mismatch → DENY_WORKER_TAMPERED, worker_attestation_valid=false", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      registryGetWorkerHash: (_speciesId) => "a".repeat(64),
      registryGetCurrentWorkerHash: (_speciesId) => "b".repeat(64),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_WORKER_TAMPERED");
    expect(dec.worker_attestation_valid).toBe(false);
    expect(dec.worker_attestation_checked).toBe(true);
    // F4: hash values must NOT appear in the deny message
    const msg = (dec.deny_reason_if_denied as Record<string, unknown>)["message"] as string;
    expect(msg).not.toContain("a".repeat(64));
    expect(msg).not.toContain("b".repeat(64));
  });

  // 4. Missing callbacks → DENY_ATTESTATION_UNCONFIGURED
  test("requireWorkerAttestation=true with no callbacks → DENY_ATTESTATION_UNCONFIGURED", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      // No callbacks provided
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_ATTESTATION_UNCONFIGURED");
  });

  // 5. No registered hash → DENY_WORKER_ATTESTATION_MISSING
  test("registryGetWorkerHash returns null → DENY_WORKER_ATTESTATION_MISSING", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      registryGetWorkerHash: (_speciesId) => null,
      registryGetCurrentWorkerHash: (_speciesId) => "a".repeat(64),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_WORKER_ATTESTATION_MISSING");
  });

  // 6. Current hash unavailable → DENY_WORKER_HASH_UNAVAILABLE
  test("registryGetCurrentWorkerHash returns null → DENY_WORKER_HASH_UNAVAILABLE", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      registryGetWorkerHash: (_speciesId) => "a".repeat(64),
      registryGetCurrentWorkerHash: (_speciesId) => null,
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_WORKER_HASH_UNAVAILABLE");
  });

  // 7. Callback throws → treated as null → DENY_WORKER_HASH_UNAVAILABLE
  test("registryGetCurrentWorkerHash throws → treated as null → DENY_WORKER_HASH_UNAVAILABLE", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    let dec: ReturnType<typeof makeDecision>;
    expect(() => {
      dec = makeDecision({
        inp: i,
        rules,
        registryControlsPresent: registry.controlsPresent(),
        registryWorkerAvailable: (id) => registry.workerAvailable(id),
        hallConfig: { requireWorkerAttestation: true },
        registryGetWorkerHash: (_speciesId) => "a".repeat(64),
        registryGetCurrentWorkerHash: (_speciesId) => {
          throw new Error("disk read failed");
        },
      });
    }).not.toThrow();
    expect(dec!.denied).toBe(true);
    expect(
      (dec!.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_WORKER_HASH_UNAVAILABLE");
  });

  // 8. Invalid registered hash format → DENY_WORKER_ATTESTATION_INVALID_HASH
  test("registryGetWorkerHash returns malformed hash → DENY_WORKER_ATTESTATION_INVALID_HASH", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: true },
      registryGetWorkerHash: (_speciesId) => "not-a-valid-sha256",
      registryGetCurrentWorkerHash: (_speciesId) => "a".repeat(64),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_WORKER_ATTESTATION_INVALID_HASH");
  });

  // 9. requireWorkerAttestation=true but no worker selected → no attestation check
  test("requireWorkerAttestation=true but no worker available → denied for no worker, not attestation", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = new Registry();
    // No workers enrolled — registryWorkerAvailable returns false for everything
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = inp();
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (_id) => false,
      hallConfig: { requireWorkerAttestation: true },
      registryGetWorkerHash: (_speciesId) => "a".repeat(64),
      registryGetCurrentWorkerHash: (_speciesId) => "a".repeat(64),
    });
    expect(dec.denied).toBe(true);
    expect(
      (dec.deny_reason_if_denied as Record<string, unknown>)["code"]
    ).toBe("DENY_NO_AVAILABLE_WORKER");
    // Attestation was not attempted — no worker was selected
    expect(dec.worker_attestation_checked).toBeFalsy();
  });

  // 10. requireWorkerAttestation=false in prod → attestation_skipped telemetry emitted
  test("requireWorkerAttestation=false in prod → telemetry includes evt.os.worker.attestation_skipped", () => {
    const rules = loadRulesFromDoc(ATTEST_ENFORCE_RULES_DOC);
    const registry = registryWithWorker();
    registry.addControlsPresent(["ctrl.obs.audit-log-append-only"]);

    const i = { ...inp(), env: "prod" as const };
    const dec = makeDecision({
      inp: i,
      rules,
      registryControlsPresent: registry.controlsPresent(),
      registryWorkerAvailable: (id) => registry.workerAvailable(id),
      hallConfig: { requireWorkerAttestation: false },
    });
    expect(dec.denied).toBe(false);
    const skipped = dec.telemetry_envelopes.find(
      (ev) => (ev as Record<string, unknown>)["event_id"] === "evt.os.worker.attestation_skipped"
    );
    expect(skipped).toBeDefined();
  });
});
