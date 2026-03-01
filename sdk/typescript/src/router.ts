/**
 * src/router.ts — WCP core routing engine.
 *
 * makeDecision() is the single entry point. It takes a RouteInput and
 * returns a RouteDecision. It never throws — all failures are expressed
 * as denied decisions.
 *
 * Exception: the conformanceSpec code path intentionally throws — it is designed
 * for CI/testing environments only. Do not provide conformanceSpec in production
 * code. All other error conditions return a denied RouteDecision.
 *
 * Routing pipeline (WCP-Full):
 *   1. Input validation (TS-F9, TS-F20)
 *   2. HallConfig signatory check (TS-F14)
 *   3. Null-rule filter (TS-F12)
 *   4. Match first routing rule (fail-closed if no match)
 *   5. Verify preconditions (correlation_id, etc.) with hall-level floors (TS-F5, TS-F15)
 *   6. Verify required controls against registry
 *   7. Blast radius scoring and gating (TS-F13: hall floor enforces in prod regardless of rule)
 *   8. Policy gate evaluation (if escalation.policy_gate is true) (TS-F1, TS-F4, TS-F10)
 *   9. Select first available worker candidate (TS-F19: try/catch; TS-F17: accurate skip_reason)
 *  10. Privilege envelope enforcement (TS-F2, TS-F18: no class-name leak)
 *  11. Emit mandatory telemetry with log-safe IDs (TS-F16: control character stripping)
 *  12. Dry_run marker propagation (TS-F11)
 *  13. Optional conformance check (CI/test mode only)
 *  14. Return RouteDecision
 *
 * Mirrors pyhall/router.py exactly (with Round 3 + Round 4 security fixes applied).
 */

import type {
  RouteInput,
  RouteDecision,
  CandidateWorker,
  Escalation,
  PreconditionsChecked,
  HallConfig,
} from "./models.js";
import { routeFirstMatch, type Rule } from "./rules.js";
import {
  osTaskRouted,
  osWorkerSelected,
  osPolicyGated,
  govBlastScored,
  govPrivilegeEnvelopeChecked,
  osTaskDenied,
} from "./telemetry.js";
import { uuidV4, nowUtc } from "./common.js";
import {
  validateRequiredFields,
  validateRequiredTelemetry,
  type ConformanceSpec,
} from "./conformance.js";
import type { PrivilegeEnvelope } from "./models.js";
import type { PolicyGateEvaluator, PolicyGateContext } from "./policyGate.js";

const DEFAULT_POLICY_VERSION = "policy.v0";

// ---------------------------------------------------------------------------
// Blast radius scoring helpers
// ---------------------------------------------------------------------------

/**
 * Heuristic blast radius scorer.
 * Computes a 0–100 score based on RouteInput fields. Higher = more dangerous.
 * Mirrors _compute_blast_score() in router.py.
 */
function computeBlastScore(inp: RouteInput): number {
  let score = 10; // baseline
  if (inp.data_label === "INTERNAL") score += 20;
  else if (inp.data_label === "RESTRICTED") score += 40;
  if (inp.env === "prod" || inp.env === "edge") score += 15;
  if (inp.qos_class === "P0") score += 10;
  const req = (inp.request ?? {}) as Record<string, unknown>;
  if (req["egress"] || req["external_call"]) score += 15;
  if (req["writes"] || req["mutates_state"]) score += 15;
  return Math.min(100, score);
}

/**
 * Gate a blast score.
 * Returns [allowed, reason].
 * Denies scores >= 85 in prod/edge — requires human review.
 */
function blastGate(score: number, inp: RouteInput): [boolean, string] {
  if ((inp.env === "prod" || inp.env === "edge") && score >= 85) {
    return [false, "REQUIRE_HUMAN_HIGH_BLAST"];
  }
  return [true, "blast_ok"];
}

// ---------------------------------------------------------------------------
// Precondition helpers
// ---------------------------------------------------------------------------

function ensureCorrelationId(inp: RouteInput): boolean {
  return Boolean(inp.correlation_id && inp.correlation_id.trim());
}

// ---------------------------------------------------------------------------
// TS-F9: Runtime input validation
// ---------------------------------------------------------------------------

const VALID_ENVS = ["dev", "stage", "prod", "edge"] as const;
// TS-F20: Runtime enum validation for fields that affect routing and telemetry.
// TypeScript union types are compile-time only — a JS caller can pass arbitrary strings.
const VALID_DATA_LABELS = ["PUBLIC", "INTERNAL", "RESTRICTED"] as const;
const VALID_TENANT_RISKS = ["low", "medium", "high"] as const;
const VALID_QOS_CLASSES = ["P0", "P1", "P2", "P3"] as const;

/**
 * Validate that RouteInput has the expected types and values.
 * Returns an error message string if invalid, or null if valid.
 * This guards against runtime type coercion attacks (e.g. passing null for env)
 * and enum injection (e.g. data_label="HACKED") — TS-F9, TS-F20.
 */
function validateRouteInput(inp: RouteInput): string | null {
  const requiredStrings: Array<keyof RouteInput> = [
    "capability_id",
    "env",
    "data_label",
    "tenant_risk",
    "qos_class",
    "tenant_id",
    "correlation_id",
  ];
  // Fields where empty-string is checked at a later, dedicated stage (correlation_id
  // is handled by ensureCorrelationId after rule matching, producing a more specific
  // deny code DENY_MISSING_CORRELATION_ID).
  const skipEmptyCheck = new Set<string>(["correlation_id"]);

  const inpAsAny = inp as unknown as Record<string, unknown>;
  for (const field of requiredStrings) {
    const val = inpAsAny[field];
    if (val === null || val === undefined) {
      return `required field '${field}' is null or undefined`;
    }
    if (typeof val !== "string") {
      return `required field '${field}' must be a string, got ${typeof val}`;
    }
    if (!skipEmptyCheck.has(field) && (val as string).length === 0) {
      return `required field '${field}' must not be empty`;
    }
  }
  if (!(VALID_ENVS as readonly string[]).includes(inp.env)) {
    return `env must be one of ${VALID_ENVS.join("|")}, got '${inp.env}'`;
  }
  // TS-F20: Validate remaining enum fields at runtime
  if (!(VALID_DATA_LABELS as readonly string[]).includes(inp.data_label)) {
    return `data_label must be one of ${VALID_DATA_LABELS.join("|")}, got '${inp.data_label}'`;
  }
  if (!(VALID_TENANT_RISKS as readonly string[]).includes(inp.tenant_risk)) {
    return `tenant_risk must be one of ${VALID_TENANT_RISKS.join("|")}, got '${inp.tenant_risk}'`;
  }
  if (!(VALID_QOS_CLASSES as readonly string[]).includes(inp.qos_class)) {
    return `qos_class must be one of ${VALID_QOS_CLASSES.join("|")}, got '${inp.qos_class}'`;
  }
  // VULN-TS-1: blast_score range validation — must be in [0, 100] if provided.
  // Negative values bypass the blast gate (score < 85 is allowed), so an invalid
  // score must be rejected here, before any routing continues.
  if (inp.blast_score !== null && inp.blast_score !== undefined) {
    if (typeof inp.blast_score !== "number" || !Number.isFinite(inp.blast_score)) {
      return `blast_score must be a finite number in [0, 100], got ${JSON.stringify(inp.blast_score)}`;
    }
    if (inp.blast_score < 0 || inp.blast_score > 100) {
      return `blast_score must be in [0, 100], got ${inp.blast_score}`;
    }
  }
  return null; // valid
}

// ---------------------------------------------------------------------------
// PATCH-XSDK-SHADOW-003: Shadow rule detection
// ---------------------------------------------------------------------------

/** A warning emitted when one rule's broad match hides a narrower rule below it. */
export interface ShadowWarning {
  shadowingRuleId: string;
  shadowedRuleId: string;
  field: string;
}

/**
 * Return true if condA semantically covers (matches a superset of) condB.
 *
 * - undefined (absent)   → unconstrained, equivalent to {any: true} — covers anything
 * - {any: true}          → explicit wildcard — covers anything
 * - {in: [...]}          → covers only the values in the list
 * - "exact_value"        → covers only that exact value
 *
 * Mirrors Python's _condition_covers().
 */
function conditionCovers(condA: unknown, condB: unknown): boolean {
  // Absent or {any: true} on A → A covers everything for this field
  if (condA === undefined || condA === null) return true;
  if (
    typeof condA === "object" &&
    (condA as Record<string, unknown>)["any"] === true
  ) return true;

  // If B is also unconstrained/wildcard, A covers it regardless of what A is
  if (condB === undefined || condB === null) return true;
  if (
    typeof condB === "object" &&
    (condB as Record<string, unknown>)["any"] === true
  ) return true;

  // A is {in: [...]} — covers B if B is an exact string in A's list, or B is
  // a subset {in: [...]} of A's list
  if (typeof condA === "object" && Array.isArray((condA as Record<string, unknown>)["in"])) {
    const listA = (condA as Record<string, unknown>)["in"] as unknown[];
    if (typeof condB === "string") return listA.includes(condB);
    if (typeof condB === "object" && Array.isArray((condB as Record<string, unknown>)["in"])) {
      const listB = (condB as Record<string, unknown>)["in"] as unknown[];
      return listB.every((v) => listA.includes(v));
    }
    if (typeof condB === "object" && typeof (condB as Record<string, unknown>)["eq"] === "string") {
      return listA.includes((condB as Record<string, unknown>)["eq"]);
    }
    return false;
  }

  // A is {eq: "value"} — covers B only if B is the same exact value
  if (typeof condA === "object" && typeof (condA as Record<string, unknown>)["eq"] === "string") {
    const valA = (condA as Record<string, unknown>)["eq"] as string;
    if (typeof condB === "string") return valA === condB;
    if (typeof condB === "object" && (condB as Record<string, unknown>)["eq"] === valA) return true;
    return false;
  }

  // A is an exact string — covers B only if B is the identical string or {eq: same}
  if (typeof condA === "string") {
    if (typeof condB === "string") return condA === condB;
    if (typeof condB === "object" && (condB as Record<string, unknown>)["eq"] === condA) return true;
    return false;
  }

  return false;
}

/**
 * Return true if ruleA (early) semantically shadows ruleB (late).
 *
 * ruleA shadows ruleB when every input that matches ruleB also matches ruleA
 * — i.e., ruleA's match conditions are at least as broad as ruleB's on every
 * field that ruleB constrains. ruleB can therefore never be reached first.
 *
 * For each field that ruleB constrains: ruleA must cover it (be at least as
 * broad). If ruleA has a specific constraint on a field that ruleB leaves
 * unconstrained, ruleA is MORE restrictive on that field — it does NOT shadow.
 *
 * VULN-TS-26: Absent field constraint on ruleA = wildcard = covers everything.
 * Mirrors Python's _rule_semantically_shadows().
 */
function ruleSemanticallyshadows(
  matchA: Record<string, unknown>,
  matchB: Record<string, unknown>,
): boolean {
  // Identical match conditions = duplicate (handled separately)
  if (JSON.stringify(matchA) === JSON.stringify(matchB)) return false;

  const MATCH_FIELDS = ["capability_id", "env", "data_label", "tenant_risk", "qos_class"] as const;

  for (const field of MATCH_FIELDS) {
    const condA = matchA[field];
    const condB = matchB[field];

    if (condB === undefined) {
      // ruleB is unconstrained on this field — it matches any value here.
      // If ruleA has a specific (non-wildcard) constraint, ruleA is more
      // restrictive than ruleB on this field → ruleA cannot shadow ruleB.
      const aIsWildcard =
        condA === undefined ||
        (typeof condA === "object" &&
          condA !== null &&
          (condA as Record<string, unknown>)["any"] === true);
      if (!aIsWildcard) return false;
      // else: both sides unconstrained — OK, continue checking other fields
    } else {
      // ruleB has a constraint — ruleA must cover it to be at least as broad
      if (!conditionCovers(condA, condB)) return false;
    }
  }

  return true;
}

/**
 * Detect shadow rules in a rule list.
 *
 * A rule A (at index i) shadows rule B (at index j > i) when A's match
 * conditions are semantically a superset of B's — every input that matches B
 * also matches A, so B can never be reached first.
 *
 * This check is holistic (per rule pair, not per field):
 *   - absent field constraint on ruleA = wildcard = covers any value (VULN-TS-26)
 *   - {any: true} = explicit wildcard — covers any value
 *   - ruleA with match: {} has no constraints — it matches every input
 *
 * Mirrors Python's detect_shadow_rules() / _rule_semantically_shadows().
 *
 * Returns an array of ShadowWarning objects (empty when no shadows found).
 * The `field` property reports the first field on which the shadow is evident,
 * or "*" when ruleA is entirely unconstrained (match: {}).
 */
export function detectShadowRules(rules: Rule[]): ShadowWarning[] {
  const warnings: ShadowWarning[] = [];
  const MATCH_FIELDS = ["capability_id", "env", "data_label", "tenant_risk", "qos_class"] as const;

  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      const ruleA = rules[i];
      const ruleB = rules[j];
      const matchA = ruleA.match ?? {};
      const matchB = ruleB.match ?? {};

      if (!ruleSemanticallyshadows(matchA, matchB)) continue;

      // Report shadow: find the first field where ruleB has a constraint and
      // ruleA is absent/wildcard (makes the shadow visible). Fall back to "*"
      // when ruleA is completely unconstrained (match: {}).
      let reportField = "*";
      for (const field of MATCH_FIELDS) {
        if (matchB[field] !== undefined && matchA[field] === undefined) {
          reportField = field;
          break;
        }
        if (
          matchB[field] !== undefined &&
          typeof matchA[field] === "object" &&
          matchA[field] !== null &&
          (matchA[field] as Record<string, unknown>)["any"] === true
        ) {
          reportField = field;
          break;
        }
      }

      warnings.push({
        shadowingRuleId: ruleA.rule_id,
        shadowedRuleId: ruleB.rule_id,
        field: reportField,
      });
    }
  }

  return warnings;
}

// ---------------------------------------------------------------------------
// Default values
// ---------------------------------------------------------------------------

const DEFAULT_PRECONDITIONS: Required<PreconditionsChecked> = {
  must_have_correlation_id: true,
  must_attach_policy_version: true,
  must_record_artifact_hash_if_executes: true,
  deny_if_missing_required_controls: true,
  deny_if_unsigned_artifact_in_prod: false,
  deny_if_no_attestation_in_prod: false,
};

const DEFAULT_ESCALATION: Required<Escalation> = {
  policy_gate: false,
  msavx_step_up: false,
  human_required_default: false,
  human_required_if: [],
  rationale: null,
};

function buildPreconditions(raw: Record<string, unknown>): PreconditionsChecked {
  const result: PreconditionsChecked = {};
  for (const k of Object.keys(DEFAULT_PRECONDITIONS) as Array<keyof PreconditionsChecked>) {
    (result as Record<string, unknown>)[k] =
      k in raw ? raw[k] : DEFAULT_PRECONDITIONS[k];
  }
  return result;
}

function buildEscalation(raw: Record<string, unknown>): Escalation {
  return {
    policy_gate: (raw["policy_gate"] as boolean) ?? DEFAULT_ESCALATION.policy_gate,
    msavx_step_up: (raw["msavx_step_up"] as boolean) ?? DEFAULT_ESCALATION.msavx_step_up,
    human_required_default:
      (raw["human_required_default"] as boolean) ?? DEFAULT_ESCALATION.human_required_default,
    human_required_if:
      (raw["human_required_if"] as Record<string, unknown>[]) ??
      DEFAULT_ESCALATION.human_required_if,
    rationale: (raw["rationale"] as string | null) ?? null,
  };
}

// ---------------------------------------------------------------------------
// TS-F6: Deny helper — always emits osTaskDenied telemetry
// ---------------------------------------------------------------------------

function deny(
  inp: RouteInput,
  matchedRuleId: string,
  code: string,
  message: string,
  preChecked?: PreconditionsChecked,
  requiredControls?: string[],
  escalation?: Escalation,
  extra?: Record<string, unknown>,
): RouteDecision {
  const reason: Record<string, unknown> = { code, message, ...(extra ?? {}) };
  // TS-F6: Every deny path emits at least one telemetry event (evt.os.task.denied)
  const telemetry: Record<string, unknown>[] = [
    osTaskDenied(inp.correlation_id, inp.tenant_id, inp.capability_id, code),
  ];
  return {
    decision_id: uuidV4(),
    timestamp: nowUtc(),
    correlation_id: inp.correlation_id,
    tenant_id: inp.tenant_id,
    capability_id: inp.capability_id,
    matched_rule_id: matchedRuleId,
    env: inp.env,
    data_label: inp.data_label,
    tenant_risk: inp.tenant_risk,
    qos_class: inp.qos_class,
    denied: true,
    deny_reason_if_denied: reason,
    selected_worker_species_id: null,
    candidate_workers_ranked: [],
    required_controls_effective: requiredControls ? [...requiredControls].sort() : [],
    recommended_profiles_effective: [],
    escalation_effective: escalation ?? DEFAULT_ESCALATION,
    preconditions_checked: preChecked ?? { ...DEFAULT_PRECONDITIONS },
    dry_run: inp.dry_run ?? false,
    telemetry_envelopes: telemetry,
  };
}

// ---------------------------------------------------------------------------
// makeDecision — the Hall's core dispatch function
// ---------------------------------------------------------------------------

export interface MakeDecisionOptions {
  inp: RouteInput;
  rules: Rule[];
  registryControlsPresent: Set<string>;
  registryWorkerAvailable: (speciesId: string) => boolean;
  registryGetPrivilegeEnvelope?: (speciesId: string) => PrivilegeEnvelope | undefined;
  registryPolicyAllowsPrivilege?: (
    env: string,
    dataLabel: string,
    envelope: PrivilegeEnvelope | undefined
  ) => [boolean, string];
  policyGateEval?: PolicyGateEvaluator | null;
  conformanceSpec?: ConformanceSpec | null;
  taskId?: string;
  /** TS-F5: Hall-level governance floors applied to all decisions. */
  hallConfig?: HallConfig;
  /** Callback to get the registered code hash for a worker species. Required when hallConfig.requireWorkerAttestation is true. */
  registryGetWorkerHash?: ((speciesId: string) => string | null) | null;
  /** Callback to compute the current on-disk code hash for a worker species. Required when hallConfig.requireWorkerAttestation is true. */
  registryGetCurrentWorkerHash?: ((speciesId: string) => string | null) | null;
}

/**
 * Make a WCP routing decision.
 *
 * This is the Hall's core function. Call it with a RouteInput and the
 * active rules + registry state to get a RouteDecision.
 *
 * Never throws for normal routing operations — all failures are expressed as
 * denied RouteDecisions.
 *
 * @throws {Error} ONLY when conformanceSpec is provided and the decision fails
 *   validation. The conformanceSpec path is intentionally assertion-style for
 *   CI/testing environments. Do not provide conformanceSpec in production code.
 *   All other error conditions return a denied RouteDecision without throwing.
 */
export function makeDecision(opts: MakeDecisionOptions): RouteDecision {
  const {
    inp,
    registryControlsPresent,
    registryWorkerAvailable,
    registryGetPrivilegeEnvelope,
    registryPolicyAllowsPrivilege,
    policyGateEval,
    conformanceSpec,
    taskId = "task_default",
    hallConfig,
    registryGetWorkerHash,
    registryGetCurrentWorkerHash,
  } = opts;

  // TS-F5: Extract hall-level floors (defaults: enforceCorrelationId=true, enforceRequiredControls=true)
  const hallEnforceCorrelationId = hallConfig?.enforceCorrelationId !== false;
  const hallEnforcePrivilege = hallConfig?.enforcePrivilegeEnvelopes === true;
  // TS-F13: Hall floor — enforce blast scoring in prod/edge regardless of rule controls.
  // A rule omitting ctrl.blast_radius_scoring cannot bypass the blast gate in prod.
  const hallEnforceBlastInProd = hallConfig?.enforceBlastScoringInProd !== false;
  // PATCH-TS-004: Warn when blast scoring floor is disabled in prod/edge.
  // Silently disabling this guardrail in production is unsafe — emit a visible warning.
  if ((inp.env === "prod" || inp.env === "edge") && hallConfig?.enforceBlastScoringInProd === false) {
    console.warn(
      "[pyhall] WARNING: enforceBlastScoringInProd=false in prod/edge environment. " +
      "Blast scoring floor is disabled. This is unsafe for production use."
    );
  }
  // TS-F15: Hall floor — enforce required controls check regardless of per-rule flag.
  const hallEnforceRequiredControls = hallConfig?.enforceRequiredControls !== false;

  // -------------------------------------------------------------------------
  // TS-F9, TS-F20: Input validation — before any processing
  // -------------------------------------------------------------------------
  const validationError = validateRouteInput(inp);
  if (validationError) {
    return deny(inp, "NO_MATCH", "DENY_INVALID_INPUT", validationError);
  }

  // -------------------------------------------------------------------------
  // TS-F14: Signatory enforcement — deny tenants not in the allowedTenants list.
  // requireSignatory was previously declared in HallConfig but never enforced.
  // -------------------------------------------------------------------------
  if (hallConfig?.requireSignatory === true) {
    const allowed = hallConfig.allowedTenants ?? [];
    if (!allowed.includes(inp.tenant_id)) {
      return deny(
        inp,
        "NO_MATCH",
        "DENY_UNKNOWN_TENANT",
        `tenant '${inp.tenant_id}' is not in the Hall's allowedTenants list.`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // TS-F12: Null rule filter — guard against null/undefined entries in rules array
  // -------------------------------------------------------------------------
  const safeRules = (opts.rules ?? []).filter((r): r is Rule => r != null);

  // -------------------------------------------------------------------------
  // Step 0.5: PATCH-XSDK-SHADOW-003 — Shadow rule detection
  // Detect rules that are unreachable because a broader rule appears before
  // them in the list. In prod/edge this is a hard deny to prevent silent
  // misrouting. In dev/stage it is a logged warning only (non-blocking).
  // -------------------------------------------------------------------------
  const shadowWarnings = detectShadowRules(safeRules);
  if (shadowWarnings.length > 0) {
    const pairsMsg = shadowWarnings
      .map((w) => `rule '${w.shadowingRuleId}' shadows '${w.shadowedRuleId}' on field '${w.field}'`)
      .join("; ");

    if (inp.env === "prod" || inp.env === "edge") {
      return deny(
        inp,
        "NO_MATCH",
        "DENY_SHADOW_RULES_DETECTED",
        `Shadow rules detected — misconfigured rule set. ${pairsMsg}`,
        undefined,
        undefined,
        undefined,
        { shadow_warnings: shadowWarnings },
      );
    } else {
      console.warn(
        `[pyhall] WARNING: Shadow rules detected in '${inp.env}' environment. ` +
        `Fix before promoting to prod. ${pairsMsg}`
      );
    }
  }

  // -------------------------------------------------------------------------
  // Step 1: Rule matching (fail-closed)
  // -------------------------------------------------------------------------
  const inpDict = inp as unknown as Record<string, unknown>;
  const matched = routeFirstMatch(safeRules, inpDict);

  if (matched === null) {
    return {
      decision_id: uuidV4(),
      timestamp: nowUtc(),
      correlation_id: inp.correlation_id,
      tenant_id: inp.tenant_id,
      capability_id: inp.capability_id,
      matched_rule_id: "NO_MATCH",
      env: inp.env,
      data_label: inp.data_label,
      tenant_risk: inp.tenant_risk,
      qos_class: inp.qos_class,
      denied: true,
      deny_reason_if_denied: {
        code: "DENY_NO_MATCHING_RULE",
        message: "No routing rule matched. Fail-closed per WCP spec section 5.1.",
      },
      candidate_workers_ranked: [],
      required_controls_effective: [],
      recommended_profiles_effective: [],
      escalation_effective: { ...DEFAULT_ESCALATION },
      preconditions_checked: { ...DEFAULT_PRECONDITIONS },
      dry_run: inp.dry_run ?? false,
      telemetry_envelopes: [
        osTaskDenied(inp.correlation_id, inp.tenant_id, inp.capability_id, "DENY_NO_MATCHING_RULE"),
      ],
    };
  }

  const d = matched.decision ?? {};
  const candidates = (d["candidate_workers_ranked"] as Array<Record<string, unknown>>) ?? [];
  const requiredControlsSet = new Set<string>(
    (d["required_controls_suggested"] as string[]) ?? []
  );
  const escalationRaw = (d["escalation"] as Record<string, unknown>) ?? {};
  const preRaw = (d["preconditions"] as Record<string, unknown>) ?? {};

  // -------------------------------------------------------------------------
  // Step 2: Preconditions — with TS-F5 hall-level floor
  // -------------------------------------------------------------------------
  const preChecked = buildPreconditions(preRaw);

  // TS-F5: Hall floor: enforce correlation_id if hallConfig says to (default true),
  // regardless of per-rule precondition setting.
  if ((preChecked.must_have_correlation_id || hallEnforceCorrelationId) && !ensureCorrelationId(inp)) {
    return deny(
      inp,
      matched.rule_id,
      "DENY_MISSING_CORRELATION_ID",
      "correlation_id is required but absent or empty.",
      preChecked,
      [...requiredControlsSet],
    );
  }

  // Attestation state — populated in the attestation block below (after worker selection)
  // These are declared here so they are in scope when the final RouteDecision is assembled.
  let workerAttestationChecked = false;
  let workerAttestationValid: boolean | null = null;

  // -------------------------------------------------------------------------
  // Step 3: Controls check
  // TS-F15: Apply hall floor — hallEnforceRequiredControls=true (default) overrides
  // any per-rule setting of deny_if_missing_required_controls=false.
  // -------------------------------------------------------------------------
  const missingControls = [...requiredControlsSet]
    .filter((c) => !registryControlsPresent.has(c))
    .sort();

  if ((preChecked.deny_if_missing_required_controls || hallEnforceRequiredControls) && missingControls.length > 0) {
    return deny(
      inp,
      matched.rule_id,
      "DENY_MISSING_REQUIRED_CONTROLS",
      "Required controls not present in registry.",
      preChecked,
      [...requiredControlsSet],
      undefined,
      { missing: missingControls },
    );
  }

  // -------------------------------------------------------------------------
  // Step 4: Blast radius gating (WCP-Full)
  // TS-F3: Guard against NaN blast_score bypassing the gate.
  // TS-F13: Hall floor — enforceBlastScoringInProd=true (default) applies blast gating
  // in prod/edge even when the matched rule omits ctrl.blast_radius_scoring.
  // A rule author cannot opt out of blast scoring in production environments.
  // -------------------------------------------------------------------------
  const shouldRunBlastGate =
    requiredControlsSet.has("ctrl.blast_radius_scoring") ||
    ((inp.env === "prod" || inp.env === "edge") && hallEnforceBlastInProd);

  if (shouldRunBlastGate) {
    // TS-F3: Only use pre-computed score if it is a finite number (not NaN/Infinity)
    const score =
      inp.blast_score != null && Number.isFinite(inp.blast_score)
        ? inp.blast_score
        : computeBlastScore(inp);
    const [blastOk, blastReason] = blastGate(score, inp);
    if (!blastOk) {
      return {
        decision_id: uuidV4(),
        timestamp: nowUtc(),
        correlation_id: inp.correlation_id,
        tenant_id: inp.tenant_id,
        capability_id: inp.capability_id,
        matched_rule_id: matched.rule_id,
        env: inp.env,
        data_label: inp.data_label,
        tenant_risk: inp.tenant_risk,
        qos_class: inp.qos_class,
        denied: true,
        deny_reason_if_denied: {
          code: "DENY_REQUIRES_HUMAN",
          message: "Blast radius too high for autonomous execution.",
          blast_score: score,
          reason: blastReason,
        },
        candidate_workers_ranked: [],
        required_controls_effective: [...requiredControlsSet].sort(),
        recommended_profiles_effective: (d["recommended_profiles"] as Record<string, unknown>[]) ?? [],
        escalation_effective: {
          ...buildEscalation(escalationRaw),
          human_required_default: true,
          rationale: blastReason,
        },
        preconditions_checked: preChecked,
        dry_run: inp.dry_run ?? false,
        telemetry_envelopes: [
          osTaskDenied(inp.correlation_id, inp.tenant_id, inp.capability_id, "DENY_REQUIRES_HUMAN"),
        ],
      };
    }
  }

  // -------------------------------------------------------------------------
  // Step 5: Policy gate evaluation (WCP-Full)
  // TS-F1: Handle REQUIRE_HUMAN as a deny (not silently passing)
  // TS-F4: Return deny on missing policyGateEval (instead of throwing)
  // TS-F4: Wrap policyGateEval call in try/catch
  // TS-F10: Strict allowlist — any non-ALLOW/DENY/REQUIRE_HUMAN response is denied
  // -------------------------------------------------------------------------
  let policyVersion = DEFAULT_POLICY_VERSION;
  const escalationObj = buildEscalation(escalationRaw);

  if (escalationObj.policy_gate) {
    // TS-F4: Return deny instead of throw when policyGateEval not provided
    if (!policyGateEval) {
      return deny(
        inp,
        matched.rule_id,
        "DENY_POLICY_GATE_UNCONFIGURED",
        "escalation.policy_gate=true but policyGateEval not provided",
        preChecked,
        [...requiredControlsSet],
      );
    }
    const gateContext: PolicyGateContext = {
      capability_id: inp.capability_id,
      tenant_id: inp.tenant_id,
      env: inp.env,
      data_label: inp.data_label,
      tenant_risk: inp.tenant_risk,
      qos_class: inp.qos_class,
      policy_version: DEFAULT_POLICY_VERSION,
    };

    let gateDecision: string;
    let gatePolicyVersion: string;
    let gateReason: string;

    // TS-F4: Wrap policyGateEval in try/catch — exceptions become deny decisions
    try {
      [gateDecision, gatePolicyVersion, gateReason] = policyGateEval(gateContext);
    } catch (_err) {
      return deny(
        inp,
        matched.rule_id,
        "DENY_INTERNAL_ERROR",
        "policyGateEval raised an exception. See server logs for details.",
        preChecked,
        [...requiredControlsSet],
      );
    }

    policyVersion = gatePolicyVersion;

    // TS-F1: Handle REQUIRE_HUMAN explicitly before DENY
    if (gateDecision === "REQUIRE_HUMAN") {
      return deny(
        inp,
        matched.rule_id,
        "DENY_REQUIRES_HUMAN_APPROVAL",
        `policy gate requires human approval: ${gateReason}`,
        preChecked,
        [...requiredControlsSet],
      );
    }

    if (gateDecision === "DENY") {
      return {
        decision_id: uuidV4(),
        timestamp: nowUtc(),
        correlation_id: inp.correlation_id,
        tenant_id: inp.tenant_id,
        capability_id: inp.capability_id,
        matched_rule_id: matched.rule_id,
        env: inp.env,
        data_label: inp.data_label,
        tenant_risk: inp.tenant_risk,
        qos_class: inp.qos_class,
        denied: true,
        deny_reason_if_denied: {
          code: "DENY_POLICY_GATE",
          message: "Policy gate denied.",
          reason: gateReason,
          policy_version: policyVersion,
        },
        candidate_workers_ranked: [],
        required_controls_effective: [...requiredControlsSet].sort(),
        recommended_profiles_effective: [],
        escalation_effective: { ...escalationObj, rationale: gateReason },
        preconditions_checked: preChecked,
        dry_run: inp.dry_run ?? false,
        telemetry_envelopes: [
          osTaskDenied(inp.correlation_id, inp.tenant_id, inp.capability_id, "DENY_POLICY_GATE"),
        ],
      };
    }

    // TS-F10: Strict allowlist — reject any response that isn't ALLOW
    if (gateDecision !== "ALLOW") {
      return deny(
        inp,
        matched.rule_id,
        "DENY_POLICY_GATE_INVALID_RESPONSE",
        `policy gate returned unrecognized response: ${JSON.stringify(gateDecision)}`,
        preChecked,
        [...requiredControlsSet],
      );
    }
  }

  // -------------------------------------------------------------------------
  // Step 6: Select first available worker candidate
  // TS-F19: registryWorkerAvailable wrapped in try/catch — a throwing callback must
  // not propagate out of makeDecision (never-throws contract).
  // TS-F17: accurate skip_reason — distinguish "unavailable" from "already_selected".
  // -------------------------------------------------------------------------
  const candModels: CandidateWorker[] = [];
  let selected: string | null = null;

  for (const c of candidates) {
    const wid = c["worker_species_id"] as string | undefined;
    const cm: CandidateWorker = {
      worker_species_id: wid ?? "__missing__",
      score_hint: (c["score_hint"] as number) ?? null,
    };
    if (selected === null && wid) {
      let isAvailable = false;
      try {
        isAvailable = registryWorkerAvailable(wid);
      } catch (_err) {
        // TS-F19: callback threw — treat as unavailable, do not propagate
        cm.skip_reason = "availability_check_failed";
        candModels.push(cm);
        continue;
      }
      if (isAvailable) {
        selected = wid;
        // No skip_reason set — this candidate was selected
      } else {
        // TS-F17: worker is genuinely unavailable (not available in registry)
        cm.skip_reason = "unavailable";
      }
    } else if (!wid) {
      cm.skip_reason = "missing_id";
    } else {
      // TS-F17: worker was available but an earlier candidate was already selected
      cm.skip_reason = "already_selected";
    }
    candModels.push(cm);
  }

  if (selected === null) {
    return {
      decision_id: uuidV4(),
      timestamp: nowUtc(),
      correlation_id: inp.correlation_id,
      tenant_id: inp.tenant_id,
      capability_id: inp.capability_id,
      matched_rule_id: matched.rule_id,
      env: inp.env,
      data_label: inp.data_label,
      tenant_risk: inp.tenant_risk,
      qos_class: inp.qos_class,
      denied: true,
      deny_reason_if_denied: {
        code: "DENY_NO_AVAILABLE_WORKER",
        message: "No available worker candidates. Route to review queue.",
      },
      candidate_workers_ranked: candModels,
      required_controls_effective: [...requiredControlsSet].sort(),
      recommended_profiles_effective: (d["recommended_profiles"] as Record<string, unknown>[]) ?? [],
      escalation_effective: escalationObj,
      preconditions_checked: preChecked,
      dry_run: inp.dry_run ?? false,
      telemetry_envelopes: [
        osTaskDenied(inp.correlation_id, inp.tenant_id, inp.capability_id, "DENY_NO_AVAILABLE_WORKER"),
      ],
    };
  }

  // -------------------------------------------------------------------------
  // Step 6.5: Worker Code Attestation (WCP §5.10)
  // Mirrors Python router.py lines 583-683 exactly.
  // Gate: only runs when hallConfig.requireWorkerAttestation=true AND selected is not null.
  // -------------------------------------------------------------------------
  const VALID_HASH = /^[0-9a-f]{64}$/;

  if (hallConfig?.requireWorkerAttestation === true && selected !== null) {
    workerAttestationChecked = true;

    // Missing callbacks → deny (F2: missing callables are a deny, not a skip)
    if (!registryGetWorkerHash || !registryGetCurrentWorkerHash) {
      return deny(
        inp,
        matched.rule_id,
        "DENY_ATTESTATION_UNCONFIGURED",
        "requireWorkerAttestation is true but hash callables were not provided. " +
          "Pass registryGetWorkerHash and registryGetCurrentWorkerHash to makeDecision().",
        preChecked,
        [...requiredControlsSet],
        escalationObj,
      );
    }

    // F11: Wrap hash callables — exceptions become hash-unavailable denials
    let registeredHash: string | null;
    let currentHash: string | null;
    try {
      registeredHash = registryGetWorkerHash(selected);
    } catch (_err) {
      registeredHash = null;
    }
    try {
      currentHash = registryGetCurrentWorkerHash(selected);
    } catch (_err) {
      currentHash = null;
    }

    // No registered hash → deny
    if (registeredHash === null) {
      return deny(
        inp,
        matched.rule_id,
        "DENY_WORKER_ATTESTATION_MISSING",
        `Worker '${selected}' has no registered code hash. ` +
          "Register the worker with an attestation hash before enabling requireWorkerAttestation.",
        preChecked,
        [...requiredControlsSet],
        escalationObj,
      );
    }

    // F5: Validate registered hash format — must be SHA-256 (64 lowercase hex chars)
    if (!VALID_HASH.test(registeredHash)) {
      return deny(
        inp,
        matched.rule_id,
        "DENY_WORKER_ATTESTATION_INVALID_HASH",
        `Worker '${selected}' registered hash is not a valid SHA-256 digest. ` +
          "Re-register with a 64-character lowercase hex SHA-256 hash.",
        preChecked,
        [...requiredControlsSet],
        escalationObj,
      );
    }

    // Current hash unavailable or malformed → deny
    if (currentHash === null || !VALID_HASH.test(currentHash)) {
      return deny(
        inp,
        matched.rule_id,
        "DENY_WORKER_HASH_UNAVAILABLE",
        `Worker '${selected}' current code hash could not be retrieved or is invalid. ` +
          "Verify the registryGetCurrentWorkerHash implementation.",
        preChecked,
        [...requiredControlsSet],
        escalationObj,
      );
    }

    // Hash mismatch → TAMPERED
    // F4: Do NOT include hash values in the deny message — returning registered_hash
    // tells the attacker their target.
    if (currentHash !== registeredHash) {
      workerAttestationValid = false;
      return {
        decision_id: uuidV4(),
        timestamp: nowUtc(),
        correlation_id: inp.correlation_id,
        tenant_id: inp.tenant_id,
        capability_id: inp.capability_id,
        matched_rule_id: matched.rule_id,
        env: inp.env,
        data_label: inp.data_label,
        tenant_risk: inp.tenant_risk,
        qos_class: inp.qos_class,
        denied: true,
        deny_reason_if_denied: {
          code: "DENY_WORKER_TAMPERED",
          message:
            `Worker '${selected}' code hash mismatch. ` +
            "Worker may have been modified after attestation. " +
            "Re-attest the worker or investigate for tampering.",
          worker_species_id: selected,
        },
        selected_worker_species_id: null,
        candidate_workers_ranked: candModels,
        required_controls_effective: [...requiredControlsSet].sort(),
        recommended_profiles_effective: (d["recommended_profiles"] as Record<string, unknown>[]) ?? [],
        escalation_effective: escalationObj,
        preconditions_checked: preChecked,
        dry_run: inp.dry_run ?? false,
        worker_attestation_checked: true,
        worker_attestation_valid: false,
        telemetry_envelopes: [
          osTaskDenied(inp.correlation_id, inp.tenant_id, inp.capability_id, "DENY_WORKER_TAMPERED"),
        ],
      };
    }

    // Hash matched — attestation valid
    workerAttestationValid = true;
  }

  // -------------------------------------------------------------------------
  // TS-F2: Privilege envelope enforcement — actually call the callables
  // -------------------------------------------------------------------------
  if (requiredControlsSet.has("ctrl.privilege_envelopes_required") || hallEnforcePrivilege) {
    if (!registryGetPrivilegeEnvelope || !registryPolicyAllowsPrivilege) {
      return deny(
        inp,
        matched.rule_id,
        "DENY_PRIVILEGE_ENVELOPE_UNCONFIGURED",
        "ctrl.privilege_envelopes_required declared but privilege envelope callables not provided",
        preChecked,
        [...requiredControlsSet],
      );
    }
    let envelope: PrivilegeEnvelope | undefined;
    let privAllowed: boolean;
    let privReason: string;
    try {
      envelope = registryGetPrivilegeEnvelope(selected);
      [privAllowed, privReason] = registryPolicyAllowsPrivilege(inp.env, inp.data_label, envelope);
    } catch (_err) {
      // TS-F18: Do not leak internal class names via err.constructor.name.
      // Exception details are for server logs only — caller receives only the deny code.
      return deny(
        inp,
        matched.rule_id,
        "DENY_INTERNAL_ERROR",
        "Privilege envelope check raised an exception. See server logs for details.",
        preChecked,
        [...requiredControlsSet],
      );
    }
    if (!privAllowed) {
      return deny(
        inp,
        matched.rule_id,
        "DENY_PRIVILEGE_ENVELOPE_VIOLATED",
        `privilege policy denied: ${privReason}`,
        preChecked,
        [...requiredControlsSet],
      );
    }
  }

  // -------------------------------------------------------------------------
  // Step 7: Build mandatory telemetry
  // -------------------------------------------------------------------------
  let telemetry: Record<string, unknown>[] = [];

  // Governance events (WCP-Full — emitted when blast gate ran, per TS-F13 logic)
  if (shouldRunBlastGate) {
    // TS-F3: Use same NaN guard for telemetry score computation
    const score =
      inp.blast_score != null && Number.isFinite(inp.blast_score)
        ? inp.blast_score
        : computeBlastScore(inp);
    telemetry.push(
      govBlastScored(
        inp.correlation_id,
        inp.tenant_id,
        inp.env,
        inp.data_label,
        policyVersion,
        score,
        "ALLOW"
      )
    );
  }

  if (requiredControlsSet.has("ctrl.privilege_envelopes_required") || hallEnforcePrivilege) {
    telemetry.push(
      govPrivilegeEnvelopeChecked(
        inp.correlation_id,
        inp.tenant_id,
        inp.env,
        inp.data_label,
        policyVersion,
        selected,
        "ALLOW"
      )
    );
  }

  // F24: Emit telemetry when attestation was not performed in prod/edge
  if (!workerAttestationChecked && (inp.env === "prod" || inp.env === "edge")) {
    telemetry.push({
      event_id: "evt.os.worker.attestation_skipped",
      correlation_id: inp.correlation_id,
      worker_species_id: selected,
      env: inp.env,
      reason: "requireWorkerAttestation=false or hallConfig=undefined",
      severity: "warn",
    });
  }

  // Mandatory WCP telemetry (required for WCP-Standard and above)
  telemetry.push(
    osTaskRouted(
      inp.correlation_id,
      inp.tenant_id,
      taskId,
      inp.capability_id,
      matched.rule_id,
      selected,
      policyVersion,
      inp.qos_class
    )
  );
  telemetry.push(
    osWorkerSelected(
      inp.correlation_id,
      inp.tenant_id,
      inp.capability_id,
      selected,
      "first_available_candidate"
    )
  );
  telemetry.push(
    osPolicyGated(
      inp.correlation_id,
      inp.tenant_id,
      inp.capability_id,
      "ALLOW",
      policyVersion,
      escalationObj.policy_gate ? "policy_gate_allow" : "no_gate_required"
    )
  );

  // TS-F11: Mark all telemetry events with dry_run=true when in dry-run mode
  if (inp.dry_run) {
    telemetry = telemetry.map((ev) => ({ ...ev, dry_run: true }));
  }

  // -------------------------------------------------------------------------
  // Step 8: Assemble decision
  // -------------------------------------------------------------------------
  const out: RouteDecision = {
    decision_id: uuidV4(),
    timestamp: nowUtc(),
    correlation_id: inp.correlation_id,
    tenant_id: inp.tenant_id,
    capability_id: inp.capability_id,
    matched_rule_id: matched.rule_id,
    env: inp.env,
    data_label: inp.data_label,
    tenant_risk: inp.tenant_risk,
    qos_class: inp.qos_class,
    selected_worker_species_id: selected,
    candidate_workers_ranked: candModels,
    required_controls_effective: [...requiredControlsSet].sort(),
    recommended_profiles_effective: (d["recommended_profiles"] as Record<string, unknown>[]) ?? [],
    escalation_effective: escalationObj,
    preconditions_checked: preChecked,
    denied: false,
    deny_reason_if_denied: null,
    // TS-F11: Propagate dry_run flag into the decision
    dry_run: inp.dry_run ?? false,
    worker_attestation_checked: workerAttestationChecked,
    worker_attestation_valid: workerAttestationValid,
    telemetry_envelopes: telemetry,
  };

  // -------------------------------------------------------------------------
  // Step 9: Optional conformance check (CI only)
  // -------------------------------------------------------------------------
  if (conformanceSpec != null) {
    const outDict = out as unknown as Record<string, unknown>;
    const missing = validateRequiredFields(outDict, conformanceSpec);
    const telErrors = validateRequiredTelemetry(telemetry, conformanceSpec);
    if (missing.length > 0 || telErrors.length > 0) {
      throw new Error(
        `WCP conformance failure. missing_fields=${JSON.stringify(missing)} ` +
          `telemetry_errors=${JSON.stringify(telErrors)}`
      );
    }
  }

  return out;
}
