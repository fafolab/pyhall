/**
 * src/rules.ts — WCP routing rules engine.
 *
 * Routing rules are declared in JSON. The router evaluates them top-to-bottom
 * and returns the first match (fail-closed on no match per WCP spec section 5.1).
 *
 * Mirrors pyhall/rules.py exactly.
 *
 * Rule JSON format:
 *   {
 *     "rules": [
 *       {
 *         "rule_id": "rr_example_001",
 *         "match": {
 *           "capability_id": "cap.doc.summarize",
 *           "env": {"in": ["dev", "stage"]},
 *           "data_label": "INTERNAL",
 *           "tenant_risk": "low",
 *           "qos_class": {"in": ["P1", "P2"]}
 *         },
 *         "decision": {
 *           "candidate_workers_ranked": [
 *             {"worker_species_id": "wrk.doc.summarizer", "score_hint": 1.0}
 *           ],
 *           "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
 *           "recommended_profiles": [],
 *           "escalation": {"policy_gate": false, "human_required_default": false},
 *           "preconditions": {}
 *         }
 *       }
 *     ]
 *   }
 *
 * Match fields support:
 *   - Exact match:       "data_label": "INTERNAL"
 *   - Membership match:  "env": {"in": ["dev", "stage"]}
 *   - Wildcard:          "capability_id": {"any": true}
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single WCP routing rule. */
export interface Rule {
  /** Unique rule identifier, e.g. 'rr_doc_summarize_dev_001'. */
  rule_id: string;

  /** Match conditions. Keys: capability_id, env, data_label, tenant_risk, qos_class. */
  match: Record<string, unknown>;

  /** Decision payload: candidate_workers_ranked, required_controls_suggested, etc. */
  decision: Record<string, unknown>;
}

/** Shape of a rules JSON document. */
export interface RulesDocument {
  rules: Array<{
    rule_id: string;
    match?: Record<string, unknown>;
    decision?: Record<string, unknown>;
  }>;
}

// ---------------------------------------------------------------------------
// Matching logic
// ---------------------------------------------------------------------------

type MatchCondition =
  | string
  | { in: string[] }
  | { any: true }
  | Record<string, unknown>;

/**
 * Evaluate a match condition against a value.
 *
 * Supports:
 *   - {"in": ["a", "b"]}  — membership test
 *   - {"any": true}       — wildcard (always matches)
 *   - "exact_value"       — equality
 */
export function matchMembership(cond: MatchCondition, value: unknown): boolean {
  if (typeof cond === "object" && cond !== null) {
    if ((cond as { any?: boolean }).any === true) {
      return true;
    }
    const inArr = (cond as { in?: string[] }).in;
    if (Array.isArray(inArr)) {
      return inArr.includes(value as string);
    }
  }
  return value === cond;
}

/**
 * Return true if a RouteInput (as plain object) matches the given rule.
 *
 * Evaluates all match conditions. All must pass for a match.
 * A missing condition key is treated as a wildcard (passes automatically).
 */
export function ruleMatches(rule: Rule, inp: Record<string, unknown>): boolean {
  const m = rule.match ?? {};

  const cap = m["capability_id"];
  if (cap !== undefined) {
    if (!matchMembership(cap as MatchCondition, inp["capability_id"])) {
      return false;
    }
  }

  for (const field of ["env", "data_label", "tenant_risk", "qos_class"] as const) {
    const cond = m[field];
    if (cond === undefined) continue;
    if (!matchMembership(cond as MatchCondition, inp[field])) {
      return false;
    }
  }

  return true;
}

/**
 * Return the first rule that matches inp, or null if no rule matches.
 *
 * Per WCP spec section 5.1 (Fail Closed): a null result MUST produce
 * a denied routing decision. The router handles this; callers must not
 * execute workers on a null return.
 */
export function routeFirstMatch(
  rules: Rule[],
  inp: Record<string, unknown>
): Rule | null {
  for (const rule of rules) {
    if (ruleMatches(rule, inp)) {
      return rule;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Rule loading
// ---------------------------------------------------------------------------

/**
 * Load routing rules from an already-parsed RulesDocument (useful for testing
 * and browser-side use where file I/O is unavailable).
 */
export function loadRulesFromDoc(doc: RulesDocument): Rule[] {
  return (doc.rules ?? []).map((r) => ({
    rule_id: r.rule_id,
    match: r.match ?? {},
    decision: r.decision ?? {},
  }));
}

/**
 * Load routing rules from a JSON string.
 *
 * Throws SyntaxError if the JSON is invalid.
 * Throws Error if the document is missing the "rules" key.
 */
export function loadRulesFromJson(json: string): Rule[] {
  const doc = JSON.parse(json) as RulesDocument;
  if (!Array.isArray(doc.rules)) {
    throw new Error('Rules JSON must have a top-level "rules" array.');
  }
  return loadRulesFromDoc(doc);
}
