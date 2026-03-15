/**
 * src/policyGate.ts — WCP Policy Gate (stub implementation).
 *
 * The PolicyGate evaluates whether a capability request is permitted under
 * the active policy, and whether escalation or human review is required.
 *
 * This stub allows by default. Replace evaluate() with your own policy engine
 * to implement real governance rules.
 *
 * WCP compliance:
 *   - WCP-Basic: not required
 *   - WCP-Standard: must support evaluate() with ALLOW/DENY/REQUIRE_HUMAN
 *   - WCP-Full: policy_gate must integrate with privilege envelopes and
 *               blast radius gating
 *
 * Mirrors pyhall/policy_gate.py exactly.
 */

export type PolicyDecision = "ALLOW" | "DENY" | "REQUIRE_HUMAN";

/** [decision, policyVersion, reason] */
export type PolicyGateResult = [PolicyDecision, string, string];

export interface PolicyGateContext {
  capability_id: string;
  tenant_id: string;
  env: string;
  data_label: string;
  tenant_risk: string;
  qos_class: string;
  policy_version: string;
  [key: string]: unknown;
}

/** Function signature for the policy gate evaluator. */
export type PolicyGateEvaluator = (
  context: PolicyGateContext
) => PolicyGateResult;

/**
 * WCP Policy Gate.
 *
 * Evaluates a capability request context and returns a
 * [decision, policy_version, reason] triple.
 *
 * Extend this class and override evaluate() to implement real governance:
 *
 *   class MyPolicyGate extends PolicyGate {
 *     evaluate(context: PolicyGateContext): PolicyGateResult {
 *       if (context.env === "prod" && context.data_label === "RESTRICTED") {
 *         return ["REQUIRE_HUMAN", "policy.v1", "restricted_data_in_prod"];
 *       }
 *       return ["ALLOW", "policy.v1", "default_allow"];
 *     }
 *   }
 */
export class PolicyGate {
  /**
   * Evaluate a routing context against the active policy.
   *
   * @param context - Routing context fields.
   * @returns [decision, policyVersion, reason]
   */
  evaluate(context: PolicyGateContext): PolicyGateResult {
    // Default stub: allow everything. Replace with real policy logic.
    const policyVersion = context.policy_version ?? "policy.v0";
    return ["ALLOW", policyVersion, "stub_allow"];
  }
}
