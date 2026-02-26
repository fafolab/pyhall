package wcp

// PolicyGateResult holds the outcome of a policy gate evaluation.
type PolicyGateResult struct {
	// Passed is true when the policy gate allows dispatch.
	Passed bool

	// Reason explains why the gate passed or failed.
	Reason string

	// RequiresHumanReview is true when the policy mandates human approval
	// before dispatch may proceed.
	RequiresHumanReview bool

	// RequiresMSAVXStepUp is true when MSAVX step-up approval is required.
	RequiresMSAVXStepUp bool
}

// PolicyGate evaluates a routing context against configured policies.
//
// Implementations must be deterministic: identical inputs → identical outputs.
// The policy gate is evaluated after rule matching and blast radius scoring,
// before the worker is dispatched.
//
// WCP required behaviors (section 5):
//   - Fail closed: if evaluation fails or policy is missing, return Passed=false.
//   - Must support dry-run: evaluate fully even when DryRun=true, never dispatch.
//
// GO-F4 contract: When RequiresHumanReview is true, the router MUST NOT dispatch
// the worker regardless of the Passed field. RequiresHumanReview=true overrides
// Passed=true. Implementations that want to signal "human review needed" should
// set RequiresHumanReview=true; the router will convert this into
// DENY_REQUIRES_HUMAN_APPROVAL automatically.
type PolicyGate interface {
	// Evaluate runs all applicable policies against the RouteInput and the
	// matched rule's Escalation policy. Returns the gate result.
	//
	// TODO(impl): load pol.* policy objects from policy store, evaluate each,
	// aggregate results into PolicyGateResult.
	Evaluate(input RouteInput, escalation Escalation) PolicyGateResult
}

// PolicyRule is a single rule entry in a DefaultPolicyGate rule set.
// Rules are evaluated in order; the first matching rule determines the outcome.
type PolicyRule struct {
	// MatchEnv restricts the rule to a specific environment. Empty = all envs.
	MatchEnv Env

	// MatchDataLabel restricts the rule to a specific data label. Empty = all labels.
	MatchDataLabel DataLabel

	// MatchQoSClass restricts the rule to a specific QoS class. Empty = all classes.
	MatchQoSClass QoSClass

	// Passed is the policy decision when this rule matches.
	Passed bool

	// RequiresHumanReview forces human review when this rule matches.
	RequiresHumanReview bool

	// Reason is the human-readable reason for this rule's outcome.
	Reason string
}

// DefaultPolicyGate is the built-in policy gate implementation.
//
// VULN-GO-1 fix: the previous implementation returned Passed=true for all requests
// in prod/edge unless they were P0 (which got RequiresHumanReview). A governance gate
// that defaults to PASS for production restricted data is effectively no gate at all.
//
// New behavior:
//   - If Rules is empty and env is prod or edge: DENY with "no_policy_configured".
//     Operators MUST configure explicit policy rules before deploying to prod/edge.
//   - If Rules is empty and env is dev or stage: PASS (allows development without config).
//   - If Rules has entries: evaluate them in order; first matching rule wins.
//     P0 in prod/edge always gets RequiresHumanReview regardless of rule outcome.
//
// TODO(impl): Replace with a real policy engine that loads pol.* objects
// from the registry and evaluates them against the RouteInput.
type DefaultPolicyGate struct {
	// Rules is the ordered list of policy rules to evaluate.
	// If empty and env is prod/edge, the gate denies (fail-closed).
	// If empty and env is dev/stage, the gate passes (development convenience).
	Rules []PolicyRule
}

// Ensure DefaultPolicyGate satisfies the PolicyGate interface.
var _ PolicyGate = DefaultPolicyGate{}

// Evaluate runs policy evaluation.
//
// VULN-GO-1 fix: fails closed for prod/edge when no rules are configured.
// Only dev/stage environments pass through without explicit rules.
//
// GO-F4 note: when RequiresHumanReview=true is returned here, MakeDecision()
// converts the request into DENY_REQUIRES_HUMAN_APPROVAL regardless of Passed.
// The router enforces the contract — this gate does not need to set Passed=false
// when RequiresHumanReview=true; MakeDecision() handles it.
func (g DefaultPolicyGate) Evaluate(input RouteInput, escalation Escalation) PolicyGateResult {
	isProdOrEdge := input.Env == EnvProd || input.Env == EnvEdge

	// VULN-GO-1 fix: fail-closed for prod/edge when no rules are configured.
	// Without explicit policy rules, prod/edge traffic must be denied.
	// This forces operators to configure real gates before deploying.
	if len(g.Rules) == 0 {
		if isProdOrEdge {
			return PolicyGateResult{
				Passed: false,
				Reason: "no_policy_configured: DefaultPolicyGate has no rules; prod/edge requires explicit policy configuration",
			}
		}
		// dev/stage with no rules: pass through with human review for P0.
		requiresHuman := escalation.HumanRequiredDefault
		if input.QoSClass == QoSP0 {
			requiresHuman = true
		}
		return PolicyGateResult{
			Passed:              true,
			Reason:              "dev/stage: no policy rules configured; passing through",
			RequiresHumanReview: requiresHuman,
			RequiresMSAVXStepUp: escalation.MSAVXStepUp,
		}
	}

	// Evaluate rules in order; first matching rule wins.
	for _, rule := range g.Rules {
		if rule.MatchEnv != "" && rule.MatchEnv != input.Env {
			continue
		}
		if rule.MatchDataLabel != "" && rule.MatchDataLabel != input.DataLabel {
			continue
		}
		if rule.MatchQoSClass != "" && rule.MatchQoSClass != input.QoSClass {
			continue
		}
		// Rule matched.
		requiresHuman := rule.RequiresHumanReview || escalation.HumanRequiredDefault
		// Conservative: P0 in prod/edge always requires human review.
		if input.QoSClass == QoSP0 && isProdOrEdge {
			requiresHuman = true
		}
		return PolicyGateResult{
			Passed:              rule.Passed,
			Reason:              rule.Reason,
			RequiresHumanReview: requiresHuman,
			RequiresMSAVXStepUp: escalation.MSAVXStepUp,
		}
	}

	// No rule matched — fail-closed.
	return PolicyGateResult{
		Passed: false,
		Reason: "no_policy_matched: no configured rule matched this request",
	}
}
