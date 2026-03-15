/**
 * src/telemetry.ts — WCP telemetry envelope builders.
 *
 * Every WCP dispatch MUST emit three minimum telemetry events (spec section 5.4):
 *   - evt.os.task.routed
 *   - evt.os.worker.selected
 *   - evt.os.policy.gated
 *
 * The correlation_id MUST be propagated through all three events.
 *
 * Mirrors pyhall/telemetry.py exactly.
 */

import { nowUtc, uuidV4 } from "./common.js";

// ---------------------------------------------------------------------------
// TS-F16: Log injection sanitization
// ---------------------------------------------------------------------------

/**
 * Strip ASCII control characters (U+0000–U+001F and U+007F) from an ID string
 * before embedding it in telemetry payloads.
 *
 * JSON encoding escapes control characters, but line-based SIEM parsers and
 * log aggregators that process telemetry as plain text would interpret \n, \r,
 * and \0 as record boundaries — enabling injection of fake audit entries.
 *
 * Applied at all telemetry construction sites. The original values are
 * preserved in routing logic (only sanitized in emitted events).
 *
 * Defensively coerces to string — deny() may be called before full input
 * validation completes (e.g. for the DENY_INVALID_INPUT path where the raw
 * RouteInput field may not yet be a string).
 */
function sanitizeId(value: unknown): string {
  if (typeof value !== "string") {
    // Non-string value reached telemetry — coerce to empty to avoid TypeError
    return "";
  }
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1f\x7f]/g, "");
}

// ---------------------------------------------------------------------------
// ID helpers
// ---------------------------------------------------------------------------

export { nowUtc as nowIso } from "./common.js";
export { uuidV4 as newDecisionId } from "./common.js";

// ---------------------------------------------------------------------------
// Required telemetry events (WCP spec section 5.4)
// ---------------------------------------------------------------------------

/**
 * evt.os.task.routed — routing decision was made.
 * Required for all WCP-Standard and WCP-Full implementations.
 */
export function osTaskRouted(
  correlationId: string,
  tenantId: string,
  taskId: string,
  capabilityId: string,
  matchedRuleId: string,
  selectedWorkerSpeciesId: string | null | undefined,
  policyVersion: string | null | undefined,
  qosClass: string
): Record<string, unknown> {
  return {
    event_id: "evt.os.task.routed",
    timestamp: nowUtc(),
    correlation_id: sanitizeId(correlationId),          // TS-F16
    tenant_id: sanitizeId(tenantId),                    // TS-F16
    task_id: taskId,
    capability_id: sanitizeId(capabilityId),            // TS-F16
    matched_rule_id: sanitizeId(matchedRuleId),         // PATCH-TS-003
    selected_worker_species_id: selectedWorkerSpeciesId ?? null,
    policy_version: policyVersion != null ? sanitizeId(policyVersion) : null, // PATCH-TS-003
    qos_class: qosClass,
  };
}

/**
 * evt.os.worker.selected — worker species was selected.
 * Required for all WCP-Standard and WCP-Full implementations.
 */
export function osWorkerSelected(
  correlationId: string,
  tenantId: string,
  capabilityId: string,
  selectedWorkerSpeciesId: string | null | undefined,
  reason: string
): Record<string, unknown> {
  return {
    event_id: "evt.os.worker.selected",
    timestamp: nowUtc(),
    correlation_id: sanitizeId(correlationId),   // TS-F16
    tenant_id: sanitizeId(tenantId),              // TS-F16
    capability_id: sanitizeId(capabilityId),      // TS-F16
    selected_worker_species_id: selectedWorkerSpeciesId ?? null,
    reason,
  };
}

/**
 * evt.os.policy.gated — policy gate was evaluated.
 * Required for all WCP-Standard and WCP-Full implementations.
 */
export function osPolicyGated(
  correlationId: string,
  tenantId: string,
  capabilityId: string,
  decision: string,
  policyVersion: string | null | undefined,
  reason: string
): Record<string, unknown> {
  return {
    event_id: "evt.os.policy.gated",
    timestamp: nowUtc(),
    correlation_id: sanitizeId(correlationId),          // TS-F16
    tenant_id: sanitizeId(tenantId),                    // TS-F16
    capability_id: sanitizeId(capabilityId),            // TS-F16
    decision,
    policy_version: policyVersion != null ? sanitizeId(policyVersion) : null, // PATCH-TS-003
    reason,
  };
}

// ---------------------------------------------------------------------------
// Optional governance events (WCP-Full)
// ---------------------------------------------------------------------------

/** evt.gov.blast_scored — blast radius was computed and gated. */
export function govBlastScored(
  correlationId: string,
  tenantId: string,
  env: string,
  dataLabel: string,
  policyVersion: string,
  blastScore: number,
  decision: string
): Record<string, unknown> {
  return {
    event_id: "evt.gov.blast_scored",
    timestamp: nowUtc(),
    correlation_id: sanitizeId(correlationId),   // TS-F16
    tenant_id: sanitizeId(tenantId),             // TS-F16
    env,
    data_label: dataLabel,
    policy_version: sanitizeId(policyVersion),   // PATCH-TS-003
    blast_score: blastScore,
    decision,
  };
}

// ---------------------------------------------------------------------------
// TS-F6: Deny-path telemetry event (TS-F6 — all deny paths emit telemetry)
// ---------------------------------------------------------------------------

/**
 * evt.os.task.denied — routing decision was denied.
 * Emitted on every deny path so deny decisions are observable.
 */
export function osTaskDenied(
  correlationId: string,
  tenantId: string,
  capabilityId: string,
  denyCode: string,
): Record<string, unknown> {
  return {
    event_id: "evt.os.task.denied",
    timestamp: nowUtc(),
    correlation_id: sanitizeId(correlationId),   // TS-F16
    tenant_id: sanitizeId(tenantId),              // TS-F16
    capability_id: sanitizeId(capabilityId),      // TS-F16
    deny_code: denyCode,
  };
}

/** evt.gov.privilege_envelope.checked — privilege envelope was validated. */
export function govPrivilegeEnvelopeChecked(
  correlationId: string,
  tenantId: string,
  env: string,
  dataLabel: string,
  policyVersion: string,
  workerSpeciesId: string | null | undefined,
  decision: string
): Record<string, unknown> {
  return {
    event_id: "evt.gov.privilege_envelope.checked",
    timestamp: nowUtc(),
    correlation_id: sanitizeId(correlationId),   // TS-F16
    tenant_id: sanitizeId(tenantId),             // TS-F16
    env,
    data_label: dataLabel,
    policy_version: sanitizeId(policyVersion),   // PATCH-TS-003
    worker_species_id: workerSpeciesId ?? null,
    decision,
  };
}
