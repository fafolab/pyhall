/**
 * src/conformance.ts — WCP conformance validation.
 *
 * Validates routing decisions against a conformance spec. Use this in CI
 * to ensure that routing rules produce decisions that meet WCP requirements.
 *
 * Mirrors pyhall/conformance.py exactly.
 *
 * Conformance spec JSON format:
 *   {
 *     "spec_version": "1.0",
 *     "decision_output_schema": {
 *       "required_fields": [
 *         "decision_id", "timestamp", "correlation_id", "capability_id",
 *         "matched_rule_id", "denied", "telemetry_envelopes"
 *       ]
 *     },
 *     "telemetry_requirements": {
 *       "required_events": [
 *         {
 *           "event": "evt.os.task.routed",
 *           "must_include_dimensions": ["correlation_id", "tenant_id", "capability_id", "qos_class"]
 *         },
 *         ...
 *       ]
 *     }
 *   }
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ConformanceSpec {
  spec_version?: string;
  decision_output_schema?: {
    required_fields?: string[];
  };
  telemetry_requirements?: {
    required_events?: Array<{
      event: string;
      must_include_dimensions?: string[];
    }>;
  };
}

// ---------------------------------------------------------------------------
// Validation functions
// ---------------------------------------------------------------------------

/**
 * Validate that a RouteDecision object contains all required fields.
 *
 * @returns List of missing field names. Empty array means compliant.
 */
export function validateRequiredFields(
  decision: Record<string, unknown>,
  spec: ConformanceSpec
): string[] {
  const required =
    spec.decision_output_schema?.required_fields ?? [];
  return required.filter((f) => !(f in decision));
}

/**
 * Validate that mandatory WCP telemetry events are present and complete.
 *
 * Per WCP spec section 5.4, every dispatch MUST emit:
 *   - evt.os.task.routed
 *   - evt.os.worker.selected
 *   - evt.os.policy.gated
 *
 * @returns List of error strings. Empty array means compliant.
 */
export function validateRequiredTelemetry(
  telemetryEvents: Record<string, unknown>[],
  spec: ConformanceSpec
): string[] {
  const errors: string[] = [];
  const required = spec.telemetry_requirements?.required_events ?? [];

  // Index events by event_id
  const byEvent: Map<string, Record<string, unknown>[]> = new Map();
  for (const event of telemetryEvents) {
    const id = event["event_id"] as string;
    if (!byEvent.has(id)) byEvent.set(id, []);
    byEvent.get(id)!.push(event);
  }

  for (const req of required) {
    const eventId = req.event;
    const mustDims = req.must_include_dimensions ?? [];

    if (!byEvent.has(eventId)) {
      errors.push(`missing_required_event:${eventId}`);
      continue;
    }

    // At least one instance must have all required dimensions
    const instances = byEvent.get(eventId)!;
    const satisfied = instances.some((instance) =>
      mustDims.every(
        (k) => k in instance && instance[k] !== null && instance[k] !== undefined
      )
    );
    if (!satisfied) {
      errors.push(`event_missing_dimensions:${eventId}`);
    }
  }

  return errors;
}

/**
 * Return the default WCP conformance spec (WCP-Standard requirements).
 *
 * Use this when you don't have a custom spec file. Validates the three
 * mandatory telemetry events and core decision fields.
 */
export function defaultConformanceSpec(): ConformanceSpec {
  return {
    spec_version: "1.0",
    decision_output_schema: {
      required_fields: [
        "decision_id",
        "timestamp",
        "correlation_id",
        "tenant_id",
        "capability_id",
        "matched_rule_id",
        "denied",
        "telemetry_envelopes",
      ],
    },
    telemetry_requirements: {
      required_events: [
        {
          event: "evt.os.task.routed",
          must_include_dimensions: [
            "correlation_id",
            "tenant_id",
            "capability_id",
            "qos_class",
          ],
        },
        {
          event: "evt.os.worker.selected",
          must_include_dimensions: ["correlation_id", "capability_id"],
        },
        {
          event: "evt.os.policy.gated",
          must_include_dimensions: ["correlation_id", "decision"],
        },
      ],
    },
  };
}

/**
 * Load a conformance spec from a JSON string.
 */
export function loadConformanceSpecFromJson(json: string): ConformanceSpec {
  return JSON.parse(json) as ConformanceSpec;
}
