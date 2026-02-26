/**
 * src/models.ts — WCP routing envelope types.
 *
 * RouteInput  — what the agent sends to the Hall.
 * RouteDecision — what the Hall returns.
 *
 * These are the core data contracts of the Worker Class Protocol.
 * Mirrors pyhall/models.py exactly.
 */

// ---------------------------------------------------------------------------
// Enum-style union types (mirrors Python Literal)
// ---------------------------------------------------------------------------

export type Env = "dev" | "stage" | "prod" | "edge";
export type DataLabel = "PUBLIC" | "INTERNAL" | "RESTRICTED";
export type QoSClass = "P0" | "P1" | "P2" | "P3";
export type TenantRisk = "low" | "medium" | "high";

// ---------------------------------------------------------------------------
// RouteInput
// ---------------------------------------------------------------------------

/**
 * The capability request envelope sent to the Hall.
 * Required fields follow the WCP spec section 4.1.
 */
export interface RouteInput {
  /** The WCP capability being requested, e.g. 'cap.doc.summarize'. */
  capability_id: string;

  /** Deployment environment. */
  env: Env;

  /** Data sensitivity label. */
  data_label: DataLabel;

  /** Risk tier of the requesting tenant. */
  tenant_risk: TenantRisk;

  /** Quality of Service priority: P0 (highest) through P3 (background). */
  qos_class: QoSClass;

  /** Identifier of the requesting tenant or system. */
  tenant_id: string;

  /** UUID v4 correlation ID. Must be propagated through all downstream calls. */
  correlation_id: string;

  /** Arbitrary payload for the target worker. */
  request?: Record<string, unknown>;

  /** Pre-computed blast radius dimensions if available. */
  blast_radius?: Record<string, unknown> | null;

  /** Pre-computed blast score (0–100). Router computes it if undefined. */
  blast_score?: number | null;

  /** Privilege context for envelope enforcement. */
  privilege_context?: Record<string, unknown> | null;

  /** If true, full routing decision is made but no worker is executed. */
  dry_run?: boolean;
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/** A worker species candidate considered during routing. */
export interface CandidateWorker {
  /** WCP worker species ID, e.g. 'wrk.doc.summarizer'. */
  worker_species_id: string;

  /** Optional pre-ranked score from the rules engine. */
  score_hint?: number | null;

  /** Minimum controls this candidate requires. */
  requires_controls_minimum?: string[] | null;

  /** Populated when this candidate was considered but not selected. */
  skip_reason?: string | null;
}

/** Escalation policy from the matched routing rule. */
export interface Escalation {
  /** Whether the policy gate must be evaluated. */
  policy_gate?: boolean;

  /** Whether MSAVX step-up approval is required. */
  msavx_step_up?: boolean;

  /** Whether human review is required by default. */
  human_required_default?: boolean;

  /** Conditional human review triggers. */
  human_required_if?: Record<string, unknown>[];

  /** Reason for escalation requirement. */
  rationale?: string | null;
}

/** Precondition flags applied during routing. */
export interface PreconditionsChecked {
  /** Deny if correlation_id is absent or empty. */
  must_have_correlation_id?: boolean;

  /** Policy version must be propagated. */
  must_attach_policy_version?: boolean;

  /** SHA-256 of request payload must be recorded on execution. */
  must_record_artifact_hash_if_executes?: boolean;

  /** Deny dispatch if declared required controls are not present in registry. */
  deny_if_missing_required_controls?: boolean;

  /**
   * Deny unsigned artifacts in production (WCP-Full).
   * @notImplemented Worker attestation subsystem not yet implemented in TypeScript SDK (v0.1). This flag is stored but not enforced.
   */
  deny_if_unsigned_artifact_in_prod?: boolean;

  /**
   * Deny workers without attestation records in production.
   * Enforced by the router when hallConfig.requireWorkerAttestation=true (WCP §5.10).
   */
  deny_if_no_attestation_in_prod?: boolean;
}

// ---------------------------------------------------------------------------
// RouteDecision
// ---------------------------------------------------------------------------

/**
 * The routing decision returned by the Hall.
 *
 * On success: denied=false, selected_worker_species_id is set.
 * On denial:  denied=true, deny_reason_if_denied is set.
 *
 * All decisions — allowed or denied — include telemetry_envelopes.
 */
export interface RouteDecision {
  /** UUID v4 identifying this specific routing decision. */
  decision_id: string;

  /** ISO 8601 UTC timestamp of the decision. */
  timestamp: string;

  /** Propagated from RouteInput.correlation_id. */
  correlation_id: string;

  /** Propagated from RouteInput.tenant_id. */
  tenant_id: string;

  /** The capability that was requested. */
  capability_id: string;

  /** The routing rule that matched. 'NO_MATCH' if none matched. */
  matched_rule_id: string;

  env: Env;
  data_label: DataLabel;
  tenant_risk: TenantRisk;
  qos_class: QoSClass;

  // Decision outcome
  denied: boolean;
  deny_reason_if_denied?: Record<string, unknown> | null;

  // Selected worker
  selected_worker_species_id?: string | null;
  candidate_workers_ranked: CandidateWorker[];

  // Governance state
  required_controls_effective: string[];
  recommended_profiles_effective: Record<string, unknown>[];
  escalation_effective: Escalation;
  preconditions_checked: PreconditionsChecked;

  /** True when this decision was made in dry-run mode — no worker was dispatched. */
  dry_run?: boolean;

  // Worker Code Attestation (WCP §5.10)
  /** True when the Hall attempted to verify the selected worker's code hash. */
  worker_attestation_checked?: boolean;

  /** true = hash matched. false = TAMPERED. null/undefined = attestation not checked. */
  worker_attestation_valid?: boolean | null;

  // Mandatory telemetry (WCP section 5.4)
  telemetry_envelopes: Record<string, unknown>[];
}

// ---------------------------------------------------------------------------
// TS-F5: HallConfig — hall-level governance floors
// ---------------------------------------------------------------------------

/**
 * Hall-level configuration that sets governance floors for all decisions.
 * Individual rules may tighten but never loosen these floors.
 */
export interface HallConfig {
  /** When true, deny any RouteInput whose tenant_id is not in allowedTenants. Default: false. */
  requireSignatory?: boolean;
  /** List of allowed tenant IDs. Only enforced when requireSignatory is true. */
  allowedTenants?: string[];
  /**
   * When true, Hall requires a non-empty correlation_id regardless of per-rule preconditions.
   * Default: true.
   */
  enforceCorrelationId?: boolean;
  /**
   * When true, Hall enforces required_controls check regardless of per-rule preconditions.
   * Default: true.
   */
  enforceRequiredControls?: boolean;
  /**
   * When true, blast scoring gate is enforced in prod/edge regardless of rule's required_controls.
   * Default: true.
   */
  enforceBlastScoringInProd?: boolean;
  /**
   * When true, privilege envelope checking is required regardless of per-rule controls.
   * Default: false.
   */
  enforcePrivilegeEnvelopes?: boolean;
  /**
   * Require worker code attestation at dispatch time (WCP §5.10).
   * When true, makeDecision() will verify the selected worker's code hash against
   * the registered attestation before dispatching. Requires registryGetWorkerHash
   * and registryGetCurrentWorkerHash callbacks to be provided. Default: false.
   */
  requireWorkerAttestation?: boolean;
}

// ---------------------------------------------------------------------------
// Worker registry record (WCP spec section 6)
// ---------------------------------------------------------------------------

export interface WorkerRegistryRecord {
  worker_id: string;
  worker_species_id: string;
  capabilities: string[];
  risk_tier?: string;
  required_controls?: string[];
  currently_implements?: string[];
  allowed_environments?: string[];
  blast_radius?: Record<string, unknown>;
  privilege_envelope?: PrivilegeEnvelope;
  owner?: string;
  contact?: string;
  notes?: string;
  catalog_version_min?: string;
  [key: string]: unknown;
}

export interface PrivilegeEnvelope {
  secrets_access?: string[];
  network_egress?: string;
  filesystem_writes?: string[];
  tools?: string[];
  egress?: {
    allowlist?: string[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
}
