/**
 * src/index.ts — pyhall-ts public API.
 *
 * The TypeScript/Node.js WCP reference implementation.
 *
 * Quick start:
 *
 *   import { makeDecision, Registry, loadRulesFromDoc } from "@pyhall/core";
 *
 *   const rules = loadRulesFromDoc(myRulesJson);
 *   const registry = new Registry();
 *   registry.enroll(myWorkerRecord);
 *
 *   const decision = makeDecision({
 *     inp: {
 *       capability_id: "cap.hello.greet",
 *       env: "dev",
 *       data_label: "PUBLIC",
 *       tenant_risk: "low",
 *       qos_class: "P2",
 *       tenant_id: "demo",
 *       correlation_id: "550e8400-e29b-41d4-a716-446655440000",
 *     },
 *     rules,
 *     registryControlsPresent: registry.controlsPresent(),
 *     registryWorkerAvailable: (id) => registry.workerAvailable(id),
 *   });
 *
 *   console.log(decision.denied);                     // false
 *   console.log(decision.selected_worker_species_id); // "wrk.hello.greeter"
 */

// Core routing
export { makeDecision } from "./router.js";
export type { MakeDecisionOptions } from "./router.js";

// Models / types
export type {
  RouteInput,
  RouteDecision,
  CandidateWorker,
  Escalation,
  PreconditionsChecked,
  Env,
  DataLabel,
  QoSClass,
  TenantRisk,
  WorkerRegistryRecord,
  PrivilegeEnvelope,
} from "./models.js";

// Rules engine
export {
  loadRulesFromDoc,
  loadRulesFromJson,
  routeFirstMatch,
  ruleMatches,
  matchMembership,
} from "./rules.js";
export type { Rule, RulesDocument } from "./rules.js";

// Registry (local WCP registry)
export { Registry } from "./registry.js";

// Registry API client (pyhall.dev HTTP API)
export { RegistryClient, RegistryRateLimitError } from "./registryClient.js";
export type { VerifyResponse, BanEntry, RegistryClientOptions, AttestationResponse } from "./registryClient.js";

// Attestation
export {
  ATTEST_MANIFEST_MISSING,
  ATTEST_MANIFEST_ID_MISMATCH,
  ATTEST_HASH_MISMATCH,
  ATTEST_SIGNATURE_MISSING,
  ATTEST_SIG_INVALID,
  canonicalPackageHash,
  buildManifest,
  writeManifest,
  scaffoldPackage,
  PackageAttestationVerifier,
} from "./attestation.js";
export type { BuildManifestOptions, AttestResult, VerifierOptions } from "./attestation.js";

// Policy gate
export { PolicyGate } from "./policyGate.js";
export type {
  PolicyGateEvaluator,
  PolicyGateContext,
  PolicyGateResult,
  PolicyDecision,
} from "./policyGate.js";

// Conformance
export {
  validateRequiredFields,
  validateRequiredTelemetry,
  defaultConformanceSpec,
  loadConformanceSpecFromJson,
} from "./conformance.js";
export type { ConformanceSpec } from "./conformance.js";

// Telemetry builders
export {
  osTaskRouted,
  osWorkerSelected,
  osPolicyGated,
  govBlastScored,
  govPrivilegeEnvelopeChecked,
} from "./telemetry.js";

// Common utilities
export { nowUtc, uuidV4, sha256Hex, ok, err, partial } from "./common.js";
export type { ResultStatus, WorkerResultEnvelope } from "./common.js";

// Package version
export const VERSION = "0.1.0";
export const WCP_VERSION = "0.1";
