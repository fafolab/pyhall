/**
 * workers/examples/hello-worker/worker.ts — Minimal canonical WCP worker (TypeScript).
 *
 * Implements: cap.hello.greet
 * Species:    wrk.hello.greeter
 *
 * This is the simplest possible complete WCP worker in TypeScript.
 * Use it as a template when building your own workers.
 *
 * Run (after compiling):
 *   node dist/workers/examples/hello-worker/worker.js '{"name": "Alice"}'
 *
 * Or in stdio mode:
 *   echo '{"name": "Alice"}' | node dist/workers/examples/hello-worker/worker.js --stdio
 */

import { createHash } from "crypto";

// ---------------------------------------------------------------------------
// Standard WCP worker context and result types
// ---------------------------------------------------------------------------

interface WorkerContext {
  correlation_id: string;
  tenant_id: string;
  env: string;
  data_label: string;
  qos_class: string;
  capability_id: string;
  policy_version?: string;
}

interface WorkerResult {
  status: "ok" | "denied" | "error";
  result: Record<string, unknown>;
  telemetry: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
  deny_reason?: Record<string, unknown> | null;
}

// ---------------------------------------------------------------------------
// Worker identity constants
// ---------------------------------------------------------------------------

const WORKER_ID = "org.example.hello-greeter";
const WORKER_SPECIES_ID = "wrk.hello.greeter";
const CAPABILITY_ID = "cap.hello.greet";
const RISK_TIER = "low";

function nowUtc(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

/**
 * Execute the greeting capability.
 *
 * Input:
 *   {
 *     "name": "Alice",          (optional, defaults to "World")
 *     "correlation_id": "...",  (required for telemetry)
 *     "tenant_id": "...",       (required for telemetry)
 *     "capability_id": "cap.hello.greet"
 *   }
 */
export function execute(request: Record<string, unknown>): WorkerResult {
  const correlationId = (request["correlation_id"] as string) ?? "unknown";
  const tenantId = (request["tenant_id"] as string) ?? "unknown";
  const name = (request["name"] as string) ?? "World";

  // The actual work — dead simple on purpose
  const greeting = `Hello, ${name}!`;

  // Telemetry event (workers should emit at minimum evt.worker.executed.v1)
  const telemetryEvent: Record<string, unknown> = {
    event_id: "evt.worker.executed.v1",
    timestamp: nowUtc(),
    correlation_id: correlationId,
    tenant_id: tenantId,
    worker_id: WORKER_ID,
    worker_species_id: WORKER_SPECIES_ID,
    capability_id: CAPABILITY_ID,
    status: "ok",
  };

  // Evidence receipt (WCP spec section 5.7)
  const payloadBytes = JSON.stringify(
    Object.fromEntries(
      Object.entries(request).sort(([a], [b]) => a.localeCompare(b))
    )
  );
  const artifactHash =
    "sha256:" + createHash("sha256").update(payloadBytes, "utf8").digest("hex");

  const evidenceReceipt: Record<string, unknown> = {
    correlation_id: correlationId,
    dispatched_at: nowUtc(),
    worker_id: WORKER_ID,
    capability_id: CAPABILITY_ID,
    policy_decision: "ALLOW",
    controls_verified: ["ctrl.obs.audit-log-append-only"],
    artifact_hash: artifactHash,
  };

  return {
    status: "ok",
    result: {
      greeting,
      name,
      worker_id: WORKER_ID,
    },
    telemetry: [telemetryEvent],
    evidence: [evidenceReceipt],
  };
}

// ---------------------------------------------------------------------------
// Run modes
// ---------------------------------------------------------------------------

function runStdio(): void {
  const chunks: Buffer[] = [];
  process.stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
  process.stdin.on("end", () => {
    const raw = Buffer.concat(chunks).toString("utf8").trim();
    if (!raw) {
      process.stdout.write(
        JSON.stringify({ status: "error", error: "Empty request" }) + "\n"
      );
      return;
    }
    let request: Record<string, unknown>;
    try {
      request = JSON.parse(raw) as Record<string, unknown>;
    } catch (e) {
      process.stdout.write(
        JSON.stringify({ status: "error", error: `Invalid JSON: ${e}` }) + "\n"
      );
      return;
    }
    try {
      const result = execute(request);
      process.stdout.write(JSON.stringify(result) + "\n");
    } catch (e) {
      process.stdout.write(
        JSON.stringify({ status: "error", deny_reason: { message: String(e) } }) +
          "\n"
      );
    }
  });
}

function runCli(): void {
  const args = process.argv.slice(2);
  if (args.includes("--stdio")) {
    runStdio();
    return;
  }

  let request: Record<string, unknown> = {};
  if (args.length > 0) {
    try {
      request = JSON.parse(args[0]) as Record<string, unknown>;
    } catch {
      request = {};
    }
  }

  try {
    const result = execute(request);
    console.log(JSON.stringify(result, null, 2));
  } catch (e) {
    const result: WorkerResult = {
      status: "error",
      result: {},
      telemetry: [],
      evidence: [],
      deny_reason: { message: String(e) },
    };
    console.log(JSON.stringify(result, null, 2));
  }
}

// Entry point
runCli();
