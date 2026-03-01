/**
 * src/common.ts — Shared utilities for pyhall-ts.
 *
 * Browser-compatible: no Node.js-specific APIs.
 * Mirrors pyhall/telemetry.py helpers + pyhall/common.py (if any).
 */

import { createHash } from "crypto";

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/** ISO 8601 UTC timestamp. Browser-compatible. */
export function nowUtc(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// UUID v4
// ---------------------------------------------------------------------------

/**
 * Generate a UUID v4 string.
 * Uses crypto.randomUUID() where available (browsers + Node 14.17+),
 * falls back to Math.random-based generation for legacy environments.
 */
export function uuidV4(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // Legacy fallback (RFC 4122 compliant)
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256 hex digest of a string payload.
 * Node.js implementation via crypto module.
 * For browser use, replace with SubtleCrypto.
 */
export function sha256Hex(payload: string): string {
  return createHash("sha256").update(payload, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Result helpers (ok / err / partial)
// ---------------------------------------------------------------------------

export type ResultStatus = "ok" | "error" | "partial" | "denied";

export interface WorkerResultEnvelope<T = Record<string, unknown>> {
  status: ResultStatus;
  result: T;
  telemetry: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
  deny_reason?: Record<string, unknown> | null;
}

export function ok<T extends Record<string, unknown>>(
  result: T,
  opts?: Partial<Omit<WorkerResultEnvelope<T>, "status" | "result">>
): WorkerResultEnvelope<T> {
  return {
    status: "ok",
    result,
    telemetry: opts?.telemetry ?? [],
    evidence: opts?.evidence ?? [],
    deny_reason: null,
  };
}

export function err(
  message: string,
  opts?: Partial<Omit<WorkerResultEnvelope, "status">>
): WorkerResultEnvelope {
  return {
    status: "error",
    result: { error: message },
    telemetry: opts?.telemetry ?? [],
    evidence: opts?.evidence ?? [],
    deny_reason: opts?.deny_reason ?? { message },
  };
}

export function partial<T extends Record<string, unknown>>(
  result: T,
  opts?: Partial<Omit<WorkerResultEnvelope<T>, "status" | "result">>
): WorkerResultEnvelope<T> {
  return {
    status: "partial",
    result,
    telemetry: opts?.telemetry ?? [],
    evidence: opts?.evidence ?? [],
    deny_reason: null,
  };
}
