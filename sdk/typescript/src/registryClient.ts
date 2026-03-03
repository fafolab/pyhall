/**
 * registryClient.ts — HTTP client for the pyhall.dev registry API (v0.2.0)
 *
 * Wraps the public and authenticated endpoints of api.pyhall.dev.
 * Use RegistryClient to:
 *   - Verify a worker's current attestation status
 *   - Check if a hash appears on the community ban-list
 *   - Integrate registry verification into makeDecision() via prefetch+callback
 *
 * v0.2.0 security notes:
 *   - 404 on verify() is not an error — returns status 'unknown' (IDOR-safe)
 *   - 429 on any call throws RegistryRateLimitError (retryable=true)
 *   - Owner self-reports are pending (confirmed=0) until admin review
 */

export interface VerifyResponse {
  worker_id: string;
  status: 'active' | 'revoked' | 'banned' | 'unknown';
  current_hash: string | null;
  banned: boolean;
  ban_reason: string | null;
  attested_at: string | null;
  ai_generated: boolean;
  ai_service: string | null;
  ai_model: string | null;
  ai_session_fingerprint: string | null;
}

export interface BanEntry {
  sha256: string;
  reason: string;
  reported_at: string;
  source: string;
  review_status?: string;
}

export interface RegistryClientOptions {
  /** Registry API base URL. Default: 'https://api.pyhall.dev' */
  baseUrl?: string;
  /** pyhall_session JWT value for authenticated calls. Sent as Cookie header. */
  sessionToken?: string;
  /** Request timeout in ms. Default: 10000 */
  timeout?: number;
  /** Prefetch cache TTL in ms. Default: 60000 */
  cacheTtl?: number;
}

export class RegistryRateLimitError extends Error {
  readonly retryable = true;
  constructor(path: string) {
    super(`pyhall registry rate limit exceeded on ${path} — try again later`);
    this.name = 'RegistryRateLimitError';
  }
}

interface CacheEntry {
  response: VerifyResponse;
  expiresAt: number;
}

export class RegistryClient {
  private readonly baseUrl: string;
  private readonly sessionToken: string | undefined;
  private readonly timeout: number;
  private readonly cacheTtl: number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(opts: RegistryClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? 'https://api.pyhall.dev').replace(/\/$/, '');
    this.sessionToken = opts.sessionToken;
    this.timeout = opts.timeout ?? 10_000;
    this.cacheTtl = opts.cacheTtl ?? 60_000;
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private async _fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
      });
      if (res.status === 429) throw new RegistryRateLimitError(path);
      return res;
    } finally {
      clearTimeout(timer);
    }
  }

  private _authHeaders(): Record<string, string> {
    if (!this.sessionToken) return {};
    return { Cookie: `pyhall_session=${this.sessionToken}` };
  }

  // ── Public endpoints (no auth) ────────────────────────────────────────────

  /**
   * Verify a worker's current attestation status.
   * Returns `{ status: 'unknown' }` on 404 — does NOT throw (IDOR-safe uniform response).
   */
  async verify(workerId: string): Promise<VerifyResponse> {
    const res = await this._fetch(`/api/v1/verify/${encodeURIComponent(workerId)}`);
    if (res.status === 404) {
      return {
        worker_id: workerId, status: 'unknown', current_hash: null,
        banned: false, ban_reason: null, attested_at: null,
        ai_generated: false, ai_service: null, ai_model: null,
        ai_session_fingerprint: null,
      };
    }
    if (!res.ok) throw new Error(`registry verify failed: ${res.status}`);
    return res.json() as Promise<VerifyResponse>;
  }

  /**
   * Check if a SHA-256 hash appears on the confirmed ban-list.
   * Fetches the full ban-list and searches client-side.
   * Returns true only for confirmed=1 entries (community reports pending review return false).
   */
  async isHashBanned(sha256: string): Promise<boolean> {
    const list = await this.getBanList();
    return list.some(e => e.sha256 === sha256);
  }

  /**
   * Fetch the public ban-list (confirmed=1 entries only).
   */
  async getBanList(limit = 500): Promise<BanEntry[]> {
    const res = await this._fetch(`/api/v1/ban-list?limit=${limit}`);
    if (!res.ok) throw new Error(`registry ban-list failed: ${res.status}`);
    return res.json() as Promise<BanEntry[]>;
  }

  /**
   * Fetch the registry health endpoint.
   */
  async health(): Promise<{ ok: boolean; version: string }> {
    const res = await this._fetch('/health');
    if (!res.ok) throw new Error(`registry health check failed: ${res.status}`);
    return res.json() as Promise<{ ok: boolean; version: string }>;
  }

  // ── Authenticated endpoints ───────────────────────────────────────────────

  /**
   * Submit a community hash report (requires session token).
   * Reports are written with confirmed=0 and require admin review before appearing in ban-list.
   */
  async reportHash(sha256: string, reason: string, evidenceUrl?: string): Promise<void> {
    const res = await this._fetch('/api/v1/ban-list/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...this._authHeaders() },
      body: JSON.stringify({ sha256, reason, ...(evidenceUrl ? { evidence_url: evidenceUrl } : {}) }),
    });
    if (!res.ok) throw new Error(`registry report failed: ${res.status}`);
  }

  // ── makeDecision() integration ────────────────────────────────────────────

  /**
   * Pre-fetch and cache verify() results for a list of worker IDs.
   * Call before makeDecision() to ensure getWorkerHashCallback() has data.
   * Cache TTL is configurable (default 60 s).
   */
  async prefetch(workerIds: string[]): Promise<void> {
    const now = Date.now();
    await Promise.all(workerIds.map(async (id) => {
      const entry = this.cache.get(id);
      if (entry && entry.expiresAt > now) return; // still fresh
      try {
        const response = await this.verify(id);
        this.cache.set(id, { response, expiresAt: now + this.cacheTtl });
      } catch {
        // Non-fatal: cache miss means callback returns null
      }
    }));
  }

  /**
   * Returns a synchronous callback suitable for makeDecision()'s
   * `worker_available_fn` or attestation-check hook.
   *
   * Returns the worker's current attested hash, or null if:
   *   - The worker is not in the prefetch cache
   *   - The worker is not found / has no attestation
   *   - The worker is revoked or banned
   *
   * Always call prefetch(workerIds) before makeDecision() to populate the cache.
   */
  getWorkerHashCallback(): (workerId: string) => string | null {
    const now = Date.now();
    return (workerId: string): string | null => {
      const entry = this.cache.get(workerId);
      if (!entry || entry.expiresAt <= now) return null;
      const { status, current_hash } = entry.response;
      if (status === 'active' && current_hash) return current_hash;
      return null;
    };
  }
}
