/**
 * tests/registryClient.test.ts — RegistryClient unit tests
 *
 * Uses Jest's global.fetch mock (no external deps).
 * All tests are against mock responses — no real HTTP calls made.
 */

import { RegistryClient, RegistryRateLimitError } from '../src/registryClient.js';

// ── Mock fetch ───────────────────────────────────────────────────────────────

const mockFetch = jest.fn();
global.fetch = mockFetch;

function mockResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

const ACTIVE_WORKER = {
  worker_id: 'x.test.worker1',
  status: 'active',
  current_hash: 'a'.repeat(64),
  banned: false,
  ban_reason: null,
  attested_at: '2026-03-03T00:00:00Z',
  ai_generated: false,
  ai_service: null,
  ai_model: null,
  ai_session_fingerprint: null,
};

const BAN_LIST = [
  {
    sha256: 'b'.repeat(64),
    reason: 'malware',
    reported_at: '2026-03-01T00:00:00Z',
    source: 'community',
    review_status: 'approved',
  },
];

// ── Tests ────────────────────────────────────────────────────────────────────

describe('RegistryClient', () => {
  let client: RegistryClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = new RegistryClient({ baseUrl: 'https://api.pyhall.dev' });
  });

  // ── verify() ───────────────────────────────────────────────────────────────

  describe('verify()', () => {
    it('returns active worker with all fields', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(ACTIVE_WORKER));
      const r = await client.verify('x.test.worker1');
      expect(r.status).toBe('active');
      expect(r.current_hash).toBe('a'.repeat(64));
      expect(r.banned).toBe(false);
      expect(r.ai_generated).toBe(false);
    });

    it('returns status unknown on 404 — does not throw', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({ error: 'not found' }, 404));
      const r = await client.verify('x.nonexistent.worker');
      expect(r.status).toBe('unknown');
      expect(r.current_hash).toBeNull();
      expect(r.banned).toBe(false);
    });

    it('throws RegistryRateLimitError on 429', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, 429));
      await expect(client.verify('x.test.w')).rejects.toBeInstanceOf(RegistryRateLimitError);
    });

    it('RegistryRateLimitError has retryable=true', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({}, 429));
      const err = await client.verify('x.test.w').catch(e => e);
      expect(err.retryable).toBe(true);
    });

    it('throws on unexpected server error', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({ error: 'internal' }, 500));
      await expect(client.verify('x.test.w')).rejects.toThrow('500');
    });
  });

  // ── isHashBanned() ─────────────────────────────────────────────────────────

  describe('isHashBanned()', () => {
    it('returns true for hash on ban-list', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(BAN_LIST));
      expect(await client.isHashBanned('b'.repeat(64))).toBe(true);
    });

    it('returns false for hash not on ban-list', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(BAN_LIST));
      expect(await client.isHashBanned('c'.repeat(64))).toBe(false);
    });
  });

  // ── getBanList() ───────────────────────────────────────────────────────────

  describe('getBanList()', () => {
    it('returns ban-list entries', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(BAN_LIST));
      const list = await client.getBanList();
      expect(list).toHaveLength(1);
      expect(list[0].sha256).toBe('b'.repeat(64));
      expect(list[0].review_status).toBe('approved');
    });

    it('includes limit param in request URL', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse([]));
      await client.getBanList(100);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('limit=100'),
        expect.anything(),
      );
    });
  });

  // ── health() ──────────────────────────────────────────────────────────────

  describe('health()', () => {
    it('returns version from health endpoint', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({ ok: true, version: '0.2.0' }));
      const h = await client.health();
      expect(h.version).toBe('0.2.0');
      expect(h.ok).toBe(true);
    });
  });

  // ── reportHash() ──────────────────────────────────────────────────────────

  describe('reportHash()', () => {
    it('POSTs to ban-list/report with auth cookie', async () => {
      const authedClient = new RegistryClient({ sessionToken: 'test-jwt-value' });
      mockFetch.mockResolvedValueOnce(mockResponse({ ok: true }));
      await authedClient.reportHash('d'.repeat(64), 'malicious package detected in test');
      const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
      expect(url).toContain('/api/v1/ban-list/report');
      expect((init.headers as Record<string, string>)['Cookie']).toContain('pyhall_session=test-jwt-value');
      expect(init.method).toBe('POST');
    });

    it('includes evidence_url when provided', async () => {
      const authedClient = new RegistryClient({ sessionToken: 'tok' });
      mockFetch.mockResolvedValueOnce(mockResponse({ ok: true }));
      await authedClient.reportHash('e'.repeat(64), 'at least twenty chars reason', 'https://example.com/report');
      const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body.evidence_url).toBe('https://example.com/report');
    });
  });

  // ── prefetch() + getWorkerHashCallback() ──────────────────────────────────

  describe('prefetch() + getWorkerHashCallback()', () => {
    it('callback returns hash for prefetched active worker', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(ACTIVE_WORKER));
      await client.prefetch(['x.test.worker1']);
      const cb = client.getWorkerHashCallback();
      expect(cb('x.test.worker1')).toBe('a'.repeat(64));
    });

    it('callback returns null for worker not in cache', async () => {
      const cb = client.getWorkerHashCallback();
      expect(cb('x.unknown.worker')).toBeNull();
    });

    it('callback returns null for revoked worker', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({ ...ACTIVE_WORKER, status: 'revoked' }));
      await client.prefetch(['x.test.worker1']);
      const cb = client.getWorkerHashCallback();
      expect(cb('x.test.worker1')).toBeNull();
    });

    it('callback returns null for banned worker', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({ ...ACTIVE_WORKER, status: 'banned' }));
      await client.prefetch(['x.test.worker1']);
      const cb = client.getWorkerHashCallback();
      expect(cb('x.test.worker1')).toBeNull();
    });

    it('prefetch skips fetch for cached entries within TTL', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse(ACTIVE_WORKER));
      await client.prefetch(['x.test.worker1']);
      await client.prefetch(['x.test.worker1']); // second call — should not fetch again
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('prefetch is non-fatal on 404 — unknown worker cached as miss', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({ error: 'not found' }, 404));
      await expect(client.prefetch(['x.nonexistent.w'])).resolves.not.toThrow();
      const cb = client.getWorkerHashCallback();
      expect(cb('x.nonexistent.w')).toBeNull(); // unknown → no hash
    });
  });

  // ── C4 parity stubs: submitAttestation / AttestationResponse ────────────
  // Python SDK exposes AttestationResponse + submit_attestation().
  // TS SDK does not yet expose equivalent API surface.
  describe('submitAttestation() parity (TODO)', () => {
    test.todo('exposes AttestationResponse shape equivalent to Python (id, worker_id, sha256)');
    test.todo('submitAttestation validates package_hash format (64 lowercase hex)');
    test.todo('submitAttestation PUTs /api/v1/workers/:id/attest');
    test.todo('submitAttestation includes optional label and AI provenance fields');
    test.todo('submitAttestation uses bearer token precedence over session cookie when provided');
    test.todo('submitAttestation throws RegistryRateLimitError on 429');
    test.todo('submitAttestation propagates 401/403/404 as HTTP errors');
  });
});
