/**
 * tests/registry.test.ts — `pyhall registry` command tests
 *
 * Mocks global.fetch and captures console output.
 * No real HTTP calls made.
 *
 * theme is mocked because chalk v5 is ESM-only and can't be loaded by ts-jest (CJS).
 */

// Mock theme before any imports that pull in chalk.
jest.mock('../src/theme', () => ({
  theme: new Proxy({}, { get: (_t, prop) => (s: string) => s }),
}));

import { runRegistryVerify, runRegistryCheckHash, runRegistryBanList, runRegistryStatus } from '../src/commands/registry';

// ── Mock fetch ────────────────────────────────────────────────────────────────

const mockFetch = jest.fn();
global.fetch = mockFetch;

function mockResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

let consoleOutput: string[] = [];
let errorOutput: string[] = [];

function captureOutput() {
  consoleOutput = [];
  errorOutput = [];
  jest.spyOn(console, 'log').mockImplementation((...args) => {
    consoleOutput.push(args.join(' '));
  });
  jest.spyOn(console, 'error').mockImplementation((...args) => {
    errorOutput.push(args.join(' '));
  });
}

function outputText(): string {
  // Strip ANSI codes for easier assertion
  return consoleOutput.join('\n').replace(/\x1b\[[0-9;]*m/g, '');
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeEach(() => {
  mockFetch.mockReset();
  captureOutput();
});

afterEach(() => {
  jest.restoreAllMocks();
});

// ── runRegistryVerify ─────────────────────────────────────────────────────────

describe('runRegistryVerify()', () => {
  it('prints active worker status table', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({
      worker_id: 'x.test.worker1', status: 'active',
      current_hash: 'a'.repeat(64), banned: false, ban_reason: null,
      attested_at: '2026-03-03T00:00:00Z', ai_generated: false,
      ai_service: null, ai_model: null, ai_session_fingerprint: null,
    }));
    await runRegistryVerify('x.test.worker1');
    const out = outputText();
    expect(out).toContain('x.test.worker1');
    expect(out).toContain('ACTIVE');
    expect(out).toContain('a'.repeat(64));
    expect(out).toContain('no'); // not banned
  });

  it('prints unknown message on 404', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ error: 'not found' }, 404));
    await runRegistryVerify('x.nonexistent.w');
    const out = outputText();
    expect(out).toContain('unknown');
  });

  it('calls registry with encoded worker ID', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ error: 'not found' }, 404));
    await runRegistryVerify('x.test.worker1');
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/verify/x.test.worker1'),
    );
  });

  it('exits on 429 rate limit', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({}, 429));
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runRegistryVerify('x.test.w')).rejects.toThrow('exit');
    mockExit.mockRestore();
  });
});

// ── runRegistryCheckHash ──────────────────────────────────────────────────────

describe('runRegistryCheckHash()', () => {
  it('prints BANNED for hash on ban-list', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse([
      { sha256: 'b'.repeat(64), reason: 'malware', source: 'community', review_status: 'approved' },
    ]));
    await runRegistryCheckHash('b'.repeat(64));
    expect(outputText()).toContain('BANNED');
    expect(outputText()).toContain('malware');
  });

  it('prints CLEAN for hash not on ban-list', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse([]));
    await runRegistryCheckHash('c'.repeat(64));
    expect(outputText()).toContain('CLEAN');
  });

  it('exits on invalid sha256 format', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runRegistryCheckHash('not-a-hash')).rejects.toThrow('exit');
    mockExit.mockRestore();
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

// ── runRegistryBanList ────────────────────────────────────────────────────────

describe('runRegistryBanList()', () => {
  it('prints ban-list entries', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse([
      { sha256: 'd'.repeat(64), reason: 'supply chain attack', reported_at: '2026-03-01T00:00:00Z', source: 'admin' },
    ]));
    await runRegistryBanList({});
    const out = outputText();
    expect(out).toContain('dddddddddddd'); // first 12 chars of sha256
    expect(out).toContain('supply chain attack');
  });

  it('prints empty message for empty ban-list', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse([]));
    await runRegistryBanList({});
    expect(outputText()).toContain('empty');
  });

  it('includes limit param in request', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse([]));
    await runRegistryBanList({ limit: '50' });
    expect(mockFetch).toHaveBeenCalledWith(expect.stringContaining('limit=50'));
  });
});

// ── runRegistryStatus ─────────────────────────────────────────────────────────

describe('runRegistryStatus()', () => {
  it('prints version and ok status', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ ok: true, version: '0.2.0' }));
    await runRegistryStatus();
    const out = outputText();
    expect(out).toContain('0.2.0');
    expect(out).toContain('ok');
  });

  it('prints unreachable on non-ok response', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({}, 503));
    await runRegistryStatus();
    const out = outputText();
    expect(out).toContain('unreachable');
  });
});
