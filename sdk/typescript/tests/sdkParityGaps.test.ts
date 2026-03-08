/**
 * tests/sdkParityGaps.test.ts
 *
 * C4 classification output for python test_cli_user.py + test_hall_api.py:
 * - CLI command UX/exit-code tests are Python CLI-specific (not TS SDK parity targets).
 * - Flask Hall API endpoint tests are server-specific (not TS SDK parity targets).
 * - Remaining SDK-level parity candidates are captured as TODO stubs below.
 */

describe('SDK-level parity gaps from CLI/Hall-API suites (C4)', () => {
  describe('Python CLI-specific (no TS SDK parity test expected)', () => {
    test.todo('search/explain/browse command UX tests are CLI-only');
    test.todo('discord-lab and discord-bootstrap workflows are CLI-only');
    test.todo('dispatch command output-format tests are CLI wrapper tests');
  });

  describe('Hall API server-specific (no TS SDK parity test expected)', () => {
    test.todo('/health, /status, /workers, /alerts endpoint tests are Flask-server only');
    test.todo('/enroll and /decisions/ingest endpoint behavior is Hall API service surface');
    test.todo('/wcp/registry/* proxy route tests belong to Hall API integration tests');
  });

  describe('SDK-level candidates tracked as parity TODOs', () => {
    test.todo('artifact hash helper parity: deterministic hash and tamper detection helpers');
    test.todo('registry verification unknown-worker normalization parity (404 -> status=unknown)');
    test.todo('ban-list client parity for network-failure classification and retryability');
  });
});

