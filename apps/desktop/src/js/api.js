/**
 * api.js — Hall server HTTP polling via Tauri commands
 *
 * All backend calls go through window.__TAURI__.core.invoke().
 * If Tauri is not available (browser dev mode), falls back to
 * mock data so UI can be developed without a running app.
 */

const TAURI_AVAILABLE = typeof window.__TAURI__ !== 'undefined';

/**
 * Invoke a Tauri command. Falls back to mock if not in Tauri.
 */
async function tauriInvoke(cmd, args = {}) {
  if (!TAURI_AVAILABLE) {
    return MOCK_FALLBACKS[cmd] ? MOCK_FALLBACKS[cmd](args) : {};
  }
  return window.__TAURI__.core.invoke(cmd, args);
}

/**
 * Mock responses used when running outside Tauri (browser dev)
 * or when the Hall server is unreachable.
 */
const MOCK_FALLBACKS = {
  get_hall_status: () => ({
    online: false,
    url: 'http://localhost:8765',
    workers: 14,
    dispatches_today: 847,
    refusals_today: 12,
    uptime_seconds: 15780,
    rules_loaded: 214,
    profile: 'prof.dev.permissive',
    latency_ms: null,
  }),

  get_dispatch_feed: () => ({
    events: MOCK_DISPATCH_EVENTS,
    source: 'mock',
  }),

  get_active_dispatches: () => ({
    active: MOCK_ACTIVE_JOBS,
    source: 'mock',
  }),

  get_workers: () => ({
    workers: MOCK_WORKERS,
    source: 'mock',
  }),

  get_alerts: () => ({
    alerts: MOCK_ALERTS,
    source: 'mock',
  }),

  list_enrolled_workers: () => ({
    workers: [],
    source: 'local',
  }),

  read_config: () => ({
    hall_url: 'http://localhost:8765',
    poll_interval: 3,
    auth_token: null,
    default_profile: 'prof.dev.permissive',
    notifications: {
      hall_offline: true,
      worker_failure: true,
      steward_hold: true,
      every_denial: false,
    },
    display: {
      tray_on_minimize: true,
      launch_at_login: false,
      feed_max_rows: 500,
    },
  }),

  save_config: () => true,
  enroll_worker: () => true,
  validate_registry_record: (args) => ({ valid: false, checks: [], record: {} }),
};

// ─── Public API functions ──────────────────────────────────────────────────

window.HallAPI = {
  /** Get Hall server health/status */
  async getHallStatus(url) {
    return tauriInvoke('get_hall_status', { url });
  },

  /** Get recent dispatch events */
  async getDispatchFeed(url, limit = 100) {
    return tauriInvoke('get_dispatch_feed', { url, limit });
  },

  /** Get currently active dispatches */
  async getActiveDispatches(url) {
    return tauriInvoke('get_active_dispatches', { url });
  },

  /** Get enrolled workers from Hall */
  async getWorkers(url) {
    return tauriInvoke('get_workers', { url });
  },

  /** Get active alerts */
  async getAlerts(url) {
    return tauriInvoke('get_alerts', { url });
  },

  /** List locally enrolled workers */
  async listEnrolledWorkers() {
    return tauriInvoke('list_enrolled_workers');
  },

  /** Enroll a worker (save registry_record.json locally) */
  async enrollWorker(recordJson) {
    return tauriInvoke('enroll_worker', { record_json: recordJson });
  },

  /** Validate a registry_record.json before enrollment */
  async validateRegistryRecord(recordJson) {
    return tauriInvoke('validate_registry_record', { record_json: recordJson });
  },

  /** Read app config */
  async readConfig() {
    return tauriInvoke('read_config');
  },

  /** Save app config */
  async saveConfig(config) {
    return tauriInvoke('save_config', { config });
  },

  /**
   * Check a worker's attestation status via pyhall.dev registry API.
   * @param {string} workerId - Worker ID to verify
   * @param {string} [registryUrl] - Override registry base URL
   * @returns {Promise<{status: string, current_hash: string|null, banned: boolean, ...}>}
   */
  async checkRegistryStatus(workerId, registryUrl) {
    const url = (registryUrl || window.AppState?.config?.registry_url || 'https://api.pyhall.dev').replace(/\/$/, '');
    return tauriInvoke('check_registry_status', { registry_url: url, worker_id: workerId });
  },
};

// ─── Shared app state ──────────────────────────────────────────────────────

window.AppState = {
  hallOnline: false,
  hallUrl: 'http://localhost:8765',
  config: null,
  workerCount: 14,
  dispatchesToday: 847,
  refusalsToday: 12,
  alertCount: 0,
  pollInterval: null,
  pollMs: 3000,
};

// ─── Utility helpers ───────────────────────────────────────────────────────

/**
 * Format a UTC ISO timestamp as Central Time display string.
 * e.g. "2026-02-25T20:32:17Z" → "14:32:17 CST"
 */
window.formatTimeCT = function(isoStr) {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString('en-US', {
      timeZone: 'America/Chicago',
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }) + ' CT';
  } catch {
    return isoStr;
  }
};

window.formatDateCT = function(isoStr) {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString('en-US', {
      timeZone: 'America/Chicago',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).replace(',', '') + ' CT';
  } catch {
    return isoStr;
  }
};

window.formatUptime = function(seconds) {
  if (!seconds) return '—';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
};

window.blastTierClass = function(score) {
  if (score <= 30) return 'blast-low';
  if (score <= 60) return 'blast-medium';
  if (score <= 80) return 'blast-high';
  return 'blast-critical';
};

window.blastTierLabel = function(score) {
  if (score <= 30) return 'LOW';
  if (score <= 60) return 'MEDIUM';
  if (score <= 80) return 'HIGH';
  return 'CRITICAL';
};

// ─── Mock data ─────────────────────────────────────────────────────────────

const _now = () => new Date().toISOString();
const _ago = (s) => new Date(Date.now() - s * 1000).toISOString();

window.MOCK_ACTIVE_JOBS = [
  { started_at: _ago(82), worker: 'wrk.doc.summarizer', capability: 'cap.doc.summarize', blast_score: 12, tenant_id: 'fafolab', env: 'prod' },
  { started_at: _ago(76), worker: 'wrk.mem.retriever',  capability: 'cap.mem.retrieve',  blast_score: 18, tenant_id: 'fafolab', env: 'prod' },
  { started_at: _ago(69), worker: 'wrk.doc.summarizer', capability: 'cap.doc.summarize', blast_score: 12, tenant_id: 'fafolab', env: 'prod' },
];

window.MOCK_DISPATCH_EVENTS = [
  { id: 'evt-001', timestamp: _ago(3),  outcome: 'DISPATCHED',   worker: 'wrk.doc.summarizer', capability: 'cap.doc.summarize',        blast_score: 12, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-002', timestamp: _ago(5),  outcome: 'DISPATCHED',   worker: 'wrk.mem.retriever',  capability: 'cap.mem.retrieve',         blast_score: 18, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-003', timestamp: _ago(9),  outcome: 'STEWARD_HOLD', worker: null,                 capability: 'cap.secrets.read',         blast_score: 91, env: 'prod', tenant_id: 'fafolab', profile: 'prof.prod.strict', reason: 'blast:91 · prof.prod.strict' },
  { id: 'evt-004', timestamp: _ago(11), outcome: 'DISPATCHED',   worker: 'wrk.notify.pusher',  capability: 'cap.notify.send',          blast_score: 22, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-005', timestamp: _ago(13), outcome: 'STEWARD_HOLD', worker: null,                 capability: 'cap.db.write',             blast_score: 78, env: 'prod', tenant_id: 'fafolab', profile: 'prof.prod.strict', reason: 'blast:78 · human approval required' },
  { id: 'evt-006', timestamp: _ago(17), outcome: 'DISPATCHED',   worker: 'wrk.mem.retriever',  capability: 'cap.mem.retrieve',         blast_score: 18, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-007', timestamp: _ago(19), outcome: 'DISPATCHED',   worker: 'wrk.doc.summarizer', capability: 'cap.doc.summarize',        blast_score: 12, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-008', timestamp: _ago(25), outcome: 'REFUSED',      worker: null,                 capability: 'cap.fs.write.unrestricted', blast_score: 95, env: 'prod', tenant_id: 'fafolab', profile: 'prof.prod.strict', reason: 'no worker registered for capability' },
  { id: 'evt-009', timestamp: _ago(32), outcome: 'DISPATCHED',   worker: 'wrk.embed.runner',   capability: 'cap.embed.generate',       blast_score: 20, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-010', timestamp: _ago(38), outcome: 'DISPATCHED',   worker: 'wrk.doc.ocr',        capability: 'cap.doc.ocr',              blast_score: 15, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-011', timestamp: _ago(44), outcome: 'DISPATCHED',   worker: 'wrk.mem.retriever',  capability: 'cap.mem.search',           blast_score: 18, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-012', timestamp: _ago(55), outcome: 'STEWARD_HOLD', worker: null,                 capability: 'cap.db.delete',            blast_score: 82, env: 'prod', tenant_id: 'fafolab', profile: 'prof.prod.strict', reason: 'blast:82 · CRITICAL threshold' },
  { id: 'evt-013', timestamp: _ago(67), outcome: 'DISPATCHED',   worker: 'wrk.doc.summarizer', capability: 'cap.doc.summarize',        blast_score: 12, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-014', timestamp: _ago(78), outcome: 'DISPATCHED',   worker: 'wrk.notify.pusher',  capability: 'cap.notify.send',          blast_score: 22, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-015', timestamp: _ago(95), outcome: 'DISPATCHED',   worker: 'wrk.embed.runner',   capability: 'cap.embed.generate',       blast_score: 20, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-016', timestamp: _ago(110), outcome: 'REFUSED',     worker: null,                 capability: 'cap.secrets.write',        blast_score: 99, env: 'prod', tenant_id: 'fafolab', profile: 'prof.prod.strict', reason: 'no worker registered + blast critical' },
  { id: 'evt-017', timestamp: _ago(125), outcome: 'DISPATCHED',  worker: 'wrk.doc.summarizer', capability: 'cap.doc.summarize',        blast_score: 12, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-018', timestamp: _ago(140), outcome: 'DISPATCHED',  worker: 'wrk.mem.retriever',  capability: 'cap.mem.retrieve',         blast_score: 18, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-019', timestamp: _ago(158), outcome: 'DISPATCHED',  worker: 'wrk.doc.ocr',        capability: 'cap.doc.ocr',              blast_score: 15, env: 'prod', tenant_id: 'fafolab', profile: 'prof.dev.permissive' },
  { id: 'evt-020', timestamp: _ago(171), outcome: 'STEWARD_HOLD',worker: null,                 capability: 'cap.db.write',             blast_score: 78, env: 'prod', tenant_id: 'fafolab', profile: 'prof.prod.strict', reason: 'blast:78 · steward hold #7' },
];

window.MOCK_WORKERS = [
  {
    species_id: 'wrk.doc.summarizer',
    status: 'active',
    pack: 'Document Pipeline (Pack 10)',
    capabilities: ['cap.doc.summarize'],
    guarantee: 'best-effort',
    blast_score: 12,
    profile: 'prof.low-risk-autonomous',
    dispatches_today: 312,
    failures_today: 2,
    dlq_count: 0,
    risk_tier: 'low',
    source: 'server',
  },
  {
    species_id: 'wrk.mem.retriever',
    status: 'active',
    pack: 'Memory & Context Management (Pack 20)',
    capabilities: ['cap.mem.retrieve', 'cap.mem.search'],
    guarantee: 'at-least-once',
    blast_score: 18,
    profile: 'prof.low-risk-autonomous',
    dispatches_today: 445,
    failures_today: 0,
    dlq_count: 0,
    risk_tier: 'low',
    source: 'server',
  },
  {
    species_id: 'wrk.db.writer',
    status: 'gated',
    pack: 'Data Plane (Pack 22)',
    capabilities: ['cap.db.write', 'cap.db.delete'],
    guarantee: 'exactly-once',
    blast_score: 78,
    profile: 'prof.prod.strict',
    dispatches_today: 0,
    failures_today: 0,
    dlq_count: 0,
    risk_tier: 'high',
    source: 'server',
  },
  {
    species_id: 'wrk.notify.pusher',
    status: 'error',
    pack: 'Notification / Deliverability (Pack 11)',
    capabilities: ['cap.notify.send'],
    guarantee: 'at-least-once',
    blast_score: 22,
    profile: 'prof.low-risk-autonomous',
    dispatches_today: 48,
    failures_today: 12,
    dlq_count: 12,
    risk_tier: 'low',
    source: 'server',
  },
  {
    species_id: 'wrk.embed.runner',
    status: 'idle',
    pack: 'Model Ops (Pack 19)',
    capabilities: ['cap.embed.generate'],
    guarantee: 'best-effort',
    blast_score: 20,
    profile: 'prof.low-risk-autonomous',
    dispatches_today: 42,
    failures_today: 0,
    dlq_count: 0,
    risk_tier: 'low',
    source: 'server',
  },
  {
    species_id: 'wrk.doc.ocr',
    status: 'active',
    pack: 'Document Pipeline (Pack 10)',
    capabilities: ['cap.doc.ocr'],
    guarantee: 'best-effort',
    blast_score: 15,
    profile: 'prof.low-risk-autonomous',
    dispatches_today: 89,
    failures_today: 0,
    dlq_count: 0,
    risk_tier: 'low',
    source: 'server',
  },
];

window.MOCK_ALERTS = [
  {
    id: 'alert-001',
    type: 'STEWARD_HOLD_REPEATED',
    severity: 'warning',
    title: 'STEWARD HOLD — repeated',
    body: 'cap.db.write has triggered the policy gate 7 times in the last 30 minutes. All dispatches denied. Blast score: 78. Threshold: 50.',
    last_event: _ago(549),
    acknowledged: false,
  },
  {
    id: 'alert-002',
    type: 'WORKER_FAILURE_SPIKE',
    severity: 'error',
    title: 'WORKER FAILURE SPIKE',
    body: 'wrk.notify.pusher has failed 12 times in the last 10 minutes (normal: <1/hr). DLQ count: 12. Last error: "Connection refused: 127.0.0.1:5672"',
    last_event: _ago(936),
    acknowledged: false,
  },
  {
    id: 'alert-003',
    type: 'HALL_RECONNECTED',
    severity: 'info',
    title: 'HALL SERVER RECONNECTED',
    body: 'Hall was unreachable for 3m 12s. Now back online. 47 events may be missing from feed.',
    last_event: _ago(1277),
    acknowledged: false,
  },
];
