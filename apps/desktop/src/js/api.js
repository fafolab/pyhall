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
    agents: 0,
    agents_list: [],
    active_jobs: 0,
    dispatches_today: 0,
    refusals_today: 0,
    uptime_seconds: 0,
    wcp_enabled: false,
    wcp_mode: null,
    latency_ms: null,
  }),

  get_dispatch_feed: () => ({
    events: [],
    source: 'offline',
  }),

  get_active_dispatches: () => ({
    active: [],
    source: 'offline',
  }),

  get_workers: () => ({
    workers: [],
    source: 'offline',
  }),

  get_alerts: () => ({
    alerts: [],
    source: 'offline',
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

  // ── MCP Server management ────────────────────────────────────────────────

  /** List all registered MCP servers */
  async listMcpServers() {
    const url = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
    const r = await fetch(`${url}/api/mcp/servers`, {
      headers: window.AppState?.sessionToken
        ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` }
        : {},
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  },

  /** Register a new MCP server */
  async addMcpServer(data) {
    const url = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
    const r = await fetch(`${url}/api/mcp/servers`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(window.AppState?.sessionToken ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` } : {}),
      },
      body: JSON.stringify(data),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.reason || d.error || `HTTP ${r.status}`);
    }
    return r.json();
  },

  /** Remove a registered MCP server by ID */
  async removeMcpServer(id) {
    const url = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
    const r = await fetch(`${url}/api/mcp/servers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: window.AppState?.sessionToken
        ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` }
        : {},
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.reason || d.error || `HTTP ${r.status}`);
    }
    return r.json();
  },

  /** Ping an MCP server to refresh its status */
  async pingMcpServer(id) {
    const url = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
    const r = await fetch(`${url}/api/mcp/servers/${encodeURIComponent(id)}/ping`, {
      method: 'POST',
      headers: window.AppState?.sessionToken
        ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` }
        : {},
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.reason || d.error || `HTTP ${r.status}`);
    }
    return r.json();
  },
};

// ─── Shared app state ──────────────────────────────────────────────────────

window.AppState = {
  hallOnline: false,
  hallUrl: 'http://localhost:8765',
  config: null,
  sessionToken: null,   // auth token — session memory only, never written to disk
  agentCount: 0,
  dispatchesToday: 0,
  refusalsToday: 0,
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

// ─── DEMO_MODE ─────────────────────────────────────────────────────────────
// Set to true only for live product demos. All screens show clean empty
// states when Hall is offline. NEVER enable in production builds.
window.DEMO_MODE = false;

