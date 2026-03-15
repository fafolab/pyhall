/* Copyright (c) 2026 pyhall.dev — https://pyhall.dev
 * All Rights Reserved.
 */
/**
 * mcp.js — MCP Configuration screen
 * Manage MCP transports, filesystem roots, execution policy,
 * sampling requests, and auto-discovery.
 *
 * Data sources (Hall Server port 8765):
 *   GET  /api/mcp/roots             — filesystem roots
 *   PUT  /api/mcp/roots             — update filesystem roots
 *   GET  /api/mcp/policy            — execution policy
 *   PUT  /api/mcp/policy            — update policy
 *   GET  /api/mcp/sampling          — pending sampling requests
 *   POST /api/mcp/sampling/<id>/respond — respond to sampling request
 *   GET  /.well-known/mcp.json      — discovery endpoint
 */

window.McpScreen = (() => {
  let roots = [];
  let policy = {};
  let samplingRequests = [];

  // ── Helpers ───────────────────────────────────────────────────────────────

  function hallUrl() {
    return window.AppState?.hallUrl || 'http://localhost:8765';
  }

  function authHeaders() {
    const token = window.AppState?.sessionToken || '';
    return token ? { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
                 : { 'Content-Type': 'application/json' };
  }

  async function apiFetch(path, options = {}) {
    const url = `${hallUrl()}${path}`;
    const res = await fetch(url, {
      headers: authHeaders(),
      ...options,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }

  function showResult(elId, msg, isError = false) {
    const el = document.getElementById(elId);
    if (!el) return;
    el.textContent = msg;
    el.style.color = isError ? 'var(--error)' : 'var(--success)';
    el.style.display = 'inline';
    setTimeout(() => { el.style.display = 'none'; }, 4000);
  }

  // ── Filesystem Roots ──────────────────────────────────────────────────────

  async function loadRoots() {
    try {
      const data = await apiFetch('/api/mcp/roots');
      roots = data.roots || [];
      renderRoots();
    } catch (e) {
      document.getElementById('mcp-roots-list').innerHTML =
        `<span style="color:var(--text-muted); font-size:12px;">Could not load roots: ${e.message}</span>`;
    }
  }

  function renderRoots() {
    const el = document.getElementById('mcp-roots-list');
    if (!el) return;
    if (roots.length === 0) {
      el.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">No filesystem roots configured. Add one below.</span>';
      return;
    }
    el.innerHTML = roots.map((r, i) => `
      <div style="display:flex; align-items:center; gap:8px; padding:6px 0; border-bottom:1px solid var(--bg-border);">
        <code style="flex:1; font-size:12px;">${esc(r.uri)}</code>
        <span style="font-size:12px; color:var(--text-muted); min-width:120px;">${esc(r.name || '')}</span>
        <button class="btn btn-ghost btn-sm" data-root-remove="${i}" style="color:var(--error);">✕</button>
      </div>
    `).join('');
    el.querySelectorAll('[data-root-remove]').forEach(btn => {
      btn.addEventListener('click', () => removeRoot(parseInt(btn.dataset.rootRemove)));
    });
  }

  async function removeRoot(idx) {
    roots = roots.filter((_, i) => i !== idx);
    await saveRoots();
  }

  async function saveRoots() {
    try {
      await apiFetch('/api/mcp/roots', {
        method: 'PUT',
        body: JSON.stringify({ roots }),
      });
      renderRoots();
    } catch (e) {
      showResult('policy-save-result', `Roots error: ${e.message}`, true);
    }
  }

  document.getElementById('btn-root-add')?.addEventListener('click', async () => {
    const uri = document.getElementById('mcp-new-root')?.value.trim();
    const label = document.getElementById('mcp-new-root-label')?.value.trim();
    if (!uri) return;
    if (!uri.startsWith('file://')) {
      showResult('policy-save-result', 'URI must start with file://', true);
      return;
    }
    roots.push({ uri, name: label || uri.replace('file://', '') });
    document.getElementById('mcp-new-root').value = '';
    document.getElementById('mcp-new-root-label').value = '';
    await saveRoots();
  });

  document.getElementById('btn-roots-reload')?.addEventListener('click', loadRoots);

  // ── Execution Policy ──────────────────────────────────────────────────────

  async function loadPolicy() {
    try {
      const data = await apiFetch('/api/mcp/policy');
      policy = data.policy || {};
      renderPolicy();
    } catch (e) {
      // fail silently — defaults remain
    }
  }

  function renderPolicy() {
    const permEl = document.getElementById('mcp-policy-permission');
    const maxEl = document.getElementById('mcp-policy-max-workers');
    const sandboxEl = document.getElementById('mcp-policy-sandbox');
    const daysEl = document.getElementById('mcp-policy-days');
    const hoursEl = document.getElementById('mcp-policy-hours');
    if (permEl) permEl.value = policy.default_permission || 'read_only';
    if (maxEl) maxEl.value = policy.max_concurrent_workers || 5;
    if (sandboxEl) sandboxEl.value = policy.sandbox_mode || 'subprocess';
    if (policy.time_window && daysEl && hoursEl) {
      daysEl.value = (policy.time_window.days || []).join(',');
      const h = policy.time_window.hours || [];
      hoursEl.value = h.length === 2 ? `${h[0]}-${h[1]}` : '';
    }
  }

  document.getElementById('btn-policy-save')?.addEventListener('click', async () => {
    const perm = document.getElementById('mcp-policy-permission')?.value || 'read_only';
    const maxW = parseInt(document.getElementById('mcp-policy-max-workers')?.value || '5');
    const sandbox = document.getElementById('mcp-policy-sandbox')?.value || 'subprocess';
    const daysStr = document.getElementById('mcp-policy-days')?.value.trim();
    const hoursStr = document.getElementById('mcp-policy-hours')?.value.trim();

    let time_window = null;
    if (daysStr) {
      const days = daysStr.split(',').map(d => d.trim().toLowerCase()).filter(Boolean);
      const hours = hoursStr ? hoursStr.split('-').map(Number).filter(n => !isNaN(n)) : null;
      time_window = { days, ...(hours && hours.length === 2 ? { hours } : {}) };
    }

    try {
      const data = await apiFetch('/api/mcp/policy', {
        method: 'PUT',
        body: JSON.stringify({
          default_permission: perm,
          max_concurrent_workers: maxW,
          sandbox_mode: sandbox,
          time_window,
        }),
      });
      policy = data.policy || policy;
      showResult('policy-save-result', 'Policy saved.');
    } catch (e) {
      showResult('policy-save-result', `Error: ${e.message}`, true);
    }
  });

  // ── Sampling Requests ─────────────────────────────────────────────────────

  async function loadSampling() {
    try {
      const data = await apiFetch('/api/mcp/sampling?status=pending');
      samplingRequests = data.requests || [];
      renderSampling();
    } catch (e) {
      // fail silently
    }
  }

  function renderSampling() {
    const el = document.getElementById('mcp-sampling-list');
    const badge = document.getElementById('mcp-sampling-badge');
    if (!el) return;

    const pending = samplingRequests.filter(r => r.status === 'pending');
    if (badge) {
      badge.style.display = pending.length > 0 ? 'inline' : 'none';
      badge.textContent = String(pending.length);
    }

    if (pending.length === 0) {
      el.innerHTML = `<div class="empty-state" style="padding:20px 0;">
        <div class="empty-state-text">No pending sampling requests.</div>
      </div>`;
      return;
    }

    el.innerHTML = pending.map(r => `
      <div class="sampling-card" id="sample-${r.id}" style="border:1px solid var(--bg-border); border-radius:6px; padding:12px; margin-bottom:8px;">
        <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">
          Request ID: ${r.id.slice(0, 8)}… · ${formatDateCT(r.created_at)}
        </div>
        <div style="font-size:12px; margin-bottom:8px;">
          ${(r.messages || []).map(m => `
            <div style="background:var(--bg-panel); padding:6px; border-radius:4px; margin-bottom:4px;">
              <strong>${esc(m.role || 'user')}:</strong> ${esc(typeof m.content === 'string' ? m.content : JSON.stringify(m.content))}
            </div>
          `).join('')}
        </div>
        ${r.system_prompt ? `<div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">System: ${esc(r.system_prompt.slice(0, 100))}…</div>` : ''}
        <div style="display:flex; gap:8px; align-items:flex-start;">
          <textarea id="sample-resp-${r.id}" rows="3" style="flex:1; font-size:12px; background:var(--bg-input); border:1px solid var(--bg-border); border-radius:4px; padding:6px; color:var(--text-primary); resize:vertical;" placeholder="Enter LLM response…"></textarea>
          <button class="btn btn-primary btn-sm" data-sample-respond="${r.id}">Respond</button>
        </div>
      </div>
    `).join('');

    el.querySelectorAll('[data-sample-respond]').forEach(btn => {
      btn.addEventListener('click', () => respondToSample(btn.dataset.sampleRespond));
    });
  }

  async function respondToSample(id) {
    const textarea = document.getElementById(`sample-resp-${id}`);
    const content = textarea?.value.trim();
    if (!content) return;
    try {
      await apiFetch(`/api/mcp/sampling/${id}/respond`, {
        method: 'POST',
        body: JSON.stringify({ content, model: 'manual-response' }),
      });
      await loadSampling();
    } catch (e) {
      showResult('policy-save-result', `Sampling error: ${e.message}`, true);
    }
  }

  document.getElementById('btn-sampling-refresh')?.addEventListener('click', loadSampling);

  // ── Auto-Discovery ────────────────────────────────────────────────────────

  document.getElementById('btn-mcp-discover')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('mcp-discovery-result');
    if (!resultEl) return;
    try {
      const data = await apiFetch('/.well-known/mcp.json');
      resultEl.textContent = JSON.stringify(data, null, 2);
      resultEl.style.display = 'block';
    } catch (e) {
      resultEl.textContent = `Error: ${e.message}`;
      resultEl.style.color = 'var(--error)';
      resultEl.style.display = 'block';
    }
  });

  // ── New SSE Session ───────────────────────────────────────────────────────

  document.getElementById('btn-mcp-sse-new')?.addEventListener('click', async () => {
    try {
      const data = await apiFetch('/api/mcp/sessions', { method: 'POST', body: '{}' });
      const statusEl = document.getElementById('mcp-sse-status');
      const sessEl = document.getElementById('mcp-sse-sessions');
      if (statusEl) statusEl.innerHTML = '<span class="badge badge-success">Active</span>';
      if (sessEl) sessEl.textContent = data.token ? data.token.slice(0, 8) + '…' : '1';
      showResult('mcp-connect-result', `SSE session created: ${data.token?.slice(0, 8)}…`);
    } catch (e) {
      showResult('mcp-connect-result', `Error: ${e.message}`, true);
    }
  });

  // ── Refresh button ────────────────────────────────────────────────────────

  document.getElementById('btn-mcp-refresh')?.addEventListener('click', refresh);

  // ── Transport label update ─────────────────────────────────────────────────

  document.getElementById('mcp-new-transport')?.addEventListener('change', (e) => {
    const label = document.getElementById('mcp-new-endpoint-label');
    const input = document.getElementById('mcp-new-endpoint');
    if (e.target.value === 'stdio') {
      if (label) label.textContent = 'Command';
      if (input) input.placeholder = 'e.g. npx @modelcontextprotocol/server-filesystem /path';
    } else {
      if (label) label.textContent = 'URL';
      if (input) input.placeholder = 'e.g. http://localhost:9090/sse';
    }
  });

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  async function refresh() {
    await Promise.allSettled([loadRoots(), loadPolicy(), loadSampling()]);
  }

  function reset() {
    if (window.AppState?.hallOnline) {
      refresh();
    }
  }

  return { refresh, reset };
})();

// ── Utilities (may already be defined globally) ────────────────────────────

if (typeof esc === 'undefined') {
  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}

if (typeof formatDateCT === 'undefined') {
  function formatDateCT(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString('en-US', { timeZone: 'America/Chicago', hour12: false });
    } catch { return iso; }
  }
}
