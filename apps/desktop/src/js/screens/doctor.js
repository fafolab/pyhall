/* Copyright (c) 2026 pyhall.dev — https://pyhall.dev
 * All Rights Reserved.
 */
/**
 * doctor.js — Doctor Mode screen
 * Runs 6 health checks against the Hall Server and displays results.
 * Provides an export button to download a diagnostic bundle.
 */

window.DoctorScreen = (() => {
  let lastResult = null;

  // ── Status styling ─────────────────────────────────────────────────────────

  const STATUS_COLOR = {
    ok:   '#4ec94e',
    warn: '#e5a50a',
    fail: '#f44747',
  };

  const STATUS_ICON = {
    ok:   '✓',
    warn: '⚠',
    fail: '✗',
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  function render(result, loading) {
    const container = document.getElementById('doctor-checks-list');
    const overallEl = document.getElementById('doctor-overall');
    const checkedAtEl = document.getElementById('doctor-checked-at');
    const exportBtn = document.getElementById('btn-doctor-export');

    if (!container) return;

    if (loading) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:16px 0;">Running diagnostics...</div>';
      if (overallEl) overallEl.textContent = '';
      if (checkedAtEl) checkedAtEl.textContent = '';
      return;
    }

    if (!result) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:16px 0;">No results yet. Click Run Diagnostics.</div>';
      if (overallEl) overallEl.textContent = '';
      return;
    }

    const overall = result.overall || 'unknown';
    const color = STATUS_COLOR[overall] || '#d4d4d4';
    const icon = STATUS_ICON[overall] || '?';

    if (overallEl) {
      overallEl.innerHTML = `<span style="color:${color};font-weight:700;">${icon} ${overall.toUpperCase()}</span>`;
    }

    if (checkedAtEl && result.checked_at) {
      checkedAtEl.textContent = `Checked: ${formatDateCT(result.checked_at)}`;
    }

    const CHECK_LABELS = {
      connectivity:      'Registry Connectivity',
      auth:              'Auth / Session',
      binary_integrity:  'Binary Integrity',
      hall_server:       'Hall Server Process',
      db:                'Database',
      config:            'Configuration',
    };

    const checks = result.checks || {};
    const order = ['connectivity', 'auth', 'binary_integrity', 'hall_server', 'db', 'config'];

    container.innerHTML = order.map(key => {
      const check = checks[key];
      if (!check) return '';
      const st = check.status || 'unknown';
      const c = STATUS_COLOR[st] || '#d4d4d4';
      const ic = STATUS_ICON[st] || '?';
      const label = CHECK_LABELS[key] || key;
      return `
        <div style="display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid var(--bg-border);">
          <span style="font-size:16px;color:${c};min-width:20px;text-align:center;line-height:1.4;">${ic}</span>
          <div style="flex:1;">
            <div style="font-size:13px;font-weight:600;color:var(--text-bright);">${esc(label)}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">${esc(check.message || '')}</div>
          </div>
          <span style="font-size:11px;font-weight:600;color:${c};text-transform:uppercase;padding:2px 7px;border:1px solid ${c};border-radius:3px;line-height:1.5;">${esc(st)}</span>
        </div>
      `;
    }).join('');

    if (exportBtn) exportBtn.disabled = false;
  }

  // ── Run diagnostics ────────────────────────────────────────────────────────

  async function runDiagnostics() {
    const url = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
    const runBtn = document.getElementById('btn-doctor-run');
    const exportBtn = document.getElementById('btn-doctor-export');

    if (runBtn) runBtn.disabled = true;
    if (exportBtn) exportBtn.disabled = true;
    render(null, true);

    try {
      const headers = {};
      if (window.AppState?.sessionToken) {
        headers['Authorization'] = `Bearer ${window.AppState.sessionToken}`;
      }
      const resp = await fetch(`${url}/api/doctor`, { headers });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      lastResult = await resp.json();
      render(lastResult, false);
    } catch (e) {
      const container = document.getElementById('doctor-checks-list');
      if (container) {
        container.innerHTML = `<div style="color:#f44747;font-size:13px;padding:16px 0;">Failed to reach Hall Server: ${esc(String(e))}</div>`;
      }
      const overallEl = document.getElementById('doctor-overall');
      if (overallEl) overallEl.innerHTML = '<span style="color:#f44747;font-weight:700;">✗ UNREACHABLE</span>';
    } finally {
      if (runBtn) runBtn.disabled = false;
    }
  }

  // ── Export diagnostic bundle ───────────────────────────────────────────────

  async function exportBundle() {
    const url = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
    const exportBtn = document.getElementById('btn-doctor-export');
    const exportStatus = document.getElementById('doctor-export-status');

    if (exportBtn) exportBtn.disabled = true;
    if (exportStatus) exportStatus.textContent = 'Generating bundle...';

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (window.AppState?.sessionToken) {
        headers['Authorization'] = `Bearer ${window.AppState.sessionToken}`;
      }
      const resp = await fetch(`${url}/api/doctor/export`, { method: 'POST', headers });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const bundle = await resp.json();

      // Download as JSON file
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const ts = (bundle.export_at || new Date().toISOString()).replace(/[:.]/g, '-').slice(0, 19);
      a.href = blobUrl;
      a.download = `hall-monitor-diagnostics-${ts}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);

      if (exportStatus) exportStatus.textContent = 'Bundle downloaded.';
      setTimeout(() => { if (exportStatus) exportStatus.textContent = ''; }, 3000);
    } catch (e) {
      if (exportStatus) exportStatus.textContent = `Export failed: ${esc(String(e))}`;
    } finally {
      if (exportBtn) exportBtn.disabled = false;
    }
  }

  // ── Wire up buttons ────────────────────────────────────────────────────────

  function init() {
    const runBtn = document.getElementById('btn-doctor-run');
    const exportBtn = document.getElementById('btn-doctor-export');
    if (runBtn) runBtn.addEventListener('click', runDiagnostics);
    if (exportBtn) exportBtn.addEventListener('click', exportBundle);
  }

  // ── Public interface ───────────────────────────────────────────────────────

  function onActivate() {
    // Auto-run diagnostics when screen becomes active
    runDiagnostics();
  }

  // Init on load
  init();
  render(null, false);

  return { onActivate, runDiagnostics };
})();
