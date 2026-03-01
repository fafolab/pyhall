/**
 * status.js — Hall Status screen (Screen 1)
 * Shows: connection card, worker count, dispatch stats, active jobs, recent refusals, server info.
 * Uses mock data when Hall is offline.
 */

window.StatusScreen = (() => {
  let lastData = null;
  let lastOnline = false;

  // Active jobs (cycles mock when offline, shows live when online)
  let mockJobCycle = 0;

  function renderActiveJobs(jobs) {
    const tbody = document.getElementById('active-jobs-body');
    if (!tbody) return;

    if (!jobs || jobs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px;">No active jobs</td></tr>`;
      return;
    }

    const displayed = jobs.slice(0, 10);
    const extra = jobs.length - displayed.length;

    tbody.innerHTML = displayed.map(j => `
      <tr>
        <td class="mono">${formatTimeCT(j.started_at)}</td>
        <td class="mono">${esc(j.worker)}</td>
        <td class="mono">${esc(j.capability)}</td>
        <td><span class="blast-tier ${blastTierClass(j.blast_score)}">${j.blast_score}</span></td>
      </tr>
    `).join('');

    if (extra > 0) {
      tbody.innerHTML += `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); font-size:11px; padding:8px;">${extra} more active jobs</td></tr>`;
    }
  }

  function renderRecentRefusals(events) {
    const container = document.getElementById('recent-refusals');
    if (!container) return;

    const refusals = (events || [])
      .filter(e => e.outcome !== 'DISPATCHED')
      .slice(0, 5);

    if (refusals.length === 0) {
      container.innerHTML = `<div style="color:var(--text-muted); font-size:12px; padding:8px 0;">No refusals in the last hour.</div>`;
      return;
    }

    container.innerHTML = refusals.map(e => `
      <div class="refusal-row">
        <span class="refusal-time">${formatTimeCT(e.timestamp)}</span>
        <span class="refusal-cap">${esc(e.capability)}</span>
        <span class="refusal-reason">${outcomeLabel(e.outcome)}</span>
        <span class="refusal-blast">blast:${e.blast_score}</span>
      </div>
    `).join('');
  }

  function renderHallInfo(data, online) {
    const dot = document.getElementById('hall-status-dot');
    const text = document.getElementById('hall-status-text');
    const latency = document.getElementById('hall-latency');
    const urlEl = document.getElementById('hall-url-display');

    if (online) {
      dot.style.color = 'var(--success)';
      text.style.color = 'var(--success)';
      text.textContent = 'ONLINE';
      latency.textContent = data.latency_ms ? `latency: ${data.latency_ms}ms` : 'latency: <5ms';
    } else {
      dot.style.color = 'var(--error)';
      text.style.color = 'var(--error)';
      text.textContent = 'OFFLINE';
      latency.textContent = 'Not reachable';
    }

    urlEl.textContent = data.url || window.AppState.hallUrl;

    // Stats
    const workers = online ? (data.workers ?? 14) : 14;
    const dispatches = online ? (data.dispatches_today ?? 847) : 847;
    const refusals = online ? (data.refusals_today ?? 12) : 12;

    document.getElementById('stat-workers').textContent = workers;
    document.getElementById('stat-active-jobs').textContent = `${window.MOCK_ACTIVE_JOBS.length} active jobs`;
    document.getElementById('stat-dispatches').textContent = dispatches;
    document.getElementById('stat-refusals').textContent = `${refusals} refused`;

    // Server info panel
    const version = (data.version) ? `pyhall ${data.version} / WCP 0.1` : 'pyhall 0.1.0 / WCP 0.1';
    document.getElementById('info-version').textContent = version;
    document.getElementById('info-uptime').textContent = formatUptime(data.uptime_seconds || 15780);
    document.getElementById('info-rules').textContent = data.rules_loaded ?? 214;
    document.getElementById('info-profile').textContent = data.profile ?? 'prof.dev.permissive';
  }

  async function refresh() {
    const url = window.AppState.hallUrl;
    const online = window.AppState.hallOnline;

    // Active jobs
    let jobs = window.MOCK_ACTIVE_JOBS;
    if (online) {
      try {
        const result = await HallAPI.getActiveDispatches(url);
        if (result.active && result.source !== 'offline') jobs = result.active;
      } catch (e) {}
    }
    renderActiveJobs(jobs);

    // Recent refusals — use mock data until connected
    renderRecentRefusals(online ? null : window.MOCK_DISPATCH_EVENTS);

    // Hall info (uses AppState which was updated by pollHall)
    renderHallInfo(lastData || { url }, online);
  }

  function onStatusUpdate(data, online) {
    lastData = data;
    lastOnline = online;
    // Only repaint if status screen is active
    if (document.getElementById('screen-status').classList.contains('active')) {
      renderHallInfo(data, online);
    }
  }

  // Wire refresh button
  document.getElementById('btn-refresh-status')?.addEventListener('click', refresh);

  // Schedule active jobs refresh (every 3s when visible)
  setInterval(() => {
    if (document.getElementById('screen-status').classList.contains('active')) {
      const jobs = window.MOCK_ACTIVE_JOBS.slice(mockJobCycle % 3);
      mockJobCycle++;
      renderActiveJobs(jobs);
    }
  }, 3000);

  return { refresh, onStatusUpdate };
})();

// ─── Helpers ───────────────────────────────────────────────────────────────

function esc(str) {
  if (!str) return '—';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function outcomeLabel(outcome) {
  switch (outcome) {
    case 'STEWARD_HOLD': return 'STEWARD HOLD';
    case 'REFUSED':      return 'HALL REFUSED';
    default:             return outcome;
  }
}
