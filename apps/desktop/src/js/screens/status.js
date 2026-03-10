/**
 * status.js — Hall Status screen (Screen 1)
 * Shows: connection card, agent count, dispatch stats, active jobs, recent refusals, server info.
 */

window.StatusScreen = (() => {
  let lastData = null;
  let lastOnline = false;

  // ── Grace countdown banner ──────────────────────────────────────────────────
  // Ticks down locally every second; server-polled value resets it each refresh.
  let _graceSecondsRemaining = null;
  let _graceIntervalId = null;

  function _startGraceCountdown(seconds) {
    _graceSecondsRemaining = seconds;
    if (_graceIntervalId) clearInterval(_graceIntervalId);
    _graceIntervalId = setInterval(() => {
      if (_graceSecondsRemaining === null) return;
      _graceSecondsRemaining = Math.max(0, _graceSecondsRemaining - 1);
      _renderGraceBanner();
    }, 1000);
  }

  function _stopGraceCountdown() {
    if (_graceIntervalId) { clearInterval(_graceIntervalId); _graceIntervalId = null; }
    _graceSecondsRemaining = null;
  }

  function _formatHMS(totalSeconds) {
    const s = Math.max(0, Math.floor(totalSeconds));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
  }

  function _renderGraceBanner() {
    const banner = document.getElementById('grace-countdown-banner');
    if (!banner) return;
    const standing = (lastData || {}).account_standing;
    if (!standing || standing === 'ok') {
      banner.style.display = 'none';
      return;
    }
    banner.style.display = '';
    if (standing === 'grace' && _graceSecondsRemaining > 0) {
      banner.textContent = `Account verification failed. Hall goes offline in ${_formatHMS(_graceSecondsRemaining)}. Resolve your account to continue.`;
    } else {
      banner.textContent = 'Hall is in degraded mode. New dispatches are on hold. Resolve your account.';
    }
  }

  function _updateGraceBanner(data) {
    const standing = (data || {}).account_standing;
    if (!standing || standing === 'ok') {
      _stopGraceCountdown();
      _renderGraceBanner();
      return;
    }
    const remaining = (data || {}).grace_seconds_remaining;
    if (standing === 'grace' && remaining != null && remaining > 0) {
      _startGraceCountdown(remaining);
    } else {
      // degraded or expired grace — stop ticking, show static message
      _stopGraceCountdown();
      _renderGraceBanner();
    }
  }

  function renderActiveJobs(jobs) {
    const tbody = document.getElementById('active-jobs-body');
    if (!tbody) return;

    if (!jobs || jobs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px;">No active jobs</td></tr>`;
      return;
    }

    const displayed = jobs.slice(0, 10);
    const extra = jobs.length - displayed.length;

    tbody.innerHTML = displayed.map(j => {
      // Support both WCP dispatch format (worker/capability/blast_score)
      // and coord task format (owner/title/id)
      const worker     = j.worker     || j.owner   || '—';
      const capability = j.capability || j.title   || j.id || '—';
      const blast      = j.blast_score;
      const blastCell  = blast != null
        ? `<span class="blast-tier ${blastTierClass(blast)}">${blast}</span>`
        : `<span style="color:var(--text-dim)">—</span>`;
      return `
        <tr>
          <td class="mono">${formatTimeCT(j.started_at)}</td>
          <td class="mono">${esc(worker)}</td>
          <td class="mono">${esc(capability)}</td>
          <td>${blastCell}</td>
        </tr>`;
    }).join('');

    if (extra > 0) {
      tbody.innerHTML += `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); font-size:11px; padding:8px;">${extra} more active jobs</td></tr>`;
    }
  }

  function renderRecentRefusals(events) {
    const container = document.getElementById('recent-refusals');
    if (!container) return;

    const refusals = (events || [])
      .filter(e => e.decision === 'deny' || e.outcome === 'REFUSED' || e.outcome === 'STEWARD_HOLD')
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

    // Use server state machine — server reachable but locked/ready is NOT "online"
    const state = online ? (data.state || 'locked') : 'offline';
    const stateDisplay = {
      offline:  { color: 'var(--error)',   label: 'OFFLINE',  latency: 'Not reachable' },
      locked:   { color: 'var(--warning)', label: 'LOCKED',   latency: 'Log in to activate' },
      ready:    { color: '#f59e0b',         label: 'READY',    latency: 'Press Go Online to activate' },
      online:   { color: 'var(--success)', label: 'ONLINE',   latency: data.latency_ms ? `latency: ${data.latency_ms}ms` : 'latency: <5ms' },
    };
    const s = stateDisplay[state] || stateDisplay.offline;
    dot.style.color  = s.color;
    text.style.color = s.color;
    text.textContent = s.label;
    latency.textContent = s.latency;

    urlEl.textContent = data.url || window.AppState.hallUrl;

    // Stats
    const agents = online ? (data.agents ?? 0) : '—';
    const dispatches = online ? (data.dispatches_today ?? 0) : '—';
    const refusals = online ? (data.refusals_today ?? 0) : '—';

    document.getElementById('stat-workers').textContent = agents;
    document.getElementById('stat-active-jobs').textContent = online ? `${data.tasks_in_progress ?? 0} active jobs` : '— active jobs';
    document.getElementById('stat-dispatches').textContent = dispatches;
    document.getElementById('stat-refusals').textContent = `${refusals} refused`;

    // Server info panel
    const version = data.version ? `${data.version} / WCP 0.2` : 'pyhall 0.3.0 / WCP 0.2';
    document.getElementById('info-version').textContent = version;
    document.getElementById('info-uptime').textContent = formatUptime(data.uptime_seconds || 0);

    // Governance / WCP
    const wcpBadge = document.getElementById('info-wcp-badge');
    const wcpMode  = document.getElementById('info-wcp-mode');
    if (wcpBadge) {
      if (online && data.wcp_enabled) {
        wcpBadge.style.color = 'var(--success)';
        wcpBadge.textContent = '● WCP enabled';
      } else if (online) {
        wcpBadge.style.color = 'var(--text-dim)';
        wcpBadge.textContent = '○ WCP disabled';
      } else {
        wcpBadge.style.color = 'var(--text-dim)';
        wcpBadge.textContent = '—';
      }
    }
    if (wcpMode) {
      wcpMode.textContent = online && data.wcp_mode ? `${data.wcp_mode} mode` : '';
    }

    // Connected agents list
    renderAgentList(online ? (data.agents_list || []) : []);

    // Signed in as — read from config
    const config = window.AppState?.config || {};
    const signedInEl = document.getElementById('info-signed-in-user');
    if (signedInEl) {
      const sessionToken = window.AppState?.sessionToken;
      const githubLogin = window.AppState?.githubLogin;
      if (sessionToken || config.auth_token) {
        const loginLabel = githubLogin ? `@${githubLogin}` : 'authenticated';
        signedInEl.innerHTML = `<span style="color:var(--success)">● ${loginLabel}</span>
          — <a href="#" id="link-go-profile" style="color:var(--accent-hover);">view profile</a>`;
      } else {
        signedInEl.innerHTML = `<span style="color:var(--text-dim)">not logged in</span>
          — <a href="#" id="link-go-profile" style="color:var(--accent-hover);">sign in</a>`;
      }
      document.getElementById('link-go-profile')?.addEventListener('click', (e) => {
        e.preventDefault();
        if (window.navigateTo) window.navigateTo('profile');
      });
    }
  }

  function renderAgentList(agents) {
    const el = document.getElementById('status-agent-list');
    if (!el) return;
    if (!agents || agents.length === 0) {
      el.innerHTML = `<span style="color:var(--text-dim); font-size:12px;">No agents connected — agents self-register via the Hall MCP.</span>`;
      return;
    }
    el.innerHTML = agents.map(a => {
      const name = esc(a.name || a.id || '?');
      const type = esc(a.type || 'agent');
      const since = a.registered_at ? formatTimeCT(a.registered_at) : '';
      return `<span class="agent-badge" title="${type}${since ? ' · since ' + since : ''}">${name}</span>`;
    }).join('');
  }

  async function refresh() {
    const url = window.AppState.hallUrl;
    const online = window.AppState.hallOnline;

    // Active jobs — real data only, empty state when none
    let jobs = [];
    if (online) {
      try {
        const result = await HallAPI.getActiveDispatches(url);
        if (result.active && result.source !== 'offline') jobs = result.active;
      } catch (e) {}
    }
    renderActiveJobs(jobs);

    // Recent refusals — real data from dispatch feed, empty state when none
    let refusalEvents = [];
    if (online) {
      try {
        const result = await HallAPI.getDispatchFeed(url, 50);
        if (result.events) refusalEvents = result.events;
      } catch (e) {}
    }
    renderRecentRefusals(refusalEvents);

    // Hall info is kept current by onStatusUpdate on every poll — no re-render needed here.
  }

  function onStatusUpdate(data, online) {
    lastData = data;
    lastOnline = online;
    updateLogBtn(online);
    _updateGraceBanner(online ? data : {});
    // Only repaint if status screen is active
    if (document.getElementById('screen-status').classList.contains('active')) {
      renderHallInfo(data, online);
    }
  }

  // Wire refresh button
  document.getElementById('btn-refresh-status')?.addEventListener('click', refresh);

  // ── Open Log File (H10) ────────────────────────────────────────────────────
  // Show button only when Hall Server is online; clicking opens the log file.

  function updateLogBtn(online) {
    const btn = document.getElementById('btn-open-log-from-status');
    if (btn) btn.style.display = online ? '' : 'none';
  }

  document.getElementById('btn-open-log-from-status')?.addEventListener('click', async () => {
    const url = window.AppState?.hallUrl || 'http://localhost:8765';
    const pathEl = document.getElementById('status-log-path-display');
    try {
      const res = await fetch(`${url}/api/health`);
      const data = await res.json();
      const logPath = data.log_path || '';
      if (pathEl) {
        pathEl.textContent = logPath || '—';
        pathEl.style.display = logPath ? '' : 'none';
      }
      if (logPath) {
        if (window.__TAURI__?.opener?.openPath) {
          await window.__TAURI__.opener.openPath(logPath);
        } else {
          // Fallback: copy path to clipboard
          navigator.clipboard?.writeText(logPath);
          if (pathEl) pathEl.textContent = `copied: ${logPath}`;
        }
      }
    } catch (e) {
      if (pathEl) {
        pathEl.textContent = `Error: ${e}`;
        pathEl.style.display = '';
      }
    }
  });

  // Schedule active jobs refresh (every 5s when visible)
  setInterval(() => {
    if (document.getElementById('screen-status').classList.contains('active')) {
      refresh();
    }
  }, 5000);

  return { refresh, onStatusUpdate, updateLogBtn, renderGraceBanner: _renderGraceBanner };
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
