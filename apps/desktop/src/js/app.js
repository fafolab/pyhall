/* Copyright (c) 2026 pyhall.dev — https://pyhall.dev
 * All Rights Reserved.
 */
/**
 * app.js — Main application logic
 * - Navigation / screen switching
 * - Global poll loop
 * - Status bar + header updates
 * - Tauri event listener (tray nav)
 */

// ─── Navigation ────────────────────────────────────────────────────────────

const SCREENS = ['status', 'feed', 'crew', 'alerts', 'coordination', 'profile', 'enroll', 'config', 'doctor', 'about'];

function navigateTo(screen) {
  if (!SCREENS.includes(screen)) return;

  // Update nav items
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.screen === screen);
  });

  // Show/hide screens
  document.querySelectorAll('.screen').forEach(el => {
    el.classList.toggle('active', el.id === `screen-${screen}`);
  });

  // Notify coordination screen when navigating away (stops SSE + poll)
  if (screen !== 'coordination' && window.CoordinationScreen) {
    window.CoordinationScreen.onHide();
  }

  // Trigger screen-specific init
  const handlers = {
    status:       () => window.StatusScreen && window.StatusScreen.refresh(),
    feed:         () => window.FeedScreen && window.FeedScreen.onShow(),
    crew:         () => window.CrewScreen && window.CrewScreen.refresh(),
    alerts:       () => window.AlertsScreen && window.AlertsScreen.refresh(),
    coordination: () => window.CoordinationScreen && window.CoordinationScreen.onShow(),
    profile:      () => window.ProfileScreen && window.ProfileScreen.init(),
    enroll:       () => window.EnrollScreen && window.EnrollScreen.reset(),
    config:       () => window.ConfigScreen && window.ConfigScreen.load(),
    doctor:       () => window.DoctorScreen && window.DoctorScreen.onActivate(),
    about:        () => _refreshAboutScreen(),
  };
  if (handlers[screen]) handlers[screen]();
}

// Wire nav clicks
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => navigateTo(el.dataset.screen));
});

// Wire config tab chip active states
document.querySelectorAll('[data-config-tab]').forEach(chip => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('[data-config-tab]').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
  });
});

// Cross-screen navigation buttons
document.getElementById('btn-go-config-from-status')?.addEventListener('click', () => navigateTo('config'));
document.getElementById('btn-go-feed-from-status')?.addEventListener('click', () => navigateTo('feed'));
document.getElementById('btn-go-online-status')?.addEventListener('click', () => window.goOnline && window.goOnline());
document.getElementById('btn-go-offline-status')?.addEventListener('click', () => window.goOffline && window.goOffline());
document.getElementById('btn-go-enroll')?.addEventListener('click', () => navigateTo('enroll'));
document.getElementById('btn-view-crew')?.addEventListener('click', () => navigateTo('crew'));

// ─── Status bar clock ──────────────────────────────────────────────────────

function updateClock() {
  const clockEl = document.getElementById('clock');
  if (!clockEl) return;
  const now = new Date().toLocaleString('en-US', {
    timeZone: 'America/Chicago',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  clockEl.textContent = now.replace(',', '') + ' CT';
}

setInterval(updateClock, 10000);
updateClock();

// ─── Hall status update (header + status bar) ──────────────────────────────

function updateConnectionUI(online, data = {}) {
  // State machine: offline → locked → ready → online
  // online=false                      → OFFLINE  (red)
  // online=true, state=locked         → LOCKED   (yellow, not logged in)
  // online=true, state=ready          → READY    (amber, logged in, press Go Online)
  // online=true, state=online         → ONLINE   (green, fully operational)

  const state = online ? (data.state || 'locked') : 'offline';
  window.AppState.hallOnline = (state === 'online');
  window.AppState.hallState  = state;
  window.AppState.loggedIn   = data.logged_in || false;
  // Cache github_login from health response so status screen can display it
  if (data.github_login && !window.AppState.githubLogin) {
    window.AppState.githubLogin = data.github_login;
    window.AppState.githubAvatar = `https://github.com/${data.github_login}.png`;
  }

  const indicator = document.getElementById('hall-indicator');
  const indicatorLabel = document.getElementById('hall-indicator-label');
  const sbStatus = document.getElementById('sb-hall-status');

  const stateMap = {
    offline:  { cls: 'offline',    label: 'OFFLINE', sbCls: 'status-offline'  },
    locked:   { cls: 'locked',     label: 'LOCKED',  sbCls: 'status-locked'   },
    ready:    { cls: 'ready',      label: 'READY',   sbCls: 'status-ready'    },
    online:   { cls: 'online',     label: 'ONLINE',  sbCls: 'status-online'   },
    connecting:{ cls: 'connecting',label: 'RESTARTING...', sbCls: 'status-connecting' },
  };
  const s = stateMap[state] || stateMap.offline;
  if (indicator) indicator.className = `hall-indicator ${s.cls}`;
  if (indicatorLabel) indicatorLabel.textContent = s.label;
  if (sbStatus) { sbStatus.className = s.sbCls; sbStatus.textContent = s.label; }

  // Update dropdown options based on state
  _updateRestartDropdown(state, data);
  if (window._updateServerBtns) window._updateServerBtns(state);

  // Status bar counters
  if (state === 'online') {
    if (data.agents !== undefined) window.AppState.agentCount = data.agents;
    if (data.dispatches_today !== undefined) window.AppState.dispatchesToday = data.dispatches_today;
    if (data.refusals_today !== undefined) window.AppState.refusalsToday = data.refusals_today;
    document.getElementById('sb-workers').textContent = `${window.AppState.agentCount} agents`;
    document.getElementById('sb-dispatches').textContent = `${window.AppState.dispatchesToday} dispatches today`;
  } else {
    document.getElementById('sb-workers').textContent = '—';
    document.getElementById('sb-dispatches').textContent = '—';
  }
}

function _updateRestartDropdown(state, data) {
  const goOnlineBtn   = document.getElementById('btn-go-online');
  const goOfflineBtn  = document.getElementById('btn-go-offline');
  const logoutRestartBtn = document.getElementById('btn-logout-restart');
  const logoutOnlyBtn = document.getElementById('btn-logout-only');
  const lockedMsg     = document.getElementById('hall-locked-msg');
  if (!goOnlineBtn) return;

  // Show/hide based on state
  lockedMsg.style.display     = (state === 'locked')  ? '' : 'none';
  goOnlineBtn.style.display   = (state === 'ready')   ? '' : 'none';
  goOfflineBtn.style.display  = (state === 'online')  ? '' : 'none';
  logoutRestartBtn.style.display = (state !== 'offline') ? '' : 'none';
  logoutOnlyBtn.style.display    = (state !== 'offline' && state !== 'locked') ? '' : 'none';
}

// ─── Alert badge ───────────────────────────────────────────────────────────

function updateAlertBadge(count) {
  window.AppState.alertCount = count;
  const badge = document.getElementById('alert-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = 'inline';
  } else {
    badge.style.display = 'none';
  }
}

window.updateAlertBadge = updateAlertBadge;
window.updateConnectionUI = updateConnectionUI;
window.navigateTo = navigateTo;

// ─── Start / Stop Hall Server ───────────────────────────────────────────────

(function wireServerStartStop() {
  const startBtn = document.getElementById('btn-start-server');
  const stopBtn  = document.getElementById('btn-stop-server');
  const msgEl    = document.getElementById('status-server-start-msg');

  // Show Start when offline, Stop when server was started by us
  window._serverStartedByUs = false;

  window._updateServerBtns = function(state) {
    if (!startBtn) return;
    const isOffline = (state === 'offline');
    const isRunning = (state === 'locked' || state === 'ready' || state === 'online');
    const isOnline  = (state === 'online');

    // Start/Restart button
    startBtn.style.display = (isOffline || isRunning) ? '' : 'none';
    startBtn.textContent = isOffline ? 'Start Hall Server' : 'Restart Server';

    // Stop button (only if we started it)
    stopBtn.style.display = (isRunning && window._serverStartedByUs) ? '' : 'none';

    // Go Online (show when server is running but not online)
    const goOnlineBtn = document.getElementById('btn-go-online-status');
    if (goOnlineBtn) goOnlineBtn.style.display = (isRunning && !isOnline) ? '' : 'none';

    // Go Offline (show when fully online)
    const goOfflineBtn = document.getElementById('btn-go-offline-status');
    if (goOfflineBtn) goOfflineBtn.style.display = isOnline ? '' : 'none';
  };

  startBtn?.addEventListener('click', async () => {
    const wasLabel = startBtn.textContent;
    startBtn.disabled = true;
    startBtn.textContent = wasLabel === 'Restart Server' ? 'Restarting…' : 'Starting…';
    if (msgEl) { msgEl.textContent = 'Starting Hall Server…'; msgEl.style.display = ''; }

    try {
      await window.__TAURI__.core.invoke('start_hall_server_sidecar');
      window._serverStartedByUs = true;

      // Poll until server responds (up to 15s)
      let attempts = 0;
      const check = setInterval(async () => {
        attempts++;
        try {
          const r = await fetch(`${window.AppState?.hallUrl || 'http://localhost:8765'}/api/health`);
          if (r.ok) {
            clearInterval(check);
            if (msgEl) msgEl.style.display = 'none';
            startBtn.disabled = false;
            window.pollHall && window.pollHall();
            // Server is now running — show passphrase gate so user can unlock
            // (the passphrase gate transitions: first-time setup or unlock existing)
            if (window.AppState?.sessionToken) {
              _showPassphraseGate();
            }
          }
        } catch (_) {}
        if (attempts >= 15) {
          clearInterval(check);
          startBtn.disabled = false;
          startBtn.textContent = wasLabel;
          if (msgEl) { msgEl.textContent = 'Server did not respond after 15s. Check config.'; }
        }
      }, 1000);

    } catch (e) {
      startBtn.disabled = false;
      startBtn.textContent = wasLabel;
      if (msgEl) { msgEl.textContent = `Error: ${e}`; msgEl.style.display = ''; }
    }
  });

  stopBtn?.addEventListener('click', async () => {
    try {
      await window.__TAURI__.core.invoke('stop_hall_server');
      window._serverStartedByUs = false;
      if (msgEl) { msgEl.textContent = 'Server stopped.'; msgEl.style.display = ''; setTimeout(() => { if (msgEl) msgEl.style.display = 'none'; }, 3000); }
      window.pollHall && window.pollHall();
    } catch (e) {
      if (msgEl) { msgEl.textContent = `Stop error: ${e}`; msgEl.style.display = ''; }
    }
  });
})();

// ─── Hall indicator click → server/auth dropdown ───────────────────────────

(function wireRestartDropdown() {
  const indicator = document.getElementById('hall-indicator');
  if (!indicator) return;

  indicator.style.cursor = 'pointer';
  indicator.title = 'Server options';

  // Dropdown:
  //   Start Server   (disabled when server is running)
  //   Restart Server (disabled when server is offline)
  //   ─────────────
  //   Log Out        (stops server + logout → login screen)
  //   Log Out, Exit App
  const dropdown = document.createElement('div');
  dropdown.id = 'hall-restart-dropdown';
  dropdown.className = 'hall-restart-dropdown hidden';
  dropdown.innerHTML = `
    <div class="hall-restart-item" id="btn-dd-start-server">Start Server</div>
    <div class="hall-restart-item" id="btn-dd-restart-server">Restart Server</div>
    <div class="hall-restart-divider"></div>
    <div class="hall-restart-item danger" id="btn-dd-logout">Log Out</div>
    <div class="hall-restart-item danger" id="btn-dd-logout-exit">Log Out, Exit App</div>
  `;
  document.getElementById('header-status').appendChild(dropdown);

  indicator.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('hidden');
  });
  document.addEventListener('click', () => dropdown.classList.add('hidden'));

  // ── Internal helpers ──────────────────────────────────────────────────────

  async function _stopServer() {
    try { await window.__TAURI__.core.invoke('stop_hall_server'); } catch (_) {}
    // Also ask Hall Server to clear its state (best-effort)
    const url = window.AppState?.hallUrl || 'http://localhost:8765';
    try { await fetch(`${url}/api/auth/logout`, { method: 'POST', signal: AbortSignal.timeout(1500) }); } catch (_) {}
    window._serverStartedByUs = false;
  }

  async function _clearSession() {
    window.AppState.sessionToken = null;
    window.AppState.githubLogin  = null;
    window.AppState.githubAvatar = null;
    window.AppState.hallState    = 'offline';
    window.AppState.hallOnline   = false;
    window.AppState.loggedIn     = false;
  }

  function _showLoginGate() {
    const gate = document.getElementById('login-gate');
    if (gate) gate.style.display = 'flex';
    // Re-enable login button in case it was waiting
    const btn = document.getElementById('btn-login-gate-github');
    if (btn) { btn.disabled = false; btn.textContent = 'Sign in with GitHub'; }
    window.pollHall && window.pollHall();
  }

  // ── Start Server ──────────────────────────────────────────────────────────
  document.getElementById('btn-dd-start-server').addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.add('hidden');
    if (window.AppState?.hallState !== 'offline') return; // already running
    // Delegate to the start button logic already wired in wireServerStartStop()
    document.getElementById('btn-start-server')?.click();
  });

  // ── Restart Server ────────────────────────────────────────────────────────
  document.getElementById('btn-dd-restart-server').addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.add('hidden');
    if (window.AppState?.hallState === 'offline') return; // not running
    document.getElementById('btn-start-server')?.click();
  });

  // ── Log Out ───────────────────────────────────────────────────────────────
  document.getElementById('btn-dd-logout').addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.add('hidden');
    await _stopServer();
    await _clearSession();
    setPassphraseGate(false);
    _showLoginGate();
  });

  // ── Log Out, Exit App ─────────────────────────────────────────────────────
  document.getElementById('btn-dd-logout-exit').addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.add('hidden');
    await _stopServer();
    await _clearSession();
    if (window.__TAURI__?.core?.invoke) {
      window.__TAURI__.core.invoke('exit_app').catch(() => window.__TAURI__.process?.exit(0));
    }
  });

  // ── Keep dropdown items enabled/disabled based on server state ────────────
  const _origUpdate = window._updateRestartDropdown || (() => {});
  window._updateRestartDropdown = function(state, data) {
    _origUpdate(state, data);

    const startBtn   = document.getElementById('btn-dd-start-server');
    const restartBtn = document.getElementById('btn-dd-restart-server');
    if (!startBtn) return;

    const isOffline = (state === 'offline');
    // Show "Start Server" only when offline; show "Restart Server" only when running
    startBtn.style.display   = isOffline ? '' : 'none';
    restartBtn.style.display = isOffline ? 'none' : '';
  };
})();

// ── Go Online / Go Offline — exposed globally for status screen ─────────────

window.goOnline = async function() {
  if (!window.AppState?.sessionToken) {
    alert('Not logged into registry. Use "Log In" to authenticate with pyhall.dev first.');
    return;
  }
  const url = window.AppState?.hallUrl || 'http://localhost:8765';
  const body = {};
  if (window.AppState?.desktopBinaryHash) body.desktop_hash = window.AppState.desktopBinaryHash;
  try {
    const r = await fetch(`${url}/api/server/go-online`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${window.AppState.sessionToken}`,
      },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!d.ok) { alert(`Cannot go online: ${d.message || 'unknown error'}`); return; }
  } catch (_) {}
  window.pollHall && window.pollHall();
};

window.goOffline = async function() {
  const url = window.AppState?.hallUrl || 'http://localhost:8765';
  try { await fetch(`${url}/api/server/go-offline`, { method: 'POST' }); } catch (_) {}
  window.pollHall && window.pollHall();
};

// ─── Global poll loop ──────────────────────────────────────────────────────

async function pollHall() {
  const url = window.AppState.hallUrl;

  try {
    const status = await HallAPI.getHallStatus(url);

    // HTTP succeeded — server is reachable.
    // Map server-internal "offline" state (not registry-connected) to "locked"
    // so the UI state machine reflects reachability correctly.
    // "offline" in the UI is reserved for when the HTTP call fails entirely.
    if (!status.state || status.state === 'offline') {
      status.state = 'locked';
    }
    const online = (status.state === 'online');
    updateConnectionUI(true, status);

    // Cache Hall Server version for About screen
    if (status.version) window.AppState.hallVersion = status.version;

    // Forward status to status screen
    if (window.StatusScreen) {
      window.StatusScreen.onStatusUpdate(status, true);
    }

    // Poll alerts for badge update — 0 when offline, no mock fallback
    const alertsData = await HallAPI.getAlerts(url);
    const alerts = (alertsData.source !== 'offline' && alertsData.source !== 'mock')
      ? (alertsData.alerts || []) : [];
    const unresolved = alerts.filter(a => !a.acknowledged).length;
    updateAlertBadge(unresolved);

  } catch (err) {
    console.warn('Poll error:', err);
    updateConnectionUI(false);
  }
}

async function startPollLoop() {
  // Load config first
  try {
    const cfg = await HallAPI.readConfig();
    window.AppState.config = cfg;
    window.AppState.hallUrl = cfg.hall_url || 'http://localhost:8765';
    window.AppState.pollMs = (cfg.poll_interval || 3) * 1000;

    // Update URL display
    document.getElementById('hall-url-display').textContent = window.AppState.hallUrl;
    document.getElementById('cfg-hall-url').value = window.AppState.hallUrl;
  } catch (e) {
    console.warn('Config load failed, using defaults');
  }

  // Initial poll
  await pollHall();

  // Set interval (if not manual-only)
  if (window.AppState.pollMs > 0) {
    window.AppState.pollInterval = setInterval(pollHall, window.AppState.pollMs);
  }
}

function restartPollLoop(ms) {
  if (window.AppState.pollInterval) {
    clearInterval(window.AppState.pollInterval);
    window.AppState.pollInterval = null;
  }
  window.AppState.pollMs = ms;
  if (ms > 0) {
    pollHall(); // immediate
    window.AppState.pollInterval = setInterval(pollHall, ms);
  }
}

window.restartPollLoop = restartPollLoop;

// ─── Tauri event listeners ─────────────────────────────────────────────────

if (typeof window.__TAURI__ !== 'undefined') {
  try {
    // Tray navigation
    window.__TAURI__.event.listen('navigate', (event) => {
      navigateTo(event.payload);
    });

    // X button: stop server + logout + exit
    window.__TAURI__.event.listen('app_close_requested', async () => {
      try { await window.__TAURI__.core.invoke('stop_hall_server'); } catch (_) {}
      const url = window.AppState?.hallUrl || 'http://localhost:8765';
      try { await fetch(`${url}/api/auth/logout`, { method: 'POST', signal: AbortSignal.timeout(1000) }); } catch (_) {}
      window.__TAURI__.core.invoke('exit_app').catch(() => {});
    });
  } catch (e) {
    console.warn('Tauri event listener not available:', e);
  }
}

// ─── Auth gates ────────────────────────────────────────────────────────────

/**
 * Show or hide the login gate overlay.
 * When shown, all app chrome is rendered but invisible behind the overlay.
 */
function setLoginGate(show) {
  const gate = document.getElementById('login-gate');
  if (!gate) return;
  gate.style.display = show ? 'flex' : 'none';
}

/**
 * Show or hide the passphrase gate overlay.
 */
function setPassphraseGate(show) {
  const gate = document.getElementById('passphrase-gate');
  if (!gate) return;
  gate.style.display = show ? 'flex' : 'none';
}

/**
 * Check if the user's pyhall.dev account is fully set up.
 * Calls registry /api/v1/me and /api/v1/namespaces directly.
 * Returns { complete: bool, missing: string[] }
 */
async function checkAccountComplete(token) {
  const missing = [];
  try {
    const [meRes, nsRes] = await Promise.all([
      fetch('https://api.pyhall.dev/api/v1/me', {
        headers: { 'Authorization': `Bearer ${token}` },
        signal: AbortSignal.timeout(5000),
      }),
      fetch('https://api.pyhall.dev/api/v1/namespaces', {
        headers: { 'Authorization': `Bearer ${token}` },
        signal: AbortSignal.timeout(5000),
      }),
    ]);

    if (meRes.ok) {
      const me = await meRes.json();
      if (!me.email_contact) missing.push('Add a contact email to your account');
      else if (!me.email_verified) missing.push('Verify your contact email address');
    }

    if (nsRes.ok) {
      const ns = await nsRes.json();
      if (!ns || ns.length === 0) missing.push('Claim at least one namespace (x.yourname or org.yourname)');
    }
  } catch (_) {
    // Network error — let them through rather than blocking on connectivity
    return { complete: true, missing: [] };
  }

  return { complete: missing.length === 0, missing };
}

/**
 * Called once login is confirmed (token received from registry).
 * Checks account completeness first — shows incomplete screen if needed.
 * If complete: hides login gate, shows passphrase gate or status.
 */
async function onLoginConfirmed() {
  const token = window.AppState?.sessionToken;

  // Check account completeness before letting them past the gate
  const { complete, missing } = await checkAccountComplete(token);
  if (!complete) {
    // Show incomplete panel with specific items missing
    const listEl = document.getElementById('gate-incomplete-list');
    if (listEl) listEl.innerHTML = missing.map(m => `• ${m}`).join('<br>');
    _showGatePanel('incomplete');
    return;
  }

  setLoginGate(false);

  // Fetch GitHub identity for display (uses registry directly if Hall is offline)
  _fetchAndShowIdentity();

  // Check if Hall Server is reachable. If yes, show passphrase gate.
  // If no, go straight to status — user can start Hall Server from there.
  const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';
  fetch(`${hallUrl}/api/health`, { signal: AbortSignal.timeout(1500) })
    .then(r => { if (r.ok) _showPassphraseGate(); else navigateTo('status'); })
    .catch(() => navigateTo('status'));
}

async function _fetchAndShowIdentity() {
  const token = window.AppState?.sessionToken;
  if (!token) return;
  const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';

  let login = null;
  try {
    // Try Hall Server proxy first (works when server is running)
    const r = await fetch(`${hallUrl}/api/profile`, {
      headers: { 'Authorization': `Bearer ${token}` },
      signal: AbortSignal.timeout(1500),
    });
    if (r.ok) {
      const d = await r.json();
      login = (d.profile?.github_login) || d.github_login;
    }
  } catch (_) {}

  if (!login) {
    // Fallback: call registry directly (Hall Server not running)
    try {
      const r = await fetch('https://api.pyhall.dev/api/v1/me', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (r.ok) {
        const d = await r.json();
        login = d.github_login;
      }
    } catch (_) {}
  }

  if (!login) return;
  const avatarEl = document.getElementById('passphrase-avatar');
  const loginEl  = document.getElementById('passphrase-github-login');
  if (avatarEl) {
    avatarEl.src = `https://github.com/${login}.png?size=72`;
    avatarEl.style.display = 'block';
  }
  if (loginEl) loginEl.textContent = login;
  window.AppState.githubLogin = login;
  window.AppState.githubAvatar = `https://github.com/${login}.png`;
}

// Tracks whether the passphrase was unset when the gate was shown.
// Used by onPassphraseAccepted() to decide whether to show the setup wizard.
let _firstTimeSetup = false;

async function _showPassphraseGate() {
  const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';

  // Try to ask the server whether a passphrase has been set.
  // Default: assume first run (show set form). Only show unlock if server explicitly confirms passphrase_set: true.
  let passphraseSet = false;
  try {
    const r = await fetch(`${hallUrl}/api/auth/passphrase-status`, {
      headers: window.AppState.sessionToken
        ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` }
        : {},
    });
    if (r.ok) {
      const d = await r.json();
      passphraseSet = d.passphrase_set === true;
    }
  } catch (_) {}

  _firstTimeSetup = !passphraseSet;

  if (!passphraseSet) {
    // First-time: show set-passphrase form immediately
    _switchPassphraseForm('set');
  } else {
    _switchPassphraseForm('unlock');
  }

  setPassphraseGate(true);
}

function _switchPassphraseForm(which) {
  const forms = {
    'unlock':        document.getElementById('passphrase-unlock-form'),
    'set':           document.getElementById('passphrase-set-form'),
    'reset-request': document.getElementById('passphrase-reset-request-form'),
    'reset-confirm': document.getElementById('passphrase-reset-confirm-form'),
  };
  Object.entries(forms).forEach(([key, el]) => {
    if (el) el.style.display = (key === which) ? 'block' : 'none';
  });
  // Clear inputs and errors on switch
  ['passphrase-input', 'passphrase-new', 'passphrase-new-confirm',
   'passphrase-reset-token', 'passphrase-reset-new', 'passphrase-reset-confirm'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['passphrase-unlock-error', 'passphrase-set-error',
   'passphrase-reset-error', 'passphrase-reset-confirm-error'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
}

/**
 * Called once the passphrase is accepted — reveal the full app.
 * If this was a first-time setup (passphrase_set was false), show the setup wizard.
 * Otherwise navigate straight to the status screen.
 */
function onPassphraseAccepted() {
  setPassphraseGate(false);
  if (_firstTimeSetup) {
    _firstTimeSetup = false; // consume the flag
    window.SetupWizard && window.SetupWizard.show();
  } else {
    navigateTo('status');
  }
  // Auto go-online immediately after unlock (if logged into registry)
  if (window.AppState?.sessionToken) {
    setTimeout(() => window.goOnline && window.goOnline(), 300);
  }
}

window.onLoginConfirmed   = onLoginConfirmed;
window.onPassphraseAccepted = onPassphraseAccepted;

// ─── Login gate panel switching ────────────────────────────────────────────

function _showGatePanel(name) {
  ['welcome', 'new-user', 'login', 'incomplete'].forEach(p => {
    const el = document.getElementById(`gate-panel-${p}`);
    if (el) el.style.display = (p === name) ? '' : 'none';
  });
  // Animate login worker on panel transitions
  const loginWorker = document.getElementById('login-worker');
  if (loginWorker && window.WorkerWidget) {
    WorkerWidget.setAnimation(loginWorker, 'anim-enter');
    setTimeout(() => WorkerWidget.setAnimation(loginWorker, 'anim-float'), 750);
  }
}

// Ensure welcome panel is shown first (default)
_showGatePanel('welcome');

// Welcome → new user
document.getElementById('btn-gate-new-user')?.addEventListener('click', () => _showGatePanel('new-user'));

// Welcome → login
document.getElementById('btn-gate-has-account')?.addEventListener('click', () => _showGatePanel('login'));

// New user → back
document.getElementById('btn-gate-new-user-back')?.addEventListener('click', () => _showGatePanel('welcome'));

// New user → create account online
document.getElementById('btn-gate-create-account')?.addEventListener('click', () => {
  const url = 'https://pyhall.dev/signup';
  if (window.__TAURI__?.opener?.openUrl) {
    window.__TAURI__.opener.openUrl(url).catch(() => window.open(url, '_blank'));
  } else {
    window.open(url, '_blank');
  }
});

// Login → back
document.getElementById('btn-gate-login-back')?.addEventListener('click', () => _showGatePanel('welcome'));

// Incomplete → complete setup online
document.getElementById('btn-gate-complete-setup')?.addEventListener('click', () => {
  const url = 'https://pyhall.dev/account/setup';
  if (window.__TAURI__?.opener?.openUrl) {
    window.__TAURI__.opener.openUrl(url).catch(() => window.open(url, '_blank'));
  } else {
    window.open(url, '_blank');
  }
});

// Incomplete → back to sign in
document.getElementById('btn-gate-incomplete-back')?.addEventListener('click', () => {
  window.AppState.sessionToken = null;
  _showGatePanel('login');
  // Reset GitHub button in case it was in waiting state
  const ghBtn = document.getElementById('btn-login-gate-github');
  if (ghBtn) { ghBtn.disabled = false; ghBtn.textContent = 'Sign in with GitHub'; }
});

// ─── Login gate wiring ─────────────────────────────────────────────────────

(function wireLoginGate() {
  const btn = document.getElementById('btn-login-gate-github');
  if (!btn) return;

  // New flow: desktop generates a UUID session_id, includes it in the OAuth URL.
  // After GitHub auth, registry stores JWT keyed by session_id (no localhost redirect).
  // Desktop polls api.pyhall.dev/auth/desktop-poll?session=<id> directly.
  // Hall Server does NOT need to be running for login.

  let _loginPollInterval = null;

  btn.addEventListener('click', () => {
    // Generate unique session ID for this login attempt
    const sessionId = crypto.randomUUID();
    const oauthUrl = `https://api.pyhall.dev/auth/github?desktop=1&session=${sessionId}`;

    if (window.__TAURI__?.opener?.openUrl) {
      window.__TAURI__.opener.openUrl(oauthUrl).catch(() => window.open(oauthUrl, '_blank'));
    } else {
      window.open(oauthUrl, '_blank');
    }

    btn.disabled = true;
    btn.textContent = 'Waiting for GitHub...';

    let attempts = 0;
    // Poll at 8s — registry rate-limits desktop-poll at 10 req/min (1 per 6s min).
    // 8s keeps us safely under the limit. 15 attempts × 8s = 120s total timeout.
    _loginPollInterval = setInterval(async () => {
      attempts++;
      if (attempts > 15) {  // 120s timeout — reset so user can retry
        clearInterval(_loginPollInterval);
        btn.disabled = false;
        btn.textContent = 'Sign in with GitHub';
        return;
      }
      try {
        // Poll registry directly — no Hall Server required
        const r = await fetch(`https://api.pyhall.dev/auth/desktop-poll?session=${sessionId}`);
        if (r.ok) {
          const d = await r.json();
          if (d?.token) {
            clearInterval(_loginPollInterval);
            window.AppState.sessionToken = d.token;
            onLoginConfirmed();
          }
          // d.pending === true means not yet authenticated — keep polling
        } else if (r.status === 410) {
          // Expired or already claimed — reset
          clearInterval(_loginPollInterval);
          btn.disabled = false;
          btn.textContent = 'Sign in with GitHub';
        } else if (r.status === 429) {
          // Rate limited — slow down poll automatically by skipping next 2 cycles
          attempts += 2;
        }
      } catch (_) {}
    }, 8000);
  });
})();

// ─── Passphrase gate wiring ────────────────────────────────────────────────

(function wirePassphraseGate() {
  // Toggle between unlock and set forms
  document.getElementById('link-set-passphrase')?.addEventListener('click', (e) => {
    e.preventDefault();
    _switchPassphraseForm('set');
  });
  document.getElementById('link-back-to-unlock')?.addEventListener('click', (e) => {
    e.preventDefault();
    _switchPassphraseForm('unlock');
  });

  // Unlock submit
  document.getElementById('btn-passphrase-unlock')?.addEventListener('click', async () => {
    const hallUrl   = window.AppState?.hallUrl || 'http://localhost:8765';
    const input     = document.getElementById('passphrase-input');
    const keychainEl = document.getElementById('keychain-opt-in');
    const errEl     = document.getElementById('passphrase-unlock-error');
    const btn       = document.getElementById('btn-passphrase-unlock');

    const passphrase   = input?.value || '';
    const use_keychain = keychainEl?.checked || false;

    if (!passphrase) {
      if (errEl) { errEl.textContent = 'Passphrase is required.'; errEl.style.display = 'block'; }
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Unlocking...';
    if (errEl) errEl.style.display = 'none';

    try {
      const r = await fetch(`${hallUrl}/api/auth/unlock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(window.AppState.sessionToken ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` } : {}),
        },
        body: JSON.stringify({ passphrase, use_keychain }),
      });
      const d = await r.json();
      if (d.ok) {
        onPassphraseAccepted();
      } else {
        if (errEl) { errEl.textContent = d.reason || 'Incorrect passphrase.'; errEl.style.display = 'block'; }
      }
    } catch (e) {
      if (errEl) { errEl.textContent = 'Could not reach Hall Server.'; errEl.style.display = 'block'; }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Unlock';
    }
  });

  // Allow Enter key in passphrase field to submit
  document.getElementById('passphrase-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('btn-passphrase-unlock')?.click();
  });

  // Set passphrase submit
  document.getElementById('btn-passphrase-set')?.addEventListener('click', async () => {
    const hallUrl   = window.AppState?.hallUrl || 'http://localhost:8765';
    const newEl     = document.getElementById('passphrase-new');
    const confirmEl = document.getElementById('passphrase-new-confirm');
    const errEl     = document.getElementById('passphrase-set-error');
    const btn       = document.getElementById('btn-passphrase-set');

    const passphrase = newEl?.value || '';
    const confirm    = confirmEl?.value || '';

    if (!passphrase) {
      if (errEl) { errEl.textContent = 'Passphrase is required.'; errEl.style.display = 'block'; }
      return;
    }
    if (passphrase !== confirm) {
      if (errEl) { errEl.textContent = 'Passphrases do not match.'; errEl.style.display = 'block'; }
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Saving...';
    if (errEl) errEl.style.display = 'none';

    try {
      const r = await fetch(`${hallUrl}/api/auth/set-passphrase`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(window.AppState.sessionToken ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` } : {}),
        },
        body: JSON.stringify({ passphrase }),
      });
      const d = await r.json();
      if (d.ok) {
        onPassphraseAccepted();
      } else {
        if (errEl) { errEl.textContent = d.reason || 'Could not set passphrase.'; errEl.style.display = 'block'; }
      }
    } catch (e) {
      if (errEl) { errEl.textContent = 'Could not reach Hall Server.'; errEl.style.display = 'block'; }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Set Passphrase';
    }
  });

  // "Forgot passphrase?" link — show reset step 1
  document.getElementById('link-forgot-passphrase')?.addEventListener('click', (e) => {
    e.preventDefault();
    _switchPassphraseForm('reset-request');
  });

  // Back links from reset forms
  document.getElementById('link-reset-back-to-unlock')?.addEventListener('click', (e) => {
    e.preventDefault();
    _switchPassphraseForm('unlock');
  });
  document.getElementById('link-reset-back-to-unlock2')?.addEventListener('click', (e) => {
    e.preventDefault();
    _switchPassphraseForm('unlock');
  });

  // "Send Reset Email" button
  document.getElementById('btn-passphrase-reset-send')?.addEventListener('click', async () => {
    const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';
    const btn = document.getElementById('btn-passphrase-reset-send');
    const errEl = document.getElementById('passphrase-reset-error');
    if (errEl) errEl.style.display = 'none';
    btn.disabled = true;
    btn.textContent = 'Sending...';
    try {
      const r = await fetch(`${hallUrl}/api/auth/passphrase-reset/request`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(window.AppState?.sessionToken ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` } : {}),
        },
        body: JSON.stringify({}),
      });
      const d = await r.json();
      if (d.ok) {
        _switchPassphraseForm('reset-confirm');
      } else {
        if (errEl) { errEl.textContent = d.error || 'Could not send reset email.'; errEl.style.display = 'block'; }
      }
    } catch (e) {
      if (errEl) { errEl.textContent = 'Could not reach Hall Server.'; errEl.style.display = 'block'; }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Send Reset Email';
    }
  });

  // "Reset Passphrase" confirm button
  document.getElementById('btn-passphrase-reset-confirm')?.addEventListener('click', async () => {
    const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';
    const tokenEl = document.getElementById('passphrase-reset-token');
    const newEl = document.getElementById('passphrase-reset-new');
    const confirmEl = document.getElementById('passphrase-reset-confirm');
    const errEl = document.getElementById('passphrase-reset-confirm-error');
    const btn = document.getElementById('btn-passphrase-reset-confirm');
    const token = tokenEl?.value?.trim() || '';
    const newPass = newEl?.value || '';
    const confirmPass = confirmEl?.value || '';
    if (!token) { if (errEl) { errEl.textContent = 'Enter the token from your email.'; errEl.style.display = 'block'; } return; }
    if (!newPass) { if (errEl) { errEl.textContent = 'Enter a new passphrase.'; errEl.style.display = 'block'; } return; }
    if (newPass !== confirmPass) { if (errEl) { errEl.textContent = 'Passphrases do not match.'; errEl.style.display = 'block'; } return; }
    btn.disabled = true;
    btn.textContent = 'Resetting...';
    if (errEl) errEl.style.display = 'none';
    try {
      const r = await fetch(`${hallUrl}/api/auth/passphrase-reset/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_passphrase: newPass }),
      });
      const d = await r.json();
      if (d.ok) {
        onPassphraseAccepted();
      } else {
        if (errEl) { errEl.textContent = d.reason || 'Reset failed.'; errEl.style.display = 'block'; }
      }
    } catch (e) {
      if (errEl) { errEl.textContent = 'Could not reach Hall Server.'; errEl.style.display = 'block'; }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Reset Passphrase';
    }
  });
})();

// ─── Update login gate UI when Hall connection state changes ───────────────
// Login no longer requires Hall Server — button is always enabled.
// Hall Server status updates the header indicator only.

// ─── Theme toggle ──────────────────────────────────────────────────────────

function initTheme() {
  const saved = localStorage.getItem('pyhall-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('pyhall-theme', next);
  });
}

// ─── About screen ──────────────────────────────────────────────────────────

function _refreshAboutScreen() {
  // Populate platform info
  const platformEl = document.getElementById('about-platform');
  if (platformEl) {
    if (window.__TAURI__?.os?.platform) {
      window.__TAURI__.os.platform().then(p => { platformEl.textContent = p; }).catch(() => { platformEl.textContent = navigator.platform || '—'; });
    } else {
      platformEl.textContent = navigator.platform || '—';
    }
  }
  // Populate Hall Server version from cached AppState
  const hallVerEl = document.getElementById('about-hall-version');
  if (hallVerEl) {
    const ver = window.AppState?.hallVersion || '—';
    hallVerEl.textContent = ver;
  }
}

window._refreshAboutScreen = _refreshAboutScreen;

// ─── Startup ───────────────────────────────────────────────────────────────

async function checkPendingAuth() {
  // Session tokens are held in memory only (session-scoped, never persisted to disk).
  // On app start, token is always null — user must log in again.
  // (Legacy: previously polled localhost:8765/api/auth/pending; no longer needed.)
  return window.AppState?.sessionToken != null;
}

document.addEventListener('DOMContentLoaded', async () => {
  // Gates start: login-gate shown, passphrase-gate hidden.
  // The login gate is shown by default via inline style in index.html.

  // Initialize theme before rendering
  initTheme();

  // Load config so hallUrl is set before first poll
  try {
    const cfg = await HallAPI.readConfig();
    window.AppState.config = cfg;
    window.AppState.hallUrl = cfg.hall_url || 'http://localhost:8765';
    window.AppState.pollMs = (cfg.poll_interval || 3) * 1000;
    const urlDisplay = document.getElementById('hall-url-display');
    if (urlDisplay) urlDisplay.textContent = window.AppState.hallUrl;
    const cfgUrl = document.getElementById('cfg-hall-url');
    if (cfgUrl) cfgUrl.value = window.AppState.hallUrl;
  } catch (_) {}

  // Compute desktop binary hash for attestation chain.
  // Stored in AppState; passed to Hall Server on Go Online.
  // Non-critical — failure is silent and attestation proceeds without it.
  if (window.__TAURI__?.core?.invoke) {
    try {
      const hashResult = await window.__TAURI__.core.invoke('get_desktop_binary_hash');
      window.AppState.desktopBinaryHash = hashResult?.hash || null;
    } catch (_) {
      window.AppState.desktopBinaryHash = null;
    }
  }

  // Check if a token already exists from a previous navigation (e.g. OAuth callback)
  const alreadyAuthed = await checkPendingAuth();

  // Start polling Hall Server (this will also update the login gate button state)
  startPollLoop();

  if (alreadyAuthed) {
    // Token present — skip login gate, go straight to passphrase gate
    onLoginConfirmed();
  }
  // If not authed, login gate remains visible (already shown by HTML default)
});

// bfcache restore
window.addEventListener('pageshow', async (e) => {
  if (!e.persisted) return;
  if (await checkPendingAuth()) {
    window.AppState.sessionToken && window.ProfileScreen?.reload();
    onLoginConfirmed();
  }
});
