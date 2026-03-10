/**
 * app.js — Main application logic
 * - Navigation / screen switching
 * - Global poll loop
 * - Status bar + header updates
 * - Tauri event listener (tray nav)
 */

// ─── Navigation ────────────────────────────────────────────────────────────

const SCREENS = ['status', 'feed', 'crew', 'alerts', 'coordination', 'profile', 'enroll', 'config'];

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
  };
  if (handlers[screen]) handlers[screen]();
}

// Wire nav clicks
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => navigateTo(el.dataset.screen));
});

// Cross-screen navigation buttons
document.getElementById('btn-go-config-from-status')?.addEventListener('click', () => navigateTo('config'));
document.getElementById('btn-go-feed-from-status')?.addEventListener('click', () => navigateTo('feed'));
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
    // Show Start when offline; show Restart when server is running
    startBtn.style.display = (isOffline || isRunning) ? '' : 'none';
    startBtn.textContent = isOffline ? 'Start Hall Server' : 'Restart Server';
    stopBtn.style.display = (isRunning && window._serverStartedByUs) ? '' : 'none';
  };

  startBtn?.addEventListener('click', async () => {
    const cfg = window.AppState?.config || {};
    const cmd = cfg.server_start_cmd || 'pyhall start';
    const wasLabel = startBtn.textContent;
    startBtn.disabled = true;
    startBtn.textContent = wasLabel === 'Restart Server' ? 'Restarting…' : 'Starting…';
    if (msgEl) { msgEl.textContent = `Running: ${cmd}`; msgEl.style.display = ''; }

    try {
      await window.__TAURI__.core.invoke('start_hall_server', { cmd });
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

// ─── Hall indicator click → restart dropdown ────────────────────────────────

(function wireRestartDropdown() {
  const indicator = document.getElementById('hall-indicator');
  if (!indicator) return;

  // Make it look clickable
  indicator.style.cursor = 'pointer';
  indicator.title = 'Click to restart Hall Server';

  // Create dropdown (hidden by default)
  const dropdown = document.createElement('div');
  dropdown.id = 'hall-restart-dropdown';
  dropdown.className = 'hall-restart-dropdown hidden';
  dropdown.innerHTML = `
    <div class="hall-restart-item muted" id="hall-locked-msg" style="display:none">Log in to activate Hall</div>
    <div class="hall-restart-item accent" id="btn-go-online" style="display:none">Go Online</div>
    <div class="hall-restart-item" id="btn-go-offline" style="display:none">Go Offline</div>
    <div class="hall-restart-divider"></div>
    <div class="hall-restart-item" id="btn-logout-restart">Logout &amp; Restart Hall Server</div>
    <div class="hall-restart-item danger" id="btn-logout-only">Logout Only</div>
  `;
  document.getElementById('header-status').appendChild(dropdown);

  // Toggle dropdown on indicator click
  indicator.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('hidden');
  });

  // Close on outside click
  document.addEventListener('click', () => dropdown.classList.add('hidden'));

  // Logout + hard restart
  document.getElementById('btn-logout-restart').addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.add('hidden');
    const url = window.AppState.hallUrl || 'http://localhost:8765';

    // Show restarting state immediately
    const ind = document.getElementById('hall-indicator');
    const lbl = document.getElementById('hall-indicator-label');
    if (ind) ind.className = 'hall-indicator connecting';
    if (lbl) lbl.textContent = 'RESTARTING...';
    const sbStatus = document.getElementById('sb-hall-status');
    if (sbStatus) { sbStatus.className = 'status-connecting'; sbStatus.textContent = 'RESTARTING...'; }

    try {
      await fetch(`${url}/api/server/restart`, { method: 'POST' });
    } catch (_) {}
    window.AppState.sessionToken = null;
    window.AppState.githubLogin  = null;
    window.AppState.githubAvatar = null;
    const gate = document.getElementById('login-gate');
    if (gate) gate.style.display = 'flex';
    window.pollHall && window.pollHall();
  });

  // Logout only (no restart)
  document.getElementById('btn-logout-only').addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.add('hidden');
    const url = window.AppState.hallUrl || 'http://localhost:8765';
    try { await fetch(`${url}/api/auth/logout`, { method: 'POST' }); } catch (_) {}
    window.AppState.sessionToken = null;
    window.AppState.githubLogin  = null;
    window.AppState.githubAvatar = null;
    const gate = document.getElementById('login-gate');
    if (gate) gate.style.display = 'flex';
    window.pollHall && window.pollHall();
  });

  // Go Online — activate Hall after login
  document.getElementById('btn-go-online').addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.add('hidden');
    const url = window.AppState.hallUrl || 'http://localhost:8765';
    const lbl = document.getElementById('hall-indicator-label');
    if (lbl) lbl.textContent = 'ACTIVATING...';
    try {
      // Include desktop binary hash in attestation chain
      const body = {};
      if (window.AppState.desktopBinaryHash) {
        body.desktop_hash = window.AppState.desktopBinaryHash;
      }
      const r = await fetch(`${url}/api/server/go-online`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!d.ok) alert(`Cannot go online: ${d.message}`);
    } catch (_) {}
    window.pollHall && window.pollHall();
  });

  // Go Offline — without logout
  document.getElementById('btn-go-offline').addEventListener('click', async (e) => {
    e.stopPropagation();
    dropdown.classList.add('hidden');
    const url = window.AppState.hallUrl || 'http://localhost:8765';
    try { await fetch(`${url}/api/server/go-offline`, { method: 'POST' }); } catch (_) {}
    window.pollHall && window.pollHall();
  });
})();

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

// ─── Tauri event listener (tray navigation) ────────────────────────────────

if (typeof window.__TAURI__ !== 'undefined') {
  try {
    window.__TAURI__.event.listen('navigate', (event) => {
      navigateTo(event.payload);
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
 * Called once login is confirmed (token received).
 * Hides login gate, then shows passphrase gate.
 */
function onLoginConfirmed() {
  setLoginGate(false);

  // Fetch GitHub identity to display on the passphrase gate.
  _fetchAndShowIdentity();

  // Check if Hall Server has passphrase protection enabled.
  // If the server returns {passphrase_set: false}, go straight to set form.
  // If {passphrase_set: true} (or unknown), show unlock form.
  _showPassphraseGate();
}

async function _fetchAndShowIdentity() {
  const token = window.AppState?.sessionToken;
  if (!token) return;
  // Route through local Hall server proxy to avoid CORS issues calling registry directly.
  const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';
  try {
    const r = await fetch(`${hallUrl}/api/profile`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    if (!r.ok) return;
    const d = await r.json();
    const login = (d.profile?.github_login) || d.github_login;
    if (!login) return;
    const avatarEl = document.getElementById('passphrase-avatar');
    const loginEl  = document.getElementById('passphrase-github-login');
    if (avatarEl) {
      avatarEl.src = `https://github.com/${login}.png?size=72`;
      avatarEl.style.display = 'block';
    }
    if (loginEl) loginEl.textContent = login;
    // Store for use elsewhere (status screen, profile screen)
    window.AppState.githubLogin = login;
    window.AppState.githubAvatar = `https://github.com/${login}.png`;
  } catch (_) {}
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
  const unlockForm = document.getElementById('passphrase-unlock-form');
  const setForm    = document.getElementById('passphrase-set-form');
  if (unlockForm) unlockForm.style.display = which === 'unlock' ? 'block' : 'none';
  if (setForm)    setForm.style.display    = which === 'set'    ? 'block' : 'none';
  // Clear inputs and errors on switch
  ['passphrase-input', 'passphrase-new', 'passphrase-new-confirm'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['passphrase-unlock-error', 'passphrase-set-error'].forEach(id => {
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
}

window.onLoginConfirmed   = onLoginConfirmed;
window.onPassphraseAccepted = onPassphraseAccepted;

// ─── Login gate wiring ─────────────────────────────────────────────────────

(function wireLoginGate() {
  const btn = document.getElementById('btn-login-gate-github');
  if (!btn) return;

  // The login gate starts with the button disabled and "Checking Hall Server..."
  // Once first poll completes (updateConnectionUI is called), we enable/disable
  // the button depending on whether the Hall is reachable.
  // The actual OAuth flow is identical to profile.js startGitHubLogin().

  let _loginPollInterval = null;

  btn.addEventListener('click', () => {
    const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';
    const oauthUrl = `https://api.pyhall.dev/auth/github?desktop=1`;

    if (window.__TAURI__?.opener?.openUrl) {
      window.__TAURI__.opener.openUrl(oauthUrl).catch(() => window.open(oauthUrl, '_blank'));
    } else {
      window.open(oauthUrl, '_blank');
    }

    btn.disabled = true;
    btn.textContent = 'Waiting for GitHub...';

    let attempts = 0;
    _loginPollInterval = setInterval(async () => {
      attempts++;
      if (attempts > 30) {  // 60s timeout — reset so user can retry
        clearInterval(_loginPollInterval);
        btn.disabled = false;
        btn.textContent = 'Sign in with GitHub';
        return;
      }
      try {
        const r = await fetch(`${hallUrl}/api/auth/pending`);
        if (r.ok) {
          const d = await r.json();
          if (d?.token) {
            clearInterval(_loginPollInterval);
            window.AppState.sessionToken = d.token;
            onLoginConfirmed();
          }
        }
      } catch (_) {}
    }, 2000);
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
})();

// ─── Update login gate UI when Hall connection state changes ───────────────

const _origUpdateConnectionUI = window.updateConnectionUI;
window.updateConnectionUI = function(online, data = {}) {
  _origUpdateConnectionUI && _origUpdateConnectionUI(online, data);

  // Sync login gate button state with Hall availability
  const btn  = document.getElementById('btn-login-gate-github');
  const hint = document.getElementById('login-gate-hall-warn');
  if (!btn) return;

  // OAuth requires Hall Server to be running: it receives the GitHub callback at
  // localhost:8765/api/auth/callback. If server is offline, the browser would hit
  // ERR_CONNECTION_REFUSED and the one-time code expires before we can claim it.
  const hallReachable = (online && ['locked', 'ready', 'online'].includes(data.state || 'locked'));
  btn.disabled = !hallReachable;
  btn.title = hallReachable ? '' : 'Start Hall Server before signing in';
  if (hint) hint.style.display = hallReachable ? 'none' : '';
};

// ─── Startup ───────────────────────────────────────────────────────────────

async function checkPendingAuth() {
  try {
    const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';
    const r = await fetch(`${hallUrl}/api/auth/pending`);
    if (r.ok) {
      const d = await r.json();
      if (d?.token) { window.AppState.sessionToken = d.token; return true; }
    }
  } catch (_) {}
  return false;
}

document.addEventListener('DOMContentLoaded', async () => {
  // Gates start: login-gate shown, passphrase-gate hidden.
  // The login gate is shown by default via inline style in index.html.

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
