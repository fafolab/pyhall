/**
 * app.js — Main application logic
 * - Navigation / screen switching
 * - Global poll loop
 * - Status bar + header updates
 * - Tauri event listener (tray nav)
 */

// ─── Navigation ────────────────────────────────────────────────────────────

const SCREENS = ['status', 'feed', 'crew', 'alerts', 'enroll', 'config'];

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

  // Trigger screen-specific init
  const handlers = {
    status: () => window.StatusScreen && window.StatusScreen.refresh(),
    feed:   () => window.FeedScreen && window.FeedScreen.onShow(),
    crew:   () => window.CrewScreen && window.CrewScreen.refresh(),
    alerts: () => window.AlertsScreen && window.AlertsScreen.refresh(),
    enroll: () => window.EnrollScreen && window.EnrollScreen.reset(),
    config: () => window.ConfigScreen && window.ConfigScreen.load(),
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
  window.AppState.hallOnline = online;

  const indicator = document.getElementById('hall-indicator');
  const indicatorLabel = document.getElementById('hall-indicator-label');
  const sbStatus = document.getElementById('sb-hall-status');

  if (online) {
    indicator.className = 'hall-indicator online';
    indicatorLabel.textContent = 'ONLINE';
    sbStatus.className = 'status-online';
    sbStatus.textContent = 'ONLINE';
  } else {
    indicator.className = 'hall-indicator offline';
    indicatorLabel.textContent = 'OFFLINE';
    sbStatus.className = 'status-offline';
    sbStatus.textContent = 'OFFLINE';
  }

  // Update status bar counters
  if (data.workers !== undefined) window.AppState.workerCount = data.workers;
  if (data.dispatches_today !== undefined) window.AppState.dispatchesToday = data.dispatches_today;
  if (data.refusals_today !== undefined) window.AppState.refusalsToday = data.refusals_today;

  document.getElementById('sb-workers').textContent =
    `${window.AppState.workerCount} workers`;
  document.getElementById('sb-dispatches').textContent =
    `${window.AppState.dispatchesToday} dispatches today`;
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

// ─── Global poll loop ──────────────────────────────────────────────────────

async function pollHall() {
  const url = window.AppState.hallUrl;

  try {
    const status = await HallAPI.getHallStatus(url);

    const online = status.online === true;
    updateConnectionUI(online, status);

    // Forward status to status screen
    if (window.StatusScreen) {
      window.StatusScreen.onStatusUpdate(status, online);
    }

    // Poll alerts for badge update
    const alertsData = await HallAPI.getAlerts(url);
    const alerts = alertsData.alerts || window.MOCK_ALERTS;
    const unresolved = (alertsData.source === 'offline' ? window.MOCK_ALERTS : alerts)
      .filter(a => !a.acknowledged).length;
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

// ─── Startup ───────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  navigateTo('status');
  startPollLoop();
});
