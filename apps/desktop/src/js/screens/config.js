/**
 * config.js — Configuration screen (Screen 6)
 * Hall URL, poll interval, default profile, notifications, display options.
 * Persists to $HOME/.config/pyhall/config.json via Tauri command.
 */

window.ConfigScreen = (() => {

  // ── Load config into form ─────────────────────────────────────────────────

  async function load() {
    try {
      const cfg = await HallAPI.readConfig();
      window.AppState.config = cfg;
      populateForm(cfg);
    } catch (e) {
      console.warn('Config load failed:', e);
    }
  }

  function populateForm(cfg) {
    const urlEl = document.getElementById('cfg-hall-url');
    if (urlEl) urlEl.value = cfg.hall_url || 'http://localhost:8765';

    const profileEl = document.getElementById('cfg-profile');
    if (profileEl) profileEl.value = cfg.default_profile || 'prof.dev.permissive';

    // Poll interval radio
    const pollVal = String(cfg.poll_interval ?? 3);
    document.querySelectorAll('#poll-interval-group .radio-option').forEach(opt => {
      opt.classList.toggle('selected', opt.dataset.value === pollVal);
      const radio = opt.querySelector('input[type="radio"]');
      if (radio) radio.checked = radio.value === pollVal;
    });

    // Notifications
    setCheck('notif-hall-offline',   cfg.notifications?.hall_offline  ?? true);
    setCheck('notif-worker-failure', cfg.notifications?.worker_failure ?? true);
    setCheck('notif-steward-hold',   cfg.notifications?.steward_hold   ?? true);
    setCheck('notif-every-denial',   cfg.notifications?.every_denial   ?? false);

    // Display
    setCheck('display-tray',  cfg.display?.tray_on_minimize ?? true);
    setCheck('display-login', cfg.display?.launch_at_login  ?? false);

    const maxEl = document.getElementById('cfg-feed-max');
    if (maxEl) maxEl.value = cfg.display?.feed_max_rows ?? 500;
  }

  function setCheck(id, val) {
    const el = document.getElementById(id);
    if (el) el.checked = Boolean(val);
  }

  // ── Collect form values ───────────────────────────────────────────────────

  function collectConfig() {
    const pollRadio = document.querySelector('#poll-interval-group .radio-option.selected');
    const pollVal = parseInt(pollRadio?.dataset.value ?? '3', 10);

    return {
      hall_url: document.getElementById('cfg-hall-url')?.value || 'http://localhost:8765',
      poll_interval: pollVal,
      auth_token: window.AppState.config?.auth_token || null,
      default_profile: document.getElementById('cfg-profile')?.value || 'prof.dev.permissive',
      notifications: {
        hall_offline:   document.getElementById('notif-hall-offline')?.checked  ?? true,
        worker_failure: document.getElementById('notif-worker-failure')?.checked ?? true,
        steward_hold:   document.getElementById('notif-steward-hold')?.checked   ?? true,
        every_denial:   document.getElementById('notif-every-denial')?.checked   ?? false,
      },
      display: {
        tray_on_minimize: document.getElementById('display-tray')?.checked  ?? true,
        launch_at_login:  document.getElementById('display-login')?.checked ?? false,
        feed_max_rows: parseInt(document.getElementById('cfg-feed-max')?.value || '500', 10),
      },
    };
  }

  // ── Save ──────────────────────────────────────────────────────────────────

  document.getElementById('btn-save-config')?.addEventListener('click', async () => {
    const cfg = collectConfig();
    const resultEl = document.getElementById('save-config-result');

    try {
      await HallAPI.saveConfig(cfg);

      // Apply to AppState immediately
      window.AppState.config = cfg;
      window.AppState.hallUrl = cfg.hall_url;

      // Update URL display on status screen
      const urlDisplay = document.getElementById('hall-url-display');
      if (urlDisplay) urlDisplay.textContent = cfg.hall_url;

      // Restart poll loop with new interval
      if (typeof window.restartPollLoop === 'function') {
        window.restartPollLoop(cfg.poll_interval * 1000);
      }

      if (resultEl) {
        resultEl.style.display = 'inline';
        resultEl.style.color = 'var(--success)';
        resultEl.textContent = '✓ Saved';
        setTimeout(() => { if (resultEl) resultEl.style.display = 'none'; }, 3000);
      }
    } catch (e) {
      if (resultEl) {
        resultEl.style.display = 'inline';
        resultEl.style.color = 'var(--error)';
        resultEl.textContent = `✗ Save failed: ${e}`;
      }
    }
  });

  // ── Test connection ───────────────────────────────────────────────────────

  document.getElementById('btn-test-connection')?.addEventListener('click', async () => {
    const urlEl = document.getElementById('cfg-hall-url');
    const url = urlEl?.value || 'http://localhost:8765';
    const resultEl = document.getElementById('test-result-display');

    if (resultEl) {
      resultEl.className = 'test-result';
      resultEl.textContent = '◌ Connecting...';
      resultEl.style.display = 'inline-flex';
    }

    try {
      const status = await HallAPI.getHallStatus(url);
      if (status.online) {
        const workers = status.workers ?? '?';
        const version = status.version ? `pyhall ${status.version}` : 'pyhall 0.1.0';
        if (resultEl) {
          resultEl.className = 'test-result success';
          resultEl.textContent = `● Connected — ${workers} workers, ${version}`;
        }
        window.updateConnectionUI && window.updateConnectionUI(true, status);
      } else {
        if (resultEl) {
          resultEl.className = 'test-result failure';
          resultEl.textContent = '✗ Cannot reach Hall server at ' + url;
        }
      }
    } catch (e) {
      if (resultEl) {
        resultEl.className = 'test-result failure';
        resultEl.textContent = `✗ Error: ${e}`;
      }
    }
  });

  // ── Poll interval radio selection ─────────────────────────────────────────

  document.querySelectorAll('#poll-interval-group .radio-option').forEach(opt => {
    opt.addEventListener('click', () => {
      document.querySelectorAll('#poll-interval-group .radio-option').forEach(o => o.classList.remove('selected'));
      opt.classList.add('selected');
      const radio = opt.querySelector('input[type="radio"]');
      if (radio) radio.checked = true;
    });
  });

  return { load };
})();
