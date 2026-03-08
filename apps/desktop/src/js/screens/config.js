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
    // Load MCP servers independently — don't block config form on failure
    loadMcpServers().catch(e => console.warn('MCP server list load failed:', e));
  }

  function populateForm(cfg) {
    const urlEl = document.getElementById('cfg-hall-url');
    if (urlEl) urlEl.value = cfg.hall_url || 'http://localhost:8765';

    const regUrlEl = document.getElementById('cfg-registry-url');
    if (regUrlEl) regUrlEl.value = cfg.registry_url || 'https://api.pyhall.dev';

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
      registry_url: document.getElementById('cfg-registry-url')?.value || 'https://api.pyhall.dev',
      poll_interval: pollVal,
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

  // ── Open Log File ─────────────────────────────────────────────────────────

  document.getElementById('btn-open-log')?.addEventListener('click', async () => {
    const url = window.AppState?.hallUrl || 'http://localhost:8765';
    try {
      const res = await fetch(`${url}/api/health`);
      const data = await res.json();
      const logPath = data.log_path || '';
      const pathEl = document.getElementById('log-path-display');
      if (pathEl) pathEl.textContent = logPath || '—';
      if (logPath) {
        // Try Tauri opener plugin, fall back to xdg-open via shell
        if (window.__TAURI__?.opener?.openPath) {
          await window.__TAURI__.opener.openPath(logPath);
        } else if (window.__TAURI__?.shell?.open) {
          await window.__TAURI__.shell.open(logPath);
        } else {
          // Fallback: copy path to clipboard
          navigator.clipboard?.writeText(logPath);
          if (pathEl) pathEl.textContent = `copied: ${logPath}`;
        }
      }
    } catch (e) {
      const pathEl = document.getElementById('log-path-display');
      if (pathEl) pathEl.textContent = `Error: ${e}`;
    }
  });

  // Populate log path on load
  (async () => {
    const url = window.AppState?.hallUrl || 'http://localhost:8765';
    try {
      const res = await fetch(`${url}/api/health`);
      const data = await res.json();
      const pathEl = document.getElementById('log-path-display');
      if (pathEl && data.log_path) pathEl.textContent = data.log_path;
    } catch (_) {}
  })();

  // ── Poll interval radio selection ─────────────────────────────────────────

  document.querySelectorAll('#poll-interval-group .radio-option').forEach(opt => {
    opt.addEventListener('click', () => {
      document.querySelectorAll('#poll-interval-group .radio-option').forEach(o => o.classList.remove('selected'));
      opt.classList.add('selected');
      const radio = opt.querySelector('input[type="radio"]');
      if (radio) radio.checked = true;
    });
  });

  // ── Security — change passphrase ─────────────────────────────────────────

  document.getElementById('btn-show-change-passphrase')?.addEventListener('click', () => {
    const form = document.getElementById('change-passphrase-form');
    if (!form) return;
    const isVisible = form.style.display !== 'none';
    form.style.display = isVisible ? 'none' : 'block';
    if (!isVisible) {
      // Reset form on open
      ['sec-current-passphrase', 'sec-new-passphrase', 'sec-confirm-passphrase'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
      const errEl = document.getElementById('change-passphrase-error');
      if (errEl) errEl.style.display = 'none';
      document.getElementById('sec-current-passphrase')?.focus();
    }
  });

  document.getElementById('btn-change-passphrase-cancel')?.addEventListener('click', () => {
    const form = document.getElementById('change-passphrase-form');
    if (form) form.style.display = 'none';
  });

  document.getElementById('btn-change-passphrase-submit')?.addEventListener('click', async () => {
    const hallUrl   = window.AppState?.hallUrl || 'http://localhost:8765';
    const currentEl = document.getElementById('sec-current-passphrase');
    const newEl     = document.getElementById('sec-new-passphrase');
    const confirmEl = document.getElementById('sec-confirm-passphrase');
    const errEl     = document.getElementById('change-passphrase-error');
    const resultEl  = document.getElementById('security-action-result');
    const btn       = document.getElementById('btn-change-passphrase-submit');

    const current_passphrase = currentEl?.value || '';
    const new_passphrase     = newEl?.value || '';
    const confirm            = confirmEl?.value || '';

    if (errEl) errEl.style.display = 'none';

    if (!current_passphrase) {
      if (errEl) { errEl.textContent = 'Current passphrase is required.'; errEl.style.display = 'block'; }
      return;
    }
    if (!new_passphrase) {
      if (errEl) { errEl.textContent = 'New passphrase is required.'; errEl.style.display = 'block'; }
      return;
    }
    if (new_passphrase !== confirm) {
      if (errEl) { errEl.textContent = 'New passphrases do not match.'; errEl.style.display = 'block'; }
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Updating...';

    try {
      const r = await fetch(`${hallUrl}/api/auth/change-passphrase`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(window.AppState?.sessionToken ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` } : {}),
        },
        body: JSON.stringify({ current_passphrase, new_passphrase }),
      });
      const d = await r.json();
      if (d.ok) {
        document.getElementById('change-passphrase-form').style.display = 'none';
        if (resultEl) {
          resultEl.style.display = 'inline';
          resultEl.style.color = 'var(--success)';
          resultEl.textContent = 'Passphrase updated.';
          setTimeout(() => { if (resultEl) resultEl.style.display = 'none'; }, 3000);
        }
      } else {
        if (errEl) { errEl.textContent = d.reason || 'Could not update passphrase.'; errEl.style.display = 'block'; }
      }
    } catch (e) {
      if (errEl) { errEl.textContent = 'Could not reach Hall Server.'; errEl.style.display = 'block'; }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Update Passphrase';
    }
  });

  // ── Security — forget keychain ────────────────────────────────────────────

  document.getElementById('btn-forget-keychain')?.addEventListener('click', async () => {
    const hallUrl  = window.AppState?.hallUrl || 'http://localhost:8765';
    const resultEl = document.getElementById('security-action-result');
    const btn      = document.getElementById('btn-forget-keychain');

    btn.disabled = true;
    if (resultEl) { resultEl.style.display = 'inline'; resultEl.style.color = 'var(--text-muted)'; resultEl.textContent = 'Clearing...'; }

    try {
      const r = await fetch(`${hallUrl}/api/auth/forget-keychain`, {
        method: 'POST',
        headers: window.AppState?.sessionToken
          ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` }
          : {},
      });
      const d = await r.json();
      if (resultEl) {
        resultEl.style.display = 'inline';
        resultEl.style.color = d.ok ? 'var(--success)' : 'var(--error)';
        resultEl.textContent = d.ok ? 'Keychain entry cleared.' : (d.reason || 'Failed to clear keychain.');
        setTimeout(() => { if (resultEl) resultEl.style.display = 'none'; }, 3000);
      }
    } catch (e) {
      if (resultEl) { resultEl.style.display = 'inline'; resultEl.style.color = 'var(--error)'; resultEl.textContent = 'Could not reach Hall Server.'; }
    } finally {
      btn.disabled = false;
    }
  });

  // ── Connected MCPs ────────────────────────────────────────────────────────

  async function loadMcpServers() {
    const listEl   = document.getElementById('mcp-server-list');
    const emptyEl  = document.getElementById('mcp-empty-state');
    const errorEl  = document.getElementById('mcp-list-error');
    if (!listEl) return;

    if (errorEl) errorEl.style.display = 'none';

    try {
      const data = await HallAPI.listMcpServers();
      const servers = data.servers || data || [];
      renderMcpList(servers);
    } catch (e) {
      if (emptyEl) emptyEl.style.display = 'block';
      if (errorEl) {
        errorEl.textContent = `Could not load MCP servers: ${e.message || e}`;
        errorEl.style.display = 'block';
      }
    }
  }

  function renderMcpList(servers) {
    const listEl  = document.getElementById('mcp-server-list');
    const emptyEl = document.getElementById('mcp-empty-state');
    if (!listEl) return;

    // Remove existing rows (keep empty-state node)
    Array.from(listEl.querySelectorAll('.mcp-row')).forEach(el => el.remove());

    if (!servers || servers.length === 0) {
      if (emptyEl) emptyEl.style.display = 'block';
      return;
    }

    if (emptyEl) emptyEl.style.display = 'none';

    servers.forEach(srv => {
      const statusColor = srv.status === 'online'  ? '#4caf50'
                        : srv.status === 'offline' ? '#f44336'
                        : '#888';
      const statusLabel = srv.status || 'unknown';
      const transport   = (srv.transport || '').toUpperCase();
      const toolCount   = srv.tool_count != null ? srv.tool_count : '—';

      const row = document.createElement('div');
      row.className = 'mcp-row';
      row.dataset.mcpId = srv.id;
      row.style.cssText = [
        'display:flex',
        'align-items:center',
        'gap:10px',
        'padding:8px 10px',
        'margin-bottom:6px',
        'background:var(--bg-primary)',
        'border:1px solid var(--bg-border)',
        'border-radius:var(--radius-sm)',
        'font-size:12px',
      ].join(';');

      row.innerHTML = `
        <span style="width:8px;height:8px;border-radius:50%;background:${statusColor};flex-shrink:0;display:inline-block;" title="${statusLabel}"></span>
        <span style="flex:1;color:var(--text-bright);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escHtml(srv.name || srv.id)}</span>
        <span style="color:var(--text-muted);min-width:40px;">${escHtml(transport)}</span>
        <span style="color:var(--text-dim);min-width:60px;">${toolCount} tools</span>
        <span class="mcp-ping-result" style="min-width:60px;color:var(--text-dim);font-size:11px;"></span>
        <button class="btn btn-ghost btn-sm mcp-btn-ping" data-id="${escHtml(srv.id)}" style="padding:3px 8px;font-size:11px;">Ping</button>
        <button class="btn btn-ghost btn-sm mcp-btn-remove" data-id="${escHtml(srv.id)}" data-name="${escHtml(srv.name || srv.id)}" style="padding:3px 8px;font-size:11px;color:var(--error);">Remove</button>
      `;

      listEl.appendChild(row);
    });

    // Attach ping handlers
    listEl.querySelectorAll('.mcp-btn-ping').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id       = btn.dataset.id;
        const row      = btn.closest('.mcp-row');
        const resultEl = row?.querySelector('.mcp-ping-result');
        btn.disabled = true;
        if (resultEl) resultEl.textContent = 'pinging...';
        try {
          const res = await HallAPI.pingMcpServer(id);
          const dot = row?.querySelector('span[title]');
          const ok  = res.status === 'online';
          if (dot) {
            dot.style.background = ok ? '#4caf50' : '#f44336';
            dot.title = res.status || 'unknown';
          }
          if (resultEl) {
            resultEl.textContent = ok ? 'online' : 'offline';
            resultEl.style.color = ok ? '#4caf50' : '#f44336';
            setTimeout(() => { if (resultEl) { resultEl.textContent = ''; resultEl.style.color = 'var(--text-dim)'; } }, 3000);
          }
        } catch (e) {
          if (resultEl) {
            resultEl.textContent = 'error';
            resultEl.style.color = 'var(--error)';
            setTimeout(() => { if (resultEl) { resultEl.textContent = ''; resultEl.style.color = 'var(--text-dim)'; } }, 3000);
          }
        } finally {
          btn.disabled = false;
        }
      });
    });

    // Attach remove handlers
    listEl.querySelectorAll('.mcp-btn-remove').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id   = btn.dataset.id;
        const name = btn.dataset.name || id;
        const row  = btn.closest('.mcp-row');

        // Inline confirm swap
        btn.textContent = 'Sure?';
        btn.style.background = 'var(--error)';
        btn.style.color = '#fff';

        const cancel = document.createElement('button');
        cancel.className = 'btn btn-ghost btn-sm';
        cancel.textContent = 'No';
        cancel.style.cssText = 'padding:3px 8px;font-size:11px;';
        btn.after(cancel);

        cancel.addEventListener('click', () => {
          btn.textContent = 'Remove';
          btn.style.background = '';
          btn.style.color = 'var(--error)';
          cancel.remove();
        });

        btn.onclick = async () => {
          btn.disabled = true;
          cancel.remove();
          try {
            await HallAPI.removeMcpServer(id);
            row?.remove();
            // If list is now empty, show empty state
            const remaining = document.querySelectorAll('#mcp-server-list .mcp-row');
            const emptyEl = document.getElementById('mcp-empty-state');
            if (remaining.length === 0 && emptyEl) emptyEl.style.display = 'block';
          } catch (e) {
            btn.disabled = false;
            btn.textContent = 'Remove';
            btn.style.background = '';
            btn.style.color = 'var(--error)';
            const errorEl = document.getElementById('mcp-list-error');
            if (errorEl) {
              errorEl.textContent = `Remove failed: ${e.message || e}`;
              errorEl.style.display = 'block';
            }
          }
        };
      });
    });
  }

  function escHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Transport toggle
  document.getElementById('mcp-transport')?.addEventListener('change', function () {
    const isHttp = this.value === 'http';
    const urlField = document.getElementById('mcp-field-url');
    const cmdField = document.getElementById('mcp-field-command');
    if (urlField) urlField.style.display = isHttp ? '' : 'none';
    if (cmdField) cmdField.style.display = isHttp ? 'none' : '';
  });

  // Show / hide Add MCP form
  document.getElementById('btn-show-add-mcp')?.addEventListener('click', () => {
    const form = document.getElementById('add-mcp-form');
    if (!form) return;
    const visible = form.style.display !== 'none';
    form.style.display = visible ? 'none' : 'block';
    if (!visible) {
      // Reset on open
      const nameEl = document.getElementById('mcp-name');
      const urlEl  = document.getElementById('mcp-url');
      const cmdEl  = document.getElementById('mcp-command');
      const transEl= document.getElementById('mcp-transport');
      const errEl  = document.getElementById('add-mcp-error');
      if (nameEl)  nameEl.value = '';
      if (urlEl)   urlEl.value  = '';
      if (cmdEl)   cmdEl.value  = '';
      if (transEl) transEl.value = 'http';
      // Ensure url field visible, command hidden
      const urlField = document.getElementById('mcp-field-url');
      const cmdField = document.getElementById('mcp-field-command');
      if (urlField) urlField.style.display = '';
      if (cmdField) cmdField.style.display = 'none';
      if (errEl)   errEl.style.display = 'none';
      nameEl?.focus();
    }
  });

  document.getElementById('btn-add-mcp-cancel')?.addEventListener('click', () => {
    const form = document.getElementById('add-mcp-form');
    if (form) form.style.display = 'none';
  });

  document.getElementById('btn-add-mcp-submit')?.addEventListener('click', async () => {
    const nameEl  = document.getElementById('mcp-name');
    const transEl = document.getElementById('mcp-transport');
    const urlEl   = document.getElementById('mcp-url');
    const cmdEl   = document.getElementById('mcp-command');
    const errEl   = document.getElementById('add-mcp-error');
    const btn     = document.getElementById('btn-add-mcp-submit');

    const name      = nameEl?.value.trim() || '';
    const transport = transEl?.value || 'http';
    const url       = urlEl?.value.trim() || '';
    const command   = cmdEl?.value.trim() || '';

    if (errEl) errEl.style.display = 'none';

    if (!name) {
      if (errEl) { errEl.textContent = 'Name is required.'; errEl.style.display = 'block'; }
      nameEl?.focus();
      return;
    }
    if (transport === 'http' && !url) {
      if (errEl) { errEl.textContent = 'URL is required for HTTP transport.'; errEl.style.display = 'block'; }
      urlEl?.focus();
      return;
    }
    if (transport === 'stdio' && !command) {
      if (errEl) { errEl.textContent = 'Command is required for stdio transport.'; errEl.style.display = 'block'; }
      cmdEl?.focus();
      return;
    }

    const payload = { name, transport };
    if (transport === 'http')  payload.url     = url;
    if (transport === 'stdio') payload.command = command;

    btn.disabled = true;
    btn.textContent = 'Adding...';

    try {
      await HallAPI.addMcpServer(payload);
      const form = document.getElementById('add-mcp-form');
      if (form) form.style.display = 'none';
      await loadMcpServers();
    } catch (e) {
      if (errEl) {
        errEl.textContent = `Add failed: ${e.message || e}`;
        errEl.style.display = 'block';
      }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Add Server';
    }
  });

  return { load, loadMcpServers };
})();
