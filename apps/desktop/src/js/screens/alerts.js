/**
 * alerts.js — Alerts screen (Screen 4)
 * Shows active + acknowledged alerts. Severity filters.
 * Uses mock alerts when offline.
 */

window.AlertsScreen = (() => {
  let activeAlerts = [...window.MOCK_ALERTS];
  let ackedAlerts = [];
  let severityFilter = 'all';

  // ── Render ────────────────────────────────────────────────────────────────

  function getFiltered(alerts) {
    if (severityFilter === 'all') return alerts;
    return alerts.filter(a => a.severity === severityFilter);
  }

  function render() {
    const container = document.getElementById('alerts-list');
    const unresolvedEl = document.getElementById('alerts-unresolved');
    if (!container) return;

    const filtered = getFiltered(activeAlerts);
    const count = activeAlerts.filter(a => !a.acknowledged).length;

    if (unresolvedEl) unresolvedEl.textContent = `${count} unresolved`;
    window.updateAlertBadge && window.updateAlertBadge(count);

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">✓</div>
          <div class="empty-state-text">No alerts. The Hall is running clean.</div>
          <div class="empty-state-sub">All workers dispatching normally.</div>
        </div>
      `;
      return;
    }

    container.innerHTML = filtered.map(a => renderAlertCard(a)).join('');

    // Wire acknowledge buttons
    container.querySelectorAll('[data-ack]').forEach(btn => {
      btn.addEventListener('click', () => acknowledge(btn.dataset.ack));
    });
    container.querySelectorAll('[data-view-dispatches]').forEach(btn => {
      btn.addEventListener('click', () => {
        // Navigate to Live Feed with steward hold filter
        document.querySelector('[data-screen="feed"]')?.click();
      });
    });
    container.querySelectorAll('[data-view-worker]').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelector('[data-screen="crew"]')?.click();
      });
    });

    // Acknowledged section
    renderAcked();
  }

  function renderAlertCard(a) {
    const icon = a.severity === 'error' ? '✗' : a.severity === 'warning' ? '⚠' : 'ℹ';
    const extra = buildAlertActions(a);

    return `
      <div class="alert-card severity-${a.severity}" id="alert-${a.id}">
        <div class="alert-header">
          <span class="alert-icon">${icon}</span>
          <span class="alert-title">${esc(a.title)}</span>
        </div>
        <div class="alert-body">${esc(a.body)}</div>
        <div class="alert-meta">Last event: ${formatDateCT(a.last_event)}</div>
        <div class="alert-actions">
          ${extra}
          <button class="btn btn-ghost btn-sm" data-ack="${a.id}">Acknowledge</button>
        </div>
      </div>
    `;
  }

  function buildAlertActions(a) {
    switch (a.type) {
      case 'STEWARD_HOLD_REPEATED':
      case 'BLAST_RADIUS_EXCEEDED':
        return `<button class="btn btn-secondary btn-sm" data-view-dispatches="${a.id}">View dispatches</button>`;
      case 'WORKER_FAILURE_SPIKE':
      case 'WORKER_NOT_RESPONDING':
        return `<button class="btn btn-secondary btn-sm" data-view-worker="${a.id}">View worker</button>`;
      default:
        return '';
    }
  }

  function renderAcked() {
    const header = document.getElementById('ack-section-header');
    const ackedContainer = document.getElementById('acked-list');

    if (!header || !ackedContainer) return;

    if (ackedAlerts.length === 0) {
      header.style.display = 'none';
      ackedContainer.style.display = 'none';
      return;
    }

    header.style.display = 'flex';
    ackedContainer.style.display = 'block';

    ackedContainer.innerHTML = `
      <div style="color:var(--text-muted); font-size:12px; padding:8px 0; cursor:pointer;" id="acked-toggle">
        [${ackedAlerts.length} acknowledged alerts — click to expand]
      </div>
      <div id="acked-body" style="display:none;">
        ${ackedAlerts.map(a => `
          <div style="padding:8px 0; border-bottom:1px solid var(--bg-border); font-size:12px; color:var(--text-muted);">
            <span style="margin-right:10px;">${formatDateCT(a.acknowledged_at)}</span>
            ${esc(a.title)}
          </div>
        `).join('')}
      </div>
    `;

    document.getElementById('acked-toggle')?.addEventListener('click', () => {
      const body = document.getElementById('acked-body');
      if (body) body.style.display = body.style.display === 'none' ? 'block' : 'none';
    });
  }

  // ── Acknowledge ───────────────────────────────────────────────────────────

  function acknowledge(id) {
    const idx = activeAlerts.findIndex(a => a.id === id);
    if (idx === -1) return;
    const alert = activeAlerts.splice(idx, 1)[0];
    alert.acknowledged = true;
    alert.acknowledged_at = new Date().toISOString();
    ackedAlerts.unshift(alert);
    render();
  }

  // ── Load from server ──────────────────────────────────────────────────────

  async function refresh() {
    const url = window.AppState.hallUrl;

    if (window.AppState.hallOnline) {
      try {
        const result = await HallAPI.getAlerts(url);
        if (result.alerts && result.source !== 'offline') {
          activeAlerts = result.alerts.filter(a => !a.acknowledged);
          ackedAlerts = result.alerts.filter(a => a.acknowledged);
        }
      } catch (e) {}
    }

    // Keep mock alerts if nothing loaded
    if (activeAlerts.length === 0 && ackedAlerts.length === 0) {
      activeAlerts = [...window.MOCK_ALERTS];
    }

    render();
  }

  // ── Severity filters ──────────────────────────────────────────────────────

  document.querySelectorAll('[data-alert-filter]').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('[data-alert-filter]').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      severityFilter = chip.dataset.alertFilter;
      render();
    });
  });

  // Initial render with mock data
  render();

  return { refresh };
})();

function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
