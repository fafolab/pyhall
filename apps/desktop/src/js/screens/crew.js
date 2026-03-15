/* Copyright (c) 2026 pyhall.dev — https://pyhall.dev
 * All Rights Reserved.
 */
/**
 * crew.js — Crew on the Books screen (Screen 3)
 * Shows enrolled workers from server or local registry.
 * Falls back to catalog.json species when offline and no local workers.
 */

window.CrewScreen = (() => {
  let allWorkers = [];
  let crewFilter = 'all';
  let searchQuery = '';

  // Catalog fetched from Hall Server /api/catalog (real SDK catalog.json)
  let _catalogCache = null;

  async function loadCatalog(hallUrl) {
    if (_catalogCache) return _catalogCache;
    try {
      const resp = await fetch(`${hallUrl}/api/catalog?type=worker_species`);
      if (!resp.ok) return [];
      const data = await resp.json();
      _catalogCache = (data.entities || []).map(e => {
        // Compute a blast_score from blast_radius_hint (0–100)
        const bh = e.blast_radius_hint || {};
        const raw = (bh.data || 0) + (bh.network || 0) + (bh.financial || 0) + (bh.time || 0);
        const rev = bh.reversibility === 'irreversible' ? 3 : bh.reversibility === 'partially-reversible' ? 1 : 0;
        const blast_score = Math.min(100, Math.round((raw + rev) / 15 * 100));
        return {
          species_id: e.id,
          name: e.name,
          description: e.description || '',
          capabilities: e.serves_capabilities || [],
          risk_tier: e.risk_tier || 'medium',
          blast_score,
          guarantee: e.idempotency === 'full' ? 'exactly-once' : e.idempotency === 'partial' ? 'at-least-once' : 'best-effort',
          tags: e.tags || [],
          status: 'catalog',
        };
      });
      return _catalogCache;
    } catch (e) {
      return [];
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  function getFilteredWorkers() {
    return allWorkers.filter(w => {
      if (crewFilter !== 'all' && w.status !== crewFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        if (!w.species_id.toLowerCase().includes(q) &&
            !(w.capabilities || []).some(c => c.toLowerCase().includes(q)) &&
            !(w.name || '').toLowerCase().includes(q) &&
            !(w.description || '').toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }

  // Column headers — always rendered
  const CREW_TABLE_HEADER = `
    <div class="crew-table-header" style="
      display:grid;
      grid-template-columns:2fr 1fr 1fr 1fr 1fr 1fr auto;
      gap:8px;
      padding:6px 12px;
      background:var(--bg-raised);
      border:1px solid var(--bg-border);
      border-radius:var(--radius-sm);
      margin-bottom:8px;
      font-size:11px;
      font-weight:600;
      color:var(--text-muted);
      text-transform:uppercase;
      letter-spacing:0.05em;
    ">
      <span>Worker ID</span>
      <span>Namespace</span>
      <span>Species</span>
      <span>Status</span>
      <span>Enrolled At</span>
      <span>Last Seen</span>
      <span></span>
    </div>
  `;

  function renderCrew() {
    const container = document.getElementById('crew-list');
    const countEl = document.getElementById('crew-count');
    if (!container) return;

    const filtered = getFilteredWorkers();

    if (countEl) countEl.textContent = `${allWorkers.filter(w => w.status !== 'catalog').length} workers`;

    if (filtered.length === 0) {
      container.innerHTML = CREW_TABLE_HEADER + `
        <div class="empty-state">
          <div class="empty-state-icon">👷</div>
          <div class="empty-state-text">No workers match the current filter.</div>
          <div class="empty-state-sub">Enroll a worker to get started, or check back when the Hall Server is online.</div>
        </div>
      `;
      return;
    }

    container.innerHTML = CREW_TABLE_HEADER + filtered.map(w => renderWorkerCard(w)).join('');

    // Wire Details buttons
    container.querySelectorAll('[data-details]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const sid = btn.dataset.details;
        const worker = allWorkers.find(w => w.species_id === sid);
        if (worker) showWorkerDetails(worker);
      });
    });

    // Task 9: Wire "Get a copy" buttons
    container.querySelectorAll('[data-get-copy]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const workerId = btn.dataset.getCopy;
        await getCopyAction(workerId, btn);
      });
    });

    // Hydrate registry status badges for enrolled workers (async, non-blocking)
    if (window.HallAPI && window.HallAPI.checkRegistryStatus) {
      filtered.filter(w => w.status !== 'catalog').forEach(async (w) => {
        const el = container.querySelector(`[data-registry-badge="${CSS.escape(w.species_id)}"]`);
        if (!el) return;
        try {
          const r = await window.HallAPI.checkRegistryStatus(w.worker_id || w.species_id);
          if (r.status === 'active') {
            el.innerHTML = '<span class="badge-registry active" title="Attested in pyhall.dev registry">ACTIVE</span>';
          } else if (r.status === 'banned') {
            el.innerHTML = `<span class="badge-registry banned" title="${esc(r.ban_reason || 'banned')}">BANNED</span>`;
          } else if (r.status === 'error') {
            el.innerHTML = '<span class="badge-registry error" title="Registry unreachable">!</span>';
          } else {
            el.innerHTML = '<span class="badge-registry unknown" title="Not found in registry">?</span>';
          }
        } catch (_) {
          el.innerHTML = '<span class="badge-registry error" title="Registry unreachable">!</span>';
        }
      });
    }
  }

  function renderWorkerCard(w) {
    const statusBadge = statusBadgeHTML(w.status);
    const blastClass = blastTierClass(w.blast_score);
    const blastLabel = blastTierLabel(w.blast_score);
    const caps = (w.capabilities || []).join(', ') || '—';
    const isCatalog = w.status === 'catalog';
    const cardClass = w.blast_score > 80 ? 'worker-card critical-blast' : 'worker-card';

    const statsRow = !isCatalog
      ? `<div class="meta-label">Dispatches today</div>
         <div class="meta-value">${w.dispatches_today ?? 0} · Failures: ${w.failures_today ?? 0} · DLQ: ${w.dlq_count ?? 0}</div>`
      : `<div class="meta-label">Source</div>
         <div class="meta-value">WCP Catalog — available (not enrolled)</div>`;

    // Task 9: "Get a copy" button for enrolled workers (not catalog)
    const getCopyBtn = !isCatalog && w.worker_id
      ? `<button class="btn btn-ghost btn-sm" data-get-copy="${esc(w.worker_id)}" title="Download manifest.json + worker_logic.py">Get a copy</button>`
      : '';

    return `
      <div class="${cardClass}">
        <div class="worker-card-header">
          <span class="worker-species-id">${esc(w.species_id)}</span>
          ${statusBadge}
          ${!isCatalog ? `<span data-registry-badge="${esc(w.species_id)}" class="badge-registry-placeholder" title="Checking registry…">…</span>` : ''}
        </div>
        <div class="worker-card-meta">
          <span class="meta-label">Name</span>
          <span class="meta-value">${esc(w.name || w.species_id)}</span>
          <span class="meta-label">Handles</span>
          <span class="meta-value">${esc(caps)}</span>
          <span class="meta-label">Guarantee</span>
          <span class="meta-value">${esc(w.guarantee || '—')}</span>
          <span class="meta-label">Blast tier</span>
          <span class="meta-value"><span class="blast-tier ${blastClass}">${blastLabel} (score: ${w.blast_score})</span>${w.status === 'gated' ? ' ← STEWARD HOLD ACTIVE' : ''}</span>
          ${statsRow}
        </div>
        <div style="margin-top:10px; text-align:right; display:flex; gap:8px; justify-content:flex-end;">
          ${getCopyBtn}
          <button class="btn btn-ghost btn-sm" data-details="${esc(w.species_id)}">Details</button>
        </div>
      </div>
    `;
  }

  function statusBadgeHTML(status) {
    const map = {
      active:  ['●', 'ACTIVE',  'active'],
      gated:   ['⚠', 'GATED',   'gated'],
      idle:    ['◌', 'IDLE',    'idle'],
      error:   ['✗', 'ERROR',   'error'],
      catalog: ['◈', 'CATALOG', 'catalog'],
    };
    const [icon, label, cls] = map[status] || ['?', status.toUpperCase(), 'idle'];
    return `<span class="status-badge ${cls}">${icon} ${label}</span>`;
  }

  // ── Task 9: Get a copy action ──────────────────────────────────────────────

  async function getCopyAction(workerId, btn) {
    const origText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Loading...';
    try {
      const result = await window.__TAURI__.core.invoke('get_enrolled_worker_files', { worker_id: workerId });
      // Download manifest.json
      await window.__TAURI__.core.invoke('save_text_file', {
        filename: `manifest_${workerId.replace(/[^a-z0-9-]/gi, '_')}.json`,
        content: result.manifest_json,
      });
      // Download worker_logic.py
      if (result.python_code) {
        await window.__TAURI__.core.invoke('save_text_file', {
          filename: `worker_logic_${workerId.replace(/[^a-z0-9-]/gi, '_')}.py`,
          content: result.python_code,
        });
      }
      btn.textContent = 'Saved';
      setTimeout(() => { btn.textContent = origText; btn.disabled = false; }, 2000);
    } catch (err) {
      btn.textContent = 'Error';
      setTimeout(() => { btn.textContent = origText; btn.disabled = false; }, 2000);
      console.error('Get a copy failed:', err);
    }
  }

  function showWorkerDetails(w) {
    // Simple modal-style detail display using alert for now
    // In a real app this would be a slide-in panel
    const caps = (w.capabilities || []).join('\n  ');
    const details = [
      `Species ID:     ${w.species_id}`,
      `Name:           ${w.name || '—'}`,
      w.description ? `Description:    ${w.description}` : '',
      `Capabilities:\n  ${caps}`,
      `Guarantee:      ${w.guarantee || '—'}`,
      `Blast score:    ${w.blast_score} / 100 (${blastTierLabel(w.blast_score)})`,
      `Risk tier:      ${w.risk_tier || '—'}`,
      `Status:         ${w.status}`,
      `Profile:        ${w.profile || '—'}`,
      w.dispatches_today !== undefined ? `Dispatches today: ${w.dispatches_today}` : '',
      w.failures_today !== undefined ? `Failures today:   ${w.failures_today}` : '',
      w.dlq_count !== undefined ? `DLQ count:        ${w.dlq_count}` : '',
    ].filter(Boolean).join('\n');

    // Use a non-blocking info display instead of alert
    const existing = document.getElementById('worker-detail-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'worker-detail-overlay';
    overlay.style.cssText = `
      position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 1000;
      display: flex; align-items: center; justify-content: center;
    `;
    overlay.innerHTML = `
      <div style="background:var(--bg-surface); border:1px solid var(--bg-border); border-radius:var(--radius); padding:24px; max-width:500px; width:90%; max-height:70vh; overflow-y:auto;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
          <span style="font-weight:600; color:var(--text-bright); font-size:14px;">${esc(w.species_id)}</span>
          <button class="btn btn-ghost btn-sm" id="close-detail-overlay">✕</button>
        </div>
        <pre style="font-family:var(--font-mono); font-size:11px; color:var(--text-primary); white-space:pre-wrap; line-height:1.6;">${esc(details)}</pre>
      </div>
    `;
    document.body.appendChild(overlay);
    document.getElementById('close-detail-overlay').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  }

  // ── Load workers ──────────────────────────────────────────────────────────

  async function refresh() {
    const url = window.AppState.hallUrl;
    const online = window.AppState.hallOnline;

    let serverWorkers = [];
    let localWorkers = [];
    let catalogWorkers = [];

    // Load from Hall Server when online
    if (online) {
      try {
        const result = await HallAPI.getWorkers(url);
        if (result.workers && result.source !== 'offline') {
          serverWorkers = result.workers;
        }
      } catch (e) {}

      // Load catalog from SDK via Hall Server
      catalogWorkers = await loadCatalog(url);
    }

    // Local enrolled (always try)
    try {
      const local = await HallAPI.listEnrolledWorkers();
      localWorkers = (local.workers || []).map(w => Object.assign({}, w, { status: w.status || 'idle', source: 'local' }));
    } catch (e) {}

    // Merge: server > local > catalog (catalog fills in unenrolled species)
    const enrolledIds = new Set([...serverWorkers, ...localWorkers].map(w => w.species_id));
    const catalogExtra = catalogWorkers.filter(w => !enrolledIds.has(w.species_id));

    allWorkers = [...serverWorkers, ...localWorkers, ...catalogExtra];
    renderCrew();
  }

  // ── Filters ───────────────────────────────────────────────────────────────

  document.querySelectorAll('[data-crew-filter]').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('[data-crew-filter]').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      crewFilter = chip.dataset.crewFilter;
      renderCrew();
    });
  });

  document.getElementById('crew-search')?.addEventListener('input', e => {
    searchQuery = e.target.value;
    renderCrew();
  });

  // Initial load
  refresh();

  return { refresh };
})();

function esc(str) {
  if (str === null || str === undefined) return '—';
  if (typeof str !== 'string') str = String(str);
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
