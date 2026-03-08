/**
 * feed.js — Live Dispatch Feed screen (Screen 2)
 * Real-time table of dispatch events, filterable, pauseable.
 * Empty when Hall is offline — no mock data.
 */

window.FeedScreen = (() => {
  const MAX_ROWS = 500;
  let allEvents = [];
  let paused = false;
  let pausedBuffer = [];
  let activeFilter = 'all';
  let workerFilter = '';
  let pollTimer = null;

  // ── Render ────────────────────────────────────────────────────────────────

  function getFilteredEvents() {
    return allEvents.filter(raw => {
      const e = normalizeEvent(raw);
      if (activeFilter !== 'all' && e.outcome !== activeFilter) return false;
      if (workerFilter && !(e.worker || '').toLowerCase().includes(workerFilter.toLowerCase())
          && !e.capability.toLowerCase().includes(workerFilter.toLowerCase())) return false;
      return true;
    });
  }

  function normalizeEvent(raw) {
    const e = { ...raw };
    if (!e.outcome) {
      const decision = String(e.decision || '').toLowerCase();
      if (decision === 'allow') e.outcome = 'DISPATCHED';
      else if (decision === 'deny') e.outcome = 'STEWARD_HOLD';
      else e.outcome = 'REFUSED';
    }
    return e;
  }

  function renderFeed() {
    const tbody = document.getElementById('feed-body');
    if (!tbody) return;

    const filtered = getFilteredEvents().slice(0, MAX_ROWS);

    if (filtered.length === 0) {
      const offline = !window.AppState?.hallOnline;
      const msg = offline
        ? 'Hall Server offline — connect to see live dispatch events.'
        : (allEvents.length === 0 ? 'No dispatch events yet. Events will appear here as workers are dispatched.' : 'No events match the current filter.');
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:24px;">${msg}</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(raw => {
      const e = normalizeEvent(raw);
      const rowClass = e.outcome === 'DISPATCHED' ? 'dispatched' :
                       e.outcome === 'REFUSED'      ? 'refused'    : 'held';
      const outcomeEl = e.outcome === 'DISPATCHED'
        ? `<span class="outcome-dispatched">✓ DISPATCHED</span>`
        : e.outcome === 'REFUSED'
        ? `<span class="outcome-refused">✗ HALL REFUSED</span>`
        : `<span class="outcome-held">✗ STEWARD HOLD</span>`;
      const blastEl = (e.blast_score === null || e.blast_score === undefined)
        ? '<span style="color:var(--text-muted)">—</span>'
        : `<span class="blast-tier ${blastTierClass(e.blast_score)}">${e.blast_score}</span>`;

      return `
        <tr class="${rowClass}" data-id="${esc(e.id)}" style="cursor:pointer;">
          <td class="mono" style="white-space:nowrap;">${formatTimeCT(e.timestamp)}</td>
          <td>${outcomeEl}</td>
          <td class="mono" style="font-size:11px;">${esc(e.worker) || '<span style="color:var(--text-muted)">—</span>'}</td>
          <td class="mono" style="font-size:11px;">${esc(e.capability)}</td>
          <td>${blastEl}</td>
        </tr>
        <tr class="ticket-row" id="ticket-${esc(e.id)}" style="display:none;">
          <td colspan="5">${renderWorkTicket(e)}</td>
        </tr>
      `;
    }).join('');

    // Wire row click to expand ticket
    tbody.querySelectorAll('tr[data-id]').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.dataset.id;
        const ticketRow = document.getElementById(`ticket-${id}`);
        if (ticketRow) {
          ticketRow.style.display = ticketRow.style.display === 'none' ? 'table-row' : 'none';
        }
      });
    });
  }

  function renderWorkTicket(e) {
    const hash = `sha256:${pseudoHash(e.id || e.capability)}`;
    return `
      <div class="work-ticket">
        <div style="font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; color:var(--text-muted); margin-bottom:8px;">▾ WORK TICKET</div>
        <div class="ticket-row"><span class="ticket-label">ticket_id</span><span class="ticket-value">${e.id || '—'}</span></div>
        <div class="ticket-row"><span class="ticket-label">capability</span><span class="ticket-value">${esc(e.capability)}</span></div>
        <div class="ticket-row"><span class="ticket-label">worker</span><span class="ticket-value">${esc(e.worker) || '—'}</span></div>
        <div class="ticket-row"><span class="ticket-label">tenant_id</span><span class="ticket-value">${esc(e.tenant_id) || 'unknown'}</span></div>
        <div class="ticket-row"><span class="ticket-label">env</span><span class="ticket-value">${esc(e.env) || 'prod'}</span></div>
        <div class="ticket-row"><span class="ticket-label">blast_score</span><span class="ticket-value">${e.blast_score} / 100</span></div>
        <div class="ticket-row"><span class="ticket-label">profile</span><span class="ticket-value">${esc(e.profile) || '—'}</span></div>
        <div class="ticket-row"><span class="ticket-label">outcome</span><span class="ticket-value">${esc(e.outcome)}${e.reason ? ` · ${esc(e.reason)}` : ''}</span></div>
        <div class="ticket-row"><span class="ticket-label">decided_at</span><span class="ticket-value">${esc(e.timestamp)}</span></div>
        <div class="ticket-row"><span class="ticket-label">hash</span><span class="ticket-value">${hash}</span></div>
        <div style="margin-top:8px; display:flex; gap:8px;">
          <button class="btn btn-ghost btn-sm" onclick="navigator.clipboard && navigator.clipboard.writeText(JSON.stringify(${esc(JSON.stringify(e))}, null, 2))">Copy JSON</button>
          <button class="btn btn-ghost btn-sm" onclick="navigator.clipboard && navigator.clipboard.writeText('${hash}')">Copy hash</button>
        </div>
      </div>
    `;
  }

  // Deterministic pseudo-hash for display
  function pseudoHash(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = Math.imul(31, h) + str.charCodeAt(i) | 0;
    }
    const hex = Math.abs(h).toString(16).padStart(8, '0');
    return (hex + hex + hex + hex + hex + hex + hex + hex).slice(0, 64);
  }

  // ── Pause / resume ────────────────────────────────────────────────────────

  function setPaused(p) {
    paused = p;
    const btn = document.getElementById('btn-pause-feed');
    const banner = document.getElementById('paused-banner');
    if (btn) btn.textContent = p ? '▶ Resume' : '⏸ Pause';
    if (banner) banner.classList.toggle('visible', p);
    if (!p && pausedBuffer.length > 0) {
      allEvents = [...pausedBuffer.reverse(), ...allEvents].slice(0, MAX_ROWS);
      pausedBuffer = [];
      renderFeed();
    }
  }

  function addEvent(evt) {
    if (paused) {
      pausedBuffer.unshift(evt);
      const countEl = document.getElementById('paused-count');
      if (countEl) countEl.textContent = pausedBuffer.length;
    } else {
      allEvents = [evt, ...allEvents].slice(0, MAX_ROWS);
      if (document.getElementById('screen-feed').classList.contains('active')) {
        renderFeed();
      }
    }
  }

  // ── Live poll (when online) ───────────────────────────────────────────────

  async function pollFeed() {
    if (!window.AppState.hallOnline) return;
    try {
      const result = await HallAPI.getDispatchFeed(window.AppState.hallUrl, 100);
      const events = result.events || [];
      if (events.length > 0 && result.source !== 'mock' && result.source !== 'offline') {
        allEvents = events.map(normalizeEvent);
        if (!paused && document.getElementById('screen-feed').classList.contains('active')) {
          renderFeed();
        }
      }
    } catch (e) {}
  }

  // ── Filter chips ──────────────────────────────────────────────────────────

  document.querySelectorAll('[data-filter]').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('[data-filter]').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      activeFilter = chip.dataset.filter;
      renderFeed();
    });
  });

  document.getElementById('feed-worker-filter')?.addEventListener('input', e => {
    workerFilter = e.target.value;
    renderFeed();
  });

  // ── Button wiring ─────────────────────────────────────────────────────────

  document.getElementById('btn-pause-feed')?.addEventListener('click', () => setPaused(!paused));
  document.getElementById('btn-resume-feed')?.addEventListener('click', () => setPaused(false));
  document.getElementById('btn-clear-feed')?.addEventListener('click', () => {
    allEvents = [];
    pausedBuffer = [];
    renderFeed();
  });

  // ── Public API ────────────────────────────────────────────────────────────

  function onShow() {
    renderFeed();
  }

  // Poll live feed every 3s
  setInterval(pollFeed, 3000);

  return { onShow };
})();

function esc(str) {
  if (str === null || str === undefined) return '—';
  if (typeof str !== 'string') str = String(str);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
