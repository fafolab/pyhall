/**
 * coordination.js — Multi-Agent Coordination screen
 * Shows live agent roster, WCP-governed task board (Kanban), and SSE event feed.
 *
 * Data sources (Hall Server port 8765):
 *   GET /api/coord/agents  — agent roster
 *   GET /api/coord/tasks   — task list
 *   GET /events            — SSE stream
 *
 * SSE event format:
 *   { type: "tool_call"|"heartbeat"|"connected", tool: "...", args: {...}, ts: "..." }
 */

window.CoordinationScreen = (() => {

  // ── State ─────────────────────────────────────────────────────────────────

  let agents = [];
  let tasks  = [];
  let locks  = [];
  let eventLog = [];
  const MAX_EVENTS = 200;

  let pollTimer   = null;
  let sseSource   = null;
  let sseBackoff  = 5000;
  let sseRetryTimer = null;
  let isVisible   = false;
  let currentView = localStorage.getItem('coord-view') || 'kanban';

  // ── Owner → color mapping ─────────────────────────────────────────────────

  function ownerColor(owner) {
    switch ((owner || '').toLowerCase()) {
      case 'claude': return 'coord-owner-claude';
      case 'codex':  return 'coord-owner-codex';
      case 'monty':  return 'coord-owner-monty';
      case 'rob':    return 'coord-owner-rob';
      default:       return 'coord-owner-other';
    }
  }

  function agentStatusClass(status) {
    switch (status) {
      case 'active':  return 'coord-agent-active';
      case 'idle':    return 'coord-agent-idle';
      case 'offline': return 'coord-agent-offline';
      default:        return 'coord-agent-idle';
    }
  }

  function eventTypeLabel(type) {
    switch (type) {
      case 'tool_call':     return 'TOOL';
      case 'mcp_tool_call': return 'MCP';
      case 'heartbeat':     return 'HB';
      case 'connected':     return 'CONN';
      case 'agent_ping':    return 'PING';
      case 'task_created':  return 'NEW';
      case 'task_complete': return 'DONE';
      case 'dispatch':      return 'WCP';
      default:              return type.toUpperCase().slice(0, 6);
    }
  }

  function eventTypeClass(type) {
    switch (type) {
      case 'tool_call':
      case 'mcp_tool_call': return 'coord-evt-tool';
      case 'heartbeat':     return 'coord-evt-hb';
      case 'connected':     return 'coord-evt-conn';
      case 'agent_ping':    return 'coord-evt-ping';
      case 'task_created':  return 'coord-evt-new';
      case 'task_complete': return 'coord-evt-done';
      case 'dispatch':      return 'coord-evt-wcp';
      default:              return 'coord-evt-tool';
    }
  }

  function eventSummary(evt) {
    if (evt.type === 'agent_ping') {
      return `${esc(evt.from)} → ${esc(evt.to)}: ${esc(evt.message)}`;
    }
    if (evt.type === 'task_created') {
      return `new task ${esc(evt.task?.id || '')}: ${esc(evt.task?.title || '')}`;
    }
    if (evt.type === 'task_complete') {
      return `task ${esc(evt.task_id)} completed by ${esc(evt.agent)}`;
    }
    if (evt.type === 'dispatch') {
      return `${esc(evt.capability || evt.agent || '')} → ${esc(evt.decision || 'allow')}`;
    }
    const tool = evt.tool || '';
    const args = evt.args || {};
    const argStr = Object.entries(args).map(([k,v]) => `${k}=${JSON.stringify(v)}`).join(' ').slice(0, 80);
    return `${esc(tool)} ${argStr}`;
  }

  // ── Render: agent roster + dynamic dropdowns ─────────────────────────────

  function renderAgents() {
    const container = document.getElementById('coord-agent-roster');
    if (!container) return;

    if (agents.length === 0) {
      container.innerHTML = '<div class="coord-offline-msg">No agent data — Hall Server offline.</div>';
      return;
    }

    container.innerHTML = agents.map(a => {
      const statusClass = agentStatusClass(a.status);
      const lastSeen = a.last_seen ? formatTimeCT(a.last_seen) : '—';
      return `
        <div class="coord-agent-card ${statusClass}">
          <div class="coord-agent-name">${esc(a.name)}</div>
          <div class="coord-agent-type">${esc(a.type)}</div>
          <div class="coord-agent-tasks">
            <span class="coord-agent-task-count">${a.active_tasks ?? 0}</span>
            <span class="coord-agent-task-label">active</span>
          </div>
          <div class="coord-agent-seen">${lastSeen}</div>
        </div>
      `;
    }).join('');

    // Repopulate dropdowns from live registry — no hardcoding
    _populateAgentDropdowns();
  }

  function _populateAgentDropdowns() {
    // Message "to" dropdown
    const msgTo = document.getElementById('msg-to');
    if (msgTo) {
      const current = msgTo.value;
      msgTo.innerHTML = '<option value="all">→ All</option>' +
        agents.map(a => `<option value="${esc(a.id)}">${esc(a.name || a.id)}</option>`).join('');
      if ([...msgTo.options].some(o => o.value === current)) msgTo.value = current;
    }

    // Task owner dropdown
    const ntOwner = document.getElementById('nt-owner');
    if (ntOwner) {
      const current = ntOwner.value;
      ntOwner.innerHTML =
        agents.map(a => `<option value="${esc(a.id)}">${esc(a.name || a.id)}</option>`).join('') +
        '<option value="any">Any</option>';
      if ([...ntOwner.options].some(o => o.value === current)) ntOwner.value = current;
    }

    // Reassign const in coordination.js
    const registered = agents.map(a => a.id);
    if (registered.length) AGENTS.length = 0, registered.forEach(id => AGENTS.push(id));
  }

  // ── Task reassignment ─────────────────────────────────────────────────────

  const AGENTS = ['claude', 'codex', 'monty', 'rob', 'any'];

  async function reassignTask(taskId, newOwner) {
    const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';
    try {
      await fetch(`${url}/api/coord/tasks/${encodeURIComponent(taskId)}/reassign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ owner: newOwner }),
      });
      await fetchTasks();
    } catch (e) {
      console.warn('[coord] reassign failed:', e);
    }
  }

  function editButtonHtml(t) {
    if (!t) return '';
    const safeId = t.id.replace(/['"]/g, '');
    return `<button class="coord-edit-btn" onclick="window._showEditModal('${safeId}')">Edit</button>`;
  }

  function completeButtonHtml(t) {
    if (!t || t.status === 'done') return '';
    const safeId = t.id.replace(/['"]/g, '');
    return `<button class="coord-complete-btn" onclick="window._showCompleteModal('${safeId}')">Mark Complete</button>`;
  }

  function reassignDropdownHtml(taskId) {
    const options = AGENTS.map(a =>
      `<option value="${a}">${a}</option>`
    ).join('');
    const safeId = taskId.replace(/'/g, '');
    return `
      <div class="coord-reassign-row">
        <select class="coord-reassign-select" onchange="window._reassign('${safeId}', this.value); this.value=''">
          <option value="" disabled selected>reassign…</option>
          ${options}
        </select>
      </div>`;
  }

  window._reassign = (taskId, newOwner) => {
    if (!newOwner) return;
    reassignTask(taskId, newOwner);
  };

  // ── Dependency graph helpers ──────────────────────────────────────────────

  function parsePreds(str) {
    return (str || '').split(',').map(s => s.trim()).filter(Boolean);
  }

  function buildDepGraph() {
    const byId = {};
    tasks.forEach(t => { byId[t.id] = t; });
    const successors = {};
    tasks.forEach(t => {
      parsePreds(t.predecessors).forEach(pid => {
        if (!successors[pid]) successors[pid] = [];
        if (!successors[pid].includes(t.id)) successors[pid].push(t.id);
      });
    });
    return { byId, successors };
  }

  // ── View toggle ───────────────────────────────────────────────────────────

  function setView(view) {
    currentView = view;
    localStorage.setItem('coord-view', view);
    document.querySelectorAll('.coord-view-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === view);
    });
    document.getElementById('coord-kanban-view').style.display   = view === 'kanban'   ? '' : 'none';
    document.getElementById('coord-tree-view').style.display     = view === 'tree'     ? '' : 'none';
    document.getElementById('coord-swimlane-view').style.display = view === 'swimlane' ? '' : 'none';
    document.getElementById('coord-phases-view').style.display   = view === 'phases'   ? '' : 'none';
    renderTasks();
  }

  function initViewToggle() {
    document.getElementById('coord-view-toggle')?.addEventListener('click', e => {
      const btn = e.target.closest('.coord-view-btn');
      if (btn) setView(btn.dataset.view);
    });
  }

  // ── Render: dispatcher ────────────────────────────────────────────────────

  function renderTasks() {
    if (currentView === 'tree')     { renderTree();     return; }
    if (currentView === 'swimlane') { renderSwimlanes(); return; }
    if (currentView === 'phases')   { renderPhases();   return; }
    renderKanban();
  }

  // ── Render: Kanban ────────────────────────────────────────────────────────

  function renderKanban() {
    const cols = {
      pending:     document.getElementById('coord-col-pending'),
      in_progress: document.getElementById('coord-col-inprogress'),
      done:        document.getElementById('coord-col-done'),
    };

    if (!cols.pending) return;

    Object.values(cols).forEach(col => { if (col) col.innerHTML = ''; });

    const counts = { pending: 0, in_progress: 0, done: 0 };

    tasks.forEach(t => {
      const status = t.status || 'pending';
      const col = cols[status];
      if (!col) return;
      counts[status] = (counts[status] || 0) + 1;
      const ownerCls  = ownerColor(t.owner);
      const claimedBy = t.claimed_by ? `<span class="coord-task-claimed">claimed: ${esc(t.claimed_by)}</span>` : '';
      col.insertAdjacentHTML('beforeend', `
        <div class="coord-task-card coord-status-${esc(status)}">
          <div class="coord-task-header">
            <span class="coord-task-id ${ownerCls}">${esc(t.id)}</span>
            <span class="coord-task-owner-badge ${ownerCls}">${esc(t.owner || '?')}</span>
          </div>
          <div class="coord-task-title">${esc(t.title)}</div>
          ${claimedBy}
          <div class="coord-card-actions">
            ${editButtonHtml(t)}
            ${completeButtonHtml(t)}
            ${reassignDropdownHtml(t.id)}
          </div>
        </div>
      `);
    });

    const colIds = { pending: 'coord-count-pending', in_progress: 'coord-count-inprogress', done: 'coord-count-done' };
    Object.entries(colIds).forEach(([key, elId]) => {
      const el = document.getElementById(elId);
      if (el) el.textContent = counts[key] || 0;
    });
  }

  // ── Render: Dependency Tree ───────────────────────────────────────────────

  function renderTree() {
    const container = document.getElementById('coord-tree-view');
    if (!container) return;
    if (tasks.length === 0) { container.innerHTML = '<div class="coord-feed-empty">No tasks.</div>'; return; }

    const { byId, successors } = buildDepGraph();

    // Roots = tasks with no predecessors, or all predecessors are done/missing
    const roots = tasks.filter(t => {
      const preds = parsePreds(t.predecessors);
      return preds.length === 0 || preds.every(pid => !byId[pid] || byId[pid].status === 'done');
    });
    roots.sort((a, b) => (a.priority || 'p1').localeCompare(b.priority || 'p1') || (a.section || '').localeCompare(b.section || ''));

    const statusDot = { pending: '○', in_progress: '◑', done: '●' };

    function renderNode(taskId, depth, visited) {
      if (visited.has(taskId)) return '';
      visited.add(taskId);
      const t = byId[taskId];
      if (!t) return '';
      const children = (successors[taskId] || []).filter(sid => byId[sid]);
      const ownerCls = ownerColor(t.owner);
      const dot = statusDot[t.status] || '○';
      const isDone = t.status === 'done';
      const badgeHtml = `<span class="coord-owner-badge-sm ${ownerCls}">${esc(t.owner || '?')}</span>`;

      if (children.length > 0) {
        const childrenHtml = children.map(cid => renderNode(cid, depth + 1, visited)).join('');
        return `
          <details class="coord-tree-node${isDone ? ' coord-tree-done' : ''}" ${depth < 2 ? 'open' : ''}>
            <summary class="coord-tree-summary">
              <span class="coord-tree-dot coord-status-dot-${t.status}">${dot}</span>
              <span class="coord-task-id ${ownerCls}">${esc(t.id)}</span>
              <span class="coord-tree-title">${esc(t.title)}</span>
              ${badgeHtml}
              <span class="coord-tree-blocks">→ ${children.length} task${children.length !== 1 ? 's' : ''}</span>
              ${editButtonHtml(t)}
              ${completeButtonHtml(t)}
              ${reassignDropdownHtml(t.id)}
            </summary>
            <div class="coord-tree-children">${childrenHtml}</div>
          </details>`;
      } else {
        return `
          <div class="coord-tree-node coord-tree-leaf${isDone ? ' coord-tree-done' : ''}">
            <span class="coord-tree-dot coord-status-dot-${t.status}">${dot}</span>
            <span class="coord-task-id ${ownerCls}">${esc(t.id)}</span>
            <span class="coord-tree-title">${esc(t.title)}</span>
            ${badgeHtml}
            ${editButtonHtml(t)}
            ${completeButtonHtml(t)}
            ${reassignDropdownHtml(t.id)}
          </div>`;
      }
    }

    const visited = new Set();
    let html = roots.map(t => renderNode(t.id, 0, visited)).join('');
    const orphans = tasks.filter(t => !visited.has(t.id));
    if (orphans.length) {
      html += `<div class="coord-tree-orphans">${orphans.map(t => renderNode(t.id, 0, visited)).join('')}</div>`;
    }
    container.innerHTML = html || '<div class="coord-feed-empty">No tasks.</div>';
  }

  // ── Render: Order of Operations (Phases) ─────────────────────────────────
  //
  // Topological wave = computed from predecessor graph.
  // Phase overrides let Rob/agents manually push tasks to a later phase.
  // Override = stored in localStorage. Effective phase = max(computed, override).
  // Overrides can only delay (push later), never pull earlier than the graph allows.

  const PHASE_OVERRIDES_KEY = 'coord-phase-overrides';

  function phaseFromSection(section) {
    if (!section) return null;
    const m = String(section).trim().match(/^PHASE\s+(\d+)$/i);
    if (!m) return null;
    const n = Number(m[1]);
    if (!Number.isFinite(n) || n < 1) return null;
    return n - 1; // UI waves are 0-based (Phase 1 => wave 0)
  }

  function loadPhaseOverrides() {
    try { return JSON.parse(localStorage.getItem(PHASE_OVERRIDES_KEY) || '{}'); } catch { return {}; }
  }
  function savePhaseOverrides(overrides) {
    localStorage.setItem(PHASE_OVERRIDES_KEY, JSON.stringify(overrides));
  }

  window._phaseMove = (taskId, delta) => {
    const overrides = loadPhaseOverrides();
    const current = overrides[taskId] ?? null;
    if (delta < 0 && current === null) return; // already at computed wave
    if (delta < 0) {
      if (current <= 1) { delete overrides[taskId]; }
      else              { overrides[taskId] = current - 1; }
    } else {
      overrides[taskId] = (current ?? 0) + 1;
    }
    savePhaseOverrides(overrides);
    renderPhases();
  };

  window._phaseReset = () => {
    localStorage.removeItem(PHASE_OVERRIDES_KEY);
    renderPhases();
  };

  function renderPhases() {
    const container = document.getElementById('coord-phases-view');
    if (!container) return;
    if (tasks.length === 0) { container.innerHTML = '<div class="coord-feed-empty">No tasks.</div>'; return; }

    const byId = {};
    tasks.forEach(t => { byId[t.id] = t; });

    // Compute topological wave (0 = no incomplete predecessors)
    const computedWave = {};
    function getWave(taskId, visited = new Set()) {
      if (computedWave[taskId] !== undefined) return computedWave[taskId];
      if (visited.has(taskId)) { computedWave[taskId] = 0; return 0; }
      visited.add(taskId);
      const preds = parsePreds(byId[taskId]?.predecessors)
        .filter(pid => byId[pid] && byId[pid].status !== 'done');
      computedWave[taskId] = preds.length === 0
        ? 0
        : Math.max(...preds.map(pid => getWave(pid, new Set(visited)))) + 1;
      return computedWave[taskId];
    }
    tasks.filter(t => t.status !== 'done').forEach(t => getWave(t.id));

    // Apply manual overrides: effective phase = max(computed, override)
    const overrides = loadPhaseOverrides();
    const effectiveWave = {};
    tasks.filter(t => t.status !== 'done').forEach(t => {
      const computed = computedWave[t.id] ?? 0;
      const override = overrides[t.id] ?? 0;
      const sectionWave = phaseFromSection(t.section);
      effectiveWave[t.id] = Math.max(computed, override, sectionWave ?? 0);
    });

    // Group by effective wave
    const waveMap = {};
    let maxWave = 0;
    tasks.filter(t => t.status !== 'done').forEach(t => {
      const w = effectiveWave[t.id] ?? 0;
      if (!waveMap[w]) waveMap[w] = [];
      waveMap[w].push(t);
      if (w > maxWave) maxWave = w;
    });

    const doneTasks = tasks.filter(t => t.status === 'done');

    const statusIcon = { pending: '○', in_progress: '◑', done: '●', blocked: '✕' };
    const priorityBadge = { p0: '<span class="coord-phase-p0">P0</span>', p1: '', p2: '<span class="coord-phase-p2">p2</span>' };
    const hasOverrides = Object.keys(overrides).length > 0;

    function taskRow(t) {
      const ownerCls = ownerColor(t.owner);
      const icon = statusIcon[t.status] || '○';
      const pBadge = priorityBadge[t.priority || 'p1'] || '';
      const blockerPreds = parsePreds(t.predecessors).filter(pid => byId[pid] && byId[pid].status !== 'done');
      const blockedBy = blockerPreds.length
        ? `<span class="coord-phase-blocked-by">blocked by: ${blockerPreds.map(p => `<span class="coord-phase-dep">${esc(p)}</span>`).join(', ')}</span>`
        : '';
      const safeId = t.id.replace(/['"]/g, '');
      const isOverridden = overrides[t.id] !== undefined;
      const canMoveUp = isOverridden; // can only move up if manually pushed down
      const moveControls = t.status !== 'done' ? `
        <span class="coord-phase-move">
          <button class="coord-phase-move-btn" title="Move earlier" ${canMoveUp ? '' : 'disabled'} onclick="window._phaseMove('${safeId}',-1)">▲</button>
          <button class="coord-phase-move-btn" title="Move later" onclick="window._phaseMove('${safeId}',1)">▼</button>
          ${isOverridden ? `<span class="coord-phase-overridden" title="Manually adjusted">✎</span>` : ''}
        </span>` : '';
      return `
        <div class="coord-phase-row coord-status-${esc(t.status)}">
          <span class="coord-phase-dot coord-status-dot-${t.status}">${icon}</span>
          ${moveControls}
          <span class="coord-task-id ${ownerCls}">${esc(t.id)}</span>
          <span class="coord-phase-title">${esc(t.title)}</span>
          <span class="coord-owner-badge-sm ${ownerCls}">${esc(t.owner || '?')}</span>
          ${pBadge}
          ${blockedBy}
          ${editButtonHtml(t)}
          ${completeButtonHtml(t)}
          ${reassignDropdownHtml(t.id)}
        </div>`;
    }

    const resetBtn = hasOverrides
      ? `<button class="coord-phase-reset-btn" onclick="window._phaseReset()">Reset order</button>`
      : '';
    let html = resetBtn ? `<div class="coord-phase-toolbar">${resetBtn}<span class="coord-phase-toolbar-note">▲▼ to adjust phase · ✎ = manually adjusted</span></div>` : '';

    for (let w = 0; w <= maxWave; w++) {
      const phaseTasks = (waveMap[w] || []).sort((a, b) =>
        (a.priority || 'p1').localeCompare(b.priority || 'p1') ||
        (a.owner || '').localeCompare(b.owner || '')
      );
      if (!phaseTasks.length) continue;
      const isNow = w === 0;
      const humanNames = (t) => t.owner === 'rob' ? '👤 Rob' : null;
      const robTasks  = phaseTasks.filter(t => t.owner === 'rob' || t.owner === 'Claude+Rob');
      const aiTasks   = phaseTasks.filter(t => t.owner !== 'rob' && t.owner !== 'Claude+Rob');
      html += `
        <div class="coord-phase-block${isNow ? ' coord-phase-now' : ''}">
          <div class="coord-phase-header">
            <span class="coord-phase-label">Phase ${w + 1}${isNow ? ' — DO NOW' : ''}</span>
            <span class="coord-phase-count">${phaseTasks.length} task${phaseTasks.length !== 1 ? 's' : ''}</span>
          </div>
          ${robTasks.length ? `<div class="coord-phase-owner-group"><span class="coord-phase-owner-label coord-owner-rob">Rob</span>${robTasks.map(taskRow).join('')}</div>` : ''}
          ${aiTasks.length  ? `<div class="coord-phase-owner-group"><span class="coord-phase-owner-label">Agents</span>${aiTasks.map(taskRow).join('')}</div>` : ''}
        </div>`;
    }

    // Done tasks — collapsed
    if (doneTasks.length) {
      html += `
        <details class="coord-phase-done-block">
          <summary class="coord-phase-done-summary">Completed (${doneTasks.length})</summary>
          ${doneTasks.map(taskRow).join('')}
        </details>`;
    }

    container.innerHTML = html || '<div class="coord-feed-empty">No tasks.</div>';
  }

  // ── Render: CPM Swimlanes ─────────────────────────────────────────────────

  function renderSwimlanes() {
    const container = document.getElementById('coord-swimlane-view');
    if (!container) return;
    if (tasks.length === 0) { container.innerHTML = '<div class="coord-feed-empty">No tasks.</div>'; return; }

    const { byId, successors } = buildDepGraph();

    // Compute topological depth for ordering
    const depths = {};
    function depth(taskId) {
      if (depths[taskId] !== undefined) return depths[taskId];
      depths[taskId] = 0; // avoid infinite loops
      const preds = parsePreds(byId[taskId]?.predecessors).filter(pid => byId[pid]);
      if (preds.length) depths[taskId] = Math.max(...preds.map(pid => depth(pid) + 1));
      return depths[taskId];
    }
    tasks.forEach(t => depth(t.id));

    // Group by section
    const sectionOrder = [];
    const sections = {};
    tasks.forEach(t => {
      const sec = t.section || 'Other';
      if (!sections[sec]) { sections[sec] = []; sectionOrder.push(sec); }
      sections[sec].push(t);
    });
    Object.values(sections).forEach(arr => arr.sort((a, b) => (depths[a.id] || 0) - (depths[b.id] || 0)));

    const html = sectionOrder.map(section => {
      const sectionTasks = sections[section];
      const cards = sectionTasks.map(t => {
        const ownerCls = ownerColor(t.owner);
        const preds = parsePreds(t.predecessors).filter(pid => byId[pid]);
        const succs = (successors[t.id] || []).filter(sid => byId[sid]);
        const predsHtml = preds.length
          ? `<div class="coord-swim-deps">← ${preds.map(pid => `<span class="coord-swim-depid">${esc(pid)}</span>`).join(' ')}</div>`
          : '';
        const succsHtml = succs.length
          ? `<div class="coord-swim-deps">→ ${succs.map(sid => `<span class="coord-swim-depid">${esc(sid)}</span>`).join(' ')}</div>`
          : '';
        const safeId = t.id.replace(/'/g, '');
        return `
          <div class="coord-swim-card coord-status-${esc(t.status)}" data-task-id="${esc(t.id)}"
               onmouseenter="window._swimHL('${safeId}')" onmouseleave="window._swimClear()">
            <div class="coord-task-header">
              <span class="coord-task-id ${ownerCls}">${esc(t.id)}</span>
              <span class="coord-task-owner-badge ${ownerCls}">${esc(t.owner || '?')}</span>
            </div>
            <div class="coord-task-title">${esc(t.title)}</div>
            ${predsHtml}${succsHtml}
            <div class="coord-card-actions">
              ${editButtonHtml(t)}
              ${completeButtonHtml(t)}
              ${reassignDropdownHtml(t.id)}
            </div>
          </div>`;
      }).join('');
      return `
        <div class="coord-swim-lane">
          <div class="coord-swim-label">${esc(section)}</div>
          <div class="coord-swim-cards">${cards}</div>
        </div>`;
    }).join('');

    container.innerHTML = html;

    // Hover highlight: active=self, pred=gold, succ=green, dim=others
    window._swimHL = (taskId) => {
      const preds = parsePreds(byId[taskId]?.predecessors).filter(pid => byId[pid]);
      const succs = successors[taskId] || [];
      document.querySelectorAll('.coord-swim-card').forEach(el => {
        const id = el.dataset.taskId;
        el.classList.remove('coord-swim-active', 'coord-swim-pred', 'coord-swim-succ', 'coord-swim-dim');
        if      (id === taskId)      el.classList.add('coord-swim-active');
        else if (preds.includes(id)) el.classList.add('coord-swim-pred');
        else if (succs.includes(id)) el.classList.add('coord-swim-succ');
        else                         el.classList.add('coord-swim-dim');
      });
    };
    window._swimClear = () => {
      document.querySelectorAll('.coord-swim-card').forEach(el =>
        el.classList.remove('coord-swim-active', 'coord-swim-pred', 'coord-swim-succ', 'coord-swim-dim'));
    };
  }

  // ── Render: event feed ────────────────────────────────────────────────────

  function renderEventLog() {
    const container = document.getElementById('coord-event-feed');
    if (!container) return;

    if (eventLog.length === 0) {
      container.innerHTML = '<div class="coord-feed-empty">No events yet.</div>';
      return;
    }

    container.innerHTML = eventLog.map(e => {
      const ts     = formatTimeCT(e.ts);
      const tLabel = eventTypeLabel(e.type);
      const tClass = eventTypeClass(e.type);
      const summary = eventSummary(e);

      return `
        <div class="coord-feed-row ${e.type === 'agent_ping' ? 'coord-feed-row-ping' : ''}">
          <span class="coord-feed-ts">${ts}</span>
          <span class="coord-feed-type ${tClass}">${tLabel}</span>
          <span class="coord-feed-summary">${summary}</span>
        </div>
      `;
    }).join('');
  }

  // ── Offline banner ────────────────────────────────────────────────────────

  function setOfflineState(show) {
    const banner = document.getElementById('coord-offline-banner');
    if (banner) banner.style.display = show ? 'block' : 'none';
  }

  // ── Data fetch ────────────────────────────────────────────────────────────

  async function fetchAgents() {
    const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';
    try {
      const res = await fetch(`${url}/api/coord/agents`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      agents = data.agents || data || [];
      setOfflineState(false);
    } catch (_) {
      agents = [];
      setOfflineState(!window.AppState || !window.AppState.hallOnline);
    }
    renderAgents();
  }

  async function fetchTasks() {
    const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';
    try {
      const res = await fetch(`${url}/api/coord/tasks`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      tasks = data.tasks || data || [];
      setOfflineState(false);
    } catch (_) {
      tasks = [];
    }
    renderTasks();
  }

  async function fetchLocks() {
    const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';
    try {
      const res = await fetch(`${url}/api/coord/locks`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      locks = (data.locks || []).filter(l => l.released_at == null);
    } catch (_) {
      locks = [];
    }
    renderLocks();
  }

  function renderLocks() {
    const divider = document.getElementById('coord-locks-divider');
    const list = document.getElementById('coord-locks-list');
    if (!divider || !list) return;

    if (locks.length === 0) {
      divider.style.display = 'none';
      list.style.display = 'none';
      return;
    }

    divider.style.display = '';
    list.style.display = '';
    list.innerHTML = locks.map(l => {
      const exp = l.expires_at ? formatTimeCT(l.expires_at) : '—';
      const path = l.path || l.file_path || '—';
      const holder = l.agent_id || l.holder || '—';
      return `<div class="coord-lock-row">
        <span class="coord-lock-path" title="${esc(path)}">${esc(path)}</span>
        <span class="coord-lock-holder">held by ${esc(holder)}</span>
        <span class="coord-lock-expires">exp ${exp}</span>
      </div>`;
    }).join('');
  }

  async function poll() {
    await Promise.all([fetchAgents(), fetchTasks(), fetchLocks()]);
  }

  // ── SSE subscription ──────────────────────────────────────────────────────

  function connectSSE() {
    if (sseSource) return; // already connected

    const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';

    try {
      sseSource = new EventSource(`${url}/events`);

      sseSource.addEventListener('open', () => {
        sseBackoff = 5000; // reset backoff on successful connection
      });

      sseSource.addEventListener('message', (e) => {
        let evt;
        try {
          evt = JSON.parse(e.data);
        } catch (_) {
          return;
        }

        // Refresh task board on task lifecycle events
        if (['task_created', 'task_complete', 'task_update'].includes(evt.type)) {
          fetchTasks();
        }
        // Refresh lock panel on file lock events
        if (evt.type === 'file_lock') {
          fetchLocks();
        }
        // Filter what goes into the visible event log
        if (!['tool_call', 'heartbeat', 'connected', 'mcp_tool_call', 'agent_ping',
               'task_created', 'task_complete', 'dispatch'].includes(evt.type)) return;

        eventLog = [evt, ...eventLog].slice(0, MAX_EVENTS);

        if (isVisible) renderEventLog();
      });

      sseSource.addEventListener('error', () => {
        disconnectSSE();
        // Reconnect with backoff
        sseRetryTimer = setTimeout(() => {
          if (isVisible) connectSSE();
        }, sseBackoff);
        sseBackoff = Math.min(sseBackoff * 2, 60000);
      });

    } catch (err) {
      console.warn('[CoordinationScreen] SSE connect failed:', err);
    }
  }

  function disconnectSSE() {
    if (sseSource) {
      sseSource.close();
      sseSource = null;
    }
    if (sseRetryTimer) {
      clearTimeout(sseRetryTimer);
      sseRetryTimer = null;
    }
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  function onShow() {
    isVisible = true;

    // Initial render with whatever data we have
    renderAgents();
    renderTasks();
    renderLocks();
    renderEventLog();
    setOfflineState(!window.AppState || !window.AppState.hallOnline);

    // Fetch fresh data
    poll();

    // Start poll loop (5s)
    if (!pollTimer) {
      pollTimer = setInterval(poll, 5000);
    }

    // Connect SSE
    connectSSE();
  }

  function onHide() {
    isVisible = false;

    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }

    disconnectSSE();
  }

  // ── Edit Task modal ───────────────────────────────────────────────────────

  let _editTargetId = null;

  window._showEditModal = (taskId) => {
    _editTargetId = taskId;
    const t = tasks.find(x => x.id === taskId);
    if (!t) return;
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val ?? ''; };
    set('edit-task-id-display', t.id);
    set('edit-title', t.title);
    set('edit-details', t.details || '');
    set('edit-section', t.section || '');
    set('edit-location', t.location || '');
    set('edit-owner', t.owner || 'any');
    set('edit-priority', t.priority || 'p1');
    set('edit-agent-type', t.agent_type || 'any');
    set('edit-predecessors', t.predecessors || '');
    set('edit-dep-type', t.dep_type || 'FS');
    const errEl = document.getElementById('edit-error');
    if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
    document.getElementById('edit-task-modal').style.display = 'flex';
  };

  function initEditModal() {
    const close = () => {
      document.getElementById('edit-task-modal').style.display = 'none';
      _editTargetId = null;
    };
    document.getElementById('edit-modal-close')?.addEventListener('click', close);
    document.getElementById('btn-edit-cancel')?.addEventListener('click', close);
    document.getElementById('edit-task-modal')?.addEventListener('click', e => {
      if (e.target === e.currentTarget) close();
    });

    document.getElementById('btn-edit-save')?.addEventListener('click', async () => {
      const taskId = _editTargetId;
      if (!taskId) return;
      const errEl = document.getElementById('edit-error');
      const saveBtn = document.getElementById('btn-edit-save');
      const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';

      const get = (id) => document.getElementById(id)?.value.trim() || '';

      const payload = {
        title:        get('edit-title'),
        details:      get('edit-details'),
        section:      get('edit-section'),
        location:     get('edit-location'),
        owner:        get('edit-owner'),
        priority:     get('edit-priority'),
        agent_type:   get('edit-agent-type'),
        predecessors: get('edit-predecessors'),
        dep_type:     get('edit-dep-type'),
      };

      if (!payload.title) {
        errEl.textContent = 'Title is required.';
        errEl.style.display = 'block';
        return;
      }

      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving…';
      try {
        const resp = await fetch(`${url}/api/coord/tasks/${encodeURIComponent(taskId)}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!data.ok) throw new Error(data.error || 'update failed');
        await fetchTasks();
        close();
      } catch (e) {
        errEl.textContent = `Error: ${e.message}`;
        errEl.style.display = 'block';
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save Changes';
      }
    });
  }

  // ── Complete Task modal ───────────────────────────────────────────────────

  let _completeTargetId = null;

  window._showCompleteModal = (taskId) => {
    _completeTargetId = taskId;
    const t = tasks.find(x => x.id === taskId);
    const infoEl = document.getElementById('complete-task-info');
    if (infoEl && t) infoEl.textContent = `[${t.id}] ${t.title}`;
    const summaryEl = document.getElementById('complete-summary');
    if (summaryEl) summaryEl.value = '';
    const errEl = document.getElementById('complete-error');
    if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
    const followupCb = document.getElementById('complete-create-followup');
    if (followupCb) followupCb.checked = false;
    const followupForm = document.getElementById('complete-followup-form');
    if (followupForm) followupForm.style.display = 'none';
    document.getElementById('complete-task-modal').style.display = 'flex';
  };

  function initCompleteModal() {
    // Toggle follow-up form
    document.getElementById('complete-create-followup')?.addEventListener('change', e => {
      document.getElementById('complete-followup-form').style.display = e.target.checked ? 'block' : 'none';
    });

    // Close
    const close = () => {
      document.getElementById('complete-task-modal').style.display = 'none';
      _completeTargetId = null;
    };
    document.getElementById('complete-modal-close')?.addEventListener('click', close);
    document.getElementById('btn-complete-cancel')?.addEventListener('click', close);
    document.getElementById('complete-task-modal')?.addEventListener('click', e => {
      if (e.target === e.currentTarget) close();
    });

    // Submit
    document.getElementById('btn-complete-submit')?.addEventListener('click', async () => {
      const taskId = _completeTargetId;
      if (!taskId) return;
      const summary = document.getElementById('complete-summary')?.value.trim() || '';
      const errEl   = document.getElementById('complete-error');
      const submitBtn = document.getElementById('btn-complete-submit');
      const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';

      submitBtn.disabled = true;
      submitBtn.textContent = 'Completing…';

      try {
        // 1. Mark task complete
        const resp = await fetch(`${url}/api/coord/tasks/${encodeURIComponent(taskId)}/complete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ agent_id: 'rob', summary }),
        });
        const data = await resp.json();
        if (!data.ok) throw new Error(data.error || 'complete failed');

        // 2. Broadcast to all agents
        const t = tasks.find(x => x.id === taskId);
        const broadcastMsg = `TASK COMPLETE: [${taskId}] ${t?.title || ''}${summary ? ' — ' + summary : ''}`;
        await fetch(`${url}/api/coord/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from_agent: 'rob',
            to_agent: 'all',
            message: broadcastMsg,
            task_id: taskId,
            msg_type: 'result',
          }),
        });

        // 3. Create follow-up task if requested
        const wantsFollowup = document.getElementById('complete-create-followup')?.checked;
        if (wantsFollowup) {
          const fuTitle   = document.getElementById('followup-title')?.value.trim();
          const fuOwner   = document.getElementById('followup-owner')?.value || 'any';
          const fuDepType = document.getElementById('followup-dep-type')?.value || 'FS';
          const fuPri     = document.getElementById('followup-priority')?.value || 'p1';
          const fuSection = document.getElementById('followup-section')?.value.trim() || t?.section || 'Ad Hoc';
          const fuDetails = document.getElementById('followup-details')?.value.trim() || '';

          if (fuTitle) {
            // For FS: follow-up's predecessor is completed task
            // For SS/SF: predecessor field still links them
            const preds = (fuDepType === 'FS' || fuDepType === 'SS') ? taskId : '';
            const fuResp = await fetch(`${url}/api/coord/tasks`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                title: fuTitle,
                owner: fuOwner,
                priority: fuPri,
                section: fuSection,
                details: fuDetails,
                predecessors: preds,
                dep_type: fuDepType,
                created_by: 'rob',
              }),
            });
            const fuData = await fuResp.json();
            if (fuData.ok && fuData.task) {
              tasks = [fuData.task, ...tasks];
              // Notify all agents about the new task
              await fetch(`${url}/api/coord/messages`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  from_agent: 'rob',
                  to_agent: 'all',
                  message: `NEW FOLLOW-UP TASK: [${fuData.task.id}] ${fuTitle} (owner: ${fuOwner}, dep: ${fuDepType} from ${taskId})`,
                  task_id: fuData.task.id,
                  msg_type: 'alert',
                }),
              });
            }
          }
        }

        // 4. Refresh and close
        await fetchTasks();
        close();

      } catch (e) {
        if (errEl) { errEl.textContent = `Error: ${e.message}`; errEl.style.display = 'block'; }
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Mark Complete + Notify All';
      }
    });
  }

  // ── New Task form ─────────────────────────────────────────────────────────

  function initNewTaskForm() {
    document.getElementById('btn-new-task')?.addEventListener('click', () => {
      const form = document.getElementById('new-task-form');
      if (form) form.style.display = form.style.display === 'none' ? 'block' : 'none';
    });

    document.getElementById('btn-cancel-task')?.addEventListener('click', () => {
      document.getElementById('new-task-form').style.display = 'none';
      clearTaskForm();
    });

    document.getElementById('btn-submit-task')?.addEventListener('click', submitNewTask);
  }

  function clearTaskForm() {
    ['nt-title','nt-details','nt-location','nt-section','nt-predecessors'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    const errEl = document.getElementById('new-task-error');
    if (errEl) errEl.style.display = 'none';
  }

  async function submitNewTask() {
    const title = document.getElementById('nt-title')?.value.trim();
    const errEl = document.getElementById('new-task-error');

    if (!title) {
      errEl.textContent = 'Title is required.';
      errEl.style.display = 'block';
      return;
    }

    const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';
    const payload = {
      title,
      details:      document.getElementById('nt-details')?.value.trim() || '',
      owner:        document.getElementById('nt-owner')?.value || 'any',
      priority:     document.getElementById('nt-priority')?.value || 'p1',
      agent_type:   document.getElementById('nt-agent-type')?.value || 'any',
      section:      document.getElementById('nt-section')?.value.trim() || 'Ad Hoc',
      location:     document.getElementById('nt-location')?.value.trim() || '',
      predecessors: document.getElementById('nt-predecessors')?.value.trim() || '',
      created_by:   'rob',
    };

    try {
      const submitBtn = document.getElementById('btn-submit-task');
      submitBtn.textContent = 'Creating…';
      submitBtn.disabled = true;

      const resp = await fetch(`${url}/api/coord/tasks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();

      if (data.ok && data.task) {
        // Add to local task list and re-render
        tasks = [data.task, ...tasks];
        renderTasks();
        document.getElementById('new-task-form').style.display = 'none';
        clearTaskForm();
      } else {
        errEl.textContent = data.error || 'Failed to create task.';
        errEl.style.display = 'block';
      }
    } catch (e) {
      errEl.textContent = `Error: ${e.message}`;
      errEl.style.display = 'block';
    } finally {
      const submitBtn = document.getElementById('btn-submit-task');
      submitBtn.textContent = 'Create Task';
      submitBtn.disabled = false;
    }
  }

  // Wire form and view toggle on module load
  initNewTaskForm();
  initEditModal();
  initCompleteModal();
  initViewToggle();

  // ── Agent message send bar ────────────────────────────────────────────────

  function initMessageBar() {
    const sendBtn  = document.getElementById('btn-send-msg');
    const msgInput = document.getElementById('msg-text');
    const msgTo    = document.getElementById('msg-to');

    async function sendMessage() {
      const text = msgInput?.value.trim();
      if (!text) return;
      const url = (window.AppState && window.AppState.hallUrl) || 'http://localhost:8765';
      try {
        await fetch(`${url}/api/coord/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from_agent: 'rob',
            to_agent: msgTo?.value || 'all',
            message: text,
            msg_type: 'message',
          }),
        });
        if (msgInput) msgInput.value = '';
      } catch (e) {}
    }

    sendBtn?.addEventListener('click', sendMessage);
    msgInput?.addEventListener('keydown', e => { if (e.key === 'Enter') sendMessage(); });
  }

  initMessageBar();

  // ── Public API ────────────────────────────────────────────────────────────

  return { onShow, onHide };

})();

// esc() is defined in feed.js and crew.js as a module-level function.
// Redeclare here only if not already present (guard against double-definition).
if (typeof window._coordEscDefined === 'undefined') {
  window._coordEscDefined = true;
  // Use the global esc if available, otherwise define a local one.
  // coordination.js loads after feed.js so window.esc (if any) takes precedence.
  // We reference the function-scoped esc via closure — define it at module scope
  // so it's available to all closures inside this IIFE.
}

// Local esc for this module's closures — safe to redefine since it's function-scoped
// within the IIFE (the global esc in feed.js is a script-level declaration which is
// a property of the global scope; we shadow it locally here to be safe).
function esc(str) {
  if (str === null || str === undefined) return '—';
  if (typeof str !== 'string') str = String(str);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
