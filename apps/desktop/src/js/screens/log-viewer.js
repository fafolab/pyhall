/* Copyright (c) 2026 pyhall.dev — All Rights Reserved. */
window.LogViewerScreen = (() => {
  async function refresh() {
    const el = document.getElementById('log-content');
    if (!el) return;

    el.textContent = 'Loading...';

    // Try local Tauri log file first
    let localContent = '';
    try {
      localContent = await window.__TAURI__.core.invoke('read_pyhall_log', { lines: 500 });
    } catch (_) {}

    if (localContent && localContent.trim()) {
      el.textContent = localContent;
      el.scrollTop = el.scrollHeight;
      _setMascot();
      return;
    }

    // Fallback: fetch from Hall Server /api/logs
    const hallUrl = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
    try {
      const resp = await fetch(`${hallUrl}/api/logs?lines=500`, {
        headers: window.AppState?.sessionToken
          ? { 'Authorization': `Bearer ${window.AppState.sessionToken}` }
          : {},
        signal: AbortSignal.timeout(5000),
      });
      if (resp.ok) {
        const data = await resp.json();
        // data may be { entries: [...] } or { lines: "..." } or a string
        if (data.content || data.lines) {
          el.textContent = data.content || data.lines;
        } else if (Array.isArray(data.entries)) {
          el.textContent = data.entries.map(e =>
            typeof e === 'string' ? e :
            `${e.timestamp || e.ts || ''} [${e.level || 'INFO'}] ${e.message || e.msg || JSON.stringify(e)}`
          ).join('\n');
        } else if (typeof data === 'string') {
          el.textContent = data;
        } else {
          el.textContent = JSON.stringify(data, null, 2);
        }
        if (!el.textContent.trim()) {
          el.textContent = 'No log entries yet.';
        }
      } else {
        el.textContent = 'No log entries yet.';
      }
    } catch (e) {
      el.textContent = 'No log entries yet.\n(Hall Server offline or /api/logs not available)';
    }

    el.scrollTop = el.scrollHeight;
    _setMascot();
  }

  function _setMascot() {
    const w = document.getElementById('logs-worker');
    if (w && window.WorkerWidget) WorkerWidget.setAnimation(w, 'anim-patrol');
  }

  document.getElementById('logs-refresh-btn')?.addEventListener('click', refresh);
  return { refresh };
})();
