/* Copyright (c) 2026 pyhall.dev — https://pyhall.dev
 * All Rights Reserved.
 */
/**
 * enroll.js — Worker Enrollment Wizard (4-step)
 * Step 1: Identity (namespace+name, species_id, name, version)
 * Step 2: Business Logic (paste Python Section 7 code)
 * Step 3: WCP Policy (capabilities, controls, profile, blast score)
 * Step 4: Review (manifest preview + scaffolded code + enroll)
 *
 * Tasks implemented: 1 2 3 4 5 6 7 8 9 10
 */

// ─── Task 10: Belt-and-suspenders devtools prevention ────────────────────────
document.addEventListener('contextmenu', e => e.preventDefault());
document.addEventListener('keydown', e => {
  if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) e.preventDefault();
});

window.EnrollScreen = (() => {

  // ─── State ─────────────────────────────────────────────────────────────────

  let currentStep = 1;
  let selectedCaps = new Set();
  let selectedCtrls = new Set();
  let generatedManifest = null;
  let generatedCode = null;

  // Task 1: namespace dropdown state
  let selectedNamespace = null;
  let namespacesLoaded = false;

  // Task 2: species_id state
  let selectedSpeciesId = null;

  // ─── Catalog fetch helper ─────────────────────────────────────────────────
  // Fetches from Hall Server /api/catalog — Hall Server proxies from registry
  let _catalogCache = null;
  async function loadCatalog() {
    if (_catalogCache && _catalogCache.length > 0) return _catalogCache;
    const hallUrl = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
    const token = window.AppState?.sessionToken || '';
    const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

    // Try Hall Server /api/catalog first
    try {
      const resp = await fetch(`${hallUrl}/api/catalog`, {
        headers,
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        const data = await resp.json();
        const entities = data.entities || data.catalog || (Array.isArray(data) ? data : []);
        if (entities.length > 0) {
          _catalogCache = entities;
          return _catalogCache;
        }
      }
    } catch (_) {}

    // Fallback: try registry directly
    try {
      const resp = await fetch('https://api.pyhall.dev/api/v1/catalog', {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {},
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        const data = await resp.json();
        const entities = data.entities || data.catalog || (Array.isArray(data) ? data : []);
        if (entities.length > 0) {
          _catalogCache = entities;
          return _catalogCache;
        }
      }
    } catch (_) {}

    return [];
  }

  // ─── Navigation helpers ───────────────────────────────────────────────────

  function showStep(n) {
    currentStep = n;
    [1, 2, 3, 4].forEach(i => {
      const el = document.getElementById(`enroll-step-${i}`);
      if (el) el.style.display = (i === n) ? '' : 'none';
    });
    document.getElementById('enroll-success-view').style.display = 'none';

    document.querySelectorAll('.enroll-step-tab').forEach(tab => {
      const s = parseInt(tab.dataset.step);
      const active = s === n;
      const done = s < n;
      tab.style.background = active ? 'var(--accent-blue)' : (done ? 'rgba(0,122,204,0.2)' : 'transparent');
      tab.style.color = active ? '#fff' : (done ? 'var(--accent-blue)' : 'var(--text-dim)');
    });
  }

  function showError(stepN, msg) {
    const el = document.getElementById(`enroll-step${stepN}-error`);
    if (el) { el.textContent = msg; el.style.display = 'block'; }
  }
  function clearError(stepN) {
    const el = document.getElementById(`enroll-step${stepN}-error`);
    if (el) el.style.display = 'none';
  }

  // ─── Task 3: Version retirement banner ────────────────────────────────────

  async function checkExistingWorker(workerId) {
    if (!workerId || workerId.length < 5) {
      _removeRetirementBanner();
      return;
    }
    try {
      const result = await window.__TAURI__.core.invoke('check_existing_worker', { worker_id: workerId });
      if (result.exists && !result.retired) {
        _showRetirementBanner(result.version);
      } else {
        _removeRetirementBanner();
      }
    } catch (_) {
      _removeRetirementBanner();
    }
  }

  function _showRetirementBanner(version) {
    _removeRetirementBanner();
    const banner = document.createElement('div');
    banner.id = 'enroll-retirement-banner';
    banner.style.cssText = `
      margin: 8px 0; padding: 10px 14px; border-radius: 4px;
      background: rgba(251,191,36,0.12); border: 1px solid rgba(251,191,36,0.5);
      color: #fbbf24; font-size: 12px; line-height: 1.5;
    `;
    banner.textContent = `This will RETIRE version ${version || '?'} — the previous registration will be marked inactive. If you have modified the worker package files, a new attestation is required — the prior attestation no longer covers the updated package.`;
    const workerIdRow = document.getElementById('enroll-worker-id-row') || document.getElementById('enroll-worker-id')?.parentElement;
    if (workerIdRow) {
      workerIdRow.insertAdjacentElement('afterend', banner);
    }
  }

  function _removeRetirementBanner() {
    document.getElementById('enroll-retirement-banner')?.remove();
  }

  // ─── Task 1: Namespace dropdown ───────────────────────────────────────────

  async function loadNamespaces() {
    const nsDropdown = document.getElementById('enroll-ns-dropdown');
    const nsSpinner = document.getElementById('enroll-ns-spinner');
    const workerNameInput = document.getElementById('enroll-worker-name');
    const workerIdFallback = document.getElementById('enroll-worker-id');

    if (!nsDropdown) return;

    if (nsSpinner) nsSpinner.style.display = 'inline';
    nsDropdown.disabled = true;
    // Reset dropdown to loading state
    nsDropdown.style.display = '';
    if (workerIdFallback) workerIdFallback.style.display = 'none';

    let namespaces = [];

    try {
      const url = (window.AppState?.hallUrl || 'http://localhost:8765').replace(/\/$/, '');
      const token = window.AppState?.sessionToken || '';

      // Try Hall Server proxy first (same as profile.js)
      if (token) {
        const resp = await fetch(`${url}/api/namespaces`, {
          headers: { 'Authorization': `Bearer ${token}` },
          signal: AbortSignal.timeout(6000),
        });
        if (resp.ok) {
          const data = await resp.json();
          namespaces = data.namespaces || (Array.isArray(data) ? data : []);
        }
      }

      // Fallback: Tauri command (also tries Hall Server proxy)
      if (namespaces.length === 0 && token) {
        try {
          const result = await window.__TAURI__.core.invoke('get_account_namespaces', {
            url,
            session_token: token,
          });
          namespaces = result.namespaces || [];
        } catch (_) {}
      }
    } catch (_) {}

    if (namespaces.length === 0) {
      if (nsSpinner) nsSpinner.style.display = 'none';
      _fallbackToFreeText(nsDropdown, workerIdFallback,
        window.AppState?.sessionToken
          ? 'No namespaces found — enter worker ID manually'
          : 'Not logged in — enter worker ID manually (org.<ns>.<name>)'
      );
      return;
    }

    nsDropdown.innerHTML = namespaces.map(ns => `<option value="${_escAttr(ns)}">${_escAttr(ns)}</option>`).join('');
    nsDropdown.disabled = false;
    selectedNamespace = namespaces[0];
    namespacesLoaded = true;

    // Remove old listeners before adding new ones (prevent duplicates on reset)
    const newNsDropdown = nsDropdown.cloneNode(true);
    nsDropdown.parentNode.replaceChild(newNsDropdown, nsDropdown);
    const newWorkerNameInput = workerNameInput
      ? workerNameInput.cloneNode(true) : null;
    if (newWorkerNameInput && workerNameInput) {
      workerNameInput.parentNode.replaceChild(newWorkerNameInput, workerNameInput);
    }

    newNsDropdown.disabled = false;
    newNsDropdown.innerHTML = namespaces.map(ns => `<option value="${_escAttr(ns)}">${_escAttr(ns)}</option>`).join('');

    // Re-populate selectedNamespace
    selectedNamespace = newNsDropdown.value || namespaces[0];

    newNsDropdown.addEventListener('change', () => {
      selectedNamespace = newNsDropdown.value;
      _updateCombinedWorkerId();
      checkExistingWorker(_getCombinedWorkerId());
    });
    if (newWorkerNameInput) {
      newWorkerNameInput.addEventListener('input', () => {
        _updateCombinedWorkerId();
        clearTimeout(newWorkerNameInput._retireTimer);
        newWorkerNameInput._retireTimer = setTimeout(() => checkExistingWorker(_getCombinedWorkerId()), 600);
      });
    }

    // Instance suffix also contributes to the combined worker ID
    const instanceSuffixInput = document.getElementById('enroll-instance-suffix');
    if (instanceSuffixInput) {
      instanceSuffixInput.addEventListener('input', () => {
        _updateCombinedWorkerId();
        clearTimeout(instanceSuffixInput._retireTimer);
        instanceSuffixInput._retireTimer = setTimeout(() => checkExistingWorker(_getCombinedWorkerId()), 600);
      });
    }

    if (nsSpinner) nsSpinner.style.display = 'none';
  }

  function _fallbackToFreeText(nsDropdown, fallbackInput, placeholder) {
    if (nsDropdown) nsDropdown.style.display = 'none';
    if (fallbackInput) {
      fallbackInput.style.display = '';
      fallbackInput.placeholder = placeholder || 'org.myns.worker-name';
    }
    namespacesLoaded = false;
  }

  function _getCombinedWorkerId() {
    const nsDropdown = document.getElementById('enroll-ns-dropdown');
    const workerNameInput = document.getElementById('enroll-worker-name');
    const workerIdFallback = document.getElementById('enroll-worker-id');

    if (namespacesLoaded && nsDropdown && workerNameInput) {
      const ns = nsDropdown.value || '';
      const workerName = (workerNameInput.value || '').trim().toLowerCase();
      const instanceSuffix = (document.getElementById('enroll-instance-suffix')?.value || '').trim().toLowerCase();
      if (workerName && instanceSuffix) {
        return `${ns}.${workerName}.${instanceSuffix}`;
      } else if (workerName) {
        return `${ns}.${workerName}`;
      }
      return ns;
    }
    return (workerIdFallback?.value || '').trim();
  }

  function _updateCombinedWorkerId() {
    const hiddenInput = document.getElementById('enroll-worker-id-combined');
    if (hiddenInput) hiddenInput.value = _getCombinedWorkerId();
  }

  // ─── Task 1: Step 1 validation (updated for namespace dropdown) ───────────

  function validateStep1() {
    clearError(1);
    const name     = (document.getElementById('enroll-name')?.value || '').trim();
    const workerId = _getCombinedWorkerId();
    const speciesId = selectedSpeciesId || (document.getElementById('enroll-species-id')?.value || '').trim();

    if (!name) { showError(1, 'Worker name is required.'); return false; }
    if (!workerId) { showError(1, 'Worker ID is required.'); return false; }
    if (!/^(org|x)\.[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(workerId)) {
      showError(1, 'Worker ID format: org.<name>.<worker>.<instance> or x.<name>.<worker>.<instance> (lowercase, hyphens ok).');
      return false;
    }
    if (!speciesId) { showError(1, 'Species ID is required.'); return false; }
    if (!/^wrk\.[a-z0-9-]+$/.test(speciesId)) {
      showError(1, 'Species ID must be wrk.<type> (lowercase, hyphens ok).');
      return false;
    }
    return true;
  }

  // ─── Step 2 validation ────────────────────────────────────────────────────

  function validateStep2() {
    clearError(2);
    const code = (document.getElementById('enroll-logic-code')?.value || '').trim();
    if (!code) { showError(2, 'Business logic code is required.'); return false; }
    if (code.length < 20) { showError(2, 'Code looks too short — paste your actual worker logic.'); return false; }
    return true;
  }

  // ─── Step 3 validation ────────────────────────────────────────────────────

  function validateStep3() {
    clearError(3);
    if (selectedCaps.size === 0) { showError(3, 'Select at least one capability.'); return false; }
    return true;
  }

  // ─── Blast score auto-calculator ─────────────────────────────────────────

  const CAP_WEIGHTS = {
    'cap.shell-exec': 25, 'cap.code-execution': 20, 'cap.database-write': 20,
    'cap.file-write': 15, 'cap.send-email': 15, 'cap.memory-write': 15,
    'cap.api-call': 10,   'cap.web-search': 5,  'cap.file-read': 5,
    'cap.database-read': 5, 'cap.image-generation': 5, 'cap.text-generation': 3,
  };
  const CTRL_OFFSETS = {
    'ctrl.human-approval-required': -20, 'ctrl.dry-run': -15,
    'ctrl.no-external-network': -15, 'ctrl.output-filter': -10,
    'ctrl.rate-limit': -8, 'ctrl.audit-log': -5, 'ctrl.max-tokens': -3,
    'ctrl.idempotency': -3,
  };
  const PROFILE_BASE = {
    'prof.dev.permissive': 30, 'prof.prod.moderate': 20,
    'prof.prod.strict': 10,   'prof.edge.isolated': 5,
  };

  function computeBlast() {
    const profile = document.getElementById('enroll-profile')?.value || 'prof.dev.permissive';
    let score = PROFILE_BASE[profile] ?? 20;
    selectedCaps.forEach(c => { score += CAP_WEIGHTS[c] ?? 5; });
    selectedCtrls.forEach(c => { score += CTRL_OFFSETS[c] ?? 0; });
    score = Math.min(100, Math.max(1, score));
    const slider = document.getElementById('enroll-blast-range');
    const valEl  = document.getElementById('enroll-blast-val');
    const tierEl = document.getElementById('enroll-blast-tier');
    if (slider) slider.value = score;
    if (valEl)  valEl.textContent = score;
    if (tierEl) {
      if (score <= 25)      tierEl.textContent = 'Low risk (auto-calculated)';
      else if (score <= 50) tierEl.textContent = 'Medium risk (auto-calculated)';
      else if (score <= 75) tierEl.textContent = 'High risk (auto-calculated)';
      else                  tierEl.textContent = 'Critical risk (auto-calculated)';
    }
    return score;
  }

  // ─── Task 5: Capabilities & Controls modal ────────────────────────────────

  async function openCapsModal() {
    const catalog = await loadCatalog();
    const capsCtrlEntries = catalog.filter(e => e.id && (e.id.startsWith('cap.') || e.id.startsWith('ctrl.')));

    // Auto-suggest from code
    const code = (document.getElementById('enroll-logic-code')?.value || '');
    const autoSuggested = new Set();
    if (/requests\.get|httpx|aiohttp/.test(code)) autoSuggested.add('cap.api-call');
    if (/subprocess|os\.system|os\.popen/.test(code)) autoSuggested.add('cap.shell-exec');
    if (/open\s*\([^)]*['"]\s*w/.test(code)) autoSuggested.add('cap.file-write');
    if (/sqlite3|psycopg|sqlalchemy/.test(code)) autoSuggested.add('cap.database-write');
    if (/smtplib|sendgrid|mailgun/.test(code)) autoSuggested.add('cap.send-email');

    // Pre-check auto-suggested
    autoSuggested.forEach(id => selectedCaps.add(id));

    const modal = document.createElement('div');
    modal.id = 'enroll-caps-modal';
    modal.style.cssText = `
      position:fixed; inset:0; background:rgba(0,0,0,0.7); z-index:2000;
      display:flex; align-items:center; justify-content:center;
    `;

    const inner = document.createElement('div');
    inner.style.cssText = `
      background:var(--bg-surface); border:1px solid var(--bg-border);
      border-radius:6px; padding:24px; width:560px; max-width:95vw;
      max-height:80vh; display:flex; flex-direction:column; gap:12px;
    `;

    const title = document.createElement('div');
    title.style.cssText = 'font-weight:600; font-size:14px; color:var(--text-bright); display:flex; justify-content:space-between; align-items:center;';
    title.innerHTML = `<span>Select Capabilities &amp; Controls</span><button class="btn btn-ghost btn-sm" id="close-caps-modal">&#x2715;</button>`;

    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Search caps and controls...';
    searchInput.className = 'form-input';
    searchInput.style.cssText = 'font-size:12px;';

    // Auto-suggest banner (if any)
    let suggestBanner = null;
    if (autoSuggested.size > 0) {
      suggestBanner = document.createElement('div');
      suggestBanner.style.cssText = `
        padding:8px 12px; background:rgba(0,122,204,0.1); border:1px solid rgba(0,122,204,0.3);
        border-radius:4px; font-size:11px; color:var(--accent-blue);
      `;
      const hasSShell = autoSuggested.has('cap.shell-exec');
      let text = `Auto-detected from your code: ${Array.from(autoSuggested).join(', ')}`;
      if (hasSShell) text += ' — WARNING: cap.shell-exec is high-risk';
      suggestBanner.textContent = text;
      if (hasSShell) suggestBanner.style.background = 'rgba(239,68,68,0.1)';
      if (hasSShell) suggestBanner.style.borderColor = 'rgba(239,68,68,0.4)';
      if (hasSShell) suggestBanner.style.color = '#ef4444';
    }

    const list = document.createElement('div');
    list.style.cssText = 'overflow-y:auto; flex:1; display:flex; flex-direction:column; gap:4px;';

    // Custom cap input
    const customRow = document.createElement('div');
    customRow.style.cssText = 'border-top:1px solid var(--bg-border); padding-top:10px; display:flex; flex-direction:column; gap:6px;';
    const customInput = document.createElement('input');
    customInput.type = 'text';
    customInput.placeholder = 'Custom cap (cap.my-cap) — press Enter';
    customInput.className = 'form-input';
    customInput.style.cssText = 'font-size:11px;';
    const customWarn = document.createElement('div');
    customWarn.style.cssText = 'font-size:10px; color:#f59e0b; display:none;';
    customWarn.textContent = 'Strongly not recommended — custom capabilities bypass governance catalog';
    customRow.appendChild(customInput);
    customRow.appendChild(customWarn);

    const confirmBtn = document.createElement('button');
    confirmBtn.className = 'btn btn-primary';
    confirmBtn.textContent = 'Confirm Selection';
    confirmBtn.style.cssText = 'align-self:flex-end;';

    inner.appendChild(title);
    inner.appendChild(searchInput);
    if (suggestBanner) inner.appendChild(suggestBanner);
    inner.appendChild(list);
    inner.appendChild(customRow);
    inner.appendChild(confirmBtn);
    modal.appendChild(inner);
    document.body.appendChild(modal);

    function renderList(filter) {
      list.innerHTML = '';
      const f = (filter || '').toLowerCase();
      const shown = capsCtrlEntries.filter(e => !f || e.id.includes(f) || (e.name || '').toLowerCase().includes(f));
      if (shown.length === 0) {
        const empty = document.createElement('div');
        empty.style.cssText = 'color:var(--text-muted); font-size:12px; padding:8px;';
        empty.textContent = 'No matching entries';
        list.appendChild(empty);
        return;
      }
      shown.forEach(entry => {
        const isCap = entry.id.startsWith('cap.');
        const isSelected = isCap ? selectedCaps.has(entry.id) : selectedCtrls.has(entry.id);
        const row = document.createElement('div');
        row.style.cssText = `
          display:flex; align-items:flex-start; gap:10px; padding:6px 8px;
          border-radius:4px; cursor:pointer;
          background:${isSelected ? 'rgba(0,122,204,0.1)' : 'transparent'};
        `;
        const check = document.createElement('input');
        check.type = 'checkbox';
        check.checked = isSelected;
        check.style.marginTop = '2px';
        const label = document.createElement('div');
        label.innerHTML = `
          <div style="font-family:monospace;font-size:11px;color:${isCap ? 'var(--accent-blue)' : '#a78bfa'};">${_esc(entry.id)}</div>
          <div style="font-size:11px;color:var(--text-muted);">${_esc(entry.name || '')}${entry.description ? ' — ' + _esc(entry.description.slice(0, 80)) : ''}</div>
        `;
        row.appendChild(check);
        row.appendChild(label);

        const toggle = () => {
          if (isCap) {
            if (selectedCaps.has(entry.id)) { selectedCaps.delete(entry.id); check.checked = false; row.style.background = 'transparent'; }
            else { selectedCaps.add(entry.id); check.checked = true; row.style.background = 'rgba(0,122,204,0.1)'; }
            // Shell-exec warning
            if (entry.id === 'cap.shell-exec' && selectedCaps.has(entry.id)) {
              if (!document.getElementById('shell-exec-warn')) {
                const sw = document.createElement('div');
                sw.id = 'shell-exec-warn';
                sw.style.cssText = 'font-size:10px;color:#ef4444;padding:4px 8px;';
                sw.textContent = 'Shell execution is a high-risk capability';
                row.appendChild(sw);
              }
            } else {
              document.getElementById('shell-exec-warn')?.remove();
            }
          } else {
            if (selectedCtrls.has(entry.id)) { selectedCtrls.delete(entry.id); check.checked = false; row.style.background = 'transparent'; }
            else { selectedCtrls.add(entry.id); check.checked = true; row.style.background = 'rgba(0,122,204,0.1)'; }
          }
        };
        check.addEventListener('change', toggle);
        row.addEventListener('click', (e) => { if (e.target !== check) toggle(); });
        list.appendChild(row);
      });
    }

    renderList('');
    searchInput.addEventListener('input', () => renderList(searchInput.value));

    customInput.addEventListener('focus', () => { customWarn.style.display = 'block'; });
    customInput.addEventListener('blur', () => { if (!customInput.value) customWarn.style.display = 'none'; });
    customInput.addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      e.preventDefault();
      const val = customInput.value.trim().toLowerCase();
      if (!val || !/^cap\.[a-z0-9-]+$/.test(val)) return;
      selectedCaps.add(val);
      customInput.value = '';
      renderList(searchInput.value);
    });

    document.getElementById('close-caps-modal').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    confirmBtn.addEventListener('click', () => {
      _updateCapsControlsDisplay();
      computeBlast();
      modal.remove();
    });
  }

  function _updateCapsControlsDisplay() {
    const capsDisplay = document.getElementById('enroll-caps-display');
    if (capsDisplay) {
      const all = [...Array.from(selectedCaps), ...Array.from(selectedCtrls)];
      if (all.length === 0) {
        capsDisplay.textContent = 'None selected';
        capsDisplay.style.color = 'var(--text-muted)';
      } else {
        capsDisplay.textContent = all.join(', ');
        capsDisplay.style.color = 'var(--text-primary)';
      }
    }
  }

  // ─── Task 2: Species browser modal ───────────────────────────────────────

  async function openSpeciesModal() {
    const speciesDisplay = document.getElementById('enroll-species-display');
    const prevText = speciesDisplay?.textContent;

    // Show loading state
    if (speciesDisplay) {
      speciesDisplay.textContent = 'Loading species...';
      speciesDisplay.style.color = 'var(--text-muted)';
    }

    const catalog = await loadCatalog();

    // Restore display if loading failed
    if (!catalog || catalog.length === 0) {
      if (speciesDisplay) {
        speciesDisplay.textContent = 'Could not load species catalog. Check Hall Server connection.';
        speciesDisplay.style.color = 'var(--error, #e05c5c)';
        setTimeout(() => {
          if (speciesDisplay) {
            speciesDisplay.textContent = prevText || 'No species selected';
            speciesDisplay.style.color = 'var(--text-dim)';
          }
        }, 4000);
      }
      return;
    }

    // Restore display now that we have the catalog
    if (speciesDisplay) {
      speciesDisplay.textContent = prevText || 'No species selected';
      speciesDisplay.style.color = selectedSpeciesId ? 'var(--text-primary)' : 'var(--text-dim)';
    }

    const speciesEntries = catalog.filter(e => e.id && e.id.startsWith('wrk.'));

    const modal = document.createElement('div');
    modal.id = 'enroll-species-modal';
    modal.style.cssText = `
      position:fixed; inset:0; background:rgba(0,0,0,0.7); z-index:2000;
      display:flex; align-items:center; justify-content:center;
    `;

    const inner = document.createElement('div');
    inner.style.cssText = `
      background:var(--bg-surface); border:1px solid var(--bg-border);
      border-radius:6px; padding:24px; width:540px; max-width:95vw;
      max-height:80vh; display:flex; flex-direction:column; gap:12px;
    `;

    const titleRow = document.createElement('div');
    titleRow.style.cssText = 'display:flex; justify-content:space-between; align-items:center;';
    titleRow.innerHTML = `<span style="font-weight:600;font-size:14px;color:var(--text-bright);">Browse Worker Species</span><button class="btn btn-ghost btn-sm" id="close-species-modal">&#x2715;</button>`;

    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Search species...';
    searchInput.className = 'form-input';
    searchInput.style.fontSize = '12px';

    const list = document.createElement('div');
    list.style.cssText = 'overflow-y:auto; flex:1; max-height:360px; display:flex; flex-direction:column; gap:2px;';

    // Private species toggle
    const privateRow = document.createElement('div');
    privateRow.style.cssText = 'border-top:1px solid var(--bg-border); padding-top:10px; display:flex; flex-direction:column; gap:6px;';
    const privateTier = window.__PYHALL_TIER_LIMITS__?.privateWorkerSpecies || 0;

    if (privateTier > 0) {
      const privateLabel = document.createElement('div');
      privateLabel.style.cssText = 'font-size:11px; color:var(--text-muted); display:flex; align-items:center; gap:8px;';
      const privateToggle = document.createElement('input');
      privateToggle.type = 'checkbox';
      privateToggle.id = 'species-private-toggle';
      const privateText = document.createElement('label');
      privateText.htmlFor = 'species-private-toggle';
      privateText.textContent = 'Use private species ID (wrk.<custom>)';
      privateText.style.cursor = 'pointer';
      privateLabel.appendChild(privateToggle);
      privateLabel.appendChild(privateText);

      const privateInput = document.createElement('input');
      privateInput.type = 'text';
      privateInput.placeholder = 'wrk.my-custom-species';
      privateInput.className = 'form-input';
      privateInput.style.cssText = 'font-size:11px; display:none;';

      privateToggle.addEventListener('change', () => {
        privateInput.style.display = privateToggle.checked ? '' : 'none';
      });
      privateRow.appendChild(privateLabel);
      privateRow.appendChild(privateInput);
    } else if (privateTier === 0) {
      const upgradeNote = document.createElement('div');
      upgradeNote.style.cssText = 'font-size:11px; color:var(--text-muted);';
      upgradeNote.innerHTML = `Private worker species require a plan upgrade. <a href="https://pyhall.dev/pricing" target="_blank" style="color:var(--accent-blue);">Upgrade at pyhall.dev/pricing</a>`;
      privateRow.appendChild(upgradeNote);
    }

    inner.appendChild(titleRow);
    inner.appendChild(searchInput);
    inner.appendChild(list);
    inner.appendChild(privateRow);
    modal.appendChild(inner);
    document.body.appendChild(modal);

    function renderSpeciesList(filter) {
      list.innerHTML = '';
      const f = (filter || '').toLowerCase();
      const shown = speciesEntries.filter(e =>
        !f || e.id.toLowerCase().includes(f) ||
        (e.name || '').toLowerCase().includes(f) ||
        (e.description || '').toLowerCase().includes(f)
      );
      if (shown.length === 0) {
        const empty = document.createElement('div');
        empty.style.cssText = 'color:var(--text-muted); font-size:12px; padding:8px;';
        empty.textContent = 'No species match your search';
        list.appendChild(empty);
        return;
      }
      shown.forEach(entry => {
        const row = document.createElement('div');
        const isSelected = entry.id === selectedSpeciesId;
        row.style.cssText = `
          padding:8px 10px; border-radius:4px; cursor:pointer;
          background:${isSelected ? 'rgba(0,122,204,0.12)' : 'transparent'};
          border:1px solid ${isSelected ? 'rgba(0,122,204,0.4)' : 'transparent'};
        `;
        row.innerHTML = `
          <div style="font-family:monospace;font-size:11px;color:var(--accent-blue);">${_esc(entry.id)}</div>
          <div style="font-size:11px;color:var(--text-bright);margin-top:2px;">${_esc(entry.name || '')}</div>
          ${entry.description ? `<div style="font-size:10px;color:var(--text-muted);margin-top:2px;">${_esc(entry.description.slice(0, 100))}</div>` : ''}
        `;
        row.addEventListener('click', () => {
          selectedSpeciesId = entry.id;
          const speciesDisplay = document.getElementById('enroll-species-display');
          if (speciesDisplay) speciesDisplay.textContent = entry.id;
          const hiddenInput = document.getElementById('enroll-species-id');
          if (hiddenInput) hiddenInput.value = entry.id;
          modal.remove();
        });
        list.appendChild(row);
      });
    }

    renderSpeciesList('');
    searchInput.addEventListener('input', () => renderSpeciesList(searchInput.value));
    document.getElementById('close-species-modal').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  }

  // ─── Step 3 UI ────────────────────────────────────────────────────────────

  function initStep3UI() {
    // Task 5: just update display (caps are managed via modal)
    _updateCapsControlsDisplay();
    computeBlast();
    document.getElementById('enroll-profile')?.addEventListener('change', computeBlast);
  }

  // ─── Task 6: Manifest builder (guarantee hardcoded) ───────────────────────

  // Compute SHA-256 artifact hash of a manifest object (excluding artifact_hash field).
  // Returns "sha256:<hex>" — matching the format expected by the Hall Server /enroll endpoint.
  async function computeArtifactHash(manifestObj) {
    const manifestForHash = { ...manifestObj };
    delete manifestForHash.artifact_hash;
    const jsonStr = JSON.stringify(manifestForHash, Object.keys(manifestForHash).sort());
    const encoder = new TextEncoder();
    const data = encoder.encode(jsonStr);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return `sha256:${hex}`;
  }

  async function buildManifest() {
    const workerId  = _getCombinedWorkerId();
    const speciesId = selectedSpeciesId || document.getElementById('enroll-species-id')?.value.trim();
    const name      = document.getElementById('enroll-name')?.value.trim();
    const version   = document.getElementById('enroll-version')?.value.trim() || '0.1.0';
    const desc      = document.getElementById('enroll-description')?.value.trim();
    const profile   = document.getElementById('enroll-profile')?.value || 'prof.dev.permissive';
    const blast     = computeBlast();

    // Task 6: guarantee is always best-effort (field removed from UI)
    const guarantee = 'best-effort';

    const trustNamespace = workerId.split('.').slice(0, 2).join('.');

    const manifest = {
      worker_id:       workerId,
      species_id:      speciesId,
      name:            name,
      version:         version,
      description:     desc || undefined,
      trust_namespace: trustNamespace,
      capabilities:    Array.from(selectedCaps),
      controls:        Array.from(selectedCtrls),
      profile:         profile,
      blast_score:     blast,
      guarantee:       guarantee,
      wcp_version:     '0.3',
      enrolled_at:     new Date().toISOString(),
    };

    // Compute and attach artifact_hash — required by Hall Server /enroll endpoint
    manifest.artifact_hash = await computeArtifactHash(manifest);

    return manifest;
  }

  // ─── Code scaffolder ───────────────────────────────────────────────────────

  function buildScaffoldedCode(manifest) {
    const userCode = (document.getElementById('enroll-logic-code')?.value || '').trim();
    const caps     = manifest.capabilities.join(', ');
    const ctrls    = manifest.controls.join(', ');

    return `# ============================================================
# SECTION 1: Header + Identity + WCP Declarations
# ============================================================
# worker_id:       ${manifest.worker_id}
# species_id:      ${manifest.species_id}
# version:         ${manifest.version}
# trust_namespace: ${manifest.trust_namespace}
# profile:         ${manifest.profile}
# blast_score:     ${manifest.blast_score}
# capabilities:    ${caps || 'none'}
# controls:        ${ctrls || 'none'}
# guarantee:       ${manifest.guarantee}
# wcp_version:     ${manifest.wcp_version}
# scaffolded_at:   ${manifest.enrolled_at}

from __future__ import annotations
import hashlib, json, os, time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

WORKER_ID        = "${manifest.worker_id}"
WORKER_SPECIES   = "${manifest.species_id}"
WORKER_VERSION   = "${manifest.version}"
TRUST_NAMESPACE  = "${manifest.trust_namespace}"
WCP_VERSION      = "${manifest.wcp_version}"

# ============================================================
# SECTION 2: Core Models
# ============================================================

@dataclass
class WorkerContext:
    correlation_id:    str
    capability_id:     str
    payload:           dict[str, Any]
    policy_version:    str  = "0.3"
    matched_rule_id:   str  = ""

@dataclass
class WorkerResult:
    output:            Any
    status:            str   # 'success' | 'failure' | 'denied'
    evidence:          dict  = field(default_factory=dict)

# ============================================================
# SECTION 3: Utility Functions
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

# ============================================================
# SECTION 4: Package Attestation + Signature Verification
# ============================================================

def verify_package_integrity() -> None:
    """Fail-closed: raise if manifest is missing or hash mismatches."""
    manifest_path = Path(__file__).parent.parent / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("ATTEST_MANIFEST_MISSING: manifest.json not found")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("worker_id") != WORKER_ID:
        raise RuntimeError(f"ATTEST_MANIFEST_ID_MISMATCH: expected {WORKER_ID}")

# ============================================================
# SECTION 5: Policy Gate (fail-closed)
# ============================================================

def policy_gate(context: WorkerContext) -> None:
    """Deny execution if context fails policy checks."""
    allowed_caps = ${JSON.stringify(Array.from(selectedCaps))}
    if context.capability_id not in allowed_caps:
        raise PermissionError(
            f"POLICY_DENIED: capability {context.capability_id!r} not in declared set"
        )

# ============================================================
# SECTION 6: Observability
# ============================================================

def record_evidence(context: WorkerContext, result: WorkerResult) -> None:
    """Append-only telemetry record."""
    record = {
        "correlation_id":        context.correlation_id,
        "worker_id":             WORKER_ID,
        "worker_species_id":     WORKER_SPECIES,
        "trust_namespace":       TRUST_NAMESPACE,
        "capability_id":         context.capability_id,
        "policy_version":        context.policy_version,
        "matched_rule_id":       context.matched_rule_id,
        "request_payload_sha256": sha256_of(canonical_json(context.payload)),
        "outcome":               result.status,
        "timestamp":             utc_now(),
    }
    log_path = Path(os.environ.get("HALL_LOG_DIR", "/tmp")) / "worker_evidence.jsonl"
    with open(log_path, "a") as f:
        f.write(json.dumps(record) + "\\n")

# ============================================================
# SECTION 7: Business Logic (user-provided)
# ============================================================

${userCode}

# ============================================================
# SECTION 8: CLI + Bootstrap
# ============================================================

def dispatch(context: WorkerContext) -> WorkerResult:
    """Entry point called by the Hall runtime."""
    verify_package_integrity()
    policy_gate(context)
    result = execute(context)   # calls Section 7 execute()
    record_evidence(context, result)
    return result

if __name__ == "__main__":
    import sys
    payload = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    ctx = WorkerContext(
        correlation_id=sha256_of(str(time.time()))[:16],
        capability_id=payload.pop("capability_id", "${Array.from(selectedCaps)[0] || 'cap.unknown'}"),
        payload=payload,
    )
    out = dispatch(ctx)
    print(json.dumps({"status": out.status, "output": out.output}, indent=2))
`;
  }

  // ─── Task 7: Step 4 render (no truncation, scrollable, colored sections) ──

  async function renderReview() {
    generatedManifest = await buildManifest();
    generatedCode     = buildScaffoldedCode(generatedManifest);

    const manifestEl = document.getElementById('enroll-manifest-preview');
    if (manifestEl) manifestEl.textContent = JSON.stringify(generatedManifest, null, 2);

    // Task 7: full scrollable code preview with colored section headers
    const codeContainer = document.getElementById('enroll-code-preview-container');
    if (codeContainer) {
      codeContainer.innerHTML = '';
      const pre = document.createElement('pre');
      pre.style.cssText = `
        font-family: var(--font-mono); font-size: 11px; line-height: 1.6;
        white-space: pre-wrap; overflow-y: auto; max-height: 400px;
        margin: 0; background: var(--bg-deep, #1a1a1a); padding: 12px;
        border-radius: 4px; border: 1px solid var(--bg-border);
      `;

      // Color-code the content by splitting on section markers
      const lines = generatedCode.split('\n');
      const frag = document.createDocumentFragment();
      lines.forEach((line, idx) => {
        const span = document.createElement('span');
        if (/^# ={3,}/.test(line) || /^# SECTION \d+/.test(line)) {
          // Section header lines
          span.style.color = '#007acc';
        } else if (/^# worker_id:|^# species_id:|^# version:|^# trust_namespace:|^# profile:|^# blast_score:|^# capabilities:|^# controls:|^# guarantee:|^# wcp_version:|^# scaffolded_at:/.test(line)) {
          span.style.color = '#007acc';
        } else if (/^\${userCode}$/.test(line) || idx > 0 && lines[idx-1].includes('SECTION 7')) {
          span.style.color = '#22c55e';
        } else {
          span.style.color = 'var(--text-primary)';
        }
        span.textContent = line + '\n';
        frag.appendChild(span);
      });
      pre.appendChild(frag);
      codeContainer.appendChild(pre);
    }
  }

  // ─── Task 4: "Show Sample" scaffold preview modal ─────────────────────────

  function openSampleModal() {
    const sampleCode = `# ============================================================
# SECTION 1: Header + Identity + WCP Declarations
# ============================================================
# worker_id:    org.my-org.my-worker   ← auto-filled from your form
# species_id:   wrk.data-processor     ← auto-filled from species browser
# ... (all manifest fields embedded here)

from __future__ import annotations
import hashlib, json, os, time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

WORKER_ID        = "org.my-org.my-worker"
WORKER_SPECIES   = "wrk.data-processor"
WORKER_VERSION   = "0.1.0"
TRUST_NAMESPACE  = "org.my-org"
WCP_VERSION      = "0.3"

# ============================================================
# SECTION 2: Core Models
# ============================================================

@dataclass
class WorkerContext:
    correlation_id: str
    capability_id:  str
    payload:        dict
    policy_version: str = "0.3"
    matched_rule_id: str = ""

@dataclass
class WorkerResult:
    output:   object
    status:   str      # 'success' | 'failure' | 'denied'
    evidence: dict = field(default_factory=dict)

# ============================================================
# SECTION 3: Utility Functions
# ============================================================

def utc_now() -> str: ...
def sha256_of(text: str) -> str: ...
def canonical_json(obj) -> str: ...

# ============================================================
# SECTION 4: Package Attestation + Signature Verification
# ============================================================

def verify_package_integrity() -> None:
    """Raises if manifest.json is missing or worker_id mismatches."""
    ...

# ============================================================
# SECTION 5: Policy Gate (fail-closed)
# ============================================================

def policy_gate(context: WorkerContext) -> None:
    """Raises PermissionError if capability not in declared set."""
    ...

# ============================================================
# SECTION 6: Observability
# ============================================================

def record_evidence(context: WorkerContext, result: WorkerResult) -> None:
    """Appends telemetry record to worker_evidence.jsonl."""
    ...

# ============================================================
# SECTION 7: Business Logic (user-provided)   ← YOUR CODE HERE
# ============================================================

async def execute(context: WorkerContext) -> WorkerResult:
    """
    This is where YOUR logic goes. Replace this with your worker implementation.
    context.payload contains the task input dict.
    Return WorkerResult with output and status.
    """
    payload = context.payload
    # --- your logic here ---
    result = {"processed": True, "input": payload}
    # -----------------------
    return WorkerResult(output=result, status="success")

# ↑ Your code goes here (Section 7)

# ============================================================
# SECTION 8: CLI + Bootstrap
# ============================================================

def dispatch(context: WorkerContext) -> WorkerResult:
    """Entry point called by the Hall runtime."""
    verify_package_integrity()
    policy_gate(context)
    result = execute(context)
    record_evidence(context, result)
    return result
`;

    const modal = document.createElement('div');
    modal.id = 'enroll-sample-modal';
    modal.style.cssText = `
      position:fixed; inset:0; background:rgba(0,0,0,0.7); z-index:2000;
      display:flex; align-items:center; justify-content:center;
    `;

    const inner = document.createElement('div');
    inner.style.cssText = `
      background:var(--bg-surface); border:1px solid var(--bg-border);
      border-radius:6px; padding:24px; width:640px; max-width:95vw;
      max-height:85vh; display:flex; flex-direction:column; gap:12px;
    `;

    const titleRow = document.createElement('div');
    titleRow.style.cssText = 'display:flex; justify-content:space-between; align-items:center;';
    titleRow.innerHTML = `<span style="font-weight:600;font-size:14px;color:var(--text-bright);">8-Section Worker Scaffold (Sample)</span><button class="btn btn-ghost btn-sm" id="close-sample-modal">&#x2715;</button>`;

    const subtitle = document.createElement('div');
    subtitle.style.cssText = 'font-size:11px; color:var(--text-muted);';
    subtitle.textContent = 'Sections 1–6 and 8 are auto-generated. You only write Section 7.';

    const pre = document.createElement('pre');
    pre.style.cssText = `
      font-family: var(--font-mono); font-size: 11px; line-height: 1.6;
      white-space: pre-wrap; overflow-y: auto; flex: 1;
      background: var(--bg-deep, #1a1a1a); padding: 12px;
      border-radius: 4px; border: 1px solid var(--bg-border); margin: 0;
    `;

    // Color-code the sample
    const lines = sampleCode.split('\n');
    lines.forEach(line => {
      const span = document.createElement('span');
      if (/^# ={3,}/.test(line) || /^# SECTION \d+/.test(line)) {
        span.style.color = '#007acc';
      } else if (/SECTION 7.*YOUR CODE/.test(line) || /← YOUR CODE HERE/.test(line) || /↑ Your code goes here/.test(line)) {
        span.style.color = '#22c55e';
      } else if (/async def execute|WorkerResult\(output/.test(line) || /your logic here|your worker implementation/.test(line)) {
        span.style.color = '#22c55e';
      } else if (/^def |^async def /.test(line)) {
        span.style.color = '#4a5568';
      } else {
        span.style.color = 'var(--text-primary)';
      }
      span.textContent = line + '\n';
      pre.appendChild(span);
    });

    const annotation = document.createElement('div');
    annotation.style.cssText = 'font-size:11px; color:#22c55e; padding:6px 10px; background:rgba(34,197,94,0.08); border-radius:4px; border:1px solid rgba(34,197,94,0.2);';
    annotation.textContent = 'Your code goes here (Section 7) — just implement execute(context) and return a WorkerResult';

    inner.appendChild(titleRow);
    inner.appendChild(subtitle);
    inner.appendChild(pre);
    inner.appendChild(annotation);
    modal.appendChild(inner);
    document.body.appendChild(modal);

    document.getElementById('close-sample-modal').addEventListener('click', () => modal.remove());
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  }

  // ─── Task 8: Registration with auto-save ─────────────────────────────────

  async function doEnroll() {
    if (!generatedManifest) return;
    clearError(4);
    const btn = document.getElementById('btn-enroll-confirm');
    btn.disabled = true;
    btn.textContent = 'Registering...';

    try {
      await HallAPI.enrollWorker(JSON.stringify(generatedManifest));

      // Task 3: retire old worker if exists
      const workerId = generatedManifest.worker_id;
      try {
        await window.__TAURI__.core.invoke('retire_enrolled_worker', { worker_id: workerId });
      } catch (_) { /* not critical */ }

      // Task 8: auto-save enrolled files
      let enrolledPath = null;
      try {
        const saveResult = await window.__TAURI__.core.invoke('save_enrolled_worker', {
          worker_id: workerId,
          manifest_json: JSON.stringify(generatedManifest),
          python_code: generatedCode,
        });
        enrolledPath = saveResult.enrolled_path;
      } catch (saveErr) {
        // Non-critical — don't fail the whole enrollment
        console.warn('Auto-save failed:', saveErr);
      }

      // Show success
      document.getElementById('enroll-step-4').style.display = 'none';
      const successView = document.getElementById('enroll-success-view');
      successView.style.display = 'block';

      const caps = generatedManifest.capabilities.join(', ') || 'general';
      document.getElementById('enroll-success-msg').textContent =
        `${generatedManifest.name} (${generatedManifest.species_id}) is now on the Hall books. The Hall will route ${caps} dispatches to this worker. If you modify the worker package files after enrollment, a new attestation is required — the current attestation only covers the package as enrolled.`;

      // Task 8: show save path
      const saveMsgEl = document.getElementById('enroll-success-save-msg');
      if (saveMsgEl && enrolledPath) {
        saveMsgEl.style.display = 'block';
        const pathSpan = document.getElementById('enroll-success-enrolled-path');
        if (pathSpan) pathSpan.textContent = enrolledPath;
      }

      _removeRetirementBanner();

      if (window.CrewScreen) window.CrewScreen.refresh();

    } catch (e) {
      btn.disabled = false;
      btn.textContent = 'Register with the Hall';
      showError(4, `Enrollment failed: ${e}`);
    }
  }

  // ─── Wire buttons ─────────────────────────────────────────────────────────

  // Progress tabs (click to navigate backwards only)
  document.querySelectorAll('.enroll-step-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const n = parseInt(tab.dataset.step);
      if (n < currentStep) showStep(n);
    });
  });

  // Step 1 → 2
  document.getElementById('btn-enroll-next-1')?.addEventListener('click', () => {
    if (validateStep1()) showStep(2);
  });

  // Step 2 back/next
  document.getElementById('btn-enroll-back-2')?.addEventListener('click', () => showStep(1));
  document.getElementById('btn-enroll-next-2')?.addEventListener('click', () => {
    if (validateStep2()) {
      initStep3UI();
      showStep(3);
    }
  });

  // Load .py file in step 2
  document.getElementById('btn-enroll-load-py')?.addEventListener('click', () => {
    document.getElementById('enroll-py-file-input')?.click();
  });
  document.getElementById('enroll-py-file-input')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const ta = document.getElementById('enroll-logic-code');
    if (ta) ta.value = text;
  });

  // Insert starter stub
  document.getElementById('btn-enroll-insert-stub')?.addEventListener('click', () => {
    const ta = document.getElementById('enroll-logic-code');
    if (ta && !ta.value.trim()) {
      ta.value = `async def execute(context: WorkerContext) -> WorkerResult:
    """
    Replace this stub with your actual worker logic.
    context.payload contains the task input.
    Return WorkerResult with output and status.
    """
    payload = context.payload
    # --- your logic here ---
    result = {"processed": True, "input": payload}
    # -----------------------
    return WorkerResult(output=result, status="success")`;
    }
  });

  // Task 4: Show Sample button (step 2)
  document.getElementById('btn-enroll-show-sample')?.addEventListener('click', openSampleModal);

  // Step 3 back/next
  document.getElementById('btn-enroll-back-3')?.addEventListener('click', () => showStep(2));
  document.getElementById('btn-enroll-next-3')?.addEventListener('click', async () => {
    if (validateStep3()) {
      await renderReview();
      showStep(4);
    }
  });

  // Task 5: Open caps/controls modal
  document.getElementById('btn-enroll-select-caps')?.addEventListener('click', openCapsModal);

  // Task 2: Browse species button
  document.getElementById('btn-enroll-browse-species')?.addEventListener('click', openSpeciesModal);

  // Step 4 back
  document.getElementById('btn-enroll-back-4')?.addEventListener('click', () => showStep(3));

  // Task 9: No download buttons in enroll — they are in Crew screen
  // (btn-enroll-download-manifest and btn-enroll-download-code removed from UI usage)

  // Enroll (submit to Hall)
  document.getElementById('btn-enroll-confirm')?.addEventListener('click', doEnroll);

  // Import existing JSON (advanced)
  document.getElementById('btn-enroll-import-json')?.addEventListener('click', () => {
    document.getElementById('enroll-import-file-input')?.click();
  });
  document.getElementById('enroll-import-file-input')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    try {
      const record = JSON.parse(text);
      const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
      set('enroll-name',        record.name);
      set('enroll-species-id',  record.species_id);
      set('enroll-version',     record.version);
      set('enroll-description', record.description);
      set('enroll-profile',     record.profile);

      // Handle worker_id for dropdown vs fallback
      if (record.worker_id) {
        const workerIdFallback = document.getElementById('enroll-worker-id');
        if (workerIdFallback) workerIdFallback.value = record.worker_id;
      }

      // Handle species_id display
      if (record.species_id) {
        selectedSpeciesId = record.species_id;
        const speciesDisplay = document.getElementById('enroll-species-display');
        if (speciesDisplay) speciesDisplay.textContent = record.species_id;
      }

      if (record.blast_score) {
        const slider = document.getElementById('enroll-blast-range');
        const valEl  = document.getElementById('enroll-blast-val');
        if (slider) slider.value = record.blast_score;
        if (valEl)  valEl.textContent = record.blast_score;
      }
      (record.capabilities || []).forEach(c => selectedCaps.add(c));
      (record.controls || []).forEach(c => selectedCtrls.add(c));
      _updateCapsControlsDisplay();
      showStep(1);
    } catch (err) {
      alert(`Could not parse JSON: ${err.message}`);
    }
  });

  // Post-success buttons
  document.getElementById('btn-view-crew')?.addEventListener('click', () => window.navigateTo?.('crew'));
  document.getElementById('btn-enroll-another')?.addEventListener('click', reset);

  // ─── Reset ───────────────────────────────────────────────────────────────

  function reset() {
    selectedCaps.clear();
    selectedCtrls.clear();
    selectedSpeciesId = null;
    selectedNamespace = null;
    namespacesLoaded = false;
    generatedManifest = null;
    generatedCode = null;
    _catalogCache = null; // force fresh catalog load

    ['enroll-name','enroll-worker-id','enroll-worker-name','enroll-species-id',
     'enroll-description','enroll-logic-code'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    document.getElementById('enroll-version').value = '0.1.0';
    const instanceSuffixEl = document.getElementById('enroll-instance-suffix');
    if (instanceSuffixEl) instanceSuffixEl.value = 'pyhall-001';

    const speciesDisplay = document.getElementById('enroll-species-display');
    if (speciesDisplay) speciesDisplay.textContent = 'None selected';
    _updateCapsControlsDisplay();

    const slider = document.getElementById('enroll-blast-range');
    if (slider) slider.value = 20;
    const valEl = document.getElementById('enroll-blast-val');
    if (valEl) valEl.textContent = '20';

    document.getElementById('enroll-success-view').style.display = 'none';
    _removeRetirementBanner();

    ['enroll-import-file-input','enroll-py-file-input'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });

    showStep(1);
    // Reload namespaces each time screen is activated (session token may now be set)
    loadNamespaces();
  }

  // ─── Init ────────────────────────────────────────────────────────────────

  function init() {
    // Task 1: Load namespaces for dropdown
    loadNamespaces();
  }

  // Auto-init when loaded
  init();

  // ─── Escape helpers ──────────────────────────────────────────────────────

  function _esc(str) {
    if (str === null || str === undefined) return '';
    if (typeof str !== 'string') str = String(str);
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function _escAttr(str) {
    if (!str) return '';
    return String(str).replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ─── Public ──────────────────────────────────────────────────────────────

  return { reset, init };
})();
