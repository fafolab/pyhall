/**
 * enroll.js — Worker Enrollment screen (Screen 5)
 * Drag-and-drop or file picker for registry_record.json.
 * Validates fields, shows preview, enrolls via Tauri command.
 */

window.EnrollScreen = (() => {
  let currentRecord = null;
  let currentJson = '';

  // ── Drop zone ─────────────────────────────────────────────────────────────

  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  dropZone?.addEventListener('click', () => fileInput?.click());

  dropZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone?.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer?.files?.[0];
    if (file) handleFile(file);
  });

  fileInput?.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    if (file) handleFile(file);
  });

  document.getElementById('btn-browse-file')?.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput?.click();
  });

  // ── File handling ─────────────────────────────────────────────────────────

  async function handleFile(file) {
    if (!file.name.endsWith('.json')) {
      showError('Expected a .json file (registry_record.json)');
      return;
    }

    const text = await file.text();
    currentJson = text;

    // Validate via Tauri command
    try {
      const result = await HallAPI.validateRegistryRecord(text);
      currentRecord = result.record;
      showPreview(result);
    } catch (e) {
      // Fallback: parse locally
      try {
        const parsed = JSON.parse(text);
        currentRecord = parsed;
        showPreview({ valid: true, checks: [], record: parsed });
      } catch (parseErr) {
        showError(`Invalid JSON: ${parseErr.message}`);
      }
    }
  }

  function showError(msg) {
    dropZone && (dropZone.style.borderColor = 'var(--error)');
    const sub = dropZone?.querySelector('.drop-zone-sub');
    if (sub) sub.innerHTML = `<span style="color:var(--error);">${esc(msg)}</span>`;
  }

  function showPreview(validation) {
    const dropzoneView = document.getElementById('enroll-dropzone-view');
    const previewView = document.getElementById('enroll-preview-view');
    const successView = document.getElementById('enroll-success-view');

    if (dropzoneView) dropzoneView.style.display = 'none';
    if (previewView) previewView.style.display = 'block';
    if (successView) successView.style.display = 'none';

    renderPreview(validation.record);
    renderValidation(validation.checks, validation.valid);
  }

  function renderPreview(record) {
    const container = document.getElementById('worker-preview');
    if (!container || !record) return;

    const caps = Array.isArray(record.capabilities) ? record.capabilities.join(', ') : (record.capabilities || '—');
    const score = record.blast_score ?? '—';
    const blastClass = typeof score === 'number' ? blastTierClass(score) : '';
    const blastLabel = typeof score === 'number' ? blastTierLabel(score) : '—';

    container.innerHTML = `
      <div class="preview-row">
        <span class="preview-label">Species ID</span>
        <span class="preview-value">${esc(record.species_id || '—')}</span>
      </div>
      <div class="preview-row">
        <span class="preview-label">Capabilities</span>
        <span class="preview-value">${esc(caps)}</span>
      </div>
      <div class="preview-row">
        <span class="preview-label">Guarantee</span>
        <span class="preview-value">${esc(record.guarantee || '—')}</span>
      </div>
      <div class="preview-row">
        <span class="preview-label">Blast score</span>
        <span class="preview-value"><span class="blast-tier ${blastClass}">${score} / 100 (${blastLabel})</span></span>
      </div>
      <div class="preview-row">
        <span class="preview-label">Profile</span>
        <span class="preview-value">${esc(record.profile || '—')}</span>
      </div>
      <div class="preview-row">
        <span class="preview-label">Controls</span>
        <span class="preview-value">${esc((record.controls || []).join(', ') || '—')}</span>
      </div>
    `;
  }

  function renderValidation(checks, valid) {
    const container = document.getElementById('validation-list');
    if (!container) return;

    if (!checks || checks.length === 0) {
      container.innerHTML = `<li><span class="check-ok">✓</span> JSON parsed successfully</li>`;
      return;
    }

    container.innerHTML = checks.map(c => {
      const icon = c.ok ? '✓' : (c.warning ? '⚠' : '✗');
      const cls = c.ok ? 'check-ok' : (c.warning ? 'check-warn' : 'check-fail');
      return `<li><span class="${cls}">${icon}</span> ${esc(c.message)}</li>`;
    }).join('');
  }

  // ── Enroll confirm ────────────────────────────────────────────────────────

  document.getElementById('btn-enroll-confirm')?.addEventListener('click', async () => {
    if (!currentJson) return;

    const btn = document.getElementById('btn-enroll-confirm');
    btn.textContent = 'Registering...';
    btn.disabled = true;

    try {
      await HallAPI.enrollWorker(currentJson);

      const speciesId = currentRecord?.species_id || 'unknown';
      const caps = (currentRecord?.capabilities || []).join(', ');

      document.getElementById('enroll-preview-view').style.display = 'none';
      document.getElementById('enroll-success-view').style.display = 'block';
      document.getElementById('enroll-success-msg').textContent =
        `${speciesId} is now on the Hall books. The Hall will route ${caps} dispatches to this worker.`;

      // Reload crew screen
      if (window.CrewScreen) window.CrewScreen.refresh();

    } catch (e) {
      btn.textContent = 'Register with the Hall';
      btn.disabled = false;
      showError(`Enrollment failed: ${e}`);
    }
  });

  document.getElementById('btn-enroll-cancel')?.addEventListener('click', reset);

  document.getElementById('btn-enroll-another')?.addEventListener('click', reset);

  document.getElementById('link-cli-wizard')?.addEventListener('click', (e) => {
    e.preventDefault();
    // Would open terminal with `hall scaffold` — for now show info
    const msg = document.createElement('div');
    msg.style.cssText = 'position:fixed; bottom:40px; right:20px; background:var(--bg-surface); border:1px solid var(--accent-blue); border-radius:var(--radius); padding:12px 16px; font-size:12px; color:var(--text-primary); z-index:100;';
    msg.textContent = 'Run: hall scaffold — in your terminal to generate a registry_record.json';
    document.body.appendChild(msg);
    setTimeout(() => msg.remove(), 4000);
  });

  // ── Reset ─────────────────────────────────────────────────────────────────

  function reset() {
    currentRecord = null;
    currentJson = '';

    if (fileInput) fileInput.value = '';
    if (dropZone) {
      dropZone.style.borderColor = '';
      const sub = dropZone.querySelector('.drop-zone-sub');
      if (sub) sub.innerHTML = `registry_record.json · or <button class="btn btn-ghost btn-sm" id="btn-browse-file" style="display:inline-flex;">Browse</button>`;
      // Re-wire browse button after innerHTML update
      document.getElementById('btn-browse-file')?.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput?.click();
      });
    }

    document.getElementById('enroll-dropzone-view').style.display = 'block';
    document.getElementById('enroll-preview-view').style.display = 'none';
    document.getElementById('enroll-success-view').style.display = 'none';

    const btn = document.getElementById('btn-enroll-confirm');
    if (btn) { btn.textContent = 'Register with the Hall'; btn.disabled = false; }
  }

  return { reset };
})();

function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
