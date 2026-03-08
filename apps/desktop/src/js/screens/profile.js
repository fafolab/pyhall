/**
 * profile.js — Profile & Namespaces screen
 *
 * Fetches user profile + owned namespaces from Hall Server,
 * which bridges to api.pyhall.dev using the session JWT.
 * JWT is session-only (window.AppState.sessionToken) — never written to disk.
 */

window.ProfileScreen = (() => {
  let _loaded = false;

  function init() {
    if (_loaded) return;
    _loaded = true;
    loadProfile();
  }

  function reload() {
    _loaded = false;
    init();
  }

  async function loadProfile() {
    const config = await window.HallAPI.readConfig();
    const hallUrl = config?.hall_url || 'http://localhost:8765';

    // Auth token is session-only — never persisted to disk.
    // If an old token exists in config (migration), move it to session memory and clean up.
    if (config?.auth_token && !window.AppState.sessionToken) {
      window.AppState.sessionToken = config.auth_token;
      const clean = Object.assign({}, config);
      delete clean.auth_token;
      window.HallAPI.saveConfig(clean).catch(() => {});
    }
    const token = window.AppState.sessionToken;

    if (!token) {
      showNotLoggedIn(hallUrl);
      return;
    }

    setLoading(true);

    try {
      // Token sent as Authorization header, not URL param (tokens must not appear in URLs)
      const headers = { 'Authorization': `Bearer ${token}` };
      const [profileResp, nsResp] = await Promise.all([
        fetch(`${hallUrl}/api/profile`, { headers }),
        fetch(`${hallUrl}/api/namespaces`, { headers }),
      ]);

      const profileData = profileResp.ok ? await profileResp.json() : null;
      const nsData = nsResp.ok ? await nsResp.json() : null;

      renderProfile(profileData?.profile, nsData?.namespaces, token);
    } catch (e) {
      renderError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function showNotLoggedIn(hallUrl) {
    const container = document.getElementById('profile-content');
    if (!container) return;
    const hallOnline = window.AppState?.hallOnline;
    container.innerHTML = `
      <div class="profile-unauthenticated">
        <div class="profile-icon">👤</div>
        <h3>Not logged in</h3>
        <p>Sign in with GitHub to see your namespaces and account settings.</p>
        ${!hallOnline ? `<p class="profile-hint" style="color:var(--error);">Hall Server must be running to complete sign-in.</p>` : ''}
        <button class="btn-primary" id="btn-github-login" style="margin-bottom:12px;"${!hallOnline ? ' disabled' : ''}>Sign in with GitHub</button>
      </div>
    `;
    document.getElementById('btn-github-login')?.addEventListener('click', startGitHubLogin);
  }

  function renderProfile(profile, namespaces, token) {
    const container = document.getElementById('profile-content');
    if (!container) return;

    const user = profile || {};
    const github_login = user.github_login || user.username || 'Unknown';
    const tier = user.tier || user.plan || 'free';
    const nsList = Array.isArray(namespaces) ? namespaces : (namespaces?.items || []);
    // Group namespaces: x.* | org.* | everything else
    const nsId = n => n.prefix || n.namespace || n.id || '';
    const xNs = nsList.filter(n => nsId(n).startsWith('x.'));
    const orgNs = nsList.filter(n => nsId(n).startsWith('org.'));
    const otherNs = nsList.filter(n => !nsId(n).startsWith('x.') && !nsId(n).startsWith('org.'));

    container.innerHTML = `
      <div class="profile-header">
        ${user.avatar_url ? `<img class="profile-avatar" src="${escHtml(user.avatar_url)}" alt="avatar">` : '<div class="profile-avatar-placeholder">👤</div>'}
        <div class="profile-info">
          <div class="profile-name">${escHtml(github_login)}</div>
          <div class="profile-tier tier-badge tier-${escHtml(tier)}">${escHtml(tier.toUpperCase())}</div>
        </div>
        <button class="btn-refresh" onclick="window.ProfileScreen.reload()" title="Refresh">↺</button>
      </div>

      <div class="profile-section">
        <div class="profile-section-title">Namespaces <span class="profile-count">${nsList.length}</span></div>
        ${nsList.length === 0 ? '<div class="profile-empty">No namespaces yet. Register your first namespace at <a href="https://pyhall.dev" target="_blank">pyhall.dev</a>.</div>' : ''}

        ${xNs.length > 0 ? `
          <div class="ns-group">
            <div class="ns-group-label">x.* — Community</div>
            ${xNs.map(n => renderNs(n)).join('')}
          </div>` : ''}

        ${orgNs.length > 0 ? `
          <div class="ns-group">
            <div class="ns-group-label">org.* — Organizations</div>
            ${orgNs.map(n => renderNs(n)).join('')}
          </div>` : ''}

        ${otherNs.length > 0 ? `
          <div class="ns-group">
            <div class="ns-group-label">Other</div>
            ${otherNs.map(n => renderNs(n)).join('')}
          </div>` : ''}
      </div>

      ${profile?.created_at ? `
        <div class="profile-section">
          <div class="profile-section-title">Account</div>
          <div class="profile-kv">
            <span class="profile-key">Registry</span>
            <span class="profile-val"><a href="https://pyhall.dev" target="_blank">pyhall.dev</a></span>
          </div>
          ${user.created_at ? `<div class="profile-kv">
            <span class="profile-key">Member since</span>
            <span class="profile-val">${new Date(user.created_at).toLocaleDateString()}</span>
          </div>` : ''}
          ${user.namespace_limit !== undefined ? `<div class="profile-kv">
            <span class="profile-key">Namespace limit</span>
            <span class="profile-val">${nsList.length} / ${user.namespace_limit === -1 ? '∞' : user.namespace_limit}</span>
          </div>` : ''}
        </div>` : ''}
    `;
  }

  function renderNs(ns) {
    const id = escHtml(ns.prefix || ns.namespace || ns.id || ns.name || '—');
    const workerRaw = ns.worker_count ?? ns.workers;
    const workerStr = (workerRaw !== undefined && workerRaw !== null) ? `${workerRaw} workers` : '—';
    const visibility = ns.public ? 'public' : (ns.visibility || 'private');
    return `
      <div class="ns-row">
        <span class="ns-id">${id}</span>
        <span class="ns-meta">${workerStr} · ${visibility}</span>
      </div>
    `;
  }

  function renderError(msg) {
    const container = document.getElementById('profile-content');
    if (!container) return;
    container.innerHTML = `
      <div class="profile-error">
        <div>Could not load profile from registry.</div>
        <div class="profile-error-detail">${escHtml(msg)}</div>
        <button class="btn-secondary" onclick="window.ProfileScreen.reload()">Retry</button>
      </div>
    `;
  }

  function setLoading(on) {
    const el = document.getElementById('profile-loading');
    if (el) el.style.display = on ? 'block' : 'none';
  }

  function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function goToConfig() {
    if (window.navigateTo) window.navigateTo('config');
  }

  let _authPollInterval = null;

  function startGitHubLogin() {
    const hallUrl = window.AppState?.hallUrl || 'http://localhost:8765';
    const oauthUrl = `https://api.pyhall.dev/auth/github?desktop=1`;

    // Open OAuth in system browser — app keeps running, no navigation away.
    // Tauri v2: use opener plugin namespace directly.
    if (window.__TAURI__?.opener?.openUrl) {
      window.__TAURI__.opener.openUrl(oauthUrl).catch(() => window.open(oauthUrl, '_blank'));
    } else {
      window.open(oauthUrl, '_blank');
    }

    // Poll for token every 2s (up to 3 minutes)
    let attempts = 0;
    _authPollInterval = setInterval(async () => {
      attempts++;
      if (attempts > 90) { clearInterval(_authPollInterval); return; }
      try {
        const r = await fetch(`${hallUrl}/api/auth/pending`);
        if (r.ok) {
          const d = await r.json();
          if (d?.token) {
            clearInterval(_authPollInterval);
            window.AppState.sessionToken = d.token;
            // If called from within the login gate flow, hand off to the gate.
            // Otherwise (navigated directly to Profile while already logged in), just reload.
            if (window.onLoginConfirmed) {
              window.onLoginConfirmed();
            } else {
              reload();
            }
          }
        }
      } catch (_) {}
    }, 2000);
  }

  return { init, reload, goToConfig };
})();
