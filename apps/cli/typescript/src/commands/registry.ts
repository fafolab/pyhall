/**
 * commands/registry.ts — `pyhall registry` subcommands
 *
 * Queries the pyhall.dev registry API (v0.2.0).
 *   pyhall registry verify <worker-id>
 *   pyhall registry check-hash <sha256>
 *   pyhall registry ban-list [--limit N]
 *   pyhall registry status
 *
 * Base URL: PYHALL_REGISTRY_URL env var, or 'https://api.pyhall.dev'.
 */

import { theme } from '../theme.js';

// ── Config ────────────────────────────────────────────────────────────────────

function registryBaseUrl(): string {
  return (process.env['PYHALL_REGISTRY_URL'] ?? 'https://api.pyhall.dev').replace(/\/$/, '');
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

async function registryFetch(path: string): Promise<Response> {
  const base = registryBaseUrl();
  const res = await fetch(`${base}${path}`);
  if (res.status === 429) {
    console.error(theme.error('Rate limited — try again later'));
    process.exit(1);
  }
  return res;
}

// ── pyhall registry verify <worker-id> ───────────────────────────────────────

export async function runRegistryVerify(workerId: string): Promise<void> {
  const res = await registryFetch(`/api/v1/verify/${encodeURIComponent(workerId)}`);

  if (res.status === 404) {
    console.log('');
    console.log(`  ${theme.dim('Worker:')}  ${workerId}`);
    console.log(`  ${theme.warning('Status:')}  unknown — not found in registry`);
    console.log('');
    return;
  }

  if (!res.ok) {
    console.error(theme.error(`Registry error: ${res.status}`));
    process.exit(1);
  }

  const w = await res.json() as {
    worker_id: string; status: string; current_hash: string | null;
    banned: boolean; ban_reason: string | null; attested_at: string | null;
    ai_generated: boolean; ai_service: string | null; ai_model: string | null;
    ai_session_fingerprint: string | null;
  };

  const statusColor = w.status === 'active' ? theme.success
    : w.status === 'banned' ? theme.error
    : theme.warning;

  console.log('');
  console.log(`  ${theme.subheading('Worker:')}              ${theme.primary(w.worker_id)}`);
  console.log(`  ${theme.subheading('Status:')}              ${statusColor(w.status.toUpperCase())}`);
  console.log(`  ${theme.subheading('Current hash:')}        ${w.current_hash ?? theme.dim('none')}`);
  console.log(`  ${theme.subheading('Banned:')}              ${w.banned ? theme.error('yes') : theme.success('no')}`);
  if (w.ban_reason) {
    console.log(`  ${theme.subheading('Ban reason:')}          ${w.ban_reason}`);
  }
  console.log(`  ${theme.subheading('Attested at:')}         ${w.attested_at ?? theme.dim('never')}`);
  console.log(`  ${theme.subheading('AI generated:')}        ${w.ai_generated ? 'yes' : 'no'}`);
  if (w.ai_service) console.log(`  ${theme.subheading('AI service:')}          ${w.ai_service}`);
  if (w.ai_model) console.log(`  ${theme.subheading('AI model:')}            ${w.ai_model}`);
  if (w.ai_session_fingerprint) {
    console.log(`  ${theme.subheading('Session fingerprint:')}  ${w.ai_session_fingerprint}`);
  }
  console.log('');
}

// ── pyhall registry check-hash <sha256> ──────────────────────────────────────

export async function runRegistryCheckHash(sha256: string): Promise<void> {
  if (!/^[0-9a-f]{64}$/i.test(sha256)) {
    console.error(theme.error('Invalid sha256: must be 64 hex characters'));
    process.exit(1);
  }

  const res = await registryFetch('/api/v1/ban-list');
  if (!res.ok) {
    console.error(theme.error(`Registry error: ${res.status}`));
    process.exit(1);
  }

  const list = await res.json() as Array<{ sha256: string; reason: string; source: string; review_status?: string }>;
  const entry = list.find(e => e.sha256 === sha256);

  console.log('');
  if (entry) {
    console.log(`  ${theme.error('BANNED')}   ${sha256}`);
    console.log(`  ${theme.dim('Reason:')}  ${entry.reason}`);
    console.log(`  ${theme.dim('Source:')}  ${entry.source}`);
    if (entry.review_status) {
      console.log(`  ${theme.dim('Review:')}  ${entry.review_status}`);
    }
  } else {
    console.log(`  ${theme.success('CLEAN')}    ${sha256}`);
    console.log(`  ${theme.dim('Not found on the confirmed ban-list.')}`);
  }
  console.log('');
}

// ── pyhall registry ban-list [--limit N] ─────────────────────────────────────

export async function runRegistryBanList(opts: { limit?: string }): Promise<void> {
  const limit = parseInt(opts.limit ?? '20', 10);
  const res = await registryFetch(`/api/v1/ban-list?limit=${limit}`);
  if (!res.ok) {
    console.error(theme.error(`Registry error: ${res.status}`));
    process.exit(1);
  }

  const list = await res.json() as Array<{
    sha256: string; reason: string; reported_at: string; source: string; review_status?: string;
  }>;

  console.log('');
  if (list.length === 0) {
    console.log(theme.dim('  Ban-list is empty.'));
    console.log('');
    return;
  }

  console.log(`  ${theme.subheading(`Confirmed ban-list (${list.length} entries):`)}`);
  console.log('');
  for (const entry of list) {
    const short = entry.sha256.slice(0, 12) + '…';
    const date = entry.reported_at.slice(0, 10);
    console.log(
      `  ${theme.error(short)}  ${theme.dim(date)}  ${theme.dim(`[${entry.source}]`)}  ${entry.reason.slice(0, 60)}`,
    );
  }
  console.log('');
}

// ── pyhall registry status ────────────────────────────────────────────────────

export async function runRegistryStatus(): Promise<void> {
  const base = registryBaseUrl();
  const res = await registryFetch('/health');
  if (!res.ok) {
    console.log('');
    console.log(`  ${theme.subheading('Registry:')}  ${base}`);
    console.log(`  ${theme.error('Status:')}    unreachable (${res.status})`);
    console.log('');
    return;
  }

  const h = await res.json() as { ok: boolean; version: string };
  console.log('');
  console.log(`  ${theme.subheading('Registry:')}  ${base}`);
  console.log(`  ${theme.success('Status:')}    ${h.ok ? 'ok' : 'degraded'}`);
  console.log(`  ${theme.subheading('Version:')}   ${h.version}`);
  console.log('');
}
