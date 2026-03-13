// Copyright (c) 2026 pyhall.dev — https://pyhall.dev
// Licensed under the Apache License, Version 2.0 (see LICENSE)
/**
 * commands/skill.ts — `pyhall skill` subcommands
 *
 * Scaffold, build, certify, publish, install, and verify pyhall skills.
 *
 *   pyhall skill init
 *   pyhall skill build
 *   pyhall skill certify
 *   pyhall skill publish
 *   pyhall skill install <skill-id>
 *   pyhall skill verify
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { theme } from '../theme.js';

// ── Config ────────────────────────────────────────────────────────────────────

function registryBaseUrl(): string {
  return (process.env['PYHALL_REGISTRY_URL'] ?? 'https://api.pyhall.dev').replace(/\/$/, '');
}

// ── Readline prompt helper ────────────────────────────────────────────────────

async function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

// ── SKILL.md parser ───────────────────────────────────────────────────────────

interface SkillFrontmatter {
  name: string;
  description: string;
  version: string;
  license: string;
  compatibility: string;
  author: string;
  homepage: string;
  repository: string;
  registry: string;
}

function parseSkillMd(content: string): SkillFrontmatter {
  // Extract YAML frontmatter between --- delimiters
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) {
    throw new Error('SKILL.md is missing YAML frontmatter (--- delimiters)');
  }

  const fm = match[1]!;

  function extract(key: string): string {
    const re = new RegExp(`^${key}:\\s*(.+)$`, 'm');
    const m = fm.match(re);
    return m ? m[1]!.trim().replace(/^["']|["']$/g, '') : '';
  }

  // Multi-line description (> folded scalar) — grab until next key
  const descMatch = fm.match(/^description:\s*>\s*\r?\n([\s\S]*?)(?=^\w|\z)/m);
  let description = '';
  if (descMatch) {
    description = descMatch[1]!
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .join(' ');
  } else {
    description = extract('description');
  }

  // Extract metadata sub-fields
  const versionMatch = fm.match(/^\s+version:\s*["']?([^"'\r\n]+)["']?/m);
  const authorMatch = fm.match(/^\s+author:\s*(.+)/m);
  const homepageMatch = fm.match(/^\s+homepage:\s*(.+)/m);
  const repositoryMatch = fm.match(/^\s+repository:\s*(.+)/m);
  const registryMatch = fm.match(/^\s+registry:\s*(.+)/m);

  return {
    name: extract('name'),
    description,
    version: versionMatch ? versionMatch[1]!.trim() : '1.0.0',
    license: extract('license'),
    compatibility: extract('compatibility'),
    author: authorMatch ? authorMatch[1]!.trim() : '',
    homepage: homepageMatch ? homepageMatch[1]!.trim() : '',
    repository: repositoryMatch ? repositoryMatch[1]!.trim() : '',
    registry: registryMatch ? registryMatch[1]!.trim() : '',
  };
}

// ── SKILL.md template ─────────────────────────────────────────────────────────

function skillMdTemplate(opts: { name: string; description: string; version: string }): string {
  return `---
name: ${opts.name}
description: >
  ${opts.description}
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, VS Code Copilot, and any Agent Skills-compatible tool
metadata:
  author: your-org
  version: "${opts.version}"
  homepage: https://pyhall.dev
  repository: https://github.com/your-org/${opts.name}
  registry: https://api.pyhall.dev
---

# ${opts.name}

${opts.description}

## What you can do

- <!-- Describe key capability 1 -->
- <!-- Describe key capability 2 -->
- <!-- Describe key capability 3 -->

## Quick reference

\`\`\`bash
# Example usage
pyhall skill install your-org/${opts.name}
\`\`\`

## Safe execution defaults

1. Prefer read-only commands first.
2. Require explicit operator confirmation before mutation commands.
3. Never print raw secrets/tokens in output.
4. Deny-by-default on ambiguous context.

## Environment variables

\`\`\`bash
PYHALL_API_KEY=your-api-key    # registry authentication
PYHALL_REGISTRY_URL=https://api.pyhall.dev   # override for self-hosted
\`\`\`

## Getting started

1. \`pyhall skill install your-org/${opts.name}\`
2. <!-- Add step 2 -->
3. <!-- Add step 3 -->

Full documentation: https://pyhall.dev/docs/skills/
`;
}

// ── Adapter generators ────────────────────────────────────────────────────────

function buildMcpTool(fm: SkillFrontmatter): object {
  return {
    name: fm.name,
    description: fm.description,
    input_schema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          description: 'The action to perform with this skill',
        },
        parameters: {
          type: 'object',
          description: 'Action-specific parameters',
        },
      },
      required: ['action'],
    },
  };
}

function buildOpenAiFunction(fm: SkillFrontmatter): object {
  return {
    name: fm.name.replace(/-/g, '_'),
    description: fm.description,
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          description: 'The action to perform with this skill',
        },
        parameters: {
          type: 'object',
          description: 'Action-specific parameters',
        },
      },
      required: ['action'],
    },
  };
}

function buildGeminiFunction(fm: SkillFrontmatter): object {
  return {
    name: fm.name.replace(/-/g, '_'),
    description: fm.description,
    parameters: {
      type: 'OBJECT',
      properties: {
        action: {
          type: 'STRING',
          description: 'The action to perform with this skill',
        },
        parameters: {
          type: 'OBJECT',
          description: 'Action-specific parameters',
        },
      },
      required: ['action'],
    },
  };
}

// ── pyhall skill init ─────────────────────────────────────────────────────────

export async function runSkillInit(): Promise<void> {
  const skillMdPath = path.resolve(process.cwd(), 'SKILL.md');

  if (fs.existsSync(skillMdPath)) {
    console.error(theme.error('SKILL.md already exists in this directory. Aborting.'));
    process.exit(1);
  }

  console.log('');
  console.log(theme.primary.bold('  pyhall skill init') + theme.dim(' — scaffold a new skill'));
  console.log(theme.dim('  ' + '─'.repeat(60)));
  console.log('');

  const name = await prompt('  Skill name (e.g. my-org/my-skill): ');
  if (!name) {
    console.error(theme.error('Skill name is required.'));
    process.exit(1);
  }

  const description = await prompt('  Description: ');
  if (!description) {
    console.error(theme.error('Description is required.'));
    process.exit(1);
  }

  const versionInput = await prompt('  Version [1.0.0]: ');
  const version = versionInput || '1.0.0';

  const content = skillMdTemplate({ name, description, version });
  fs.writeFileSync(skillMdPath, content, 'utf8');

  console.log('');
  console.log(`  ${theme.success('created')}  ${skillMdPath}`);
  console.log('');
  console.log(theme.dim('  Next steps:'));
  console.log(theme.dim(`    1. Edit SKILL.md — fill in your skill documentation`));
  console.log(theme.dim(`    2. pyhall skill build — generate adapter files`));
  console.log(theme.dim(`    3. pyhall skill certify — submit for certification`));
  console.log('');
}

// ── pyhall skill build ────────────────────────────────────────────────────────

export async function runSkillBuild(): Promise<void> {
  const skillMdPath = path.resolve(process.cwd(), 'SKILL.md');

  if (!fs.existsSync(skillMdPath)) {
    console.error(theme.error('SKILL.md not found in current directory. Run: pyhall skill init'));
    process.exit(1);
  }

  const content = fs.readFileSync(skillMdPath, 'utf8');
  let fm: SkillFrontmatter;
  try {
    fm = parseSkillMd(content);
  } catch (err) {
    console.error(theme.error(`Failed to parse SKILL.md: ${(err as Error).message}`));
    process.exit(1);
  }

  if (!fm.name) {
    console.error(theme.error('SKILL.md is missing required field: name'));
    process.exit(1);
  }

  const adaptersDir = path.resolve(process.cwd(), 'skill-adapters');
  if (!fs.existsSync(adaptersDir)) {
    fs.mkdirSync(adaptersDir, { recursive: true });
  }

  const adapters = [
    { file: 'mcp-tool.json',        label: 'MCP tool definition',           data: buildMcpTool(fm) },
    { file: 'openai-function.json', label: 'OpenAI function object',        data: buildOpenAiFunction(fm) },
    { file: 'gemini-function.json', label: 'Google Gemini function declaration', data: buildGeminiFunction(fm) },
  ];

  for (const adapter of adapters) {
    const filePath = path.join(adaptersDir, adapter.file);
    fs.writeFileSync(filePath, JSON.stringify(adapter.data, null, 2) + '\n', 'utf8');
  }

  console.log('');
  console.log(`  ${theme.success('Built 3 adapters')} → ${theme.primary('./skill-adapters/')}`);
  for (const adapter of adapters) {
    console.log(`    ${theme.dim('·')} ${adapter.file}  ${theme.dim(adapter.label)}`);
  }
  console.log('');
}

// ── pyhall skill certify ──────────────────────────────────────────────────────

export async function runSkillCertify(): Promise<void> {
  const skillMdPath = path.resolve(process.cwd(), 'SKILL.md');
  const adaptersDir = path.resolve(process.cwd(), 'skill-adapters');

  if (!fs.existsSync(skillMdPath)) {
    console.error(theme.error('SKILL.md not found. Run: pyhall skill build first.'));
    process.exit(1);
  }

  if (!fs.existsSync(adaptersDir)) {
    console.error(theme.error('skill-adapters/ not found. Run: pyhall skill build first.'));
    process.exit(1);
  }

  let token = process.env['PYHALL_SESSION_TOKEN'] ?? '';
  if (!token) {
    token = await prompt('  PYHALL_SESSION_TOKEN: ');
  }
  if (!token) {
    console.error(theme.error('Authentication token is required. Set PYHALL_SESSION_TOKEN or provide at prompt.'));
    process.exit(1);
  }

  const skillMdContent = fs.readFileSync(skillMdPath, 'utf8');
  let fm: SkillFrontmatter;
  try {
    fm = parseSkillMd(skillMdContent);
  } catch (err) {
    console.error(theme.error(`Failed to parse SKILL.md: ${(err as Error).message}`));
    process.exit(1);
  }

  const adapterFiles: Record<string, unknown> = {};
  for (const file of ['mcp-tool.json', 'openai-function.json', 'gemini-function.json']) {
    const filePath = path.join(adaptersDir, file);
    if (fs.existsSync(filePath)) {
      adapterFiles[file] = JSON.parse(fs.readFileSync(filePath, 'utf8')) as unknown;
    }
  }

  const payload = {
    skill_name: fm.name,
    version: fm.version,
    skill_md: skillMdContent,
    adapters: adapterFiles,
  };

  const base = registryBaseUrl();
  console.log('');
  console.log(theme.dim(`  Submitting to ${base}/api/v1/skills/certify ...`));

  let res: Response;
  try {
    res = await fetch(`${base}/api/v1/skills/certify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error(theme.error(`Network error: ${(err as Error).message}`));
    process.exit(1);
  }

  if (!res.ok) {
    const body = await res.text();
    console.error(theme.error(`Certification failed (${res.status}): ${body}`));
    process.exit(1);
  }

  const result = await res.json() as { certification_id: string; status: string };
  console.log('');
  console.log(`  ${theme.success('Certification submitted')}`);
  console.log(`  ${theme.subheading('Certification ID:')}  ${result.certification_id}`);
  console.log(`  ${theme.subheading('Status:')}            ${result.status}`);
  console.log('');
  console.log(theme.dim('  Next: pyhall skill publish — once certification is approved'));
  console.log('');
}

// ── pyhall skill publish ──────────────────────────────────────────────────────

export async function runSkillPublish(): Promise<void> {
  const skillMdPath = path.resolve(process.cwd(), 'SKILL.md');

  if (!fs.existsSync(skillMdPath)) {
    console.error(theme.error('SKILL.md not found. Run: pyhall skill certify first.'));
    process.exit(1);
  }

  let token = process.env['PYHALL_SESSION_TOKEN'] ?? '';
  if (!token) {
    token = await prompt('  PYHALL_SESSION_TOKEN: ');
  }
  if (!token) {
    console.error(theme.error('Authentication token is required. Set PYHALL_SESSION_TOKEN or provide at prompt.'));
    process.exit(1);
  }

  const skillMdContent = fs.readFileSync(skillMdPath, 'utf8');
  let fm: SkillFrontmatter;
  try {
    fm = parseSkillMd(skillMdContent);
  } catch (err) {
    console.error(theme.error(`Failed to parse SKILL.md: ${(err as Error).message}`));
    process.exit(1);
  }

  const payload = {
    skill_name: fm.name,
    version: fm.version,
  };

  const base = registryBaseUrl();
  console.log('');
  console.log(theme.dim(`  Publishing ${fm.name}@${fm.version} to ${base} ...`));

  let res: Response;
  try {
    res = await fetch(`${base}/api/v1/skills/publish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error(theme.error(`Network error: ${(err as Error).message}`));
    process.exit(1);
  }

  if (!res.ok) {
    const body = await res.text();
    console.error(theme.error(`Publish failed (${res.status}): ${body}`));
    process.exit(1);
  }

  const result = await res.json() as { skill_url: string; status: string };
  console.log('');
  console.log(`  ${theme.success('Skill published')}`);
  console.log(`  ${theme.subheading('URL:')}     ${result.skill_url}`);
  console.log(`  ${theme.subheading('Status:')}  ${result.status}`);
  console.log('');
}

// ── pyhall skill install <skill-id> ──────────────────────────────────────────

// Strict skill ID format: org/skill-name — only lowercase alphanumeric, dots, underscores, hyphens.
// Rejects anything with '..', extra slashes, backslashes, or path separators beyond a single '/'.
const SKILL_ID_RE = /^[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/;

export async function runSkillInstall(skillId: string): Promise<void> {
  if (!skillId || !SKILL_ID_RE.test(skillId)) {
    console.error(theme.error('Invalid skill ID. Format: org/skill-name using only lowercase letters, digits, dots, underscores, hyphens (e.g. pyhall/python-sdk)'));
    process.exit(1);
  }

  const base = registryBaseUrl();
  const skillsRoot = path.resolve(process.cwd(), '.pyhall', 'skills');
  const installDir = path.resolve(skillsRoot, skillId);

  // Guard: resolved path must stay inside skillsRoot (defence-in-depth against
  // OS-level path manipulation or future regex edge cases).
  if (!installDir.startsWith(skillsRoot + path.sep) && installDir !== skillsRoot) {
    console.error(theme.error(`Skill ID resolved outside expected install directory. Aborting.`));
    process.exit(1);
  }

  console.log('');
  console.log(theme.dim(`  Fetching ${skillId} from ${base} ...`));

  let res: Response;
  try {
    res = await fetch(`${base}/api/v1/skills/${encodeURIComponent(skillId)}`);
  } catch (err) {
    console.error(theme.error(`Network error: ${(err as Error).message}`));
    process.exit(1);
  }

  if (res.status === 404) {
    console.error(theme.error(`Skill not found: ${skillId}`));
    process.exit(1);
  }

  if (!res.ok) {
    console.error(theme.error(`Registry error: ${res.status}`));
    process.exit(1);
  }

  const data = await res.json() as {
    skill_md: string;
    adapters?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
  };

  if (!fs.existsSync(installDir)) {
    fs.mkdirSync(installDir, { recursive: true });
  }

  // Write SKILL.md
  const skillMdPath = path.join(installDir, 'SKILL.md');
  fs.writeFileSync(skillMdPath, data.skill_md ?? '', 'utf8');

  // Write adapters if present
  if (data.adapters) {
    const adaptersDir = path.join(installDir, 'skill-adapters');
    if (!fs.existsSync(adaptersDir)) {
      fs.mkdirSync(adaptersDir, { recursive: true });
    }
    for (const [filename, content] of Object.entries(data.adapters)) {
      // Use basename only — prevent registry from supplying traversal filenames like ../../evil
      const safeFilename = path.basename(filename);
      fs.writeFileSync(
        path.join(adaptersDir, safeFilename),
        JSON.stringify(content, null, 2) + '\n',
        'utf8',
      );
    }
  }

  // Write metadata manifest
  if (data.metadata) {
    fs.writeFileSync(
      path.join(installDir, 'manifest.json'),
      JSON.stringify(data.metadata, null, 2) + '\n',
      'utf8',
    );
  }

  console.log('');
  console.log(`  ${theme.success('Installed')}  ${skillId}`);
  console.log(`  ${theme.subheading('Path:')}      ${installDir}`);
  console.log('');
}

// ── pyhall skill verify ───────────────────────────────────────────────────────

export async function runSkillVerify(): Promise<void> {
  const skillsRoot = path.resolve(process.cwd(), '.pyhall', 'skills');

  if (!fs.existsSync(skillsRoot)) {
    console.log('');
    console.log(theme.dim('  No installed skills found (.pyhall/skills/ does not exist).'));
    console.log('');
    return;
  }

  // Discover installed skills: .pyhall/skills/<org>/<name>/SKILL.md
  const installedSkills: string[] = [];
  for (const org of fs.readdirSync(skillsRoot)) {
    const orgDir = path.join(skillsRoot, org);
    if (!fs.statSync(orgDir).isDirectory()) continue;
    for (const skillName of fs.readdirSync(orgDir)) {
      const skillDir = path.join(orgDir, skillName);
      if (!fs.statSync(skillDir).isDirectory()) continue;
      if (fs.existsSync(path.join(skillDir, 'SKILL.md'))) {
        installedSkills.push(`${org}/${skillName}`);
      }
    }
  }

  if (installedSkills.length === 0) {
    console.log('');
    console.log(theme.dim('  No installed skills found.'));
    console.log('');
    return;
  }

  const base = registryBaseUrl();
  console.log('');
  console.log(`  ${theme.subheading(`Verifying ${installedSkills.length} installed skill(s)...`)}`);
  console.log('');

  for (const skillId of installedSkills) {
    const skillDir = path.join(skillsRoot, skillId);
    const localContent = fs.readFileSync(path.join(skillDir, 'SKILL.md'), 'utf8');

    let status: 'verified' | 'tampered' | 'unknown' = 'unknown';
    let remoteVersion = '';

    try {
      const res = await fetch(`${base}/api/v1/skills/${encodeURIComponent(skillId)}`);
      if (res.ok) {
        const data = await res.json() as { skill_md?: string; metadata?: { version?: string } };
        remoteVersion = data.metadata?.version ?? '';
        if (data.skill_md === localContent) {
          status = 'verified';
        } else {
          status = 'tampered';
        }
      }
    } catch {
      status = 'unknown';
    }

    const statusLabel =
      status === 'verified' ? theme.success('verified')
      : status === 'tampered' ? theme.error('TAMPERED')
      : theme.warning('unknown');

    const versionLabel = remoteVersion ? theme.dim(`  v${remoteVersion}`) : '';
    console.log(`  ${statusLabel}  ${skillId}${versionLabel}`);
  }

  console.log('');
}
