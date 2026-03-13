/**
 * tests/skill.test.ts — `pyhall skill` command tests
 *
 * Tests for skill init, build, certify, publish, install, verify.
 * Uses tmp directories to avoid side effects.
 *
 * theme is mocked because chalk v5 is ESM-only and can't be loaded by ts-jest (CJS).
 */

// Mock theme before any imports that pull in chalk.
jest.mock('../src/theme', () => ({
  theme: new Proxy({}, {
    get: (_t, prop) => {
      const fn = (s: string) => s;
      // Support chaining like theme.primary.bold(...)
      fn.bold = (s: string) => s;
      fn.dim = (s: string) => s;
      return fn;
    },
  }),
}));

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  runSkillInit,
  runSkillBuild,
  runSkillCertify,
  runSkillPublish,
  runSkillInstall,
  runSkillVerify,
} from '../src/commands/skill';

// ── Mock fetch ────────────────────────────────────────────────────────────────

const mockFetch = jest.fn();
global.fetch = mockFetch;

function mockResponse(body: unknown, status = 200): Response {
  const bodyText = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
    text: async () => bodyText,
  } as unknown as Response;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

let consoleOutput: string[] = [];
let errorOutput: string[] = [];

function captureOutput() {
  consoleOutput = [];
  errorOutput = [];
  jest.spyOn(console, 'log').mockImplementation((...args) => {
    consoleOutput.push(args.join(' '));
  });
  jest.spyOn(console, 'error').mockImplementation((...args) => {
    errorOutput.push(args.join(' '));
  });
}

function outputText(): string {
  return consoleOutput.join('\n').replace(/\x1b\[[0-9;]*m/g, '');
}

function errorText(): string {
  return errorOutput.join('\n').replace(/\x1b\[[0-9;]*m/g, '');
}

// Tmp directory per test
let tmpDir: string;
let originalCwd: string;

function setupTmpDir() {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pyhall-skill-test-'));
  originalCwd = process.cwd();
  jest.spyOn(process, 'cwd').mockReturnValue(tmpDir);
}

function cleanupTmpDir() {
  jest.spyOn(process, 'cwd').mockRestore();
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch { /* ignore */ }
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeEach(() => {
  mockFetch.mockReset();
  captureOutput();
  setupTmpDir();
});

afterEach(() => {
  jest.restoreAllMocks();
  cleanupTmpDir();
});

// ── Minimal valid SKILL.md for tests ─────────────────────────────────────────

const MINIMAL_SKILL_MD = `---
name: test-skill
description: A test skill for unit tests
license: Apache-2.0
compatibility: Claude Code
metadata:
  author: test-org
  version: "1.0.0"
  homepage: https://pyhall.dev
  repository: https://github.com/test-org/test-skill
  registry: https://api.pyhall.dev
---

# Test Skill

A test skill for unit tests.
`;

// ── runSkillInit ──────────────────────────────────────────────────────────────

describe('runSkillInit()', () => {
  it('exits 1 when SKILL.md already exists', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), 'existing content', 'utf8');

    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    // Mock readline to avoid hanging
    jest.mock('node:readline', () => ({
      createInterface: () => ({ question: (_q: string, cb: (s: string) => void) => cb(''), close: () => {} }),
    }));

    await expect(runSkillInit()).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('already exists');
    mockExit.mockRestore();
  });

  it('creates SKILL.md with provided name/description/version', async () => {
    // Mock readline prompt sequence: name, description, version
    const answers = ['my-org/my-skill', 'Does something cool', '2.0.0'];
    let callIndex = 0;

    // Mock node:readline createInterface to supply canned answers
    const mockRl = {
      question: jest.fn((_q: string, cb: (s: string) => void) => {
        cb(answers[callIndex++] ?? '');
      }),
      close: jest.fn(),
    };

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const rl = require('readline') as typeof import('readline');
    jest.spyOn(rl, 'createInterface').mockReturnValue(mockRl as unknown as import('readline').Interface);

    await runSkillInit();

    const skillMdPath = path.join(tmpDir, 'SKILL.md');
    expect(fs.existsSync(skillMdPath)).toBe(true);

    const content = fs.readFileSync(skillMdPath, 'utf8');
    expect(content).toContain('my-org/my-skill');
    expect(content).toContain('Does something cool');
    expect(content).toContain('2.0.0');
    expect(outputText()).toContain('created');
  });
});

// ── runSkillBuild ─────────────────────────────────────────────────────────────

describe('runSkillBuild()', () => {
  it('exits 1 when SKILL.md is missing', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillBuild()).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('SKILL.md not found');
    mockExit.mockRestore();
  });

  it('generates 3 adapter files from valid SKILL.md', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');

    await runSkillBuild();

    const adaptersDir = path.join(tmpDir, 'skill-adapters');
    expect(fs.existsSync(adaptersDir)).toBe(true);
    expect(fs.existsSync(path.join(adaptersDir, 'mcp-tool.json'))).toBe(true);
    expect(fs.existsSync(path.join(adaptersDir, 'openai-function.json'))).toBe(true);
    expect(fs.existsSync(path.join(adaptersDir, 'gemini-function.json'))).toBe(true);
  });

  it('prints "Built 3 adapters" message', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');

    await runSkillBuild();

    expect(outputText()).toContain('Built 3 adapters');
    expect(outputText()).toContain('./skill-adapters/');
  });

  it('mcp-tool.json has correct name field', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');

    await runSkillBuild();

    const mcpPath = path.join(tmpDir, 'skill-adapters', 'mcp-tool.json');
    const mcp = JSON.parse(fs.readFileSync(mcpPath, 'utf8')) as { name: string };
    expect(mcp.name).toBe('test-skill');
  });

  it('openai-function.json uses underscore name', async () => {
    const content = MINIMAL_SKILL_MD.replace('name: test-skill', 'name: test-skill-with-dashes');
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), content, 'utf8');

    await runSkillBuild();

    const fnPath = path.join(tmpDir, 'skill-adapters', 'openai-function.json');
    const fn = JSON.parse(fs.readFileSync(fnPath, 'utf8')) as { name: string };
    expect(fn.name).toBe('test_skill_with_dashes');
  });

  it('gemini-function.json uses OBJECT type', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');

    await runSkillBuild();

    const geminiPath = path.join(tmpDir, 'skill-adapters', 'gemini-function.json');
    const gem = JSON.parse(fs.readFileSync(geminiPath, 'utf8')) as { parameters: { type: string } };
    expect(gem.parameters.type).toBe('OBJECT');
  });

  it('all adapters contain description from SKILL.md', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');

    await runSkillBuild();

    const adaptersDir = path.join(tmpDir, 'skill-adapters');
    for (const file of ['mcp-tool.json', 'openai-function.json', 'gemini-function.json']) {
      const data = JSON.parse(fs.readFileSync(path.join(adaptersDir, file), 'utf8')) as { description: string };
      expect(data.description).toContain('test skill');
    }
  });
});

// ── runSkillCertify ───────────────────────────────────────────────────────────

describe('runSkillCertify()', () => {
  it('exits 1 when SKILL.md is missing', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillCertify()).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    mockExit.mockRestore();
  });

  it('exits 1 when skill-adapters/ is missing', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');

    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillCertify()).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('skill-adapters/');
    mockExit.mockRestore();
  });

  it('POSTs with Bearer token and prints certification ID', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');
    fs.mkdirSync(path.join(tmpDir, 'skill-adapters'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'skill-adapters', 'mcp-tool.json'), '{}', 'utf8');

    process.env['PYHALL_SESSION_TOKEN'] = 'test-token-abc';

    mockFetch.mockResolvedValueOnce(mockResponse({
      certification_id: 'cert_xyz123',
      status: 'pending',
    }));

    await runSkillCertify();

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/skills/certify'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'Authorization': 'Bearer test-token-abc' }),
      }),
    );
    expect(outputText()).toContain('cert_xyz123');
    expect(outputText()).toContain('pending');

    delete process.env['PYHALL_SESSION_TOKEN'];
  });

  it('prints error on non-ok response', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');
    fs.mkdirSync(path.join(tmpDir, 'skill-adapters'), { recursive: true });
    process.env['PYHALL_SESSION_TOKEN'] = 'test-token';

    mockFetch.mockResolvedValueOnce(mockResponse('Unauthorized', 401));

    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillCertify()).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('401');
    mockExit.mockRestore();

    delete process.env['PYHALL_SESSION_TOKEN'];
  });
});

// ── runSkillPublish ───────────────────────────────────────────────────────────

describe('runSkillPublish()', () => {
  it('exits 1 when SKILL.md is missing', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillPublish()).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    mockExit.mockRestore();
  });

  it('POSTs and prints skill URL on success', async () => {
    fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');
    process.env['PYHALL_SESSION_TOKEN'] = 'test-token';

    mockFetch.mockResolvedValueOnce(mockResponse({
      skill_url: 'https://api.pyhall.dev/skills/test-org/test-skill',
      status: 'published',
    }));

    await runSkillPublish();

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/skills/publish'),
      expect.objectContaining({ method: 'POST' }),
    );
    expect(outputText()).toContain('https://api.pyhall.dev/skills/test-org/test-skill');
    expect(outputText()).toContain('published');

    delete process.env['PYHALL_SESSION_TOKEN'];
  });
});

// ── runSkillInstall ───────────────────────────────────────────────────────────

describe('runSkillInstall()', () => {
  it('exits 1 for invalid skill ID (no slash)', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillInstall('no-slash')).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('Invalid skill ID');
    mockExit.mockRestore();
  });

  it('exits 1 for path traversal via ../../ in skill ID', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillInstall('../../etc/passwd')).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('Invalid skill ID');
    mockExit.mockRestore();
  });

  it('exits 1 for path traversal via org/../.. in skill ID', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillInstall('org/../../../etc')).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('Invalid skill ID');
    mockExit.mockRestore();
  });

  it('exits 1 for absolute path as skill ID', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillInstall('/etc/passwd')).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('Invalid skill ID');
    mockExit.mockRestore();
  });

  it('exits 1 for uppercase in skill ID', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillInstall('Org/Skill')).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    mockExit.mockRestore();
  });

  it('exits 1 for double-slash in skill ID', async () => {
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillInstall('org//skill')).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    mockExit.mockRestore();
  });

  it('exits 1 on 404', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({ error: 'not found' }, 404));
    const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit'); });
    await expect(runSkillInstall('pyhall/no-such-skill')).rejects.toThrow('exit');
    expect(mockExit).toHaveBeenCalledWith(1);
    expect(errorText()).toContain('not found');
    mockExit.mockRestore();
  });

  it('downloads and writes SKILL.md to install path', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({
      skill_md: MINIMAL_SKILL_MD,
      adapters: {
        'mcp-tool.json': { name: 'test-skill' },
      },
      metadata: { version: '1.0.0' },
    }));

    await runSkillInstall('pyhall/test-skill');

    const installDir = path.join(tmpDir, '.pyhall', 'skills', 'pyhall', 'test-skill');
    expect(fs.existsSync(path.join(installDir, 'SKILL.md'))).toBe(true);
    expect(fs.existsSync(path.join(installDir, 'skill-adapters', 'mcp-tool.json'))).toBe(true);
    expect(fs.existsSync(path.join(installDir, 'manifest.json'))).toBe(true);
    expect(outputText()).toContain('Installed');
    expect(outputText()).toContain('pyhall/test-skill');
  });

  it('calls registry with skill-id in URL', async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({
      skill_md: MINIMAL_SKILL_MD,
      adapters: {},
      metadata: {},
    }));

    await runSkillInstall('pyhall/python-sdk');

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/skills/pyhall%2Fpython-sdk'),
    );
  });
});

// ── runSkillVerify ────────────────────────────────────────────────────────────

describe('runSkillVerify()', () => {
  it('prints message when no skills installed', async () => {
    await runSkillVerify();
    expect(outputText()).toContain('No installed skills');
  });

  it('prints verified for matching remote content', async () => {
    const skillDir = path.join(tmpDir, '.pyhall', 'skills', 'pyhall', 'my-skill');
    fs.mkdirSync(skillDir, { recursive: true });
    fs.writeFileSync(path.join(skillDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');

    mockFetch.mockResolvedValueOnce(mockResponse({
      skill_md: MINIMAL_SKILL_MD,
      metadata: { version: '1.0.0' },
    }));

    await runSkillVerify();
    expect(outputText()).toContain('verified');
    expect(outputText()).toContain('pyhall/my-skill');
  });

  it('prints TAMPERED when local content differs from registry', async () => {
    const skillDir = path.join(tmpDir, '.pyhall', 'skills', 'pyhall', 'tampered-skill');
    fs.mkdirSync(skillDir, { recursive: true });
    fs.writeFileSync(path.join(skillDir, 'SKILL.md'), MINIMAL_SKILL_MD + '\nmalicious content', 'utf8');

    mockFetch.mockResolvedValueOnce(mockResponse({
      skill_md: MINIMAL_SKILL_MD,
      metadata: { version: '1.0.0' },
    }));

    await runSkillVerify();
    expect(outputText()).toContain('TAMPERED');
  });

  it('prints unknown when registry is unreachable', async () => {
    const skillDir = path.join(tmpDir, '.pyhall', 'skills', 'pyhall', 'offline-skill');
    fs.mkdirSync(skillDir, { recursive: true });
    fs.writeFileSync(path.join(skillDir, 'SKILL.md'), MINIMAL_SKILL_MD, 'utf8');

    mockFetch.mockRejectedValueOnce(new Error('Network unreachable'));

    await runSkillVerify();
    expect(outputText()).toContain('unknown');
  });
});
