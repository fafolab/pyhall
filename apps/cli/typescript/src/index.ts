// Copyright (c) 2026 pyhall.dev — https://pyhall.dev
// Licensed under the Apache License, Version 2.0 (see LICENSE)
#!/usr/bin/env node
/**
 * index.ts — pyhall CLI entry point
 *
 * Worker Class Protocol taxonomy browser, search, and worker scaffolder.
 * https://pyhall.dev
 */

import { Command } from 'commander';
import { runVersion } from './commands/version.js';
import { runSearch } from './commands/search.js';
import { runExplain } from './commands/explain.js';
import { runBrowse } from './commands/browse.js';
import { runScaffold } from './commands/scaffold.js';
import { runRegistryVerify, runRegistryCheckHash, runRegistryBanList, runRegistryStatus } from './commands/registry.js';
import { runSkillInit, runSkillBuild, runSkillCertify, runSkillPublish, runSkillInstall, runSkillVerify } from './commands/skill.js';
import { theme } from './theme.js';

const CLI_VERSION = '0.3.0';

const program = new Command();

program
  .name('pyhall')
  .description(
    theme.primary.bold('pyhall') + ' — Worker Class Protocol CLI  ' +
    theme.dim('https://pyhall.dev')
  )
  .version(CLI_VERSION, '-v, --version', 'Print version and exit')
  .addHelpText(
    'after',
    `
${theme.dim('Examples:')}
  ${theme.primary('pyhall version')}
  ${theme.primary('pyhall search sandbox')}
  ${theme.primary('pyhall explain cap.mount.workspace')}
  ${theme.primary('pyhall browse')}
  ${theme.primary('pyhall browse --namespace cap.doc')}
  ${theme.primary('pyhall browse --type wrk')}
  ${theme.primary('pyhall scaffold')}
`
  );

// ---------------------------------------------------------------------------
// version
// ---------------------------------------------------------------------------
program
  .command('version')
  .description('Show CLI version, @pyhall/core version, and WCP spec version')
  .action(() => {
    runVersion();
  });

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------
program
  .command('search <query>')
  .description('Fuzzy search across the taxonomy catalog')
  .option('-l, --limit <n>', 'Maximum results to show', '20')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall search sandbox')}
  ${theme.primary('pyhall search doc --limit 10')}
  ${theme.primary('pyhall search egress')}
`)
  .action((query: string, opts: { limit?: string }) => {
    runSearch(query, opts);
  });

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------
program
  .command('explain <entity-id>')
  .description('Show detailed info for a taxonomy entity')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall explain cap.mount.workspace')}
  ${theme.primary('pyhall explain wrk.doc.pipeline.orchestrator')}
  ${theme.primary('pyhall explain ctrl.sandbox.no_egress_default_deny')}
`)
  .action((entityId: string) => {
    runExplain(entityId);
  });

// ---------------------------------------------------------------------------
// browse
// ---------------------------------------------------------------------------
program
  .command('browse')
  .description('Browse namespaces and entities (default: list all namespaces)')
  .option('--namespace <prefix>', 'Filter to a namespace prefix (e.g. cap.doc, cap.mem, wrk.doc)')
  .option('--type <type>', 'Filter by entity type: cap|wrk|ctrl|pol|prof')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall browse')}
  ${theme.primary('pyhall browse --namespace cap.doc')}
  ${theme.primary('pyhall browse --type wrk')}
  ${theme.primary('pyhall browse --namespace cap --type cap')}
`)
  .action((opts: { namespace?: string; type?: string }) => {
    runBrowse(opts);
  });

// ---------------------------------------------------------------------------
// scaffold
// ---------------------------------------------------------------------------
program
  .command('scaffold')
  .description('Interactive worker scaffold wizard — generates worker.ts, registry-record.json, README.md')
  .action(async () => {
    await runScaffold();
  });

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------
const registryCmd = program
  .command('registry')
  .description('pyhall.dev registry operations — verify workers, check hashes, view ban-list');

registryCmd
  .command('verify <worker-id>')
  .description('Show current attestation status for a worker')
  .action(async (workerId: string) => {
    await runRegistryVerify(workerId);
  });

registryCmd
  .command('check-hash <sha256>')
  .description('Check if a SHA-256 hash appears on the confirmed ban-list')
  .action(async (sha256: string) => {
    await runRegistryCheckHash(sha256);
  });

registryCmd
  .command('ban-list')
  .description('Show the confirmed ban-list')
  .option('--limit <n>', 'Maximum entries to show', '20')
  .action(async (opts: { limit?: string }) => {
    await runRegistryBanList(opts);
  });

registryCmd
  .command('status')
  .description('Check registry API health and version')
  .action(async () => {
    await runRegistryStatus();
  });

// ---------------------------------------------------------------------------
// skill
// ---------------------------------------------------------------------------
const skillCmd = program
  .command('skill')
  .description('Skill lifecycle — scaffold, build, certify, publish, install, verify');

skillCmd
  .command('init')
  .description('Scaffold a new SKILL.md in the current directory')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall skill init')}
`)
  .action(async () => {
    await runSkillInit();
  });

skillCmd
  .command('build')
  .description('Compile SKILL.md into platform adapter files (MCP, OpenAI, Gemini)')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall skill build')}
`)
  .action(async () => {
    await runSkillBuild();
  });

skillCmd
  .command('certify')
  .description('Submit manifest to pyhall registry for certification')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall skill certify')}
`)
  .action(async () => {
    await runSkillCertify();
  });

skillCmd
  .command('publish')
  .description('Publish certified skill to pyhall registry')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall skill publish')}
`)
  .action(async () => {
    await runSkillPublish();
  });

skillCmd
  .command('install <skill-id>')
  .description('Install a skill into the current AI environment (.pyhall/skills/)')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall skill install pyhall/python-sdk')}
  ${theme.primary('pyhall skill install org/skill-name')}
`)
  .action(async (skillId: string) => {
    await runSkillInstall(skillId);
  });

skillCmd
  .command('verify')
  .description('Check integrity of installed skills against registry')
  .addHelpText('after', `
${theme.dim('Examples:')}
  ${theme.primary('pyhall skill verify')}
`)
  .action(async () => {
    await runSkillVerify();
  });

// ---------------------------------------------------------------------------
// help (alias — commander provides --help; this adds `pyhall help`)
// ---------------------------------------------------------------------------
program
  .command('help')
  .description('Show command list and usage')
  .action(() => {
    program.outputHelp();
  });

program.parse(process.argv);
