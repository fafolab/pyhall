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
import { theme } from './theme.js';

const CLI_VERSION = '0.1.0';

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
// help (alias — commander provides --help; this adds `pyhall help`)
// ---------------------------------------------------------------------------
program
  .command('help')
  .description('Show command list and usage')
  .action(() => {
    program.outputHelp();
  });

program.parse(process.argv);
