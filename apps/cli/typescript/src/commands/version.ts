/**
 * commands/version.ts — `pyhall version`
 *
 * Show pyhall CLI version, @pyhall/core version, and WCP spec version.
 */

import { theme } from '../theme.js';
import { catalog } from '../catalog.js';

// Package version injected at build time (from package.json)
// We read it directly to avoid circular imports.
const CLI_VERSION = '0.1.0';
// @pyhall/core version — kept in sync
const CORE_VERSION = '0.1.0';

export function runVersion(): void {
  const wcpSpec = catalog._meta.wcp_spec;
  const catalogBuilt = catalog._meta.built;
  const totalEntities = catalog._meta.total_entities;
  const totalPacks = catalog._meta.packs;

  console.log('');
  console.log(theme.primary.bold('pyhall') + theme.dim(' — Worker Class Protocol CLI'));
  console.log('');
  console.log(`  ${theme.subheading('CLI version')}     ${CLI_VERSION}`);
  console.log(`  ${theme.subheading('@pyhall/core')}    ${CORE_VERSION}`);
  console.log(`  ${theme.subheading('WCP spec')}        ${wcpSpec}`);
  console.log('');
  console.log(`  ${theme.dim('Catalog:')}         ${totalEntities} entities across ${totalPacks} packs`);
  console.log(`  ${theme.dim('Catalog built:')}   ${catalogBuilt}`);
  console.log(`  ${theme.dim('Homepage:')}        https://pyhall.dev`);
  console.log(`  ${theme.dim('Spec:')}            https://pyhall.dev/spec`);
  console.log('');
}
