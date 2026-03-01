/**
 * commands/browse.ts — `pyhall browse [--namespace <prefix>] [--type cap|wrk|ctrl]`
 *
 * Browse the taxonomy catalog. Default: list all namespaces.
 * With --namespace: list entities under a namespace prefix.
 * With --type: filter to a specific entity type.
 */

import { getNamespaces, browseEntities, catalog, EntityType } from '../catalog.js';
import { theme, BANNER } from '../theme.js';

const TYPE_ALIASES: Record<string, EntityType> = {
  cap:  'capability',
  wrk:  'worker_species',
  ctrl: 'control',
  pol:  'policy',
  prof: 'profile',
};

function expandType(t: string): EntityType | undefined {
  if (TYPE_ALIASES[t]) return TYPE_ALIASES[t];
  // Also accept full names
  const full: EntityType[] = ['capability', 'worker_species', 'control', 'policy', 'profile'];
  return full.find((f) => f === t);
}

function typeTag(type: string): string {
  switch (type) {
    case 'capability':     return theme.primary('[cap]');
    case 'worker_species': return theme.subheading('[wrk]');
    case 'control':        return theme.warning('[ctrl]');
    case 'policy':         return theme.error('[pol]');
    case 'profile':        return theme.success('[prof]');
    default:               return theme.dim(`[${type}]`);
  }
}

function riskDot(risk?: string): string {
  switch (risk) {
    case 'low':      return theme.success('●');
    case 'medium':   return theme.warning('●');
    case 'high':     return theme.error('●');
    case 'critical': return theme.error.bold('◆');
    default:         return theme.dim('○');
  }
}

export function runBrowse(options: { namespace?: string; type?: string }): void {
  const namespaces = getNamespaces();

  // Resolve type filter
  let typeFilter: EntityType | undefined;
  if (options.type) {
    typeFilter = expandType(options.type);
    if (!typeFilter) {
      console.error(theme.error(`  Unknown type: "${options.type}"`));
      console.error(theme.dim('  Valid: cap, wrk, ctrl, pol, prof'));
      process.exit(1);
    }
  }

  console.log(BANNER);

  if (!options.namespace && !typeFilter) {
    // Default view: list all namespaces
    console.log(theme.primary.bold('  BROWSE') + theme.dim('  All namespaces'));
    console.log(theme.dim('  ' + '─'.repeat(72)));
    console.log('');
    console.log(
      theme.dim('  Run ') +
      theme.primary('pyhall browse --namespace <prefix>') +
      theme.dim(' to see entities in a namespace (e.g. cap.doc, cap.mem, wrk.doc).')
    );
    console.log('');

    for (const ns of namespaces) {
      const count = browseEntities({ namespace: ns }).length;
      const countStr = count > 0 ? theme.dim(`(${count} entities)`) : theme.dim('(empty)');
      console.log(`  ${theme.primary.bold(ns.padEnd(16))}  ${countStr}`);
    }
    console.log('');
    console.log(theme.dim(`  Total: ${catalog._meta.total_entities} entities across ${namespaces.length} namespaces`));
    console.log('');

  } else {
    // Filtered entity view
    const nsLabel = options.namespace ? `namespace=${options.namespace}` : '';
    const typeLabel = typeFilter ? `type=${typeFilter}` : '';
    const filterLabel = [nsLabel, typeLabel].filter(Boolean).join('  ');

    console.log(theme.primary.bold('  BROWSE') + theme.dim(`  ${filterLabel}`));
    console.log(theme.dim('  ' + '─'.repeat(72)));
    console.log('');

    const entities = browseEntities({ namespace: options.namespace, type: typeFilter });

    if (entities.length === 0) {
      console.log(theme.dim('  No entities match the filter.'));
      if (options.namespace) {
        console.log('');
        console.log(theme.dim('  Known namespaces:'));
        for (const ns of namespaces.slice(0, 10)) {
          console.log(`    ${theme.primary(ns)}`);
        }
      }
      console.log('');
      return;
    }

    if (options.namespace) {
      console.log(`  ${theme.subheading(options.namespace)}`);
      console.log('');
    }

    for (const entity of entities) {
      const risk = riskDot(entity.risk_tier);
      console.log(
        `  ${typeTag(entity.type)}  ${risk} ${theme.primary(entity.id)}`
      );
      if (entity.name) {
        console.log(`         ${entity.name}`);
      }
      console.log('');
    }

    console.log(theme.dim(`  ${entities.length} entities shown.`));
    console.log(theme.dim(`  Run pyhall explain <id> for full details.`));
    console.log('');
  }
}
