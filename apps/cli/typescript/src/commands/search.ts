/**
 * commands/search.ts — `pyhall search <query>`
 *
 * Fuzzy search across the taxonomy catalog.
 * Displays ranked results with type, pack, score, and description.
 */

import { searchCatalog } from '../catalog.js';
import { theme, BANNER } from '../theme.js';

/** Map entity type to a short colored label */
function typeLabel(type: string): string {
  switch (type) {
    case 'capability':     return theme.primary('[cap]');
    case 'worker_species': return theme.subheading('[wrk]');
    case 'control':        return theme.warning('[ctrl]');
    case 'policy':         return theme.error('[pol]');
    case 'profile':        return theme.success('[prof]');
    default:               return theme.dim(`[${type}]`);
  }
}

/** Map risk tier to colored text */
function riskLabel(risk?: string): string {
  if (!risk) return '';
  switch (risk) {
    case 'low':      return theme.success('low');
    case 'medium':   return theme.warning('medium');
    case 'high':     return theme.error('high');
    case 'critical': return theme.error.bold('critical');
    default:         return theme.dim(risk);
  }
}

function truncate(s: string | undefined, max: number): string {
  if (!s) return '';
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

export function runSearch(query: string, options: { limit?: string } = {}): void {
  const limit = options.limit ? parseInt(options.limit, 10) : 20;

  console.log(BANNER);
  console.log(theme.primary.bold('  SEARCH') + theme.dim(`  query="${query}"  limit=${limit}`));
  console.log(theme.dim('  ' + '─'.repeat(72)));
  console.log('');

  const results = searchCatalog(query, limit);

  if (results.length === 0) {
    console.log(theme.dim(`  No results for "${query}"`));
    console.log('');
    console.log(theme.dim('  Tips:'));
    console.log(theme.dim('    pyhall search sandbox'));
    console.log(theme.dim('    pyhall search doc'));
    console.log(theme.dim('    pyhall search egress'));
    console.log('');
    return;
  }

  console.log(theme.dim(`  Found ${results.length} result${results.length === 1 ? '' : 's'}`));
  console.log('');

  for (const { entity, score } of results) {
    const risk = entity.risk_tier ? `  risk=${riskLabel(entity.risk_tier)}` : '';

    console.log(
      `  ${typeLabel(entity.type)}  ${theme.primary.bold(entity.id)}${risk}  ${theme.dim('score=' + score)}`
    );
    if (entity.name) {
      console.log(`         ${theme.bold(entity.name)}`);
    }
    if (entity.description) {
      console.log(`         ${theme.dim(truncate(entity.description, 90))}`);
    }
    if (entity.wcp_namespace) {
      console.log(theme.dim(`         ns: ${entity.wcp_namespace}`));
    }
    if (entity.tags && entity.tags.length > 0) {
      console.log(theme.dim(`         tags: ${entity.tags.join(', ')}`));
    }
    console.log('');
  }

  console.log(theme.dim(`  Run ${theme.primary('pyhall explain <id>')} for full details.`));
  console.log('');
}
