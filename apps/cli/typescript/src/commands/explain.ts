/**
 * commands/explain.ts — `pyhall explain <entity-id>`
 *
 * Detailed information about a single taxonomy entity.
 */

import { getEntityById, Entity } from '../catalog.js';
import { theme, BANNER } from '../theme.js';

function riskLabel(risk?: string): string {
  if (!risk) return theme.dim('—');
  switch (risk) {
    case 'low':      return theme.success('low');
    case 'medium':   return theme.warning('medium');
    case 'high':     return theme.error('high');
    case 'critical': return theme.error.bold('critical');
    default:         return theme.dim(risk);
  }
}

function typeLabel(type: string): string {
  switch (type) {
    case 'capability':     return theme.primary('capability');
    case 'worker_species': return theme.subheading('worker_species');
    case 'control':        return theme.warning('control');
    case 'policy':         return theme.error('policy');
    case 'profile':        return theme.success('profile');
    default:               return theme.dim(type);
  }
}

function row(label: string, value: string): void {
  const padded = (label + ':').padEnd(22);
  console.log(`  ${theme.dim(padded)} ${value}`);
}

function listSection(label: string, items: string[]): void {
  if (!items || items.length === 0) return;
  console.log(`  ${theme.dim(label + ':')}`);
  for (const item of items) {
    console.log(`    ${theme.primary('•')} ${item}`);
  }
}

function nsPrefix(id: string): string {
  const parts = id.split('.');
  return parts.length >= 2 ? `${parts[0]}.${parts[1]}` : (parts[0] ?? id);
}

export function runExplain(entityId: string): void {
  const entity = getEntityById(entityId);

  if (!entity) {
    console.error('');
    console.error(theme.error(`  Entity not found: "${entityId}"`));
    console.error('');
    console.error(theme.dim('  Use `pyhall search <query>` to find valid entity IDs.'));
    console.error('');
    process.exit(1);
  }

  console.log(BANNER);
  console.log(theme.primary.bold('  EXPLAIN') + theme.dim(`  ${entityId}`));
  console.log(theme.dim('  ' + '─'.repeat(72)));
  console.log('');

  row('ID', theme.primary.bold(entity.id));
  row('Type', typeLabel(entity.type));
  if (entity.name) {
    row('Name', theme.bold(entity.name));
  }

  row('Namespace', theme.dim(nsPrefix(entity.id)));

  if (entity.wcp_namespace) {
    row('WCP namespace', entity.wcp_namespace === 'reserved'
      ? theme.warning('reserved')
      : theme.dim(entity.wcp_namespace));
  }

  console.log('');

  if (entity.description) {
    console.log(`  ${theme.subheading('Description')}`);
    console.log(`    ${entity.description}`);
    console.log('');
  }

  // Type-specific fields
  if (entity.type === 'capability' || entity.type === 'worker_species') {
    console.log(`  ${theme.subheading('Governance')}`);
    row('Risk tier', riskLabel(entity.risk_tier));
    if (entity.determinism) {
      row('Determinism', theme.dim(entity.determinism));
    }
    if (entity.idempotency) {
      row('Idempotency', theme.dim(entity.idempotency));
    }
    if (entity.enforcement_point) {
      row('Enforcement point', theme.dim(entity.enforcement_point));
    }
    if (entity.blast_radius_hint !== null && entity.blast_radius_hint !== undefined) {
      row('Blast radius', String(entity.blast_radius_hint));
    }
    console.log('');
  }

  if (entity.required_controls && entity.required_controls.length > 0) {
    listSection('Required controls', entity.required_controls);
    console.log('');
  }

  if (entity.controls_required && entity.controls_required.length > 0) {
    listSection('Controls required', entity.controls_required);
    console.log('');
  }

  if (entity.serves_capabilities && entity.serves_capabilities.length > 0) {
    listSection('Serves capabilities', entity.serves_capabilities);
    console.log('');
  }

  if (entity.tags && entity.tags.length > 0) {
    console.log(`  ${theme.dim('Tags:')} ${entity.tags.map((t) => theme.dim(t)).join(theme.dim(', '))}`);
    console.log('');
  }

  console.log(theme.dim(`  Spec: https://pyhall.dev/taxonomy/${entity.id}`));
  console.log('');
}
