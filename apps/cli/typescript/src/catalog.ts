/**
 * catalog.ts — Catalog loading and search utilities
 *
 * Loads the bundled WCP taxonomy catalog and provides fuzzy search,
 * entity lookup, namespace listing, and filter helpers.
 *
 * WCP organizes capabilities by domain namespace (cap.doc.*, cap.mem.*, etc.)
 * not by numbered packs. The domain IS the organizing principle.
 */

import rawCatalog from './taxonomy/catalog.json';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CatalogMeta {
  version: string;
  wcp_spec: string;
  total_entities: number;
  built: string;
}

export type EntityType = 'capability' | 'control' | 'profile' | 'worker_species' | 'policy';

export interface Entity {
  id: string;
  type: EntityType;
  name?: string;
  description?: string;
  risk_tier?: string;
  wcp_namespace?: string;
  blast_radius_hint?: string | number | null;
  typical_controls?: string[];
  required_controls?: string[];
  controls_required?: string[];
  serves_capabilities?: string[];
  recommended_for_risk_tiers?: string[];
  required_for_risk_tiers?: string[];
  enforcement_point?: string;
  idempotency?: string;
  determinism?: string;
  tags?: string[];
}

export interface Catalog {
  _meta: CatalogMeta;
  entities: Entity[];
}

// ---------------------------------------------------------------------------
// Catalog instance
// ---------------------------------------------------------------------------

export const catalog: Catalog = rawCatalog as Catalog;

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

export interface SearchResult {
  entity: Entity;
  score: number;
}

/**
 * Score a single entity against a query string.
 * Returns 0 if no match.
 */
export function scoreEntity(entity: Entity, query: string): number {
  const q = query.toLowerCase().trim();
  if (!q) return 0;

  const id = entity.id.toLowerCase();
  const name = (entity.name ?? '').toLowerCase();
  const desc = (entity.description ?? '').toLowerCase();
  const tags = (entity.tags ?? []).map((t) => t.toLowerCase());

  // Exact match on ID
  if (id === q) return 100;
  // ID prefix or contains
  if (id.startsWith(q)) return 85;
  if (id.includes(q)) return 80;
  // Name match
  if (name === q) return 75;
  if (name.startsWith(q)) return 72;
  if (name.includes(q)) return 70;
  // Tag exact match
  if (tags.includes(q)) return 60;
  // Tag partial
  if (tags.some((t) => t.includes(q))) return 50;
  // Description
  if (desc.includes(q)) return 40;

  return 0;
}

/**
 * Search the catalog for entities matching query.
 * Returns results sorted by score descending, filtered to score > 0.
 */
export function searchCatalog(query: string, limit = 20): SearchResult[] {
  if (!query.trim()) return [];

  const results: SearchResult[] = [];
  for (const entity of catalog.entities) {
    const score = scoreEntity(entity, query);
    if (score > 0) {
      results.push({ entity, score });
    }
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, limit);
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/**
 * Look up a single entity by its exact ID.
 * Returns undefined if not found.
 */
export function getEntityById(id: string): Entity | undefined {
  return catalog.entities.find((e) => e.id === id);
}

// ---------------------------------------------------------------------------
// Browse / Filter
// ---------------------------------------------------------------------------

/**
 * Get all unique top-level domain namespaces (e.g. "cap.doc", "cap.mem", "wrk.doc").
 * Derived from entity IDs: first two dot-separated segments.
 */
export function getNamespaces(): string[] {
  const ns = new Set<string>();
  for (const e of catalog.entities) {
    const parts = e.id.split('.');
    if (parts.length >= 2) {
      ns.add(`${parts[0]}.${parts[1]}`);
    }
  }
  return Array.from(ns).sort();
}

/**
 * Get entities, optionally filtered by namespace prefix and/or type.
 * namespace: prefix like "cap.doc" matches all entities whose ID starts with "cap.doc."
 */
export function browseEntities(opts: {
  namespace?: string;
  type?: EntityType;
}): Entity[] {
  let entities = catalog.entities;
  if (opts.namespace) {
    const prefix = opts.namespace.endsWith('.') ? opts.namespace : opts.namespace + '.';
    entities = entities.filter((e) => e.id.startsWith(prefix) || e.id === opts.namespace);
  }
  if (opts.type) {
    entities = entities.filter((e) => e.type === opts.type);
  }
  return entities;
}

/**
 * Get all unique types present in the catalog.
 */
export function getEntityTypes(): EntityType[] {
  const types = new Set<EntityType>();
  for (const e of catalog.entities) {
    types.add(e.type);
  }
  return Array.from(types).sort();
}
