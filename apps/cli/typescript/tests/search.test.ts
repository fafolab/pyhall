/**
 * search.test.ts — Tests for catalog search
 */

import { searchCatalog, scoreEntity, catalog } from '../src/catalog';

describe('scoreEntity', () => {
  const entity = {
    id: 'cap.mount.workspace',
    type: 'capability' as const,
    name: 'Mount Workspace',
    description: 'Mount a dedicated workspace directory into the execution environment.',
    risk_tier: 'medium',
    tags: ['sandbox', 'filesystem'],
    wcp_namespace: 'reserved',
  };

  test('exact ID match scores 100', () => {
    expect(scoreEntity(entity, 'cap.mount.workspace')).toBe(100);
  });

  test('ID prefix match scores 85', () => {
    expect(scoreEntity(entity, 'cap.mount')).toBe(85);
  });

  test('ID contains match scores 80', () => {
    expect(scoreEntity(entity, 'workspace')).toBe(80);
  });

  test('name contains match scores 70', () => {
    expect(scoreEntity(entity, 'Mount')).toBeGreaterThanOrEqual(70);
  });

  test('tag exact match scores 60', () => {
    expect(scoreEntity(entity, 'sandbox')).toBe(60);
  });

  test('description contains match scores 40', () => {
    expect(scoreEntity(entity, 'dedicated')).toBe(40);
  });

  test('no match scores 0', () => {
    expect(scoreEntity(entity, 'zzznomatch99xyz')).toBe(0);
  });

  test('empty query scores 0', () => {
    expect(scoreEntity(entity, '')).toBe(0);
  });
});

describe('searchCatalog', () => {
  test('returns ranked results for a valid query', () => {
    const results = searchCatalog('sandbox');
    expect(results.length).toBeGreaterThan(0);
    // Results should be sorted by score descending
    for (let i = 1; i < results.length; i++) {
      expect(results[i - 1]!.score).toBeGreaterThanOrEqual(results[i]!.score);
    }
  });

  test('returns empty array when no match', () => {
    const results = searchCatalog('zzz_no_match_at_all_xyz_999');
    expect(results).toEqual([]);
  });

  test('returns empty array for empty query', () => {
    const results = searchCatalog('');
    expect(results).toEqual([]);
  });

  test('respects limit parameter', () => {
    const results = searchCatalog('cap', 3);
    expect(results.length).toBeLessThanOrEqual(3);
  });

  test('returns entities with score > 0 only', () => {
    const results = searchCatalog('egress');
    for (const r of results) {
      expect(r.score).toBeGreaterThan(0);
    }
  });

  test('top result for exact ID match has score 100', () => {
    // pick a known entity
    const firstEntity = catalog.entities[0]!;
    const results = searchCatalog(firstEntity.id);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0]!.score).toBe(100);
    expect(results[0]!.entity.id).toBe(firstEntity.id);
  });

  test('search "doc" returns document-related entities', () => {
    const results = searchCatalog('doc');
    expect(results.length).toBeGreaterThan(0);
    const ids = results.map((r) => r.entity.id);
    // At least one doc-related entity should appear
    const hasDoc = ids.some((id) => id.includes('doc'));
    expect(hasDoc).toBe(true);
  });
});
