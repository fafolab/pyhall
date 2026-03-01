/**
 * explain.test.ts — Tests for entity lookup and browse
 */

import { getEntityById, getNamespaces, browseEntities, catalog } from '../src/catalog';

describe('getEntityById', () => {
  test('returns entity for known ID', () => {
    const entity = getEntityById('cap.mount.workspace');
    expect(entity).toBeDefined();
    expect(entity!.id).toBe('cap.mount.workspace');
    expect(entity!.type).toBe('capability');
  });

  test('returns undefined for unknown ID', () => {
    const entity = getEntityById('zzz.does.not.exist');
    expect(entity).toBeUndefined();
  });

  test('returns undefined for empty string', () => {
    const entity = getEntityById('');
    expect(entity).toBeUndefined();
  });

  test('lookup is exact-match (no partial)', () => {
    // 'cap.mount' should not match 'cap.mount.workspace'
    const entity = getEntityById('cap.mount');
    expect(entity).toBeUndefined();
  });

  test('all catalog entity IDs round-trip through lookup', () => {
    for (const catalogEntity of catalog.entities) {
      const found = getEntityById(catalogEntity.id);
      expect(found).toBeDefined();
      expect(found!.id).toBe(catalogEntity.id);
    }
  });
});

describe('getNamespaces (browse)', () => {
  test('returns namespace list', () => {
    const namespaces = getNamespaces();
    expect(Array.isArray(namespaces)).toBe(true);
    expect(namespaces.length).toBeGreaterThan(0);
  });

  test('each namespace has two dot-separated segments', () => {
    const namespaces = getNamespaces();
    for (const ns of namespaces) {
      const parts = ns.split('.');
      expect(parts.length).toBe(2);
    }
  });

  test('namespace list is sorted', () => {
    const namespaces = getNamespaces();
    for (let i = 1; i < namespaces.length; i++) {
      expect(namespaces[i - 1]! <= namespaces[i]!).toBe(true);
    }
  });

  test('namespace IDs are unique', () => {
    const namespaces = getNamespaces();
    const unique = new Set(namespaces);
    expect(unique.size).toBe(namespaces.length);
  });
});

describe('browseEntities', () => {
  test('browse by namespace cap.doc returns cap.doc.* entities', () => {
    const entities = browseEntities({ namespace: 'cap.doc' });
    expect(entities.length).toBeGreaterThan(0);
    for (const e of entities) {
      expect(e.id.startsWith('cap.doc.')).toBe(true);
    }
  });

  test('browse by type worker_species returns only worker_species', () => {
    const workers = browseEntities({ type: 'worker_species' });
    expect(workers.length).toBeGreaterThan(0);
    for (const w of workers) {
      expect(w.type).toBe('worker_species');
    }
  });

  test('browse with namespace and type filters both', () => {
    const results = browseEntities({ namespace: 'cap', type: 'capability' });
    for (const e of results) {
      expect(e.id.startsWith('cap.')).toBe(true);
      expect(e.type).toBe('capability');
    }
  });

  test('browse with unknown namespace returns empty array', () => {
    const results = browseEntities({ namespace: 'zzz.does.not.exist' });
    expect(results).toEqual([]);
  });
});
