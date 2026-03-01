/**
 * catalog.test.ts — Tests for catalog loading
 */

import { catalog, getNamespaces, getEntityTypes, browseEntities } from '../src/catalog';

describe('catalog', () => {
  test('loads without errors', () => {
    expect(catalog).toBeDefined();
    expect(catalog._meta).toBeDefined();
    expect(catalog.entities).toBeDefined();
  });

  test('has expected metadata', () => {
    expect(catalog._meta.wcp_spec).toBe('0.1');
    expect(catalog._meta.total_entities).toBeGreaterThan(0);
    expect(typeof catalog._meta.version).toBe('string');
  });

  test('entities array is non-empty', () => {
    expect(catalog.entities.length).toBeGreaterThan(0);
  });

  test('all entities have required fields', () => {
    for (const entity of catalog.entities) {
      expect(entity.id).toBeDefined();
      expect(typeof entity.id).toBe('string');
      expect(entity.type).toBeDefined();
    }
  });

  test('getNamespaces returns non-empty list', () => {
    const namespaces = getNamespaces();
    expect(namespaces.length).toBeGreaterThan(0);
    expect(typeof namespaces[0]).toBe('string');
  });

  test('getEntityTypes returns known types', () => {
    const types = getEntityTypes();
    expect(types).toContain('capability');
    expect(types).toContain('control');
    expect(types).toContain('worker_species');
  });

  test('browseEntities returns all entities when no filter', () => {
    const all = browseEntities({});
    expect(all.length).toBe(catalog.entities.length);
  });

  test('browseEntities filters by type correctly', () => {
    const caps = browseEntities({ type: 'capability' });
    expect(caps.length).toBeGreaterThan(0);
    for (const e of caps) {
      expect(e.type).toBe('capability');
    }
  });

  test('browseEntities filters by namespace correctly', () => {
    const capDocEntities = browseEntities({ namespace: 'cap.doc' });
    expect(capDocEntities.length).toBeGreaterThan(0);
    for (const e of capDocEntities) {
      expect(e.id.startsWith('cap.doc.')).toBe(true);
    }
  });
});
