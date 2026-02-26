#!/usr/bin/env python3
"""migrate_catalog.py — Fix spec compliance issues in taxonomy/src pack files.

Applies:
1. Replace underscores with hyphens in all entity IDs (spec §3.2)
2. Fix pol.pol.* doubled namespace -> pol.*
3. Add wcp_namespace: "reserved" to entities missing it (control/profile/policy/worker_species)
4. Fix "type": "worker" -> "type": "worker_species" for enriched worker entities
5. Fix cross-references in typical_controls, required_controls, controls_required, serves_capabilities
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent


def fix_id(s: str) -> str:
    """Replace underscores with hyphens. Fix pol.pol.* double-namespace."""
    fixed = s.replace('_', '-')
    if fixed.startswith('pol.pol.'):
        fixed = 'pol.' + fixed[8:]
    return fixed


def fix_ref_list(lst: list) -> list:
    return [fix_id(x) if isinstance(x, str) else x for x in lst]


def fix_entity(e: dict) -> dict:
    out = {}
    for k, v in e.items():
        if k == 'id':
            out[k] = fix_id(v)
        elif k in ('typical_controls', 'required_controls', 'controls_required', 'serves_capabilities'):
            out[k] = fix_ref_list(v)
        elif k == 'type' and v == 'worker' and (
            'serves_capabilities' in e or 'blast_radius_hint' in e or 'required_controls' in e
        ):
            out[k] = 'worker_species'
        else:
            out[k] = v
    # Add wcp_namespace if missing (for control, profile, policy, worker_species/worker)
    entity_type = out.get('type', e.get('type', ''))
    if 'wcp_namespace' not in out and entity_type in ('control', 'profile', 'policy', 'worker_species', 'worker'):
        out['wcp_namespace'] = 'reserved'
    return out


def repr_value(v, indent=0):
    """Generate repr-style Python source for a value."""
    pad = '    ' * indent
    inner_pad = '    ' * (indent + 1)

    if isinstance(v, dict):
        if not v:
            return '{}'
        items = []
        for dk, dv in v.items():
            items.append(f'{inner_pad}{repr(dk)}: {repr_value(dv, indent + 1)}')
        return '{\n' + ',\n'.join(items) + ',\n' + pad + '}'
    elif isinstance(v, list):
        if not v:
            return '[]'
        # Short lists of strings on one line
        if all(isinstance(x, str) for x in v) and len(v) <= 6:
            return '[' + ', '.join(repr(x) for x in v) + ']'
        items = []
        for item in v:
            items.append(f'{inner_pad}{repr_value(item, indent + 1)}')
        return '[\n' + ',\n'.join(items) + ',\n' + pad + ']'
    elif v is None:
        return 'None'
    elif isinstance(v, bool):
        return 'True' if v else 'False'
    else:
        return repr(v)


def entity_to_source(e: dict, indent=1) -> str:
    """Convert entity dict to Python source dict literal."""
    pad = '    ' * indent
    inner_pad = '    ' * (indent + 1)
    items = []
    for k, v in e.items():
        items.append(f'{inner_pad}{repr(k)}: {repr_value(v, indent + 1)}')
    return pad + '{\n' + ',\n'.join(items) + ',\n' + pad + '}'


def write_pack_file(pack_file: Path, packs: list, entities: list) -> None:
    """Write pack file back as valid Python source."""
    lines = []

    # Docstring from original if available, else generic
    lines.append(f'"""Pack source — {pack_file.stem}"""\n')
    lines.append('\n')

    # PACKS
    lines.append('PACKS = [\n')
    for p in packs:
        lines.append(entity_to_source(p, indent=1))
        lines.append(',\n')
    lines.append(']\n')
    lines.append('\n')

    # ENTITIES
    lines.append('ENTITIES = [\n')
    for e in entities:
        lines.append(entity_to_source(e, indent=1))
        lines.append(',\n')
    lines.append(']\n')

    pack_file.write_text(''.join(lines))


def main():
    src_dir = ROOT / 'taxonomy/src'
    pack_files = sorted(src_dir.glob('pack_*.py'))

    total_entities = 0
    total_id_fixes = 0
    total_ns_fixes = 0
    total_type_fixes = 0

    for pack_file in pack_files:
        ns = {}
        exec(pack_file.read_text(), ns)
        packs = ns.get('PACKS', [])
        raw_entities = ns.get('ENTITIES', [])

        fixed_entities = []
        id_fixes = 0
        ns_fixes = 0
        type_fixes = 0

        for e in raw_entities:
            fixed = fix_entity(e)
            if fixed.get('id') != e.get('id'):
                id_fixes += 1
            if 'wcp_namespace' not in e and 'wcp_namespace' in fixed:
                ns_fixes += 1
            if fixed.get('type') != e.get('type'):
                type_fixes += 1
            fixed_entities.append(fixed)

        write_pack_file(pack_file, packs, fixed_entities)

        total_entities += len(fixed_entities)
        total_id_fixes += id_fixes
        total_ns_fixes += ns_fixes
        total_type_fixes += type_fixes

        if id_fixes or ns_fixes or type_fixes:
            print(f'  {pack_file.name}: {id_fixes} ID fixes, {ns_fixes} wcp_namespace additions, {type_fixes} type fixes')
        else:
            print(f'  {pack_file.name}: no changes needed')

    print(f'\nMigration complete: {total_entities} entities processed.')
    print(f'  {total_id_fixes} ID fixes (underscores -> hyphens)')
    print(f'  {total_ns_fixes} wcp_namespace additions')
    print(f'  {total_type_fixes} type fixes (worker -> worker_species)')


if __name__ == '__main__':
    main()
