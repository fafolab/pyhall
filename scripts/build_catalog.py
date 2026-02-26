#!/usr/bin/env python3
"""
build_catalog.py — Generate catalog.json from taxonomy source files.

Validates all entity IDs against WCP spec §3.2/§3.4 before writing.
Fails with exit code 1 if any entity violates spec rules.

Usage: python scripts/build_catalog.py
Output: sdk/python/pyhall/taxonomy/catalog.json (and 3 other sync locations)
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CATALOG_PATHS = [
    ROOT / "sdk/python/pyhall/taxonomy/catalog.json",
    ROOT / "sdk/typescript/src/taxonomy/catalog.json",
    ROOT / "sdk/go/wcp/taxonomy/catalog.json",
    ROOT / "web/playground/data/catalog.json",
]

# WCP spec §3.2: 2-4 dot-separated segments, lowercase a-z/digits/hyphens/underscores only.
# §3.4: No version numbers in IDs (no .v1, .v2, etc.).
VALID_ID_RE = re.compile(r'^[a-z][a-z0-9\-_]*(\.[a-z][a-z0-9\-_]*){1,3}$')
VERSION_SUFFIX_RE = re.compile(r'\.[vV]\d+')


def validate_id(entity_id: str) -> list[str]:
    errors = []
    if not VALID_ID_RE.match(entity_id):
        errors.append(f"  ID '{entity_id}' fails format check (spec §3.2): must be 2-4 dot-separated lowercase segments (a-z, 0-9, hyphens, underscores)")
    if VERSION_SUFFIX_RE.search(entity_id):
        errors.append(f"  ID '{entity_id}' contains version suffix (spec §3.4): remove .v1, .v2, etc.")
    return errors


def load_sources() -> tuple[list[dict], list[dict]]:
    """Load all pack and entity definitions from taxonomy/src/."""
    src_dir = ROOT / "taxonomy/src"
    packs = []
    entities = []
    for src_file in sorted(src_dir.glob("pack_*.py")):
        namespace = {}
        exec(src_file.read_text(), namespace)
        packs.extend(namespace.get("PACKS", []))
        entities.extend(namespace.get("ENTITIES", []))
    return packs, entities


def main():
    packs, entities = load_sources()
    errors = []
    for entity in entities:
        errors.extend(validate_id(entity["id"]))

    if errors:
        print(f"CATALOG BUILD FAILED — {len(errors)} spec violations:\n")
        for e in errors:
            print(e)
        sys.exit(1)

    catalog = {
        "_meta": {
            "version": "0.1.0",
            "wcp_spec": "0.1-DRAFT",
            "total_entities": len(entities),
            "packs": len(packs),
            "generated_from": "taxonomy/src/pack_*.py",
            "built": __import__("datetime").date.today().isoformat(),
        },
        "packs": packs,
        "entities": entities,
    }

    for dest in CATALOG_PATHS:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(catalog, indent=2) + "\n")
        print(f"  wrote {dest.relative_to(ROOT)}")

    print(f"\nCatalog built: {len(entities)} entities across {len(packs)} packs.")


if __name__ == "__main__":
    main()
