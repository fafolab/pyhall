#!/usr/bin/env python3
"""
build_catalog.py — Generate catalog.json from taxonomy source files.

Validates all entity IDs against WCP spec §3.2/§3.4 before writing.
Fails with exit code 1 if any entity violates spec rules.

Usage: python scripts/build_catalog.py
Output: sdk/python/pyhall/taxonomy/catalog.json (and 3 other sync locations)
"""
import datetime
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

# WCP spec §3.2: 2-4 dot-separated segments, lowercase a-z/digits/hyphens only (no underscores).
# §3.4: No version numbers in IDs (no .v1, .v2, etc.).
VALID_ID_RE = re.compile(r'^[a-z][a-z0-9\-]*(\.[a-z][a-z0-9\-]*){1,3}$')
VERSION_SUFFIX_RE = re.compile(r'\.[vV]\d+')

# Required fields per entity type (spec §3.2/§4.x)
# NOTE: pack_id is NOT a required field — WCP §3.0 explicitly forbids pack numbers.
REQUIRED_BY_TYPE: dict[str, set[str]] = {
    "capability": {
        "id", "type", "name", "description", "risk_tier",
        "blast_radius_hint", "typical_controls", "idempotency", "determinism",
        "tags", "wcp_namespace",
    },
    "worker_species": {
        "id", "type", "name", "description", "risk_tier",
        "serves_capabilities", "blast_radius_hint", "required_controls",
        "idempotency", "determinism", "tags", "wcp_namespace",
    },
    "worker": {
        "id", "type", "name", "description", "risk_tier",
        "serves_capabilities", "blast_radius_hint", "required_controls",
        "idempotency", "determinism", "tags", "wcp_namespace",
    },
    "control": {
        "id", "type", "name", "description",
        "enforcement_point", "required_for_risk_tiers", "tags", "wcp_namespace",
    },
    "profile": {
        "id", "type", "name", "description",
        "controls_required", "recommended_for_risk_tiers", "tags", "wcp_namespace",
    },
    "event": {
        "id", "type", "name", "description", "mandatory", "tags", "wcp_namespace",
    },
    "policy": {
        "id", "type", "name", "description", "controls_required", "tags", "wcp_namespace",
    },
}


def validate_id(entity_id: str) -> list[str]:
    errors = []
    if len(entity_id) > 64:
        errors.append(f"  ID '{entity_id}' exceeds 64-character max (spec §3.2): {len(entity_id)} chars")
    if not VALID_ID_RE.match(entity_id):
        errors.append(f"  ID '{entity_id}' fails format check (spec §3.2): must be 2-4 dot-separated lowercase segments (a-z, 0-9, hyphens only — no underscores)")
    if VERSION_SUFFIX_RE.search(entity_id):
        errors.append(f"  ID '{entity_id}' contains version suffix (spec §3.4): remove .v1, .v2, etc.")
    return errors


def validate_required_fields(entity: dict) -> list[str]:
    """Validate that entity has all required fields for its type."""
    errors = []
    t = entity.get("type", "?")
    required = REQUIRED_BY_TYPE.get(t)
    if required:
        for field in sorted(required):
            if field not in entity:
                errors.append(f"  {entity.get('id', '?')} (type={t}) missing required field: {field}")
    return errors


def load_sources() -> list[dict]:
    """Load all entity definitions from taxonomy/src/."""
    src_dir = ROOT / "taxonomy/src"
    entities = []
    for src_file in sorted(src_dir.glob("pack_*.py")):
        namespace = {}
        try:
            exec(src_file.read_text(), namespace)
        except SyntaxError as exc:
            print(f"SYNTAX ERROR in {src_file.name}: {exc}", file=sys.stderr)
            sys.exit(1)
        entities.extend(namespace.get("ENTITIES", []))
    return entities


def main():
    entities = load_sources()
    errors = []
    for entity in entities:
        errors.extend(validate_id(entity["id"]))

    # Per-type required field validation
    for entity in entities:
        errors.extend(validate_required_fields(entity))

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
            "built": datetime.date.today().isoformat(),
        },
        "entities": entities,
    }

    for dest in CATALOG_PATHS:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(catalog, indent=2) + "\n")
        print(f"  wrote {dest.relative_to(ROOT)}")

    print(f"\nCatalog built: {len(entities)} entities.")


if __name__ == "__main__":
    main()
