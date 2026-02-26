"""
cap.qc.playground.validate — Validate web playground against rebuilt catalog.

Checks:
- Playground catalog.json is in sync with SDK catalog (entity IDs match exactly)
- No .v1 version suffixes in playground catalog or engine
- Shorthand alias map keys in wcp-engine.js are noted (not errors — they are
  intentional UI shorthands documented in the engine source)
- Playground index.html exists
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

V1_ENTITY_RE = re.compile(
    r'\b(?:cap|wrk|ctrl|pol|prof|evt)\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.v\d+\b'
)


def run(ctx, request):
    findings = []

    # Load SDK catalog (source of truth)
    catalog_path = ROOT / "sdk/python/pyhall/taxonomy/catalog.json"
    try:
        sdk_catalog = json.loads(catalog_path.read_text())
    except FileNotFoundError:
        findings.append({
            "severity": "error",
            "detail": "sdk/python/pyhall/taxonomy/catalog.json not found — run scripts/build_catalog.py first",
        })
        return {"passed": False, "sdk_entity_count": 0, "findings": findings}
    valid_ids = {e["id"] for e in sdk_catalog.get("entities", [])}

    # 1. Playground catalog.json sync check
    pg_catalog_path = ROOT / "web/playground/data/catalog.json"
    if not pg_catalog_path.exists():
        findings.append({
            "severity": "error",
            "detail": "web/playground/data/catalog.json not found",
        })
    else:
        pg_catalog = json.loads(pg_catalog_path.read_text())
        pg_ids = {e["id"] for e in pg_catalog.get("entities", [])}

        missing = valid_ids - pg_ids
        for eid in sorted(missing):
            findings.append({
                "severity": "error",
                "file": "web/playground/data/catalog.json",
                "detail": f"entity missing from playground catalog: {eid}",
            })

        extra = pg_ids - valid_ids
        for eid in sorted(extra):
            findings.append({
                "severity": "error",
                "file": "web/playground/data/catalog.json",
                "detail": f"stale entity in playground catalog: {eid}",
            })

        # .v1 check in playground catalog entity IDs
        for entity in pg_catalog.get("entities", []):
            eid = entity.get("id", "")
            if V1_ENTITY_RE.search(eid):
                findings.append({
                    "severity": "error",
                    "file": "web/playground/data/catalog.json",
                    "detail": f".v1 entity ID in playground catalog: {eid}",
                })

    # 2. wcp-engine.js checks
    engine_path = ROOT / "web/playground/js/wcp-engine.js"
    if not engine_path.exists():
        findings.append({
            "severity": "warning",
            "detail": "web/playground/js/wcp-engine.js not found",
        })
    else:
        engine = engine_path.read_text(encoding="utf-8", errors="replace")

        # .v1 in engine source is an error
        for match in V1_ENTITY_RE.finditer(engine):
            findings.append({
                "severity": "error",
                "file": "web/playground/js/wcp-engine.js",
                "detail": f".v1 entity ID in engine: {match.group()}",
            })

        # Detect shorthand alias keys — these are intentional UI shorthands
        # (e.g., cap.doc.summarize -> cap.doc.ingest) documented in the engine.
        # Log them as info-level notices, not errors or warnings.
        shorthand_re = re.compile(
            r"'(cap\.[a-z0-9\-.]+)'\s*:\s*'(cap\.[a-z0-9\-.]+)'"
        )
        aliases = shorthand_re.findall(engine)
        # aliases that point to valid catalog IDs are fine; target must exist
        for short_key, canonical in aliases:
            if canonical not in valid_ids:
                findings.append({
                    "severity": "warning",
                    "file": "web/playground/js/wcp-engine.js",
                    "detail": (
                        f"shorthand alias '{short_key}' maps to "
                        f"'{canonical}' which is not in the catalog"
                    ),
                })

    # 3. Playground index.html exists
    pg_index = ROOT / "web/playground/index.html"
    if not pg_index.exists():
        findings.append({
            "severity": "warning",
            "detail": "web/playground/index.html not found",
        })

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "sdk_entity_count": len(valid_ids),
        "findings": findings,
    }
