"""
cap.qc.web.validate — Validate pyhall.dev website against rebuilt catalog.

Checks:
- Required web files exist (index.html, blog post)
- No live .v1 capability IDs in JavaScript/JSON (structural code, not narrative prose)
- Brand color present in index.html
- Catalog entity count matches SDK

Note: index.html and blog HTML contain intentional narrative references to
cap.recall.fetch.v1 and cap.mem.retrieve.rag.v1 as examples of a real lab
incident. Those are inside <code> elements in prose, not live routing IDs.
The validator only flags .v1 patterns in .js and .json files, not HTML prose.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

# Matches versioned WCP capability IDs: cap.foo.bar.v1
V1_ENTITY_RE = re.compile(
    r'\b(?:cap|wrk|ctrl|pol|prof|evt)\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.v\d+\b'
)

BRAND_COLOR = "#0050D4"

# Required web files that must exist
REQUIRED_WEB_FILES = [
    "web/index.html",
    "web/blog/the-governance-gap.html",
]

# JS/JSON files to check for .v1 entity IDs (code, not prose)
CODE_FILES_TO_CHECK = [
    "web/playground/js/wcp-engine.js",
    "web/playground/js/playground.js",
    "web/playground/js/catalog.js",
    "web/playground/data/catalog.json",
]


def run(ctx, request):
    findings = []

    # Load SDK catalog for entity count check
    catalog_path = ROOT / "sdk/python/pyhall/taxonomy/catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text())
    except FileNotFoundError:
        findings.append({
            "severity": "error",
            "detail": "sdk/python/pyhall/taxonomy/catalog.json not found — run scripts/build_catalog.py first",
        })
        return {"passed": False, "sdk_entity_count": 0, "findings": findings}
    # Use set-based count (consistent with playground_validator — dedup-safe)
    expected_count = len({e["id"] for e in catalog.get("entities", [])})

    # 1. Required files exist
    for rel in REQUIRED_WEB_FILES:
        path = ROOT / rel
        if not path.exists():
            findings.append({
                "severity": "warning",
                "file": rel,
                "detail": "required web file not found",
            })

    # 2. .v1 check on JS/JSON code files only (not HTML prose)
    for rel in CODE_FILES_TO_CHECK:
        path = ROOT / rel
        if not path.exists():
            findings.append({
                "severity": "warning",
                "file": rel,
                "detail": "file not found",
            })
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for match in V1_ENTITY_RE.finditer(content):
            findings.append({
                "severity": "error",
                "file": rel,
                "detail": f".v1 capability ID in code file: {match.group()}",
            })

    # 3. Brand color check on index.html
    index_html = ROOT / "web/index.html"
    if index_html.exists():
        content = index_html.read_text(encoding="utf-8", errors="replace")
        if BRAND_COLOR not in content:
            findings.append({
                "severity": "warning",
                "file": "web/index.html",
                "detail": f"brand color {BRAND_COLOR} not found in index.html",
            })

    # 4. Playground catalog entity count matches SDK
    pg_catalog_path = ROOT / "web/playground/data/catalog.json"
    if pg_catalog_path.exists():
        pg_catalog = json.loads(pg_catalog_path.read_text())
        pg_count = len(pg_catalog.get("entities", []))
        if pg_count != expected_count:
            findings.append({
                "severity": "error",
                "file": "web/playground/data/catalog.json",
                "detail": (
                    f"entity count mismatch: playground has {pg_count}, "
                    f"SDK catalog has {expected_count}"
                ),
            })

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "sdk_entity_count": expected_count,
        "findings": findings,
    }
