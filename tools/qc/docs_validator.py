"""
cap.qc.docs.validate — Validate research docs and WCP_SPEC against catalog.

Checks:
- Published docs exist
- No .v1 version suffixes on WCP entity IDs (cap/wrk/ctrl/pol/prof/evt) in docs
- Entity IDs that appear in docs in code-fence or inline-code contexts exist
  in the catalog (warning if not found — docs may reference future IDs)

Note on WCP_SPEC.md:
- `policy.v1` (line ~378) is a JSON field value, not a WCP entity ID.
  The V1 regex only matches entity IDs with cap/wrk/ctrl/pol/prof/evt prefixes,
  so policy.v1 does NOT trigger a violation.

Note on narrative HTML (web/blog/the-governance-gap.html, web/index.html):
- These contain intentional incident references to cap.recall.fetch.v1 and
  cap.mem.retrieve.rag.v1 as examples of a real routing mismatch.
  The docs_validator skips HTML files — those are covered by web_validator
  which also explicitly excludes HTML prose from .v1 checks.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

# Matches versioned WCP entity IDs: cap.foo.bar.v1  (only cap/wrk/ctrl/pol/prof/evt)
V1_ENTITY_RE = re.compile(
    r'\b(?:cap|wrk|ctrl|pol|prof|evt)\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.v\d+\b'
)

# Matches entity IDs that look like real WCP IDs (3+ dotted segments)
ENTITY_ID_RE = re.compile(
    r'\b(?:cap|wrk|ctrl|pol|prof|evt)\.[a-z][a-z0-9\-]*\.[a-z][a-z0-9\-]+'
    r'(?:\.[a-z][a-z0-9\-]*)*\b'
)

# Markdown/code-fence docs to validate (not HTML — those are in web_validator)
PUBLISHED_DOCS = [
    "WCP_SPEC.md",
    "docs/research/WCP_EVIDENCE_CATALOG_2026-02-26.md",
    "docs/research/WCP_MARKET_VALIDATION_2026-02-26.md",
]


def _extract_code_entity_ids(content: str) -> set[str]:
    """
    Extract entity IDs that appear inside code fences or backtick spans.
    Only these are checked against the catalog — prose namespace references
    like 'cap.*' or 'wrk.*' are intentional shorthand, not literal IDs.
    """
    ids = set()

    # Fenced code blocks: ```...```
    for block in re.findall(r'```[^\n]*\n(.*?)```', content, re.DOTALL):
        ids.update(ENTITY_ID_RE.findall(block))

    # Inline code: `cap.foo.bar`
    for span in re.findall(r'`([^`]+)`', content):
        ids.update(ENTITY_ID_RE.findall(span))

    return ids


def run(ctx, request):
    findings = []

    # Load SDK catalog
    catalog_path = ROOT / "sdk/python/pyhall/taxonomy/catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text())
    except FileNotFoundError:
        findings.append({
            "severity": "error",
            "detail": "sdk/python/pyhall/taxonomy/catalog.json not found — run scripts/build_catalog.py first",
        })
        return {"passed": False, "docs_checked": 0, "findings": findings}
    valid_ids = {e["id"] for e in catalog.get("entities", [])}

    for doc_rel in PUBLISHED_DOCS:
        doc = ROOT / doc_rel
        if not doc.exists():
            findings.append({
                "severity": "warning",
                "file": doc_rel,
                "detail": "published doc file not found",
            })
            continue

        content = doc.read_text(encoding="utf-8", errors="replace")

        # .v1 entity ID check — error: versioned entity IDs must not appear in docs
        for match in V1_ENTITY_RE.finditer(content):
            eid = match.group()
            findings.append({
                "severity": "error",
                "file": doc_rel,
                "detail": f".v1 versioned entity ID in published doc: {eid}",
            })

        # Catalog cross-reference check — entity IDs in code contexts should exist
        code_ids = _extract_code_entity_ids(content)
        for eid in sorted(code_ids):
            if eid not in valid_ids:
                findings.append({
                    "severity": "warning",
                    "file": doc_rel,
                    "detail": f"entity ID in code context not found in catalog: {eid}",
                })

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "docs_checked": len(PUBLISHED_DOCS),
        "findings": findings,
    }
