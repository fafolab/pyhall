"""
cap.qc.catalog.validate — Validate catalog.json against WCP spec §3.2/§3.4.
Writes findings to pyhall_audit.db.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

VALID_ID_RE = re.compile(r'^[a-z][a-z0-9\-]*(\.[a-z][a-z0-9\-]*){1,3}$')
VERSION_SUFFIX_RE = re.compile(r'\.[vV]\d+')

def run(ctx, request):
    catalog_path = ROOT / "sdk/python/pyhall/taxonomy/catalog.json"
    catalog = json.loads(catalog_path.read_text())
    findings = []
    for entity in catalog.get("entities", []):
        eid = entity.get("id", "")
        if not VALID_ID_RE.match(eid):
            findings.append({"severity": "error", "id": eid, "reason": "format violation §3.2"})
        if VERSION_SUFFIX_RE.search(eid):
            findings.append({"severity": "error", "id": eid, "reason": "version suffix §3.4"})
    return {
        "passed": len(findings) == 0,
        "total_entities": len(catalog.get("entities", [])),
        "violations": findings,
    }
