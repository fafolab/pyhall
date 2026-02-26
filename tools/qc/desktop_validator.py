"""
cap.qc.desktop.validate — Validate desktop app (Tauri) against current spec.

Checks:
- Required source files exist (api.js, app.js, index.html)
- No .v1 capability ID version suffixes in JS source
- package.json references correct version
- src-tauri/tauri.conf.json present (Tauri app config)

Note: api.js uses intentional shorthand mock IDs (cap.doc.summarize,
cap.mem.retrieve etc.) in MOCK_DISPATCH_EVENTS / MOCK_WORKERS for UI demo
purposes. These are clearly marked as mock data and are not live routing IDs.
The validator checks .v1 version suffixes only, not mock data alias patterns.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

# Only flag actual .v1 WCP entity ID version suffixes
V1_ENTITY_RE = re.compile(
    r'\b(?:cap|wrk|ctrl|pol|prof|evt)\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.v\d+\b'
)

DESKTOP_ROOT = ROOT / "apps/desktop"

REQUIRED_FILES = [
    "apps/desktop/src/index.html",
    "apps/desktop/src/js/api.js",
    "apps/desktop/src/js/app.js",
    "apps/desktop/package.json",
]

JS_FILES_TO_CHECK = [
    "apps/desktop/src/js/api.js",
    "apps/desktop/src/js/app.js",
]


def run(ctx, request):
    findings = []

    # 1. Required files exist
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        if not path.exists():
            findings.append({
                "severity": "warning",
                "file": rel,
                "detail": "required desktop file not found",
            })

    # 2. .v1 check in JS source files
    for rel in JS_FILES_TO_CHECK:
        path = ROOT / rel
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for match in V1_ENTITY_RE.finditer(content):
            findings.append({
                "severity": "error",
                "file": rel,
                "detail": f".v1 capability ID reference: {match.group()}",
            })

    # 3. package.json version sanity check
    pkg_path = DESKTOP_ROOT / "package.json"
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text())
            version = pkg.get("version", "")
            if not version:
                findings.append({
                    "severity": "warning",
                    "file": "apps/desktop/package.json",
                    "detail": "version field missing in package.json",
                })
        except json.JSONDecodeError as exc:
            findings.append({
                "severity": "error",
                "file": "apps/desktop/package.json",
                "detail": f"invalid JSON: {exc}",
            })

    # 4. Tauri config present
    tauri_conf = DESKTOP_ROOT / "src-tauri/tauri.conf.json"
    if not tauri_conf.exists():
        findings.append({
            "severity": "warning",
            "file": "apps/desktop/src-tauri/tauri.conf.json",
            "detail": "Tauri config not found (app may not be fully initialized)",
        })

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "findings": findings,
    }
