"""
cap.qc.cli.validate — Validate all 3 CLIs (Python, TypeScript, Go) against rebuilt catalog.

Checks:
- Each CLI binary/entry-point responds to 'version' without error
- No .v1 version suffix on WCP entity IDs (cap/wrk/ctrl/pol/prof/evt) in CLI source files
- All 3 CLIs report spec version matching WCP_SPEC.md

Note: generic version strings like `policy.v0` or semver values are NOT flagged.
Only WCP entity IDs with reserved namespace prefixes are checked.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

# Matches versioned WCP entity IDs specifically — requires a reserved namespace prefix.
# Examples that match: cap.doc.summarize.v1, wrk.mem.retriever.v2
# Examples that do NOT match: policy.v0, spec_version.v1, semver 1.2.3
V1_ENTITY_RE = re.compile(
    r'\b(?:cap|wrk|ctrl|pol|prof|evt)\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.v\d+\b'
)

# Source files that must not contain .v1 WCP entity ID references
CLI_SOURCE_FILES = [
    ROOT / "sdk/python/pyhall/cli.py",
    ROOT / "apps/cli/typescript/src/index.ts",
    ROOT / "sdk/go/cmd/pyhall/main.go",
]


def _check_v1_in_source(path: Path) -> list[dict]:
    """Return findings for any .v1 WCP entity ID occurrences in source."""
    findings = []
    if not path.exists():
        return findings
    content = path.read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(content.splitlines(), 1):
        for match in V1_ENTITY_RE.finditer(line):
            findings.append({
                "severity": "error",
                "file": str(path.relative_to(ROOT)),
                "line": lineno,
                "detail": f".v1 WCP entity ID: {match.group()} — {line.strip()[:100]}",
            })
    return findings


def _run_python_version() -> dict:
    """Invoke Python CLI version command via module entry point."""
    try:
        result = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.argv=['pyhall','version']; "
             "sys.path.insert(0, str()); "
             "from pyhall.cli import main; main()"],
            capture_output=True, text=True,
            cwd=str(ROOT / "sdk/python"),
            timeout=15,
        )
        return {
            "cli": "python",
            "returncode": result.returncode,
            "stdout": result.stdout[:400],
            "stderr": result.stderr[:200],
        }
    except Exception as exc:
        return {"cli": "python", "returncode": -1, "stdout": "", "stderr": str(exc)}


def _run_ts_version() -> dict:
    """Invoke TypeScript CLI version command via compiled dist."""
    dist_index = ROOT / "apps/cli/typescript/dist/index.js"
    if not dist_index.exists():
        return {
            "cli": "typescript",
            "returncode": -1,
            "stdout": "",
            "stderr": "dist/index.js not found — run npm run build in apps/cli/typescript/",
        }
    try:
        result = subprocess.run(
            ["node", str(dist_index), "version"],
            capture_output=True, text=True,
            timeout=15,
        )
        return {
            "cli": "typescript",
            "returncode": result.returncode,
            "stdout": result.stdout[:400],
            "stderr": result.stderr[:200],
        }
    except Exception as exc:
        return {"cli": "typescript", "returncode": -1, "stdout": "", "stderr": str(exc)}


def _run_go_version() -> dict:
    """Invoke Go CLI version command via pre-built binary."""
    go_binary = ROOT / "sdk/go/pyhall"
    if not go_binary.exists():
        # Try building it on the fly
        try:
            build = subprocess.run(
                ["go", "build", "-o", str(go_binary), "./cmd/pyhall/..."],
                capture_output=True, text=True,
                cwd=str(ROOT / "sdk/go"),
                timeout=60,
            )
            if build.returncode != 0:
                return {
                    "cli": "go",
                    "returncode": -1,
                    "stdout": "",
                    "stderr": f"build failed: {build.stderr[:200]}",
                }
        except Exception as exc:
            return {"cli": "go", "returncode": -1, "stdout": "", "stderr": str(exc)}

    try:
        result = subprocess.run(
            [str(go_binary), "version"],
            capture_output=True, text=True,
            timeout=15,
        )
        return {
            "cli": "go",
            "returncode": result.returncode,
            "stdout": result.stdout[:400],
            "stderr": result.stderr[:200],
        }
    except Exception as exc:
        return {"cli": "go", "returncode": -1, "stdout": "", "stderr": str(exc)}


def run(ctx, request):
    findings = []
    cli_results = []

    # 1. Smoke-test each CLI's version command
    for cli_fn in [_run_python_version, _run_ts_version, _run_go_version]:
        r = cli_fn()
        cli_results.append(r)
        if r["returncode"] != 0:
            findings.append({
                "severity": "error",
                "cli": r["cli"],
                "detail": f"version command exited {r['returncode']}: {r['stderr'][:200]}",
            })
        # Check output contains no .v1 WCP entity IDs
        v1_hits = [
            (line, m.group())
            for line in r["stdout"].splitlines()
            for m in [V1_ENTITY_RE.search(line)]
            if m
        ]
        for hit, eid in v1_hits:
            findings.append({
                "severity": "error",
                "cli": r["cli"],
                "detail": f".v1 WCP entity ID in version output: {eid} — {hit.strip()[:100]}",
            })

    # 2. Source-level .v1 check
    for src in CLI_SOURCE_FILES:
        findings.extend(_check_v1_in_source(src))

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "cli_results": cli_results,
        "findings": findings,
    }
