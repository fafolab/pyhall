"""
cap.qc.stale.scan — Scan the monorepo for unused/stale files.
Outputs archive candidates with rationale.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

STALE_PATTERNS = [
    ("lab/workforce-os", "Predates v0.1 security rounds; outdated worker architecture"),
    ("**/*.v1.*", "Files containing legacy .v1 naming"),
    ("**/*_old.*", "Explicitly named old versions"),
    ("**/*_backup.*", "Backup files"),
]

def run(ctx, request):
    archive_candidates = []
    for pattern, reason in STALE_PATTERNS:
        if "/" in pattern and not pattern.startswith("**"):
            target = ROOT / pattern
            if target.exists():
                archive_candidates.append({
                    "path": str(target.relative_to(ROOT.parent)),
                    "reason": reason,
                    "action": "archive",
                })
        else:
            for match in ROOT.glob(pattern):
                if ".git" not in str(match):
                    archive_candidates.append({
                        "path": str(match.relative_to(ROOT.parent)),
                        "reason": reason,
                        "action": "archive",
                    })
    return {
        "passed": True,  # scanner never fails — it reports
        "archive_candidates": archive_candidates,
        "count": len(archive_candidates),
    }
