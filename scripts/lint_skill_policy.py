#!/usr/bin/env python3
"""
lint_skill_policy.py — CI guard for unsafe skill policy defaults.

Scans all agent skill manifests (*.yaml / *.yml) under the skills/ directory
and fails if any manifest:
  - Sets allow_implicit_invocation: true
  - Omits allow_implicit_invocation entirely (must be explicit)

Explicit false is the only safe default. Implicit invocation allows an AI
agent to invoke a skill without the user explicitly requesting it, bypassing
human oversight.

Exit codes:
  0 — all manifests are safe
  1 — one or more violations found
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"

# Relative paths to manifests that have a documented, approved exception.
# Format: "skills/plugin-name/agents/agent.yaml"
# Add to this list ONLY after security review and approval — never silently.
APPROVED_EXCEPTIONS: set[str] = set()


def check_manifest(path: Path) -> list[str]:
    """Return a list of violation strings for a single manifest file."""
    violations = []
    rel = path.relative_to(REPO_ROOT)

    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        violations.append(f"  {rel}: YAML parse error — {exc}")
        return violations

    if not isinstance(data, dict):
        return violations  # not a manifest with policy fields, skip

    policy = data.get("policy")
    if not isinstance(policy, dict):
        # No policy block at all — only a violation if this looks like a skill agent
        # manifest (has an 'interface' or 'dependencies' key typical of agents.yaml).
        if "interface" in data or "dependencies" in data:
            violations.append(
                f"  {rel}: missing 'policy' block — "
                "add policy.allow_implicit_invocation: false"
            )
        return violations

    val = policy.get("allow_implicit_invocation")

    if val is None:
        violations.append(
            f"  {rel}: 'allow_implicit_invocation' not set — "
            "must be explicitly false"
        )
    elif val is True:
        rel_str = str(rel)
        if rel_str in APPROVED_EXCEPTIONS:
            print(f"  [exception] {rel}: allow_implicit_invocation=true (approved)")
        else:
            violations.append(
                f"  {rel}: allow_implicit_invocation: true — "
                "implicit invocation bypasses human oversight. "
                "Set to false, or add to APPROVED_EXCEPTIONS with documented justification."
            )

    return violations


def main() -> int:
    if not SKILLS_DIR.exists():
        print(f"No skills directory found at {SKILLS_DIR} — nothing to check.")
        return 0

    manifests = list(SKILLS_DIR.rglob("*.yaml")) + list(SKILLS_DIR.rglob("*.yml"))
    if not manifests:
        print("No skill manifests found — nothing to check.")
        return 0

    print(f"Checking {len(manifests)} skill manifest(s) for unsafe policy defaults...\n")

    all_violations: list[str] = []
    for path in sorted(manifests):
        violations = check_manifest(path)
        all_violations.extend(violations)

    if all_violations:
        print("FAIL — unsafe skill policy defaults found:")
        for v in all_violations:
            print(v)
        print(
            "\nFix: set allow_implicit_invocation: false in each flagged manifest. "
            "See APPROVED_EXCEPTIONS in scripts/lint_skill_policy.py for exception process."
        )
        return 1

    print(f"OK — all {len(manifests)} manifest(s) have safe policy defaults.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
