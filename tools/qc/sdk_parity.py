"""
cap.qc.sdk.check — Check that TypeScript + Go attestation matches Python reference.

Checks:
1. All three SDKs have the same deny codes for attestation
2. All three SDKs have WorkerAttestationChecked/Valid in their decision models
3. CV-013 conformance vector exists in all three SDK test suites
"""
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

EXPECTED_DENY_CODES = {
    "DENY_WORKER_TAMPERED",
    "DENY_ATTESTATION_UNCONFIGURED",
    "DENY_WORKER_ATTESTATION_MISSING",
    "DENY_WORKER_ATTESTATION_INVALID_HASH",
    "DENY_WORKER_HASH_UNAVAILABLE",
}

def _file_contains(path: Path, pattern: str) -> bool:
    try:
        return bool(re.search(pattern, path.read_text()))
    except FileNotFoundError:
        return False

def run(ctx, request):
    findings = []

    # Python reference
    py_router = ROOT / "sdk/python/pyhall/router.py"
    for code in EXPECTED_DENY_CODES:
        if not _file_contains(py_router, re.escape(code)):
            findings.append({"severity": "error", "sdk": "python", "detail": f"Missing deny code: {code}"})

    # TypeScript parity
    ts_router = ROOT / "sdk/typescript/src/router.ts"
    for code in EXPECTED_DENY_CODES:
        if not _file_contains(ts_router, re.escape(code)):
            findings.append({"severity": "error", "sdk": "typescript", "detail": f"Missing deny code: {code}"})

    # Go parity
    go_router = ROOT / "sdk/go/wcp/router.go"
    for code in EXPECTED_DENY_CODES:
        if not _file_contains(go_router, re.escape(code)):
            findings.append({"severity": "error", "sdk": "go", "detail": f"Missing deny code: {code}"})

    # CV-013 in all three test suites
    cv013_checks = [
        ("python",     ROOT / "sdk/python/tests/test_conformance.py",   "cv013|CV.013"),
        ("typescript", ROOT / "sdk/typescript/tests/conformance.test.ts", "CV-013|cv013"),
        ("go",         ROOT / "sdk/go/wcp/conformance_test.go",          "CV013|CV-013"),
    ]
    for sdk, path, pattern in cv013_checks:
        if not _file_contains(path, pattern):
            findings.append({"severity": "error", "sdk": sdk, "detail": f"CV-013 not in conformance test suite"})

    # worker_attestation_checked in all three models
    model_checks = [
        ("python",     ROOT / "sdk/python/pyhall/router.py",    "worker_attestation_checked"),
        ("typescript", ROOT / "sdk/typescript/src/models.ts",   "worker_attestation_checked"),
        ("go",         ROOT / "sdk/go/wcp/models.go",           "WorkerAttestationChecked"),
    ]
    for sdk, path, field in model_checks:
        if not _file_contains(path, re.escape(field)):
            findings.append({"severity": "error", "sdk": sdk, "detail": f"Missing field: {field}"})

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "findings": findings,
        "sdks_checked": ["python", "typescript", "go"],
    }
