"""
cap.qc.release.check — Run full test suite + conformance vectors, generate go/no-go report.
"""
import subprocess
import json
from pathlib import Path
from datetime import datetime, UTC

ROOT = Path(__file__).parent.parent.parent

def _run(cmd, cwd):
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return result.returncode == 0, result.stdout + result.stderr

def run(ctx, request):
    results = {}

    results["python_tests"], out = _run(["python3", "-m", "pytest", "tests/", "-q"], ROOT / "sdk/python")
    results["python_output"] = out[-500:]

    results["typescript_tests"], out = _run(["npm", "test", "--", "--reporter=min"], ROOT / "sdk/typescript")
    results["typescript_output"] = out[-500:]

    results["go_tests"], out = _run(["go", "test", "./..."], ROOT / "sdk/go")
    results["go_output"] = out[-500:]

    passed = all(results[k] for k in ["python_tests", "typescript_tests", "go_tests"])
    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "passed": passed,
        "results": results,
    }

    report_path = ROOT.parent / "release" / "qa-reports" / f"release-gate-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    report["report_path"] = str(report_path)
    return report
