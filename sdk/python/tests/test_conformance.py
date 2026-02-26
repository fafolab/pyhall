"""
tests/test_conformance.py — PATCH-XSDK-001: Cross-SDK Governance Conformance Tests

Loads shared test vectors from docs/conformance/wcp_conformance_vectors.json and
verifies that this SDK produces the declared `denied` outcome (and `deny_code` where
applicable) for each vector not listed in skip_sdks.

Purpose: catch governance regressions that survive per-SDK tests because they only
manifest as cross-SDK divergence. If this test passes and the TS/Go equivalents also
pass, all three SDKs agree on governance outcomes for every shared vector.

Run:
    pytest tests/test_conformance.py -v
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from pyhall import make_decision, RouteInput, Registry, load_rules_from_dict
from pyhall.models import HallConfig

# ---------------------------------------------------------------------------
# Vector file location
# ---------------------------------------------------------------------------

_VECTORS_PATH = (
    Path(__file__).parent.parent.parent.parent  # sdk/python -> git root
    / "docs"
    / "conformance"
    / "wcp_conformance_vectors.json"
)

SDK_NAME = "python"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_vectors() -> List[Dict[str, Any]]:
    """Load and return the conformance vector list."""
    with open(_VECTORS_PATH, encoding="utf-8") as f:
        doc = json.load(f)
    return doc["vectors"]


def _build_input(raw: Dict[str, Any]) -> RouteInput:
    """Construct a RouteInput from a vector's input dict."""
    kwargs: Dict[str, Any] = {
        "capability_id": raw["capability_id"],
        "env": raw["env"],
        "data_label": raw["data_label"],
        "tenant_risk": raw["tenant_risk"],
        "qos_class": raw["qos_class"],
        "tenant_id": raw["tenant_id"],
        "correlation_id": raw["correlation_id"],
        "request": raw.get("request", {}),
    }
    if "blast_score" in raw and raw["blast_score"] is not None:
        kwargs["blast_score"] = raw["blast_score"]
    return RouteInput(**kwargs)


def _build_rules_from_vector(vector: Dict[str, Any]) -> list:
    """Build a minimal rules list from the vector's rule spec."""
    rule_spec = vector.get("rule")
    if rule_spec is None:
        # No rule defined — return empty rules list (will produce DENY_NO_MATCHING_RULE)
        return []

    doc = {"rules": [rule_spec]}
    return load_rules_from_dict(doc)


def _build_registry(vector: Dict[str, Any]) -> Registry:
    """
    Build a Registry for this vector.

    Setup rules:
    - no_workers=True: empty registry (worker_available returns False for all species)
    - control_present=True/False: add or withhold a specific control
    - Default: worker wrk.test.worker is available, no controls
    """
    setup = vector.get("setup", {})
    reg = Registry()

    if setup.get("no_workers"):
        # Empty registry — no workers available
        return reg

    # By default make wrk.test.worker available (the species used in most vectors)
    reg.add_workers_available(["wrk.test.worker"])

    # Control presence
    required_ctrl = setup.get("required_control")
    if required_ctrl is not None:
        if setup.get("control_present", False):
            reg.add_controls_present([required_ctrl])
        # else: control is absent — do not add it

    return reg


def _get_expected_denied(vector: Dict[str, Any]) -> bool:
    """Return the Python-specific expected denied outcome, falling back to generic."""
    expect = vector["expect"]
    # denied_python overrides the generic denied field for Python-specific parity gaps
    py_denied = expect.get("denied_python")
    if py_denied is not None:
        return bool(py_denied)
    return bool(expect["denied"])


def _get_expected_deny_code(vector: Dict[str, Any]) -> Optional[str]:
    """Return the Python-specific expected deny code, falling back to generic."""
    expect = vector["expect"]
    # Use Python-specific code if present, else generic deny_code
    py_code = expect.get("deny_code_python")
    if py_code:
        return py_code
    return expect.get("deny_code")


# ---------------------------------------------------------------------------
# Conformance test
# ---------------------------------------------------------------------------

def _should_skip(v: Dict[str, Any]) -> bool:
    """Return True if this vector should be skipped for this SDK.

    Vectors with skip_sdks=[SDK_NAME] or skip_sdks=["all"] are excluded from
    the parametric conformance loop. Procedural vectors (CV-013 and future
    multi-step tests) use "all" to indicate they run as standalone test functions.
    """
    skip = v.get("skip_sdks", [])
    return SDK_NAME in skip or "all" in skip


@pytest.mark.parametrize(
    "vector",
    [v for v in _load_vectors() if not _should_skip(v)],
    ids=[v["id"] for v in _load_vectors() if not _should_skip(v)],
)
def test_conformance_vector(vector: Dict[str, Any]) -> None:
    """
    For each conformance vector not skipped for this SDK:
      1. Build RouteInput from vector.input
      2. Build rules from vector.rule (if present)
      3. Build registry per vector.setup
      4. Call make_decision()
      5. Assert dec.denied == vector.expect.denied
      6. If denied, assert deny_code matches expected
      7. Assert telemetry contains no raw control characters in capability_id field
    """
    vid = vector["id"]
    desc = vector["description"]
    expected_denied: bool = _get_expected_denied(vector)
    expected_code: Optional[str] = _get_expected_deny_code(vector)

    # Build inputs
    # CV-001 has empty correlation_id — RouteInput accepts it (validation happens in router)
    try:
        inp = _build_input(vector["input"])
    except Exception as exc:
        # If RouteInput construction raises (e.g. Pydantic ValidationError for an
        # enum field), that is itself a denial-equivalent for conformance purposes.
        if expected_denied:
            # Accept: input validation raised — counts as denied
            return
        pytest.fail(
            f"{vid} ({desc}): RouteInput construction raised unexpectedly: {exc}"
        )

    rules = _build_rules_from_vector(vector)
    registry = _build_registry(vector)

    # Hall config: enforce_blast_scoring_in_prod=False so dev vectors with
    # blast_score are not blocked by the prod blast floor (not relevant for dev env).
    # Use default Hall config (no signatory enforcement, no blast in dev).
    dec = make_decision(
        inp=inp,
        rules=rules,
        registry_controls_present=registry.controls_present(),
        registry_worker_available=registry.worker_available,
    )

    # --- Assert denied outcome ---
    assert dec.denied == expected_denied, (
        f"{vid} ({desc}): expected denied={expected_denied}, "
        f"got denied={dec.denied}. "
        f"deny_reason_if_denied={dec.deny_reason_if_denied}"
    )

    # --- Assert deny code (when denied) ---
    if expected_denied and expected_code is not None:
        actual_code = (dec.deny_reason_if_denied or {}).get("code")
        assert actual_code == expected_code, (
            f"{vid} ({desc}): expected deny_code={expected_code!r}, "
            f"got {actual_code!r}. Full reason: {dec.deny_reason_if_denied}"
        )

    # --- Telemetry invariant: no raw control characters in capability_id ---
    # This applies to CV-012 and any future vector with control chars in inputs.
    if vector.get("expect", {}).get("telemetry_invariant") == "no_control_chars_in_capability_id_field_in_telemetry":
        for envelope in dec.telemetry_envelopes:
            raw_cap = envelope.get("capability_id", "")
            assert "\n" not in str(raw_cap), (
                f"{vid}: telemetry capability_id must not contain raw newline. "
                f"Got: {raw_cap!r}"
            )
            assert "\x00" not in str(raw_cap), (
                f"{vid}: telemetry capability_id must not contain null byte. "
                f"Got: {raw_cap!r}"
            )
            assert "\r" not in str(raw_cap), (
                f"{vid}: telemetry capability_id must not contain carriage return. "
                f"Got: {raw_cap!r}"
            )


# ---------------------------------------------------------------------------
# Sanity check — vector file itself is loadable and contains required IDs
# ---------------------------------------------------------------------------

def test_vector_file_has_required_ids() -> None:
    """All 13 required vector IDs must be present in the file."""
    vectors = _load_vectors()
    ids = {v["id"] for v in vectors}
    required = {f"CV-{i:03d}" for i in range(1, 14)}
    missing = required - ids
    assert not missing, f"Missing required conformance vector IDs: {missing}"


def test_vector_file_schema_valid() -> None:
    """Every vector must have id, description, and (unless procedural/all-skip) input and expect fields."""
    vectors = _load_vectors()
    for v in vectors:
        assert "id" in v, f"Vector missing 'id': {v}"
        assert "description" in v, f"Vector {v.get('id')} missing 'description'"
        # Procedural vectors (skip_sdks=["all"]) are documentation-only records and
        # intentionally omit input/expect — they are implemented as standalone tests.
        if "all" in v.get("skip_sdks", []):
            continue
        assert "input" in v, f"Vector {v.get('id')} missing 'input'"
        assert "expect" in v, f"Vector {v.get('id')} missing 'expect'"
        assert "denied" in v["expect"], (
            f"Vector {v.get('id')}.expect missing 'denied'"
        )


# ---------------------------------------------------------------------------
# CV-013: Worker attestation — standalone procedural test (WCP §5.10)
# ---------------------------------------------------------------------------

def test_cv013_worker_attestation(tmp_path: Path) -> None:
    """CV-013: Worker attestation — enroll, verify, tamper, deny.

    Release-blocking cross-SDK conformance vector. Tests the tamper detection
    path mandated by WCP §5.10.

    Steps:
      1. Enroll worker with attestation registered (SHA-256 of source file).
      2. Dispatch capability → verify worker_attestation_valid=true, denied=false.
      3. Mutate the worker source file (change one byte).
      4. Dispatch again → verify denied=true, code=DENY_WORKER_TAMPERED.
      5. Verify evidence receipt: worker_attestation_checked=true, valid=false.
      6. Verify F4: no hash values in deny payload.
    """
    worker_file = tmp_path / "worker.py"
    worker_file.write_text("def run(): pass\n")

    registry = Registry()
    registry.enroll({
        "worker_id": "org.test.cv013",
        "worker_species_id": "wrk.test.cv013",
        "capabilities": ["cap.test.cv013"],
        "risk_tier": "low",
        "required_controls": ["ctrl.obs.audit-log-append-only"],
        "currently_implements": ["ctrl.obs.audit-log-append-only"],
        "allowed_environments": ["dev"],
    })
    registry.register_attestation("wrk.test.cv013", str(worker_file))

    rules = load_rules_from_dict({
        "rules": [{
            "rule_id": "rr_cv013",
            "match": {"capability_id": "cap.test.cv013"},
            "decision": {
                "candidate_workers_ranked": [
                    {"worker_species_id": "wrk.test.cv013", "score_hint": 1.0}
                ],
                "required_controls_suggested": ["ctrl.obs.audit-log-append-only"],
                "escalation": {},
                "preconditions": {},
            },
        }]
    })
    hall_config = HallConfig(require_worker_attestation=True)
    base_input = RouteInput(
        capability_id="cap.test.cv013",
        env="dev",
        data_label="PUBLIC",
        tenant_risk="low",
        qos_class="P2",
        tenant_id="test.tenant",
        correlation_id="cv013",
    )

    # Step 2: dispatch with intact file → DISPATCHED
    decision = make_decision(
        inp=base_input,
        rules=rules,
        registry_controls_present=registry.controls_present(),
        registry_worker_available=registry.worker_available,
        registry_get_worker_hash=registry.get_worker_hash,
        get_current_worker_hash=registry.compute_current_hash,
        hall_config=hall_config,
    )
    assert not decision.denied, (
        f"Step 2: expected DISPATCHED, got denied: {decision.deny_reason_if_denied}"
    )
    assert decision.worker_attestation_checked is True, (
        "Step 2: expected worker_attestation_checked=True"
    )
    assert decision.worker_attestation_valid is True, (
        "Step 2: expected worker_attestation_valid=True"
    )

    # Step 3: tamper — change the worker file content
    worker_file.write_text("def run(): exfiltrate()\n")

    # Step 4: dispatch with tampered file → DENY_WORKER_TAMPERED
    decision2 = make_decision(
        inp=base_input,
        rules=rules,
        registry_controls_present=registry.controls_present(),
        registry_worker_available=registry.worker_available,
        registry_get_worker_hash=registry.get_worker_hash,
        get_current_worker_hash=registry.compute_current_hash,
        hall_config=hall_config,
    )
    assert decision2.denied, "Step 4: expected DENY_WORKER_TAMPERED after file mutation"
    assert (decision2.deny_reason_if_denied or {}).get("code") == "DENY_WORKER_TAMPERED", (
        f"Step 4: expected deny code DENY_WORKER_TAMPERED, got: {decision2.deny_reason_if_denied}"
    )
    # Step 5: verify evidence receipt fields
    assert decision2.worker_attestation_checked is True, (
        "Step 5: expected worker_attestation_checked=True"
    )
    assert decision2.worker_attestation_valid is False, (
        "Step 5: expected worker_attestation_valid=False"
    )
    # Step 6 / F4: hash values must NOT be in the deny payload
    assert "registered_hash" not in (decision2.deny_reason_if_denied or {}), (
        "F4 violation: registered_hash must not appear in deny payload"
    )
    assert "current_hash" not in (decision2.deny_reason_if_denied or {}), (
        "F4 violation: current_hash must not appear in deny payload"
    )
