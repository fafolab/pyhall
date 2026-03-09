"""
tests/test_attestation.py — PyHall package attestation test suite.

Tests WCP attestation compliance:
  - Canonical package hash determinism and exclusions
  - scaffold_package layout and overwrite behaviour
  - build_manifest structure and signing
  - write_manifest JSON round-trip
  - PackageAttestationVerifier deny codes and success path
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyhall.attestation import (
    ATTEST_HASH_MISMATCH,
    ATTEST_MANIFEST_ID_MISMATCH,
    ATTEST_MANIFEST_MISSING,
    ATTEST_SIG_INVALID,
    ATTEST_SIGNATURE_MISSING,
    PackageAttestationVerifier,
    build_manifest,
    canonical_package_hash,
    scaffold_package,
    write_manifest,
)

# ---------------------------------------------------------------------------
# Constants used across tests
# ---------------------------------------------------------------------------

SECRET = "test-secret-key"
WORKER_ID = "org.example.my-worker.instance-1"
SPECIES_ID = "wrk.example.my-worker"
VERSION = "1.0.0"
SECRET_ENV = "WCP_ATTEST_HMAC_KEY"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scaffolded(tmp_path: Path) -> Path:
    """Return a scaffolded package root ready for signing."""
    pkg = tmp_path / "pkg"
    scaffold_package(pkg)
    return pkg


def _build_and_write(pkg: Path, manifest_path: Path) -> dict:
    manifest = build_manifest(pkg, WORKER_ID, SPECIES_ID, VERSION, SECRET)
    write_manifest(manifest, manifest_path)
    return manifest


# ---------------------------------------------------------------------------
# canonical_package_hash
# ---------------------------------------------------------------------------

class TestCanonicalPackageHash:
    def test_deterministic_empty_dir(self, tmp_path):
        h1 = canonical_package_hash(tmp_path)
        h2 = canonical_package_hash(tmp_path)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_changes_when_file_added(self, tmp_path):
        h1 = canonical_package_hash(tmp_path)
        (tmp_path / "hello.py").write_text("print('hi')", encoding="utf-8")
        h2 = canonical_package_hash(tmp_path)
        assert h1 != h2

    def test_changes_when_file_content_changes(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text("x = 1", encoding="utf-8")
        h1 = canonical_package_hash(tmp_path)
        f.write_text("x = 2", encoding="utf-8")
        h2 = canonical_package_hash(tmp_path)
        assert h1 != h2

    def test_manifest_json_excluded(self, tmp_path):
        (tmp_path / "worker.py").write_text("pass", encoding="utf-8")
        h1 = canonical_package_hash(tmp_path)
        (tmp_path / "manifest.json").write_text('{"signature": "abc"}', encoding="utf-8")
        h2 = canonical_package_hash(tmp_path)
        assert h1 == h2

    def test_pyc_files_excluded(self, tmp_path):
        (tmp_path / "worker.py").write_text("pass", encoding="utf-8")
        h1 = canonical_package_hash(tmp_path)
        (tmp_path / "worker.cpython-312.pyc").write_bytes(b"\x00\x01\x02")
        h2 = canonical_package_hash(tmp_path)
        assert h1 == h2

    def test_pycache_contents_excluded(self, tmp_path):
        (tmp_path / "worker.py").write_text("pass", encoding="utf-8")
        h1 = canonical_package_hash(tmp_path)
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "worker.cpython-312.pyc").write_bytes(b"\xde\xad\xbe\xef")
        h2 = canonical_package_hash(tmp_path)
        assert h1 == h2


# ---------------------------------------------------------------------------
# scaffold_package
# ---------------------------------------------------------------------------

class TestScaffoldPackage:
    def test_creates_expected_layout(self, tmp_path):
        pkg = tmp_path / "pkg"
        scaffold_package(pkg)
        assert (pkg / "code" / "bootstrap.py").exists()
        assert (pkg / "code" / "worker_logic.py").exists()
        assert (pkg / "requirements.lock").exists()
        assert (pkg / "config.schema.json").exists()

    def test_injects_worker_logic_file(self, tmp_path):
        logic_src = tmp_path / "my_logic.py"
        logic_src.write_text("def run(): return 42\n", encoding="utf-8")
        pkg = tmp_path / "pkg"
        scaffold_package(pkg, worker_logic_file=logic_src)
        content = (pkg / "code" / "worker_logic.py").read_text(encoding="utf-8")
        assert "def run(): return 42" in content

    def test_raises_file_exists_error_without_overwrite(self, tmp_path):
        pkg = tmp_path / "pkg"
        scaffold_package(pkg)
        with pytest.raises(FileExistsError):
            scaffold_package(pkg, overwrite=False)

    def test_succeeds_with_overwrite(self, tmp_path):
        pkg = tmp_path / "pkg"
        scaffold_package(pkg)
        logic_src = tmp_path / "new_logic.py"
        logic_src.write_text("def run(): return 99\n", encoding="utf-8")
        scaffold_package(pkg, worker_logic_file=logic_src, overwrite=True)
        content = (pkg / "code" / "worker_logic.py").read_text(encoding="utf-8")
        assert "def run(): return 99" in content


# ---------------------------------------------------------------------------
# build_manifest
# ---------------------------------------------------------------------------

class TestBuildManifest:
    REQUIRED_KEYS = {
        "schema_version",
        "worker_id",
        "worker_species_id",
        "worker_version",
        "package_hash",
        "built_at_utc",
        "attested_at_utc",
        "build_source",
        "trust_statement",
        "signature_hmac_sha256",
    }

    def test_returns_required_keys(self, tmp_path):
        pkg = _scaffolded(tmp_path)
        manifest = build_manifest(pkg, WORKER_ID, SPECIES_ID, VERSION, SECRET)
        assert self.REQUIRED_KEYS <= manifest.keys()

    def test_package_hash_matches_canonical(self, tmp_path):
        pkg = _scaffolded(tmp_path)
        manifest = build_manifest(pkg, WORKER_ID, SPECIES_ID, VERSION, SECRET)
        assert manifest["package_hash"] == canonical_package_hash(pkg)

    def test_trust_statement_contains_namespace(self, tmp_path):
        pkg = _scaffolded(tmp_path)
        manifest = build_manifest(pkg, WORKER_ID, SPECIES_ID, VERSION, SECRET)
        ns = "org.example"  # tenant namespace derived from WORKER_ID "org.example.my-worker.instance-1"
        assert f"namespace {ns}" in manifest["trust_statement"]

    def test_timestamps_are_utc_iso8601(self, tmp_path):
        pkg = _scaffolded(tmp_path)
        manifest = build_manifest(pkg, WORKER_ID, SPECIES_ID, VERSION, SECRET)
        assert manifest["built_at_utc"].endswith("Z")
        assert manifest["attested_at_utc"].endswith("Z")

    def test_different_secrets_produce_different_signatures(self, tmp_path):
        pkg = _scaffolded(tmp_path)
        m1 = build_manifest(pkg, WORKER_ID, SPECIES_ID, VERSION, "secret-a")
        m2 = build_manifest(pkg, WORKER_ID, SPECIES_ID, VERSION, "secret-b")
        assert m1["signature_hmac_sha256"] != m2["signature_hmac_sha256"]


# ---------------------------------------------------------------------------
# write_manifest + round-trip
# ---------------------------------------------------------------------------

class TestWriteManifest:
    def test_written_file_is_valid_json_and_round_trips(self, tmp_path):
        pkg = _scaffolded(tmp_path)
        manifest = build_manifest(pkg, WORKER_ID, SPECIES_ID, VERSION, SECRET)
        manifest_path = pkg / "manifest.json"
        write_manifest(manifest, manifest_path)

        raw = manifest_path.read_text(encoding="utf-8")
        loaded = json.loads(raw)
        assert loaded == manifest


# ---------------------------------------------------------------------------
# PackageAttestationVerifier
# ---------------------------------------------------------------------------

class TestPackageAttestationVerifier:
    def _verifier(self, pkg: Path, manifest_path: Path) -> PackageAttestationVerifier:
        return PackageAttestationVerifier(
            package_root=pkg,
            manifest_path=manifest_path,
            worker_id=WORKER_ID,
            worker_species_id=SPECIES_ID,
            secret_env=SECRET_ENV,
        )

    def _setup(self, tmp_path: Path):
        pkg = _scaffolded(tmp_path)
        manifest_path = pkg / "manifest.json"
        _build_and_write(pkg, manifest_path)
        return pkg, manifest_path

    # --- success path ---

    def test_verify_returns_true_for_valid_package(self, tmp_path, monkeypatch):
        monkeypatch.setenv(SECRET_ENV, SECRET)
        pkg, manifest_path = self._setup(tmp_path)
        ok, deny_code, meta = self._verifier(pkg, manifest_path).verify()
        assert ok is True
        assert deny_code is None

    def test_verify_meta_contains_required_fields(self, tmp_path, monkeypatch):
        monkeypatch.setenv(SECRET_ENV, SECRET)
        pkg, manifest_path = self._setup(tmp_path)
        ok, _, meta = self._verifier(pkg, manifest_path).verify()
        assert ok is True
        for key in ("package_hash", "attested_at_utc", "verified_at_utc", "trust_statement"):
            assert key in meta, f"meta missing key: {key}"

    # --- ATTEST_MANIFEST_MISSING ---

    def test_missing_manifest(self, tmp_path, monkeypatch):
        monkeypatch.setenv(SECRET_ENV, SECRET)
        pkg = _scaffolded(tmp_path)
        manifest_path = pkg / "manifest.json"  # does not exist
        ok, deny_code, _ = self._verifier(pkg, manifest_path).verify()
        assert ok is False
        assert deny_code == ATTEST_MANIFEST_MISSING

    # --- ATTEST_MANIFEST_ID_MISMATCH ---

    def test_wrong_worker_id(self, tmp_path, monkeypatch):
        monkeypatch.setenv(SECRET_ENV, SECRET)
        pkg, manifest_path = self._setup(tmp_path)
        v = PackageAttestationVerifier(
            package_root=pkg,
            manifest_path=manifest_path,
            worker_id="wrk.other.worker.instance-9",
            worker_species_id=SPECIES_ID,
            secret_env=SECRET_ENV,
        )
        ok, deny_code, _ = v.verify()
        assert ok is False
        assert deny_code == ATTEST_MANIFEST_ID_MISMATCH

    def test_wrong_worker_species_id(self, tmp_path, monkeypatch):
        monkeypatch.setenv(SECRET_ENV, SECRET)
        pkg, manifest_path = self._setup(tmp_path)
        v = PackageAttestationVerifier(
            package_root=pkg,
            manifest_path=manifest_path,
            worker_id=WORKER_ID,
            worker_species_id="wrk.other.different-species",
            secret_env=SECRET_ENV,
        )
        ok, deny_code, _ = v.verify()
        assert ok is False
        assert deny_code == ATTEST_MANIFEST_ID_MISMATCH

    # --- ATTEST_HASH_MISMATCH ---

    def test_file_modified_after_signing(self, tmp_path, monkeypatch):
        monkeypatch.setenv(SECRET_ENV, SECRET)
        pkg, manifest_path = self._setup(tmp_path)
        (pkg / "code" / "worker_logic.py").write_text("# tampered\n", encoding="utf-8")
        ok, deny_code, _ = self._verifier(pkg, manifest_path).verify()
        assert ok is False
        assert deny_code == ATTEST_HASH_MISMATCH

    def test_new_file_added_after_signing(self, tmp_path, monkeypatch):
        monkeypatch.setenv(SECRET_ENV, SECRET)
        pkg, manifest_path = self._setup(tmp_path)
        (pkg / "extra.py").write_text("# injected\n", encoding="utf-8")
        ok, deny_code, _ = self._verifier(pkg, manifest_path).verify()
        assert ok is False
        assert deny_code == ATTEST_HASH_MISMATCH

    def test_manifest_modification_does_not_cause_hash_mismatch(self, tmp_path, monkeypatch):
        """manifest.json is excluded from hash; editing it must not produce ATTEST_HASH_MISMATCH."""
        monkeypatch.setenv(SECRET_ENV, SECRET)
        pkg, manifest_path = self._setup(tmp_path)
        # Re-read, add an extra field, rewrite — hash check must still pass
        # (sig check will fail, but NOT with HASH_MISMATCH)
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["extra_field"] = "injected"
        manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        ok, deny_code, _ = self._verifier(pkg, manifest_path).verify()
        assert deny_code != ATTEST_HASH_MISMATCH

    # --- ATTEST_SIGNATURE_MISSING ---

    def test_env_var_not_set(self, tmp_path, monkeypatch):
        monkeypatch.delenv(SECRET_ENV, raising=False)
        pkg, manifest_path = self._setup(tmp_path)
        ok, deny_code, _ = self._verifier(pkg, manifest_path).verify()
        assert ok is False
        assert deny_code == ATTEST_SIGNATURE_MISSING

    # --- ATTEST_SIG_INVALID ---

    def test_wrong_secret(self, tmp_path, monkeypatch):
        monkeypatch.setenv(SECRET_ENV, "wrong-secret")
        pkg, manifest_path = self._setup(tmp_path)
        ok, deny_code, _ = self._verifier(pkg, manifest_path).verify()
        assert ok is False
        assert deny_code == ATTEST_SIG_INVALID
