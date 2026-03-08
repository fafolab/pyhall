"""
pyhall/attestation.py — Full-package attestation for WCP workers.

The unit of attestation is the complete worker package:

    worker-package/
      code/
        worker_logic.py
        bootstrap.py
      requirements.lock
      config.schema.json
      manifest.json         ← signed manifest (excluded from hash input)

Trust semantics: attestation is bound to namespace-key authorization
(x.* or org.*), not to personal authorship. The trust statement reads:

    "Package attested by namespace <ns> at <UTC>; package hash sha256:<hash>."

Deny codes (fail-closed — no silent fallback):
    ATTEST_MANIFEST_MISSING      manifest.json does not exist or is unreadable
    ATTEST_MANIFEST_ID_MISMATCH  manifest worker_id/worker_species_id != declared
    ATTEST_HASH_MISMATCH         recomputed package hash != manifest package_hash
    ATTEST_SIGNATURE_MISSING     no signature in manifest or no signing secret set
    ATTEST_SIG_INVALID           HMAC-SHA256 signature does not match

Signing model: HMAC-SHA256 for portability and self-contained operation.
For production deployments, replace with Ed25519 asymmetric signing and
store the public key in the pyhall.dev registry.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Deny codes
# ---------------------------------------------------------------------------

ATTEST_MANIFEST_MISSING = "ATTEST_MANIFEST_MISSING"
ATTEST_MANIFEST_ID_MISMATCH = "ATTEST_MANIFEST_ID_MISMATCH"
ATTEST_HASH_MISMATCH = "ATTEST_HASH_MISMATCH"
ATTEST_SIGNATURE_MISSING = "ATTEST_SIGNATURE_MISSING"
ATTEST_SIG_INVALID = "ATTEST_SIG_INVALID"

# Manifest schema version
MANIFEST_SCHEMA_VERSION = "awp.v1"

# Default env var name for the HMAC signing secret
DEFAULT_SECRET_ENV = "WCP_ATTEST_HMAC_KEY"

# Files excluded from the canonical package hash.
# manifest.json is excluded because it CONTAINS the hash — including it
# would require iterative hashing. manifest.sig and manifest.tmp are
# transient signing artefacts.
_HASH_EXCLUDES: frozenset[str] = frozenset({
    ".git",
    "__pycache__",
    ".DS_Store",
    "manifest.json",
    "manifest.sig",
    "manifest.tmp",
})


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _namespace_from_species(worker_species_id: str) -> str:
    """Extract namespace prefix from a species ID (e.g. 'wrk.doc.summarizer' → 'wrk')."""
    return worker_species_id.split(".")[0] if "." in worker_species_id else worker_species_id


# ---------------------------------------------------------------------------
# Canonical package hash
# ---------------------------------------------------------------------------

def canonical_package_hash(package_root: Path) -> str:
    """
    Compute a deterministic SHA-256 hash over the full worker package content.

    Hash input format — one record per file, sorted lexicographically by
    relative POSIX path:

        <relative_posix_path>\\n<size_bytes>\\n<sha256_hex(file_content)>\\n

    Excluded from the hash: manifest.json, manifest.sig, manifest.tmp,
    .git/, __pycache__/, .DS_Store, and *.pyc files.

    This is the canonical identity of a worker package. Enrolling this hash
    in the registry proves that the holder of the namespace signing key
    authorized exactly this package content — code, dependencies, config, all.

    Args:
        package_root: Path to the worker package directory.

    Returns:
        64-character lowercase hex SHA-256 digest.
    """
    records: List[str] = []
    for p in sorted(package_root.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(package_root).as_posix()
        # Skip excluded file/directory names anywhere in the path
        if any(part in _HASH_EXCLUDES for part in p.parts):
            continue
        if p.name in _HASH_EXCLUDES:
            continue
        if rel.endswith(".pyc"):
            continue
        content = p.read_bytes()
        records.append(f"{rel}\n{len(content)}\n{_sha256_hex(content)}\n")
    return _sha256_hex("".join(records).encode("utf-8"))


# ---------------------------------------------------------------------------
# Manifest signing payload
# ---------------------------------------------------------------------------

def _canonical_manifest_payload(manifest: Dict[str, Any]) -> bytes:
    """
    Return the canonical bytes used as the HMAC signing input.

    Only a fixed subset of manifest fields are signed — this makes the
    signature stable even if the manifest gains optional fields later.
    """
    keys = [
        "schema_version",
        "worker_id",
        "worker_species_id",
        "worker_version",
        "package_hash",
        "built_at_utc",
        "build_source",
    ]
    payload = {k: manifest.get(k) for k in keys}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_hmac(manifest: Dict[str, Any], secret: str) -> str:
    return _hmac.new(secret.encode("utf-8"), _canonical_manifest_payload(manifest), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Build + write manifest
# ---------------------------------------------------------------------------

def build_manifest(
    package_root: Path,
    worker_id: str,
    worker_species_id: str,
    worker_version: str,
    signing_secret: str,
    build_source: str = "local",
) -> Dict[str, Any]:
    """
    Build and sign a worker package manifest.

    Computes the canonical package hash, assembles the manifest dict, and
    signs it with HMAC-SHA256.  The manifest is NOT written to disk — call
    ``write_manifest()`` after reviewing.

    Trust statement format (embedded in manifest):
        "Package attested by namespace <ns> at <UTC>; package hash sha256:<hash>."

    Args:
        package_root:      Directory containing the worker package.
        worker_id:         WCP worker instance ID (e.g. 'org.example.w.i-1').
        worker_species_id: WCP worker species ID (e.g. 'wrk.example.worker').
        worker_version:    Semver version string.
        signing_secret:    HMAC signing secret (namespace key holder).
        build_source:      Origin label: 'local' | 'ci' | 'agent'.

    Returns:
        Signed manifest dict ready to pass to ``write_manifest()``.
    """
    now = _utc_now_iso()
    ns = _namespace_from_species(worker_species_id)
    pkg_hash = canonical_package_hash(package_root)

    manifest: Dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "worker_id": worker_id,
        "worker_species_id": worker_species_id,
        "worker_version": worker_version,
        "package_hash": pkg_hash,
        "built_at_utc": now,
        "attested_at_utc": now,
        "build_source": build_source,
        "trust_statement": (
            f"Package attested by namespace {ns} at {now}; "
            f"package hash sha256:{pkg_hash}."
        ),
    }
    manifest["signature_hmac_sha256"] = _sign_hmac(manifest, signing_secret)
    return manifest


def write_manifest(manifest: Dict[str, Any], manifest_path: Path) -> None:
    """Write a signed manifest dict to disk as formatted JSON."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def scaffold_package(
    package_root: Path,
    worker_logic_file: Optional[Path] = None,
    overwrite: bool = False,
) -> None:
    """
    Create a minimal worker package directory layout.

    Optionally injects user/agent-provided business logic into
    ``code/worker_logic.py``.

    Layout created:
        <package_root>/
          code/
            bootstrap.py
            worker_logic.py   ← injected from worker_logic_file (or stub)
          requirements.lock
          config.schema.json

    Args:
        package_root:       Target directory (created if absent).
        worker_logic_file:  Path to the user's business logic .py file.
                            If None, a stub is written.
        overwrite:          If False, raises FileExistsError if
                            code/worker_logic.py already exists.

    Raises:
        FileExistsError: if worker_logic.py exists and overwrite=False.
    """
    package_root.mkdir(parents=True, exist_ok=True)
    code_dir = package_root / "code"
    code_dir.mkdir(parents=True, exist_ok=True)

    logic_target = code_dir / "worker_logic.py"
    if logic_target.exists() and not overwrite:
        raise FileExistsError(
            f"{logic_target} already exists. Pass overwrite=True to replace."
        )

    if worker_logic_file is not None:
        logic_target.write_text(worker_logic_file.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        logic_target.write_text(
            '"""Worker business logic — replace this stub with your implementation."""\n\n\ndef run():\n    raise NotImplementedError("Replace this stub with your worker logic.")\n',
            encoding="utf-8",
        )

    bootstrap = code_dir / "bootstrap.py"
    bootstrap.write_text(
        "#!/usr/bin/env python3\nfrom worker_logic import run\n\nif __name__ == '__main__':\n    run()\n",
        encoding="utf-8",
    )

    reqs = package_root / "requirements.lock"
    if not reqs.exists():
        reqs.write_text("# Pin your dependencies here — one package==version per line\n", encoding="utf-8")

    schema = package_root / "config.schema.json"
    if not schema.exists():
        schema.write_text(
            json.dumps({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {},
                "additionalProperties": True,
            }, indent=2) + "\n",
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# PackageAttestationVerifier
# ---------------------------------------------------------------------------

class PackageAttestationVerifier:
    """
    Verifies that a worker package is attested and unchanged at runtime.

    Fail-closed: any mismatch returns a deny code and ``ok=False``.
    No silent fallback execution.

    Deny codes returned:
        ATTEST_MANIFEST_MISSING      manifest.json absent or unreadable
        ATTEST_MANIFEST_ID_MISMATCH  manifest identity != declared worker identity
        ATTEST_HASH_MISMATCH         recomputed hash != manifest package_hash
        ATTEST_SIGNATURE_MISSING     no signature or no signing secret
        ATTEST_SIG_INVALID           HMAC does not verify

    Usage::

        verifier = PackageAttestationVerifier(
            package_root=Path("/opt/workers/my-worker"),
            manifest_path=Path("/opt/workers/my-worker/manifest.json"),
            worker_id="org.example.my-worker.instance-1",
            worker_species_id="wrk.example.my-worker",
        )
        ok, deny_code, meta = verifier.verify()
        if not ok:
            raise SystemExit(f"Attestation denied: {deny_code}")

        # meta["trust_statement"] contains the canonical namespace-key trust claim
        # meta["package_hash"] is the verified hash for embedding in evidence receipts
        # meta["verified_at_utc"] is UTC ISO 8601
    """

    def __init__(
        self,
        package_root: Path,
        manifest_path: Path,
        worker_id: str,
        worker_species_id: str,
        secret_env: str = DEFAULT_SECRET_ENV,
    ):
        self.package_root = package_root
        self.manifest_path = manifest_path
        self.worker_id = worker_id
        self.worker_species_id = worker_species_id
        self.secret_env = secret_env

    def verify(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Verify the worker package.

        Returns:
            (ok, deny_code, meta)

            ok:        True if the package passes all attestation checks.
            deny_code: None when ok=True; one of the ATTEST_* constants otherwise.
            meta:      Diagnostic dict.  When ok=True includes:
                         package_hash, manifest_schema, attested_at_utc,
                         verified_at_utc, trust_statement.
        """
        # 1. Manifest must exist and be parseable
        if not self.manifest_path.exists():
            return False, ATTEST_MANIFEST_MISSING, {}

        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return False, ATTEST_MANIFEST_MISSING, {"error": str(exc)}

        # 2. Identity check — manifest must declare the same worker
        if (
            manifest.get("worker_id") != self.worker_id
            or manifest.get("worker_species_id") != self.worker_species_id
        ):
            return False, ATTEST_MANIFEST_ID_MISMATCH, {
                "manifest_worker_id": manifest.get("worker_id"),
                "expected_worker_id": self.worker_id,
                "manifest_worker_species_id": manifest.get("worker_species_id"),
                "expected_worker_species_id": self.worker_species_id,
            }

        # 3. Package hash must match
        expected_hash = manifest.get("package_hash", "")
        computed_hash = canonical_package_hash(self.package_root)
        if not expected_hash or expected_hash != computed_hash:
            return False, ATTEST_HASH_MISMATCH, {
                "expected_hash": expected_hash,
                "computed_hash": computed_hash,
            }

        # 4. Signature must be present and valid
        sig = manifest.get("signature_hmac_sha256", "")
        secret = os.getenv(self.secret_env, "")
        if not sig or not secret:
            return False, ATTEST_SIGNATURE_MISSING, {
                "signature_present": bool(sig),
                "secret_env_set": bool(secret),
                "secret_env": self.secret_env,
            }

        expected_sig = _sign_hmac(manifest, secret)
        if not _hmac.compare_digest(sig, expected_sig):
            return False, ATTEST_SIG_INVALID, {}

        # All checks passed
        ns = _namespace_from_species(self.worker_species_id)
        verified_at = _utc_now_iso()
        attested_at = manifest.get("attested_at_utc", "unknown")
        return True, None, {
            "package_hash": computed_hash,
            "manifest_schema": manifest.get("schema_version"),
            "attested_at_utc": attested_at,
            "verified_at_utc": verified_at,
            "trust_statement": (
                f"Package attested by namespace {ns} at {attested_at}; "
                f"package hash sha256:{computed_hash}."
            ),
        }
