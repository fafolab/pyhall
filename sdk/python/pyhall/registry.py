"""
pyhall/registry.py — WCP Worker Registry.

The Registry is the Hall's source of truth for enrolled workers.

Workers enroll by providing a JSON registry record. The Registry:
  - Tracks which worker species are available
  - Maps capabilities to species
  - Tracks which controls are present
  - Enforces privilege envelope policies

For production: back this with a persistent store (SQLite, PostgreSQL,
or a remote registry API). For development and testing: use the in-memory
load from JSON files.

Worker registry record format (see WCP spec section 6):

    {
      "worker_id": "org.example.my-summarizer",
      "worker_species_id": "wrk.doc.summarizer",
      "capabilities": ["cap.doc.summarize"],
      "risk_tier": "low",
      "required_controls": ["ctrl.obs.audit-log-append-only"],
      "currently_implements": ["ctrl.obs.audit-log-append-only"],
      "allowed_environments": ["dev", "stage", "prod"],
      "blast_radius": {"data": 1, "network": 0, "financial": 0, "time": 1},
      "privilege_envelope": {
        "secrets_access": [],
        "network_egress": "none",
        "filesystem_writes": ["/tmp/"],
        "tools": []
      },
      "owner": "org.example",
      "contact": "team@example.com"
    }
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# F10: Valid WCP control ID format — ctrl.<namespace>.<name>
# Underscores are permitted (e.g. ctrl.blast_radius_scoring, ctrl.privilege_envelopes_required).
_VALID_CTRL_RE = re.compile(r'^ctrl\.[a-z0-9][a-z0-9._\-]*$')

# F13: Valid SHA-256 hash format — 64 lowercase hex chars
_VALID_HASH_RE = re.compile(r'^[0-9a-f]{64}$')


class Registry:
    """
    WCP Worker Registry.

    Loads enrollment records from a directory of JSON files.
    Provides capability lookups, controls tracking, and privilege enforcement
    for the router.

    Usage:
        # Load from a directory of JSON enrollment records
        registry = Registry(registry_dir="/path/to/enrolled/")

        # Or build programmatically for tests
        registry = Registry()
        registry.enroll(record_dict)

    The router calls:
        registry.controls_present()         -> set[str]
        registry.worker_available(species)  -> bool
        registry.get_privilege_envelope(s)  -> dict | None
        registry.policy_allows_privilege(env, label, env) -> (bool, str)
    """

    def __init__(self, registry_dir: Optional[str] = None):
        self._controls_present: set[str] = set()
        self._workers_available: set[str] = set()
        self._privilege_envelopes: Dict[str, dict] = {}
        self._enrolled: Dict[str, dict] = {}        # worker_id -> record
        self._capabilities_map: Dict[str, List[str]] = {}  # cap_id -> [species, ...]

        # Worker Code Attestation (WCP §5.10)
        self._attestation_hashes: Dict[str, str] = {}   # species_id -> registered SHA-256
        self._attestation_files: Dict[str, Path] = {}   # species_id -> source file path

        # Per-env egress allowlists (stub). Replace with real policy.
        self._egress_allowlist: Dict[str, List[str]] = {
            "dev": [],
            "stage": [],
            "prod": [],
            "edge": [],
        }

        # F17: Allowed base directories for worker source files.
        # Empty = no restriction (default, backward compat).
        # When set, source_file must resolve within one of these directories.
        self._allowed_worker_dirs: List[str] = []

        if registry_dir is not None:
            self._load_enrolled(Path(registry_dir))

    # -----------------------------------------------------------------------
    # Enrollment
    # -----------------------------------------------------------------------

    def _load_enrolled(self, dir_path: Path) -> None:
        """Load all worker JSON records from a directory."""
        if not dir_path.exists():
            return

        for record_file in sorted(dir_path.glob("*.json")):
            try:
                record = json.loads(record_file.read_text(encoding="utf-8"))
                self.enroll(record)
            except Exception as exc:
                print(
                    f"[pyhall.registry] WARNING: could not load {record_file}: {exc}",
                    file=sys.stderr,
                )

    def enroll(self, record: Dict[str, Any]) -> None:
        """
        Enroll a single worker from a registry record dict.

        Args:
            record: Worker registry record (see module docstring for schema).
        """
        worker_id = record.get("worker_id", f"unknown-{len(self._enrolled)}")
        self._enrolled[worker_id] = record

        species_id = record.get("worker_species_id")
        if species_id:
            self._workers_available.add(species_id)

        for cap in record.get("capabilities", []):
            self._capabilities_map.setdefault(cap, [])
            if species_id and species_id not in self._capabilities_map[cap]:
                self._capabilities_map[cap].append(species_id)

        for ctrl in record.get("currently_implements", []):
            # F10: Validate control ID format — reject arbitrary strings that
            # could poison the controls set and bypass governance checks.
            if not _VALID_CTRL_RE.match(ctrl):
                print(
                    f"[pyhall.registry] WARNING: invalid control ID rejected at enrollment "
                    f"for worker '{worker_id}': {ctrl!r}",
                    file=sys.stderr,
                )
                continue
            self._controls_present.add(ctrl)

        env_envelope = record.get("privilege_envelope")
        if env_envelope and species_id:
            self._privilege_envelopes[species_id] = env_envelope

        # Parse attestation block from JSON record (WCP §5.10 enrollment format)
        attestation = record.get("attestation")
        if attestation and species_id:
            code_hash = attestation.get("code_hash")
            source_file = attestation.get("source_file")
            if code_hash:
                # F13: Validate hash format at enrollment — fail loudly here rather
                # than mysteriously at dispatch time.
                if _VALID_HASH_RE.match(str(code_hash)):
                    self._attestation_hashes[species_id] = str(code_hash)
                else:
                    print(
                        f"[pyhall.registry] WARNING: invalid code_hash format for "
                        f"species '{species_id}', skipped. Must be 64 lowercase hex chars.",
                        file=sys.stderr,
                    )
            if source_file:
                # F17: Validate source_file is within allowed worker directories.
                path = Path(source_file)
                if self._is_path_allowed(path):
                    self._attestation_files[species_id] = path
                else:
                    print(
                        f"[pyhall.registry] WARNING: source_file for '{species_id}' is outside "
                        f"allowed worker directories, skipped: {source_file!r}",
                        file=sys.stderr,
                    )

    # -----------------------------------------------------------------------
    # Source file path allowlist (WCP §5.10 — F17)
    # -----------------------------------------------------------------------

    def set_allowed_worker_dirs(self, dirs: List[str]) -> None:
        """
        Restrict worker source_file paths to these base directories.

        When set, any source_file that does not resolve within one of these
        directories is rejected at enrollment and registration time.
        This prevents path traversal attacks via enrollment records.

        Args:
            dirs: List of absolute directory paths (e.g. ['/opt/workers/']).
                  Pass an empty list to remove restrictions.
        """
        self._allowed_worker_dirs = [str(Path(d).resolve()) for d in dirs]

    def _is_path_allowed(self, path: Path) -> bool:
        """Return True if path is within an allowed worker directory (or no restrictions set)."""
        if not self._allowed_worker_dirs:
            return True
        try:
            resolved = str(path.resolve())
        except Exception:
            return False
        # F27: Use exact match OR startswith(allowed + "/") to prevent prefix collision.
        # Without the path separator, "/tmp/workers" would incorrectly allow "/tmp/workers_evil/".
        return any(
            resolved == allowed or resolved.startswith(allowed + "/")
            for allowed in self._allowed_worker_dirs
        )

    # -----------------------------------------------------------------------
    # Worker Code Attestation (WCP §5.10)
    # -----------------------------------------------------------------------

    @staticmethod
    def _hash_file(path: Path) -> Optional[str]:
        """
        Read a file from disk and compute its SHA-256 digest.

        Reads the CURRENT on-disk content every call — bypasses Python's
        import cache so runtime file modifications are detected.

        Returns None if the file cannot be read.
        """
        try:
            content = path.read_bytes()
            return hashlib.sha256(content).hexdigest()
        except OSError:
            return None

    def register_attestation(self, species_id: str, source_file: str) -> str:
        """
        Register a worker's code hash by hashing its source file now.

        Call this at Hall startup (or worker enrollment time) to snapshot the
        known-good state of each worker file. The hash is stored as the
        registered hash for this species.

        Args:
            species_id:   WCP worker species ID (e.g. 'wrk.doc.summarizer').
            source_file:  Absolute path to the worker's Python source file.

        Returns:
            The computed SHA-256 hex digest (64 lowercase hex chars).

        Raises:
            FileNotFoundError: if the source file does not exist.
            ValueError: if the hash cannot be computed.
        """
        path = Path(source_file)
        if not path.exists():
            raise FileNotFoundError(f"Worker source file not found: {source_file}")
        # F17: Validate against allowed worker directories before reading the file.
        if not self._is_path_allowed(path):
            raise ValueError(
                f"source_file {source_file!r} is outside allowed worker directories. "
                f"Allowed: {self._allowed_worker_dirs or ['(no restrictions set)']}"
            )
        digest = self._hash_file(path)
        if digest is None:
            raise ValueError(f"Could not hash worker file: {source_file}")
        self._attestation_hashes[species_id] = digest
        self._attestation_files[species_id] = path
        return digest

    def get_worker_hash(self, species_id: str) -> Optional[str]:
        """
        Return the registered (known-good) SHA-256 hash for a worker species.

        This is the snapshot taken at enrollment / startup. Use as
        registry_get_worker_hash in make_decision().

        Returns None if the worker has no registered attestation hash.
        """
        return self._attestation_hashes.get(species_id)

    def compute_current_hash(self, species_id: str) -> Optional[str]:
        """
        Read the worker's source file from disk RIGHT NOW and compute its hash.

        This is the live check. Use as get_current_worker_hash in make_decision().

        Every call reads from disk — Python's import cache is bypassed.
        If the file was modified since register_attestation() was called, the
        hash will differ from get_worker_hash() and the Hall will deny dispatch.

        Returns None if the file path is unknown or unreadable.
        """
        path = self._attestation_files.get(species_id)
        if path is None:
            return None
        return self._hash_file(path)

    def attestation_callables(self):
        """
        Return the (registry_get_worker_hash, get_current_worker_hash) tuple
        for direct use in make_decision().

        Usage:
            reg_hash, cur_hash = registry.attestation_callables()
            make_decision(
                ...,
                registry_get_worker_hash=reg_hash,
                get_current_worker_hash=cur_hash,
            )
        """
        return self.get_worker_hash, self.compute_current_hash

    # -----------------------------------------------------------------------
    # Controls
    # -----------------------------------------------------------------------

    def set_controls_present(self, controls: List[str]) -> None:
        """Override the full set of present controls (replaces existing set).

        Invalid control IDs (those not matching ctrl.<namespace>.<name> format)
        are rejected with a warning and excluded from the set.
        """
        validated: set[str] = set()
        for ctrl in controls:
            if _VALID_CTRL_RE.match(ctrl):
                validated.add(ctrl)
            else:
                print(
                    f"[pyhall.registry] WARNING: invalid control ID rejected in "
                    f"set_controls_present(): {ctrl!r}",
                    file=sys.stderr,
                )
        self._controls_present = validated

    def add_controls_present(self, controls: List[str]) -> None:
        """Add controls to the existing set (additive).

        Invalid control IDs (those not matching ctrl.<namespace>.<name> format)
        are rejected with a warning and not added.
        """
        for ctrl in controls:
            if _VALID_CTRL_RE.match(ctrl):
                self._controls_present.add(ctrl)
            else:
                print(
                    f"[pyhall.registry] WARNING: invalid control ID rejected in "
                    f"add_controls_present(): {ctrl!r}",
                    file=sys.stderr,
                )

    def controls_present(self) -> set[str]:
        """Return the set of currently declared controls."""
        return set(self._controls_present)

    # -----------------------------------------------------------------------
    # Worker availability
    # -----------------------------------------------------------------------

    def set_workers_available(self, worker_species_ids: List[str]) -> None:
        """Override the full set of available worker species."""
        self._workers_available = set(worker_species_ids)

    def add_workers_available(self, worker_species_ids: List[str]) -> None:
        """Mark additional worker species as available."""
        self._workers_available.update(worker_species_ids)

    def worker_available(self, worker_species_id: str) -> bool:
        """Return True if the species is enrolled and available."""
        return worker_species_id in self._workers_available

    def workers_for_capability(self, capability_id: str) -> List[str]:
        """Return list of enrolled worker species that handle this capability."""
        return list(self._capabilities_map.get(capability_id, []))

    # -----------------------------------------------------------------------
    # Privilege envelopes
    # -----------------------------------------------------------------------

    def set_privilege_envelopes(self, envelopes: Dict[str, dict]) -> None:
        """Map worker_species_id -> privilege envelope dict."""
        self._privilege_envelopes = dict(envelopes)

    def get_privilege_envelope(self, worker_species_id: str) -> Optional[dict]:
        """Return the privilege envelope for a species, or None."""
        return self._privilege_envelopes.get(worker_species_id)

    def set_egress_allowlist(self, env: str, allowlist: List[str]) -> None:
        """Configure the egress allowlist for an environment."""
        self._egress_allowlist[env] = list(allowlist)

    def policy_allows_privilege(
        self,
        env: str,
        data_label: str,
        envelope: Optional[dict],
    ) -> Tuple[bool, str]:
        """
        Evaluate whether the privilege envelope is allowed for this
        environment and data label.

        This is a stub implementation. In production, replace with your
        organization's Pack 27 egress/secrets/write/tool policy engine.

        Returns:
            (allowed: bool, reason: str)
        """
        egress = (envelope or {}).get("egress") or {}
        if env in ("prod", "edge") and data_label == "RESTRICTED":
            dests = egress.get("allowlist") or []
            if dests:
                allowed_list = self._egress_allowlist.get(env, [])
                if allowed_list:
                    for dest in dests:
                        if dest not in allowed_list:
                            return (False, f"egress_not_allowlisted:{dest}")
                else:
                    return (False, "egress_denied_no_allowlist_configured")
        return (True, "stub_allow")

    # -----------------------------------------------------------------------
    # Introspection
    # -----------------------------------------------------------------------

    def enrolled_count(self) -> int:
        """Return the number of enrolled workers."""
        return len(self._enrolled)

    def enrolled_workers(self) -> List[dict]:
        """Return list of all enrolled worker records."""
        return list(self._enrolled.values())

    def summary(self) -> dict:
        """Return a status summary dict for display or health checks."""
        return {
            "enrolled_workers": self.enrolled_count(),
            "available_species": sorted(self._workers_available),
            "controls_present_count": len(self._controls_present),
            "controls_present": sorted(self._controls_present),
            "capabilities_mapped": sorted(self._capabilities_map.keys()),
        }
