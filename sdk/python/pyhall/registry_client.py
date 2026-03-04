"""
pyhall/registry_client.py — HTTP client for the pyhall.dev registry API (v0.2.0).

    from pyhall.registry_client import RegistryClient, RegistryRateLimitError

    client = RegistryClient()
    r = client.verify("x.my.worker")
    print(r.status)          # 'active' | 'revoked' | 'banned' | 'unknown'

    client.prefetch(["x.my.worker", "x.other.worker"])
    cb = client.get_worker_hash  # callable for make_decision()

Base URL: defaults to https://api.pyhall.dev; override via constructor or
PYHALL_REGISTRY_URL environment variable.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

from pyhall import __version__


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class VerifyResponse:
    worker_id: str
    status: str                         # 'active' | 'revoked' | 'banned' | 'unknown'
    current_hash: Optional[str]
    banned: bool
    ban_reason: Optional[str]
    attested_at: Optional[str]
    ai_generated: bool
    ai_service: Optional[str]
    ai_model: Optional[str]
    ai_session_fingerprint: Optional[str]


@dataclass
class BanEntry:
    sha256: str
    reason: str
    reported_at: str
    source: str
    review_status: Optional[str] = None


# ── Errors ────────────────────────────────────────────────────────────────────

class RegistryRateLimitError(Exception):
    """Raised when the registry API returns HTTP 429."""
    retryable: bool = True


# ── Client ────────────────────────────────────────────────────────────────────

_UNKNOWN_RESPONSE_FIELDS = dict(
    status='unknown', current_hash=None, banned=False, ban_reason=None,
    attested_at=None, ai_generated=False, ai_service=None,
    ai_model=None, ai_session_fingerprint=None,
)


class RegistryClient:
    """Thin HTTP client for the pyhall.dev worker registry API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        session_token: Optional[str] = None,
        timeout: int = 10,
        cache_ttl: float = 60.0,
    ) -> None:
        env_url = os.environ.get('PYHALL_REGISTRY_URL', 'https://api.pyhall.dev')
        self.base_url = (base_url or env_url).rstrip('/')
        self.session_token = session_token
        self.timeout = timeout
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, Tuple[VerifyResponse, float]] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def verify(self, worker_id: str) -> VerifyResponse:
        """GET /api/v1/verify/:id — 404 returns status='unknown' (IDOR-safe)."""
        cached = self._cache.get(worker_id)
        if cached and (time.monotonic() - cached[1]) < self._cache_ttl:
            return cached[0]

        try:
            data = self._get(f'/api/v1/verify/{urllib.parse.quote(worker_id, safe="")}')
            resp = VerifyResponse(**{k: data.get(k) for k in VerifyResponse.__dataclass_fields__})
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                resp = VerifyResponse(worker_id=worker_id, **_UNKNOWN_RESPONSE_FIELDS)  # type: ignore[arg-type]
            else:
                raise

        self._cache[worker_id] = (resp, time.monotonic())
        return resp

    def is_hash_banned(self, sha256: str) -> bool:
        """Returns True if the SHA-256 hash appears in the confirmed ban-list."""
        return any(e.sha256 == sha256 for e in self.get_ban_list())

    def get_ban_list(self, limit: int = 500) -> list[BanEntry]:
        """GET /api/v1/ban-list — returns all confirmed ban-list entries."""
        data = self._get(f'/api/v1/ban-list?limit={limit}')
        return [
            BanEntry(**{k: e.get(k) for k in BanEntry.__dataclass_fields__})
            for e in data
        ]

    def health(self) -> dict:
        """GET /health — returns {'ok': bool, 'version': str}."""
        return self._get('/health')

    def report_hash(self, sha256: str, reason: str, evidence_url: Optional[str] = None) -> None:
        """POST /api/v1/ban-list/report — requires session_token."""
        body: dict = {'sha256': sha256, 'reason': reason}
        if evidence_url:
            body['evidence_url'] = evidence_url
        self._post('/api/v1/ban-list/report', body)

    def prefetch(self, worker_ids: list[str]) -> None:
        """Pre-populate verify cache — non-fatal on 404 or rate limit."""
        for wid in worker_ids:
            try:
                self.verify(wid)
            except RegistryRateLimitError:
                raise
            except Exception:
                pass

    def get_worker_hash(self, worker_id: str) -> Optional[str]:
        """Returns current_hash for active workers; None otherwise.

        Suitable as the registry_get_worker_hash callback in make_decision().
        """
        r = self.verify(worker_id)
        if r.status not in ('active',):
            return None
        return r.current_hash

    # ── Internals ─────────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            'Accept': 'application/json',
            'User-Agent': f'pyhall-python/{__version__}',
        }
        if self.session_token:
            h['Cookie'] = f'pyhall_session={self.session_token}'
        return h

    def _get(self, path: str):
        req = urllib.request.Request(self.base_url + path, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise RegistryRateLimitError(
                    f'pyhall registry rate limit exceeded ({path})'
                ) from exc
            raise

    def _post(self, path: str, body: dict):
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={**self._headers(), 'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise RegistryRateLimitError(
                    f'pyhall registry rate limit exceeded ({path})'
                ) from exc
            raise
