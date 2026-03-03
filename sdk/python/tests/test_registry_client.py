"""
tests/test_registry_client.py — RegistryClient unit tests.

Uses unittest.mock to patch urllib.request.urlopen — no real HTTP calls.
"""

from __future__ import annotations

import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from pyhall.registry_client import BanEntry, RegistryClient, RegistryRateLimitError, VerifyResponse


# ── Fixtures / helpers ────────────────────────────────────────────────────────

ACTIVE_WORKER = {
    'worker_id': 'x.test.worker1',
    'status': 'active',
    'current_hash': 'a' * 64,
    'banned': False,
    'ban_reason': None,
    'attested_at': '2026-03-03T00:00:00Z',
    'ai_generated': False,
    'ai_service': None,
    'ai_model': None,
    'ai_session_fingerprint': None,
}

BAN_LIST = [
    {
        'sha256': 'b' * 64,
        'reason': 'malware',
        'reported_at': '2026-03-01T00:00:00Z',
        'source': 'community',
        'review_status': 'approved',
    },
]


def _mock_response(body, status=200):
    """Returns a context-manager mock for urllib.request.urlopen."""
    raw = json.dumps(body).encode()
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.read = MagicMock(return_value=raw)
    cm.status = status
    return cm


def _http_error(code: int):
    """Returns an HTTPError with the given code."""
    return urllib.error.HTTPError(
        url='https://api.pyhall.dev/test',
        code=code,
        msg=str(code),
        hdrs=None,  # type: ignore[arg-type]
        fp=BytesIO(b''),
    )


# ── verify() ─────────────────────────────────────────────────────────────────

class TestVerify:
    def test_returns_active_worker_fields(self):
        client = RegistryClient(base_url='https://api.pyhall.dev')
        with patch('urllib.request.urlopen', return_value=_mock_response(ACTIVE_WORKER)):
            r = client.verify('x.test.worker1')
        assert r.status == 'active'
        assert r.current_hash == 'a' * 64
        assert r.banned is False
        assert r.ai_generated is False

    def test_404_returns_unknown_not_error(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', side_effect=_http_error(404)):
            r = client.verify('x.nonexistent.worker')
        assert r.status == 'unknown'
        assert r.current_hash is None
        assert r.banned is False

    def test_429_raises_registry_rate_limit_error(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', side_effect=_http_error(429)):
            with pytest.raises(RegistryRateLimitError):
                client.verify('x.test.w')

    def test_500_raises_http_error(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', side_effect=_http_error(500)):
            with pytest.raises(urllib.error.HTTPError):
                client.verify('x.test.w')

    def test_cache_skips_second_fetch(self):
        client = RegistryClient()
        mock_open = MagicMock(return_value=_mock_response(ACTIVE_WORKER))
        with patch('urllib.request.urlopen', mock_open):
            client.verify('x.test.worker1')
            client.verify('x.test.worker1')
        assert mock_open.call_count == 1


# ── is_hash_banned() ─────────────────────────────────────────────────────────

class TestIsHashBanned:
    def test_returns_true_for_banned_hash(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', return_value=_mock_response(BAN_LIST)):
            assert client.is_hash_banned('b' * 64) is True

    def test_returns_false_for_clean_hash(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', return_value=_mock_response(BAN_LIST)):
            assert client.is_hash_banned('c' * 64) is False


# ── get_ban_list() ────────────────────────────────────────────────────────────

class TestGetBanList:
    def test_returns_ban_entries(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', return_value=_mock_response(BAN_LIST)):
            entries = client.get_ban_list()
        assert len(entries) == 1
        assert entries[0].sha256 == 'b' * 64
        assert entries[0].review_status == 'approved'

    def test_includes_limit_in_url(self):
        client = RegistryClient()
        mock_open = MagicMock(return_value=_mock_response([]))
        with patch('urllib.request.urlopen', mock_open):
            client.get_ban_list(limit=100)
        called_url = mock_open.call_args[0][0].full_url
        assert 'limit=100' in called_url


# ── health() ─────────────────────────────────────────────────────────────────

class TestHealth:
    def test_returns_version_and_ok(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', return_value=_mock_response({'ok': True, 'version': '0.2.0'})):
            h = client.health()
        assert h['version'] == '0.2.0'
        assert h['ok'] is True


# ── get_worker_hash() ─────────────────────────────────────────────────────────

class TestGetWorkerHash:
    def test_returns_hash_for_active_worker(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', return_value=_mock_response(ACTIVE_WORKER)):
            assert client.get_worker_hash('x.test.worker1') == 'a' * 64

    def test_returns_none_for_unknown_worker(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', side_effect=_http_error(404)):
            assert client.get_worker_hash('x.nonexistent') is None

    def test_returns_none_for_banned_worker(self):
        banned = {**ACTIVE_WORKER, 'status': 'banned'}
        client = RegistryClient()
        with patch('urllib.request.urlopen', return_value=_mock_response(banned)):
            assert client.get_worker_hash('x.test.worker1') is None


# ── prefetch() ────────────────────────────────────────────────────────────────

class TestPrefetch:
    def test_populates_cache(self):
        client = RegistryClient()
        mock_open = MagicMock(return_value=_mock_response(ACTIVE_WORKER))
        with patch('urllib.request.urlopen', mock_open):
            client.prefetch(['x.test.worker1'])
            client.verify('x.test.worker1')  # should hit cache
        assert mock_open.call_count == 1

    def test_non_fatal_on_404(self):
        client = RegistryClient()
        with patch('urllib.request.urlopen', side_effect=_http_error(404)):
            client.prefetch(['x.nonexistent'])  # must not raise
        assert client.get_worker_hash('x.nonexistent') is None
