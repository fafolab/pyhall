"""Tests for P1 standing contract — go-online state mapping and route behavior."""
import pytest
from unittest.mock import patch, MagicMock
import urllib.error

# Test _standing_allows_online mapping
def test_ok_allows_online():
    from hall_api.server import _standing_allows_online
    assert _standing_allows_online('ok') is True

def test_grace_allows_online():
    from hall_api.server import _standing_allows_online
    assert _standing_allows_online('grace') is True

def test_degraded_blocks_online():
    from hall_api.server import _standing_allows_online
    assert _standing_allows_online('degraded') is False

def test_suspended_blocks_online():
    from hall_api.server import _standing_allows_online
    assert _standing_allows_online('suspended') is False

def test_unknown_standing_blocks_online():
    from hall_api.server import _standing_allows_online
    assert _standing_allows_online('unknown') is False
    assert _standing_allows_online('') is False

# Test go-online route
@pytest.fixture
def client():
    from hall_api.server import create_app
    app = create_app(testing=True)
    with app.test_client() as c:
        yield c

def test_go_online_ok_standing(client):
    with patch('hall_api.server._check_standing') as mock_check:
        mock_check.return_value = {
            'standing': 'ok',
            'tier_id': 'starter',
            'github_login': 'testuser',
            'checked_at': '2026-03-09T00:00:00Z',
        }
        resp = client.post('/api/server/go-online')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['ok'] is True
        assert data['account_standing'] == 'ok'

def test_go_online_grace_standing(client):
    with patch('hall_api.server._check_standing') as mock_check:
        mock_check.return_value = {
            'standing': 'grace',
            'tier_id': 'starter',
            'github_login': 'testuser',
            'checked_at': '2026-03-09T00:00:00Z',
        }
        resp = client.post('/api/server/go-online')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['ok'] is True

def test_go_online_degraded_blocked(client):
    with patch('hall_api.server._check_standing') as mock_check:
        mock_check.return_value = {
            'standing': 'degraded',
            'tier_id': 'free',
            'github_login': 'testuser',
            'checked_at': '2026-03-09T00:00:00Z',
        }
        resp = client.post('/api/server/go-online')
        assert resp.status_code == 403
        data = resp.get_json()
        assert data['ok'] is False
        assert data['account_standing'] == 'degraded'

def test_go_online_suspended_blocked(client):
    with patch('hall_api.server._check_standing') as mock_check:
        mock_check.return_value = {
            'standing': 'suspended',
            'tier_id': 'free',
            'github_login': 'testuser',
            'checked_at': '2026-03-09T00:00:00Z',
        }
        resp = client.post('/api/server/go-online')
        assert resp.status_code == 403
        data = resp.get_json()
        assert data['ok'] is False

def test_go_online_registry_unreachable(client):
    with patch('hall_api.server._check_standing') as mock_check:
        mock_check.side_effect = Exception('Connection refused')
        resp = client.post('/api/server/go-online')
        assert resp.status_code == 503

def test_go_online_registry_401(client):
    with patch('hall_api.server._check_standing') as mock_check:
        err = urllib.error.HTTPError(url='', code=401, msg='Unauthorized', hdrs=None, fp=None)
        mock_check.side_effect = err
        resp = client.post('/api/server/go-online')
        assert resp.status_code == 401

def test_go_offline(client):
    resp = client.post('/api/server/go-offline')
    assert resp.status_code == 200
    assert resp.get_json()['ok'] is True

def test_status_includes_online_and_standing(client):
    resp = client.get('/status')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'online' in data
    assert 'account_standing' in data
