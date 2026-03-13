# Copyright (c) 2026 pyhall.dev — https://pyhall.dev
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""
Tests for pyhall.mcp.server — dynamic worker registry and routing.

Tests cover:
  - get_enrolled_workers() with mocked Hall Server response
  - get_enrolled_workers() when Hall Server is unreachable (returns [])
  - build_tool_from_worker() produces valid MCP tool schema
  - handle_tools_list() returns dynamic tools + static summarize_document
  - handle_tools_call() routes dynamic tool calls to POST /api/route
  - handle_tools_call() handles Hall Server routing errors gracefully
  - handle_tools_call() still handles the static summarize_document tool
  - refresh_tools() updates the module-level caches
  - handle_initialize() triggers refresh_tools()
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the sdk/python root is on sys.path (conftest.py also does this).
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Set PYHALL_MCP_STRICT=0 so the module loads without a real PolicyGate.
os.environ.setdefault("PYHALL_MCP_STRICT", "0")

import pyhall.mcp.server as _srv


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SENTINEL = object()


def _make_worker(
    worker_id: str = "org.example.text-classifier",
    worker_species_id: str = "wrk.nlp.classifier",
    capabilities: list | None = _SENTINEL,  # type: ignore[assignment]
    risk_tier: str = "low",
) -> dict:
    if capabilities is _SENTINEL:
        capabilities = ["cap.nlp.classify"]
    return {
        "worker_id": worker_id,
        "worker_species_id": worker_species_id,
        "capabilities": capabilities,
        "risk_tier": risk_tier,
        "enrolled_at": "2026-03-12T00:00:00Z",
        "status": "active",
    }


# ---------------------------------------------------------------------------
# get_enrolled_workers()
# ---------------------------------------------------------------------------

class TestGetEnrolledWorkers(unittest.TestCase):

    def test_returns_workers_on_success(self):
        """get_enrolled_workers() extracts workers list from Hall Server response."""
        workers = [_make_worker(), _make_worker(worker_id="org.example.other")]
        mock_response = {"workers": workers, "count": 2}
        with patch.object(_srv, "_fetch_hall_server", return_value=mock_response):
            result = _srv.get_enrolled_workers()
        self.assertEqual(result, workers)

    def test_returns_empty_list_when_hall_server_unreachable(self):
        """get_enrolled_workers() returns [] gracefully when Hall Server is down."""
        error_response = {"error": "Hall Server unreachable: Connection refused", "data": []}
        with patch.object(_srv, "_fetch_hall_server", return_value=error_response):
            result = _srv.get_enrolled_workers()
        self.assertEqual(result, [])

    def test_returns_empty_list_when_workers_key_missing(self):
        """get_enrolled_workers() returns [] if response has no 'workers' key."""
        with patch.object(_srv, "_fetch_hall_server", return_value={}):
            result = _srv.get_enrolled_workers()
        self.assertEqual(result, [])

    def test_returns_empty_list_when_workers_not_a_list(self):
        """get_enrolled_workers() returns [] if 'workers' value is not a list."""
        with patch.object(_srv, "_fetch_hall_server", return_value={"workers": None}):
            result = _srv.get_enrolled_workers()
        self.assertEqual(result, [])

    def test_calls_correct_endpoint(self):
        """get_enrolled_workers() queries /api/workers on the Hall Server."""
        with patch.object(_srv, "_fetch_hall_server", return_value={"workers": []}) as mock_fetch:
            _srv.get_enrolled_workers()
        mock_fetch.assert_called_once_with("/api/workers")


# ---------------------------------------------------------------------------
# build_tool_from_worker()
# ---------------------------------------------------------------------------

class TestBuildToolFromWorker(unittest.TestCase):

    def setUp(self):
        self.worker = _make_worker()
        self.tool = _srv.build_tool_from_worker(self.worker)

    def test_tool_has_required_keys(self):
        """build_tool_from_worker() returns a dict with name, description, inputSchema."""
        for key in ("name", "description", "inputSchema"):
            self.assertIn(key, self.tool, f"Missing key: {key}")

    def test_tool_name_prefixed_with_hall_worker(self):
        """Tool name starts with 'hall_worker_' prefix."""
        self.assertTrue(self.tool["name"].startswith("hall_worker_"))

    def test_tool_name_sanitized(self):
        """Tool name contains only alphanumeric characters and underscores."""
        name = self.tool["name"]
        for ch in name:
            self.assertTrue(ch.isalnum() or ch == "_", f"Invalid char in tool name: {ch!r}")

    def test_tool_name_derived_from_worker_id(self):
        """Tool name encodes the worker_id (dots replaced with underscores)."""
        # "org.example.text-classifier" -> "hall_worker_org_example_text_classifier"
        self.assertEqual(self.tool["name"], "hall_worker_org_example_text_classifier")

    def test_input_schema_is_valid_json_schema_object(self):
        """inputSchema is a JSON Schema object with type=object."""
        schema = self.tool["inputSchema"]
        self.assertEqual(schema["type"], "object")
        self.assertIn("properties", schema)
        self.assertIn("required", schema)

    def test_input_schema_has_payload_property(self):
        """inputSchema includes a 'payload' property (required)."""
        props = self.tool["inputSchema"]["properties"]
        self.assertIn("payload", props)
        self.assertIn("payload", self.tool["inputSchema"]["required"])

    def test_input_schema_has_env_property(self):
        """inputSchema includes an 'env' property with enum values."""
        props = self.tool["inputSchema"]["properties"]
        self.assertIn("env", props)
        self.assertIn("dev", props["env"]["enum"])

    def test_description_contains_worker_id(self):
        """Tool description mentions the worker_id."""
        self.assertIn(self.worker["worker_id"], self.tool["description"])

    def test_description_contains_capability(self):
        """Tool description mentions the primary capability."""
        self.assertIn("cap.nlp.classify", self.tool["description"])

    def test_internal_metadata_fields_present(self):
        """build_tool_from_worker() adds _worker_id and _primary_capability."""
        self.assertIn("_worker_id", self.tool)
        self.assertIn("_primary_capability", self.tool)
        self.assertEqual(self.tool["_worker_id"], self.worker["worker_id"])
        self.assertEqual(self.tool["_primary_capability"], "cap.nlp.classify")

    def test_empty_capabilities_handled_gracefully(self):
        """build_tool_from_worker() handles workers with no capabilities."""
        worker = _make_worker(capabilities=[])
        tool = _srv.build_tool_from_worker(worker)
        self.assertIn("name", tool)
        self.assertEqual(tool["_primary_capability"], "cap.unknown")

    def test_multiple_capabilities_all_mentioned(self):
        """build_tool_from_worker() mentions all capabilities in description."""
        worker = _make_worker(capabilities=["cap.a.foo", "cap.b.bar"])
        tool = _srv.build_tool_from_worker(worker)
        self.assertIn("cap.a.foo", tool["description"])
        self.assertIn("cap.b.bar", tool["description"])


# ---------------------------------------------------------------------------
# refresh_tools()
# ---------------------------------------------------------------------------

class TestRefreshTools(unittest.TestCase):

    def test_updates_dynamic_tools_cache(self):
        """refresh_tools() updates the module-level _DYNAMIC_TOOLS list."""
        workers = [_make_worker()]
        with patch.object(_srv, "get_enrolled_workers", return_value=workers):
            tools = _srv.refresh_tools()
        self.assertEqual(len(tools), 1)
        self.assertTrue(tools[0]["name"].startswith("hall_worker_"))

    def test_empty_when_no_workers(self):
        """refresh_tools() sets _DYNAMIC_TOOLS to [] when no workers enrolled."""
        with patch.object(_srv, "get_enrolled_workers", return_value=[]):
            tools = _srv.refresh_tools()
        self.assertEqual(tools, [])
        self.assertEqual(_srv._DYNAMIC_TOOLS, [])

    def test_updates_dynamic_workers_cache(self):
        """refresh_tools() updates _DYNAMIC_WORKERS with raw worker records."""
        workers = [_make_worker(worker_id="org.example.x")]
        with patch.object(_srv, "get_enrolled_workers", return_value=workers):
            _srv.refresh_tools()
        self.assertEqual(_srv._DYNAMIC_WORKERS, workers)


# ---------------------------------------------------------------------------
# handle_tools_list()
# ---------------------------------------------------------------------------

class TestHandleToolsList(unittest.TestCase):

    def test_returns_summarize_document_when_no_dynamic_tools(self):
        """tools/list returns summarize_document when _DYNAMIC_TOOLS is empty."""
        original = _srv._DYNAMIC_TOOLS[:]
        _srv._DYNAMIC_TOOLS.clear()
        try:
            resp = _srv.handle_tools_list({}, 1)
            tools = resp["result"]["tools"]
            names = [t["name"] for t in tools]
            self.assertIn("summarize_document", names)
        finally:
            _srv._DYNAMIC_TOOLS[:] = original

    def test_includes_dynamic_tools_when_present(self):
        """tools/list includes dynamic enrolled-worker tools when available."""
        worker = _make_worker()
        dynamic_tool = _srv.build_tool_from_worker(worker)
        original = _srv._DYNAMIC_TOOLS[:]
        _srv._DYNAMIC_TOOLS[:] = [dynamic_tool]
        try:
            resp = _srv.handle_tools_list({}, 1)
            tools = resp["result"]["tools"]
            names = [t["name"] for t in tools]
            self.assertIn(dynamic_tool["name"], names)
        finally:
            _srv._DYNAMIC_TOOLS[:] = original

    def test_always_includes_summarize_document_with_dynamic_tools(self):
        """tools/list always includes summarize_document alongside dynamic tools."""
        worker = _make_worker()
        dynamic_tool = _srv.build_tool_from_worker(worker)
        original = _srv._DYNAMIC_TOOLS[:]
        _srv._DYNAMIC_TOOLS[:] = [dynamic_tool]
        try:
            resp = _srv.handle_tools_list({}, 1)
            tools = resp["result"]["tools"]
            names = [t["name"] for t in tools]
            self.assertIn("summarize_document", names)
        finally:
            _srv._DYNAMIC_TOOLS[:] = original

    def test_dynamic_tools_strip_internal_metadata(self):
        """tools/list strips _worker_id and _primary_capability from exposed tools."""
        worker = _make_worker()
        dynamic_tool = _srv.build_tool_from_worker(worker)
        original = _srv._DYNAMIC_TOOLS[:]
        _srv._DYNAMIC_TOOLS[:] = [dynamic_tool]
        try:
            resp = _srv.handle_tools_list({}, 1)
            for tool in resp["result"]["tools"]:
                if tool.get("name", "").startswith("hall_worker_"):
                    self.assertNotIn("_worker_id", tool)
                    self.assertNotIn("_primary_capability", tool)
        finally:
            _srv._DYNAMIC_TOOLS[:] = original


# ---------------------------------------------------------------------------
# handle_tools_call() — dynamic worker routing via POST /api/route
# ---------------------------------------------------------------------------

class TestHandleToolsCallDynamic(unittest.TestCase):

    def setUp(self):
        self.worker = _make_worker()
        self.tool_def = _srv.build_tool_from_worker(self.worker)
        # Inject the dynamic tool into the module cache
        self._orig = _srv._DYNAMIC_TOOLS[:]
        _srv._DYNAMIC_TOOLS[:] = [self.tool_def]

    def tearDown(self):
        _srv._DYNAMIC_TOOLS[:] = self._orig

    def _call(self, tool_name: str, arguments: dict) -> dict:
        params = {"name": tool_name, "arguments": arguments}
        return _srv.handle_tools_call(params, req_id=42)

    def test_routes_to_post_api_route(self):
        """Dynamic tool call POSTs to Hall Server /api/route with correct body."""
        decision_result = {
            "decision_id": "dec_abc",
            "matched_rule_id": "auto.cap.nlp.classify.wrk.nlp.classifier",
            "outcome": "APPROVED",
        }
        with patch.object(_srv, "_post_hall_route", return_value=decision_result) as mock_post:
            resp = self._call(
                self.tool_def["name"],
                {"payload": {"text": "classify this"}, "env": "dev"},
            )
        mock_post.assert_called_once()
        call_body = mock_post.call_args[0][0]
        self.assertEqual(call_body["capability_id"], "cap.nlp.classify")
        self.assertEqual(call_body["env"], "dev")
        self.assertEqual(call_body["tenant_id"], "mcp-client")
        self.assertIn("request", call_body)
        self.assertEqual(call_body["request"], {"text": "classify this"})

    def test_response_contains_routed_to_and_result(self):
        """Dynamic tool call response contains routed_to, result, routing_metadata."""
        decision_result = {"outcome": "APPROVED", "decision_id": "dec_xyz"}
        with patch.object(_srv, "_post_hall_route", return_value=decision_result):
            resp = self._call(
                self.tool_def["name"],
                {"payload": {"text": "hello"}},
            )
        self.assertIn("result", resp)
        content = resp["result"]["content"][0]["text"]
        parsed = json.loads(content)
        self.assertIn("routed_to", parsed)
        self.assertEqual(parsed["routed_to"], self.worker["worker_id"])
        self.assertIn("result", parsed)
        self.assertIn("routing_metadata", parsed)

    def test_uses_custom_tenant_id(self):
        """Dynamic tool call forwards custom tenant_id to Hall Server."""
        with patch.object(_srv, "_post_hall_route", return_value={}) as mock_post:
            self._call(
                self.tool_def["name"],
                {"payload": {}, "tenant_id": "org.custom.tenant"},
            )
        call_body = mock_post.call_args[0][0]
        self.assertEqual(call_body["tenant_id"], "org.custom.tenant")

    def test_defaults_env_to_dev(self):
        """Dynamic tool call defaults env to 'dev' when not specified."""
        with patch.object(_srv, "_post_hall_route", return_value={}) as mock_post:
            self._call(self.tool_def["name"], {"payload": {}})
        call_body = mock_post.call_args[0][0]
        self.assertEqual(call_body["env"], "dev")

    def test_invalid_env_falls_back_to_dev(self):
        """Dynamic tool call coerces unknown env values to 'dev'."""
        with patch.object(_srv, "_post_hall_route", return_value={}) as mock_post:
            self._call(self.tool_def["name"], {"payload": {}, "env": "bogus"})
        call_body = mock_post.call_args[0][0]
        self.assertEqual(call_body["env"], "dev")

    def test_hall_server_error_returns_mcp_error(self):
        """Dynamic tool call returns MCP error when Hall Server routing fails."""
        with patch.object(
            _srv, "_post_hall_route",
            return_value={"error": "connection refused"},
        ):
            resp = self._call(self.tool_def["name"], {"payload": {}})
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32603)
        self.assertIn(self.worker["worker_id"], resp["error"]["message"])

    def test_invalid_arguments_returns_mcp_error(self):
        """Dynamic tool call with non-dict arguments returns -32602 error."""
        params = {"name": self.tool_def["name"], "arguments": "bad"}
        resp = _srv.handle_tools_call(params, req_id=1)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32602)


# ---------------------------------------------------------------------------
# handle_tools_call() — unknown tool
# ---------------------------------------------------------------------------

class TestHandleToolsCallUnknown(unittest.TestCase):

    def setUp(self):
        # Ensure _DYNAMIC_TOOLS is empty so unknown tool lookup falls through correctly
        self._orig = _srv._DYNAMIC_TOOLS[:]
        _srv._DYNAMIC_TOOLS.clear()

    def tearDown(self):
        _srv._DYNAMIC_TOOLS[:] = self._orig

    def test_unknown_tool_returns_method_not_found(self):
        """tools/call with unknown tool name returns -32601 error."""
        params = {"name": "nonexistent_tool", "arguments": {}}
        resp = _srv.handle_tools_call(params, req_id=1)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)


# ---------------------------------------------------------------------------
# handle_initialize() — triggers refresh_tools
# ---------------------------------------------------------------------------

class TestHandleInitialize(unittest.TestCase):

    def test_calls_refresh_tools_on_initialize(self):
        """handle_initialize() calls refresh_tools() to populate dynamic tool list."""
        with patch.object(_srv, "refresh_tools", return_value=[]) as mock_refresh:
            resp = _srv.handle_initialize({}, req_id=1)
        mock_refresh.assert_called_once()
        self.assertEqual(resp["result"]["protocolVersion"], "2024-11-05")

    def test_initialize_returns_valid_capabilities(self):
        """handle_initialize() returns tools, resources, and prompts capabilities."""
        with patch.object(_srv, "refresh_tools", return_value=[]):
            resp = _srv.handle_initialize({}, req_id=99)
        caps = resp["result"]["capabilities"]
        self.assertIn("tools", caps)
        self.assertIn("resources", caps)
        self.assertIn("prompts", caps)


# ---------------------------------------------------------------------------
# _post_hall_route() — HTTP POST helper
# ---------------------------------------------------------------------------

class TestPostHallRoute(unittest.TestCase):

    def test_posts_json_to_api_route(self):
        """_post_hall_route() sends POST to /api/route and parses JSON response."""
        mock_response_data = json.dumps({"outcome": "APPROVED"}).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read = MagicMock(return_value=mock_response_data)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _srv._post_hall_route({"capability_id": "cap.test", "env": "dev"})
        self.assertEqual(result.get("outcome"), "APPROVED")

    def test_returns_error_dict_on_failure(self):
        """_post_hall_route() returns {'error': ...} when connection fails."""
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            result = _srv._post_hall_route({"capability_id": "cap.test"})
        self.assertIn("error", result)

    def test_attaches_bearer_token_when_provided(self):
        """_post_hall_route() adds Authorization header when session_token provided."""
        captured = {}

        def mock_urlopen(req, timeout=None):
            captured["headers"] = dict(req.headers)
            mock_resp = MagicMock()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read = MagicMock(return_value=b'{}')
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            _srv._post_hall_route({"test": True}, session_token="tok_abc123")

        auth = captured["headers"].get("Authorization") or captured["headers"].get("authorization")
        self.assertIsNotNone(auth, "Authorization header not set")
        self.assertIn("tok_abc123", auth)

    def test_attaches_bearer_token_from_env_var(self):
        """_post_hall_route() reads HALL_SESSION_TOKEN env var when no explicit token given."""
        captured = {}

        def mock_urlopen(req, timeout=None):
            captured["headers"] = dict(req.headers)
            mock_resp = MagicMock()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read = MagicMock(return_value=b'{"outcome": "APPROVED"}')
            return mock_resp

        with patch.dict(os.environ, {"HALL_SESSION_TOKEN": "env_tok_xyz789"}):
            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                result = _srv._post_hall_route({"capability_id": "cap.test", "env": "dev"})

        auth = captured["headers"].get("Authorization") or captured["headers"].get("authorization")
        self.assertIsNotNone(auth, "Authorization header not set from env var")
        self.assertIn("env_tok_xyz789", auth)
        self.assertEqual(result.get("outcome"), "APPROVED")

    def test_explicit_token_takes_precedence_over_env_var(self):
        """_post_hall_route() uses explicit session_token over HALL_SESSION_TOKEN env var."""
        captured = {}

        def mock_urlopen(req, timeout=None):
            captured["headers"] = dict(req.headers)
            mock_resp = MagicMock()
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read = MagicMock(return_value=b'{}')
            return mock_resp

        with patch.dict(os.environ, {"HALL_SESSION_TOKEN": "env_tok_should_not_appear"}):
            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                _srv._post_hall_route({"test": True}, session_token="explicit_tok_wins")

        auth = captured["headers"].get("Authorization") or captured["headers"].get("authorization")
        self.assertIsNotNone(auth)
        self.assertIn("explicit_tok_wins", auth)
        self.assertNotIn("env_tok_should_not_appear", auth)

    def test_no_auth_header_when_no_token_set(self):
        """_post_hall_route() sends request without Authorization when no token available.
        The Hall Server will 401 — MCP should surface this as an error dict, not crash."""
        captured = {}

        def mock_urlopen(req, timeout=None):
            captured["headers"] = dict(req.headers)
            # Simulate Hall Server 401 Unauthorized
            raise urllib.error.HTTPError(
                url="http://localhost:8765/api/route",
                code=401,
                msg="Unauthorized",
                hdrs={},  # type: ignore[arg-type]
                fp=None,
            )

        env_without_token = {k: v for k, v in os.environ.items() if k != "HALL_SESSION_TOKEN"}
        with patch.dict(os.environ, env_without_token, clear=True):
            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                result = _srv._post_hall_route({"capability_id": "cap.test"})

        # Must not crash — returns error dict
        self.assertIn("error", result)
        # No Authorization header should have been sent
        auth = captured["headers"].get("Authorization") or captured["headers"].get("authorization")
        self.assertIsNone(auth)


if __name__ == "__main__":
    unittest.main()
