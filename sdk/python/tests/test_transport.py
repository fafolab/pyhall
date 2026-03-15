# Copyright (c) 2026 pyhall.dev — https://pyhall.dev
# All Rights Reserved. (tests/test_transport.py)
"""
Unit tests for pyhall.mcp.transport — McpTransport interface and concrete implementations.
"""

from __future__ import annotations

import io
import json
import os
import queue
from unittest.mock import patch

import pytest

# Must be set before any pyhall.mcp import to allow loading without a real PolicyGate.
os.environ.setdefault("PYHALL_MCP_STRICT", "0")

from pyhall.mcp.transport import (  # noqa: E402
    HttpTransport,
    McpTransport,
    SseTransport,
    StdioTransport,
    run_transport_loop,
)


# ---------------------------------------------------------------------------
# StdioTransport
# ---------------------------------------------------------------------------

class TestStdioTransport:
    def test_read_message_returns_line_content(self):
        payload = '{"jsonrpc":"2.0","method":"initialize","id":1}\n'
        fake_stdin = io.StringIO(payload)
        with patch("sys.stdin", fake_stdin):
            t = StdioTransport()
            msg = t.read_message()
        assert msg == '{"jsonrpc":"2.0","method":"initialize","id":1}'

    def test_read_message_skips_empty_lines(self):
        content = "\n  \n{'jsonrpc':'2.0'}\n"
        fake_stdin = io.StringIO(content)
        with patch("sys.stdin", fake_stdin):
            t = StdioTransport()
            msg = t.read_message()
        assert msg == "{'jsonrpc':'2.0'}"

    def test_read_message_returns_none_on_eof(self):
        fake_stdin = io.StringIO("")
        with patch("sys.stdin", fake_stdin):
            t = StdioTransport()
            msg = t.read_message()
        assert msg is None

    def test_write_message_writes_json_and_flushes(self):
        fake_stdout = io.StringIO()
        flush_called = []

        original_flush = fake_stdout.flush

        def tracking_flush():
            flush_called.append(True)
            original_flush()

        fake_stdout.flush = tracking_flush

        with patch("sys.stdout", fake_stdout):
            t = StdioTransport()
            t.write_message({"jsonrpc": "2.0", "id": 1, "result": {}})

        output = fake_stdout.getvalue()
        assert output.endswith("\n")
        parsed = json.loads(output.strip())
        assert parsed["jsonrpc"] == "2.0"
        assert parsed["id"] == 1
        assert len(flush_called) == 1

    def test_write_notification_uses_same_format(self):
        fake_stdout = io.StringIO()
        with patch("sys.stdout", fake_stdout):
            t = StdioTransport()
            t.write_notification({"jsonrpc": "2.0", "method": "notifications/progress"})

        output = fake_stdout.getvalue()
        parsed = json.loads(output.strip())
        assert parsed["method"] == "notifications/progress"

    def test_close_is_noop(self):
        # Should not raise
        t = StdioTransport()
        t.close()


# ---------------------------------------------------------------------------
# SseTransport
# ---------------------------------------------------------------------------

class TestSseTransport:
    def test_read_message_returns_queued_message(self):
        inbound: queue.Queue = queue.Queue()
        outbound: queue.Queue = queue.Queue()
        inbound.put('{"jsonrpc":"2.0","method":"tools/list","id":2}')

        t = SseTransport(inbound, outbound)
        msg = t.read_message()
        assert msg == '{"jsonrpc":"2.0","method":"tools/list","id":2}'

    def test_read_message_returns_none_sentinel(self):
        inbound: queue.Queue = queue.Queue()
        outbound: queue.Queue = queue.Queue()
        inbound.put(None)

        t = SseTransport(inbound, outbound)
        msg = t.read_message()
        assert msg is None

    def test_write_message_puts_json_in_outbound(self):
        inbound: queue.Queue = queue.Queue()
        outbound: queue.Queue = queue.Queue()

        t = SseTransport(inbound, outbound)
        t.write_message({"jsonrpc": "2.0", "id": 3, "result": {"tools": []}})

        item = outbound.get_nowait()
        parsed = json.loads(item)
        assert parsed["id"] == 3
        assert "result" in parsed

    def test_close_sends_sentinels_to_both_queues(self):
        inbound: queue.Queue = queue.Queue()
        outbound: queue.Queue = queue.Queue()

        t = SseTransport(inbound, outbound)
        t.close()

        assert inbound.get_nowait() is None
        assert outbound.get_nowait() is None

    def test_write_notification_same_as_write_message(self):
        inbound: queue.Queue = queue.Queue()
        outbound: queue.Queue = queue.Queue()

        t = SseTransport(inbound, outbound)
        t.write_notification({"jsonrpc": "2.0", "method": "notifications/initialized"})

        item = outbound.get_nowait()
        parsed = json.loads(item)
        assert parsed["method"] == "notifications/initialized"


# ---------------------------------------------------------------------------
# HttpTransport
# ---------------------------------------------------------------------------

class TestHttpTransport:
    def test_read_message_returns_body_once(self):
        body = '{"jsonrpc":"2.0","method":"tools/list","id":4}'
        t = HttpTransport(body)
        assert t.read_message() == body

    def test_read_message_returns_none_on_second_call(self):
        body = '{"jsonrpc":"2.0","method":"tools/list","id":5}'
        t = HttpTransport(body)
        t.read_message()  # consume
        assert t.read_message() is None

    def test_write_message_stores_response(self):
        t = HttpTransport('{"jsonrpc":"2.0","method":"tools/list","id":6}')
        response = {"jsonrpc": "2.0", "id": 6, "result": {"tools": []}}
        t.write_message(response)
        assert t.get_response() == response

    def test_get_response_returns_none_before_write(self):
        t = HttpTransport('{"jsonrpc":"2.0","method":"tools/list","id":7}')
        assert t.get_response() is None

    def test_close_is_noop(self):
        t = HttpTransport('{}')
        t.close()  # should not raise

    def test_write_message_overwrites_previous_response(self):
        t = HttpTransport('{}')
        t.write_message({"id": 1})
        t.write_message({"id": 2})
        assert t.get_response() == {"id": 2}


# ---------------------------------------------------------------------------
# run_transport_loop — integration test (actually calls dispatch())
# ---------------------------------------------------------------------------

class TestRunTransportLoop:
    def test_tools_list_request_returns_response(self):
        """Integration test: tools/list request flows through dispatch() correctly."""
        raw = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 99,
            "params": {},
        })
        t = HttpTransport(raw)
        run_transport_loop(t)

        response = t.get_response()
        assert response is not None
        assert response.get("jsonrpc") == "2.0"
        assert response.get("id") == 99
        # Should have result with tools key
        assert "result" in response
        assert "tools" in response["result"]

    def test_loop_exits_on_none_from_transport(self):
        """run_transport_loop exits cleanly when read_message returns None."""
        # HttpTransport with empty body — read_message immediately returns None after
        # consuming the one message. Use a notification (no response expected) to
        # exercise the None-response branch, then loop ends.
        raw = json.dumps({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            # no id — notifications return None from dispatch
        })
        t = HttpTransport(raw)
        run_transport_loop(t)
        # Loop should complete without error. No response for notifications.
        assert t.get_response() is None

    def test_invalid_json_returns_parse_error(self):
        """dispatch() returns parse error for malformed JSON."""
        t = HttpTransport("not valid json at all")
        run_transport_loop(t)

        response = t.get_response()
        assert response is not None
        assert response["error"]["code"] == -32700

    def test_unknown_method_returns_method_not_found(self):
        """dispatch() returns method-not-found for unknown methods."""
        raw = json.dumps({
            "jsonrpc": "2.0",
            "method": "nonexistent/method",
            "id": 42,
        })
        t = HttpTransport(raw)
        run_transport_loop(t)

        response = t.get_response()
        assert response is not None
        assert response["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# ABC enforcement
# ---------------------------------------------------------------------------

class TestMcpTransportAbstract:
    def test_cannot_instantiate_abstract_class(self):
        with pytest.raises(TypeError):
            McpTransport()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_all_abstract_methods(self):
        class Incomplete(McpTransport):
            def read_message(self):
                return None
            # missing write_message and close

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]
