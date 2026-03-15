# Copyright (c) 2026 pyhall.dev — https://pyhall.dev
# All Rights Reserved. (pyhall/mcp/transport.py)
"""
McpTransport — abstract base class + concrete transport implementations.

All MCP JSON-RPC 2.0 framing is handled here. The dispatch() function
in server.py has zero I/O coupling and must never be modified for transport reasons.
"""

from __future__ import annotations

import json
import queue
import sys
from abc import ABC, abstractmethod
from typing import Optional


class McpTransport(ABC):
    """Abstract base class for MCP transports."""

    @abstractmethod
    def read_message(self) -> Optional[str]:
        """Block until a message arrives. Returns None on EOF/close."""

    @abstractmethod
    def write_message(self, response: dict) -> None:
        """Serialize response dict to JSON and send it."""

    def write_notification(self, notification: dict) -> None:
        """Send a notification (no response expected, same wire format)."""
        self.write_message(notification)

    @abstractmethod
    def close(self) -> None:
        """Clean teardown."""


class StdioTransport(McpTransport):
    """MCP transport over stdin/stdout (NDJSON — one JSON object per line)."""

    def read_message(self) -> Optional[str]:
        """Read one line from stdin. Returns None on EOF."""
        while True:
            line = sys.stdin.readline()
            if not line:
                return None
            line = line.strip()
            if line:
                return line

    def write_message(self, response: dict) -> None:
        """Write JSON response to stdout and flush."""
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

    def close(self) -> None:
        """No-op — cannot close stdin/stdout."""


class SseTransport(McpTransport):
    """
    Queue-backed transport base for SSE (Server-Sent Events) delivery.

    Inbound messages arrive via inbound_queue; outbound responses are placed
    into outbound_queue. This is the base for FlaskSseTransport (implemented
    in hall_api/server.py, proprietary — not in this module).
    """

    def __init__(
        self,
        inbound_queue: queue.Queue,
        outbound_queue: queue.Queue,
    ) -> None:
        self._inbound = inbound_queue
        self._outbound = outbound_queue

    def read_message(self) -> Optional[str]:
        """Block until a message is available. Returns None on sentinel."""
        item = self._inbound.get()
        return item  # None sentinel signals EOF

    def write_message(self, response: dict) -> None:
        """Serialize response and put it into the outbound queue."""
        self._outbound.put(json.dumps(response))

    def close(self) -> None:
        """Send None sentinels to both queues to signal shutdown."""
        self._inbound.put(None)
        self._outbound.put(None)


class HttpTransport(McpTransport):
    """
    Single request/response transport for stateless HTTP delivery.

    Used by POST /api/mcp/messages in hall_api to process a single
    HTTP-delivered MCP message without a persistent connection.
    """

    def __init__(self, request_body: str) -> None:
        self._request_body = request_body
        self._consumed = False
        self._response: Optional[dict] = None

    def read_message(self) -> Optional[str]:
        """Return the request body once, then None on subsequent calls."""
        if self._consumed:
            return None
        self._consumed = True
        return self._request_body

    def write_message(self, response: dict) -> None:
        """Store the response dict internally."""
        self._response = response

    def close(self) -> None:
        """No-op — stateless, nothing to close."""

    def get_response(self) -> Optional[dict]:
        """Return the stored response, or None if not yet set."""
        return self._response


def run_transport_loop(transport: McpTransport) -> None:
    """
    Main MCP server loop. Transport-agnostic. Calls dispatch() for each message.
    Runs until transport.read_message() returns None.
    """
    from pyhall.mcp.server import dispatch

    while True:
        raw = transport.read_message()
        if raw is None:
            break
        response = dispatch(raw)
        if response is not None:
            transport.write_message(response)
    transport.close()
