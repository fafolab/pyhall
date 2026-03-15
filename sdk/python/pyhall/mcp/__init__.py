"""pyhall.mcp — WCP/MCP interop: expose a WCP worker as an MCP tool.

Provides the MCP stdio server that wraps a WCP worker as an MCP tool.
Every tool call passes through WCP Hall governance before execution.

Quick start:

    python -m pyhall.mcp          # run the example doc-summarizer server
    pyhall-mcp                    # same, via installed entry point

Swap in your own worker:

    from pyhall.mcp.server import run_stdio_loop, set_worker
    from my_package import my_worker, MyWorkerContext
    set_worker(my_worker, "wrk.my.species")
    run_stdio_loop()
"""

from pyhall.mcp.server import run_stdio_loop, dispatch
from pyhall.mcp.transport import (
    McpTransport,
    StdioTransport,
    SseTransport,
    HttpTransport,
    run_transport_loop,
)

__all__ = [
    "run_stdio_loop",
    "dispatch",
    "McpTransport",
    "StdioTransport",
    "SseTransport",
    "HttpTransport",
    "run_transport_loop",
]
