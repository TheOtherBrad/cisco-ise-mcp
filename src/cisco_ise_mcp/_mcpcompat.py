"""SDK-version compatibility adapter for the MCP Python SDK.

This is the ONLY module that imports version-specific ``mcp.server`` /
``mcp.types`` symbols. Every other module speaks a small neutral contract:
tool handlers build a raw Python ``result`` and return a neutral
``ToolResult(data=...)``; ``list_tools`` returns a plain ``list[Tool]`` built
with ``Tool(inputSchema=...)`` (accepted as a constructor kwarg on both majors).

The adapter converts neutral → SDK-specific at the single MCP boundary and owns
server construction plus the stdio run loop, so the same source tree runs under
either mcp 1.x or 2.x — selected by whichever package the venv installed:

  - v1: low-level ``Server`` with ``@server.list_tools()`` / ``@server.call_tool()``
    decorators; handlers return ``list[TextContent]`` (text only).
  - v2: ``Server(..., on_list_tools=, on_call_tool=)`` constructor kwargs;
    handlers take ``(ctx, params)`` and return ``ListToolsResult`` /
    ``CallToolResult`` — the latter also carrying ``structured_content`` so v2
    clients get a machine-readable payload.
"""

from __future__ import annotations

import importlib.metadata
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from mcp.server import Server
from mcp.types import Tool, TextContent


# --- version detection -----------------------------------------------------

def _detect_major() -> int:
    """Major version of the installed ``mcp`` package (1 or 2).

    ``importlib.metadata`` is authoritative. A source checkout without installed
    metadata falls back to feature detection: the v2 low-level ``Server`` drops
    the ``list_tools`` decorator method that v1 exposes.
    """
    try:
        return int(importlib.metadata.version("mcp").split(".", 1)[0])
    except Exception:  # noqa: BLE001 — no installed metadata; feature-detect
        return 1 if hasattr(Server, "list_tools") else 2


MCP_MAJOR = _detect_major()


# --- neutral contract ------------------------------------------------------

@dataclass
class ToolResult:
    """SDK-neutral tool result. ``data`` is a raw Python object (usually a dict
    or list); ``text`` overrides the default JSON rendering when set."""

    data: Any
    text: str | None = None


def text_result(obj: Any) -> "ToolResult":
    """Wrap a raw Python result — the one helper the surface handlers call."""
    return ToolResult(data=obj)


def tool_input_schema(tool: Tool) -> dict:
    """Read a Tool's input schema across SDK majors.

    v2 renames the attribute to ``input_schema`` (with ``inputSchema`` kept only
    as a *constructor* alias); v1 exposes ``inputSchema``.
    """
    schema = getattr(tool, "input_schema", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    return schema or {}


# --- boundary converters ---------------------------------------------------

def _content(result: "ToolResult") -> list:
    """Neutral result → the ``[TextContent(...)]`` parity output used on both."""
    text = result.text
    if text is None:
        text = json.dumps(result.data, indent=2, default=str)
    return [TextContent(type="text", text=text)]


def to_call_result(result: "ToolResult"):
    """Neutral result → the SDK-native ``call_tool`` return value.

    v1 returns ``list[TextContent]`` (text only). v2 returns a
    ``CallToolResult`` that additionally carries ``structured_content`` (a
    machine-readable payload) whenever the result data is a dict.
    """
    content = _content(result)
    if MCP_MAJOR >= 2:
        from mcp.types import CallToolResult

        structured = result.data if isinstance(result.data, dict) else None
        return CallToolResult(content=content, structured_content=structured)
    return content


# --- server construction + run loop ----------------------------------------

def make_server(
    name: str,
    version: str,
    list_tools_fn: Callable[[], Awaitable[list[Tool]]],
    call_tool_fn: Callable[[str, dict], Awaitable["ToolResult"]],
) -> Server:
    """Build a ``Server`` wired to neutral handlers, targeting the installed SDK.

    ``list_tools_fn()`` returns a plain ``list[Tool]``; ``call_tool_fn(name,
    arguments)`` returns a :class:`ToolResult`. The adapter owns the conversion
    to whatever the installed SDK major expects.
    """
    if MCP_MAJOR >= 2:
        return _make_server_v2(name, version, list_tools_fn, call_tool_fn)
    return _make_server_v1(name, version, list_tools_fn, call_tool_fn)


def _make_server_v1(name, version, list_tools_fn, call_tool_fn) -> Server:
    server = Server(name, version=version)

    @server.list_tools()
    async def _lt() -> list[Tool]:
        return await list_tools_fn()

    @server.call_tool()
    async def _ct(tool_name: str, arguments: dict | None):
        result = await call_tool_fn(tool_name, arguments or {})
        return to_call_result(result)

    return server


def _make_server_v2(name, version, list_tools_fn, call_tool_fn) -> Server:
    from mcp.types import ListToolsResult

    async def _lt(ctx, params) -> ListToolsResult:
        return ListToolsResult(tools=await list_tools_fn())

    async def _ct(ctx, params):
        result = await call_tool_fn(params.name, params.arguments or {})
        return to_call_result(result)

    return Server(name, version=version, on_list_tools=_lt, on_call_tool=_ct)


async def serve(server: Server) -> None:
    """Run the server over stdio. The stdio transport and ``server.run`` shape
    are carried over unchanged between majors; the import is guarded regardless."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )
