"""Compat adapter: runs against whichever mcp major is installed in the venv."""

import asyncio
import json

from mcp.types import Tool, TextContent

from cisco_ise_mcp import _mcpcompat as compat


def test_mcp_major_detected():
    assert compat.MCP_MAJOR in (1, 2)


def test_tool_input_schema_reads_schema():
    schema = {"type": "object", "properties": {"q": {"type": "string"}}}
    tool = Tool(name="x", description="d", inputSchema=schema)
    assert compat.tool_input_schema(tool) == schema


def test_text_result_is_neutral():
    r = compat.text_result({"a": 1})
    assert isinstance(r, compat.ToolResult)
    assert r.data == {"a": 1}
    assert r.text is None


def test_to_call_result_parity_text():
    data = {"a": 1, "b": [2, 3]}
    result = compat.to_call_result(compat.text_result(data))
    if compat.MCP_MAJOR >= 2:
        content = result.content
    else:
        content = result
    assert isinstance(content[0], TextContent)
    assert content[0].text == json.dumps(data, indent=2, default=str)


def test_to_call_result_structured_on_v2():
    data = {"a": 1}
    result = compat.to_call_result(compat.text_result(data))
    if compat.MCP_MAJOR >= 2:
        assert result.structured_content == data
    else:
        # v1 stays text-only: no structured payload.
        assert isinstance(result, list)


def test_to_call_result_non_dict_has_no_structured():
    result = compat.to_call_result(compat.text_result([1, 2, 3]))
    if compat.MCP_MAJOR >= 2:
        assert result.structured_content is None


def test_all_tools_includes_meta_and_surfaces():
    from cisco_ise_mcp import server

    tools = server.all_tools()
    names = {t.name for t in tools}
    assert tools
    assert "ise_capabilities" in names
    assert any(n.startswith("ise_ers_") for n in names)


def test_call_tool_capabilities_returns_neutral_dict():
    from cisco_ise_mcp import server

    result = asyncio.run(server.call_tool("ise_capabilities", {}))
    assert isinstance(result, compat.ToolResult)
    assert isinstance(result.data, dict)
