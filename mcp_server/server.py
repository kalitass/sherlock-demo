"""Sherlock MCP server (stdio).

Exposes the Elasticsearch hunt tools defined in mcp_server/tools.py over the
Model Context Protocol. Any MCP client -- Sherlock's own hunt engine, or a
general assistant like Claude Desktop -- can drive a threat hunt through it.

Run directly:   uv run python -m mcp_server.server
Claude Desktop: add a stdio server with command `uv`, args
                ["run","python","-m","mcp_server.server"], cwd = repo root.
"""
from __future__ import annotations

import json

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcp_server.tools import TOOLS, call

server = Server("sherlock")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=t["name"], description=t["description"], inputSchema=t["input_schema"])
        for t in TOOLS
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    result = call(name, arguments)
    return [types.TextContent(type="text", text=json.dumps(result, default=str))]


async def _main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    import anyio

    anyio.run(_main)


if __name__ == "__main__":
    main()
