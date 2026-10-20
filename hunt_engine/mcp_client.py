"""Synchronous facade over the Sherlock MCP server.

The hunt engine and the LLM agent loop are synchronous, but the MCP SDK is
async. This wraps a persistent stdio MCP session running on a dedicated
background event loop, exposing simple sync `list_tools()` / `call()` methods.

Two backends:
  * "stdio"  (default) -- a real MCP client speaking to `mcp_server.server`.
                          This is the authentic "agent talks to the stack only
                          through MCP" path.
  * "direct"          -- calls the tool functions in-process. A safety net so a
                          live demo never fails on subprocess/transport hiccups.
Select with SHERLOCK_MCP_BACKEND=stdio|direct.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from typing import Any

from common.settings import REPO_ROOT


class ToolInfo:
    def __init__(self, name: str, description: str, input_schema: dict[str, Any]):
        self.name = name
        self.description = description
        self.input_schema = input_schema


class _DirectBackend:
    """In-process backend -- imports the tool registry directly."""

    def __init__(self) -> None:
        from mcp_server.tools import TOOLS

        self._tools = TOOLS

    def start(self) -> None:  # noqa: D401 - nothing to start
        pass

    def stop(self) -> None:
        pass

    def list_tools(self) -> list[ToolInfo]:
        return [ToolInfo(t["name"], t["description"], t["input_schema"]) for t in self._tools]

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        from mcp_server.tools import call as _call

        return _call(name, arguments)


class _StdioBackend:
    """Real MCP stdio client driven from a background event loop."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._session = None
        self._ready = threading.Event()
        self._stack = None
        self._startup_error: BaseException | None = None

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._open())
        except BaseException as e:      # startup failed -> record and unblock start()
            self._startup_error = e
            self._ready.set()
            return
        self._ready.set()
        self._loop.run_forever()

    async def _open(self) -> None:
        from contextlib import AsyncExitStack

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self._stack = AsyncExitStack()
        # Minimal env: the MCP subprocess needs to import the package and reach ES,
        # nothing else. Do NOT forward LLM API keys or unrelated secrets.
        env = {"PYTHONPATH": str(REPO_ROOT), "PATH": os.environ.get("PATH", "")}
        for k in ("SHERLOCK_ES_URL", "SHERLOCK_LOG_SCOPE", "HOME", "LANG", "LC_ALL"):
            if k in os.environ:
                env[k] = os.environ[k]
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "mcp_server.server"], env=env, cwd=str(REPO_ROOT))
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()

    def start(self) -> None:
        if self._thread:
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=30):
            raise RuntimeError("MCP stdio server did not start in time")
        if self._startup_error is not None:
            raise RuntimeError(f"MCP stdio startup failed: {self._startup_error}")

    def _submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=60)

    def list_tools(self) -> list[ToolInfo]:
        res = self._submit(self._session.list_tools())
        return [ToolInfo(t.name, t.description or "", t.inputSchema or {}) for t in res.tools]

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            res = self._submit(self._session.call_tool(name, arguments or {}))
        except Exception as e:            # transport / timeout -> explicit failure
            return {"ok": False, "tool": name, "error": f"transport error: {e}"}
        text = "".join(c.text for c in res.content if getattr(c, "type", None) == "text")
        try:
            data = json.loads(text)
        except Exception:
            return {"ok": False, "tool": name, "error": "malformed (non-JSON) tool result",
                    "raw": text[:500]}
        if not isinstance(data, dict):
            return {"ok": False, "tool": name, "error": "tool result was not a JSON object",
                    "raw": text[:500]}
        return data

    def stop(self) -> None:
        if self._loop and self._stack and self._loop.is_running():
            async def _close():
                await self._stack.aclose()
            try:
                asyncio.run_coroutine_threadsafe(_close(), self._loop).result(timeout=10)
            except Exception:
                pass
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)


class MCPClient:
    VALID = ("stdio", "direct")

    def __init__(self, backend: str | None = None) -> None:
        backend = backend or os.environ.get("SHERLOCK_MCP_BACKEND", "stdio")
        if backend not in self.VALID:
            backend = "stdio"           # strict: unknown value never silently means direct
        self.backend_name = backend
        self._backend = _StdioBackend() if backend == "stdio" else _DirectBackend()
        self._started = False

    def __enter__(self) -> "MCPClient":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        if not self._started:
            try:
                self._backend.start()
            except Exception:
                # Fall back to direct backend so a hunt can always run.
                self._backend = _DirectBackend()
                self.backend_name = "direct"
                self._backend.start()
            self._started = True

    def stop(self) -> None:
        if self._started:
            self._backend.stop()
            self._started = False

    def list_tools(self) -> list[ToolInfo]:
        return self._backend.list_tools()

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        return self._backend.call(name, arguments)
