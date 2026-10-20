"""Provider-agnostic LLM client with a tool-use agent loop.

This is a thin facade over the pluggable provider layer in `common/providers.py`.
Picking a provider (Anthropic native, or any OpenAI-compatible endpoint: OpenAI,
Azure, Groq, DeepSeek, Together, OpenRouter, Mistral, xAI, Gemini, local Ollama /
vLLM / LM Studio, …) is one config line — see `.env.example`. The agent loop here
is Sherlock's own, hand-rolled on the raw provider SDKs (no CrewAI / LangChain /
agent framework) so every tool call can be recorded in the evidence ledger and
streamed to the dashboard under full control.

If no API key is configured, `available()` is False and callers fall back to the
deterministic heuristic engine -- the whole system still runs end to end.
"""
from __future__ import annotations

from typing import Any, Callable

from common.providers import (  # noqa: F401 - ToolSpec re-exported for callers
    EventCb,
    ToolSpec,
    extract_json as _extract_json,
    resolve_provider,
    safe_call as _safe_call,
)
from common.settings import settings


def _noop(_: dict[str, Any]) -> None:
    pass


class LLMClient:
    """Facade: resolves the configured provider and drives it uniformly."""

    def __init__(self) -> None:
        self._r = resolve_provider()
        self.provider = self._r.name
        self.model = self._r.model

    def available(self) -> bool:
        return self._r.available

    # -- one-shot JSON completion (used by planner / reporter) -------------
    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        text = self.complete(system, user + "\n\nRespond with a single JSON object and nothing else.")
        return _extract_json(text)

    def complete(self, system: str, user: str) -> str:
        return self._r.adapter.complete(
            self._r.model, system, user, settings.llm_temperature, settings.llm_max_tokens)

    # -- agent loop with tools -------------------------------------------
    def agent_loop(
        self,
        system: str,
        user: str,
        tools: list[ToolSpec],
        max_turns: int = 24,
        on_event: EventCb = _noop,
    ) -> str:
        return self._r.adapter.tool_loop(
            self._r.model, system, user, tools, max_turns,
            settings.llm_temperature, settings.llm_max_tokens, on_event, _safe_call)
