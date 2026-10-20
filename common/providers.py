"""Provider compatibility layer — bring-your-own-model for Sherlock's agent.

The hunt engine talks to *one* abstraction: a `ProviderAdapter` that knows how to
(a) do a one-shot completion and (b) run a tool-use agent loop. Everything that is
provider-specific (wire format, client construction, endpoints) lives in a small
adapter; everything that is Sherlock-specific (the evidence ledger wiring, the
event stream, tool dispatch, output sanitisation) stays in the hunt engine and is
provider-agnostic.

Two engines, same abstraction:

* **LiteLLM engine (default, for robustness).** A single `LiteLLMAdapter` routes to
  100+ providers through LiteLLM, inheriting its battle-tested **retries, timeouts,
  parameter-dropping and fallbacks**. LiteLLM only normalises each model *call*; the
  agent loop, tool dispatch and evidence-ledger recording are still ours — so
  observability/auditability is unaffected.
* **Native engine (zero-heavy-dependency fallback).** Hand-rolled adapters on the
  raw `anthropic` / `openai` SDKs. Used automatically if LiteLLM is not installed,
  or forced with `SHERLOCK_LLM_ENGINE=native`. Keeps the system working off a single
  point of failure and keeps the dependency surface minimal when desired.

Either way: switching provider is one config line (`SHERLOCK_LLM_PROVIDER`), and
adding a brand-new, non-OpenAI API is a ~40-line adapter + one `@register`.
"""
from __future__ import annotations

import importlib.util
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable

from common.settings import settings

# Per-call robustness defaults (overridable by env). These bound a hung provider
# so a single model call cannot stall a hunt indefinitely, and recover transient
# errors without crashing the run.
REQUEST_TIMEOUT = float(os.environ.get("SHERLOCK_LLM_TIMEOUT", "60"))
MAX_RETRIES = int(os.environ.get("SHERLOCK_LLM_RETRIES", "2"))


# --------------------------------------------------------------------------- #
# Tool specification — the one shape the engine hands to any provider.
# --------------------------------------------------------------------------- #
@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]          # JSON schema for arguments
    fn: Callable[[dict[str, Any]], Any]   # returns a JSON-serialisable result


EventCb = Callable[[dict[str, Any]], None]
Dispatch = Callable[["ToolSpec | None", dict[str, Any]], Any]


def _noop(_: dict[str, Any]) -> None:
    pass


def safe_call(tool: "ToolSpec | None", args: dict[str, Any]) -> Any:
    """Run a tool, never letting its error kill the agent loop."""
    if tool is None:
        return {"error": "unknown tool"}
    try:
        return tool.fn(args)
    except Exception as e:  # pragma: no cover - defensive
        return {"error": f"{type(e).__name__}: {e}"}


def extract_json(text: str) -> dict[str, Any]:
    """Best-effort parse of a model's JSON reply (tolerates code fences / prose)."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start : end + 1])
            except Exception:
                pass
    return {}


def _openai_tool_defs(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [{"type": "function", "function": {
        "name": t.name, "description": t.description, "parameters": t.input_schema}}
        for t in tools]


# When the tool-call budget is exhausted, we force one FINAL answer (no tools) so
# the investigation is not thrown away. Without this, running out of turns returned
# a non-JSON stub -> the verdict defaulted to inconclusive, which was the single
# biggest source of run-to-run divergence in the LLM engine.
_FORCE_FINAL = ("You have reached the investigation budget. Do NOT request any more "
                "tools. Based ONLY on the evidence already gathered, output your final "
                "answer now as the single JSON object specified in the instructions.")


def _run_openai_style_loop(create, tools, max_turns, on_event, dispatch,
                           seed_messages) -> str:
    """The shared OpenAI-format tool-use loop, used by both the OpenAI SDK adapter
    and the LiteLLM adapter (LiteLLM normalises every provider to this format).

    `create(messages, tool_defs)` performs one model call and returns a message
    object with `.content`, `.tool_calls` and `.model_dump()`. Called with an empty
    `tool_defs`, it must force a plain-text (no tool-call) completion.
    """
    tool_defs = _openai_tool_defs(tools)
    by_name = {t.name: t for t in tools}
    messages = list(seed_messages)
    for _ in range(max_turns):
        msg = create(messages, tool_defs)
        messages.append(msg.model_dump(exclude_none=True))
        if not getattr(msg, "tool_calls", None):
            return msg.content or ""
        for tc in msg.tool_calls:
            args = extract_json(tc.function.arguments or "{}")
            on_event({"type": "tool_call", "tool": tc.function.name, "arguments": args})
            out = dispatch(by_name.get(tc.function.name), args)
            on_event({"type": "tool_result", "tool": tc.function.name, "result": out})
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": json.dumps(out)[:60000]})
    # Budget exhausted: force a verdict from what we have instead of discarding it.
    messages.append({"role": "user", "content": _FORCE_FINAL})
    try:
        final = create(messages, [])
        if final.content:
            return final.content
    except Exception:
        pass
    return "Reached max turns without a final answer."


# --------------------------------------------------------------------------- #
# Adapter interface + registry.
# --------------------------------------------------------------------------- #
class ProviderAdapter(ABC):
    """The whole contract a provider must satisfy to drive a Sherlock hunt."""

    #: short family id, also the registry key
    family: str = ""

    def __init__(self, api_key: str = "", base_url: str = "", route: str = "") -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.route = route          # provider-qualified model id (LiteLLM only)

    @abstractmethod
    def complete(self, model: str, system: str, user: str,
                 temperature: float, max_tokens: int) -> str:
        """One-shot text completion (used by the planner / schema proposer)."""

    @abstractmethod
    def tool_loop(self, model: str, system: str, user: str, tools: list[ToolSpec],
                  max_turns: int, temperature: float, max_tokens: int,
                  on_event: EventCb, dispatch: Dispatch) -> str:
        """Run a tool-use agent loop, emitting events and dispatching tool calls.

        `dispatch(tool_spec_or_None, args)` executes a tool and returns its
        JSON-serialisable result; `on_event({...})` streams thoughts / tool calls /
        tool results to the dashboard. The provider only owns the wire translation.
        """


_REGISTRY: dict[str, type[ProviderAdapter]] = {}


def register(cls: type[ProviderAdapter]) -> type[ProviderAdapter]:
    """Class decorator — makes an adapter discoverable by its `family`."""
    if not cls.family:
        raise ValueError(f"{cls.__name__} must set a non-empty `family`")
    _REGISTRY[cls.family] = cls
    return cls


# --------------------------------------------------------------------------- #
# LiteLLM (default engine) — one adapter, 100+ providers, with retries/timeouts.
# --------------------------------------------------------------------------- #
_LITELLM_CONFIGURED = False


def _litellm():
    """Import LiteLLM lazily and apply robustness-friendly global settings once."""
    global _LITELLM_CONFIGURED
    import litellm

    if not _LITELLM_CONFIGURED:
        litellm.drop_params = True          # silently drop params a provider rejects
        litellm.telemetry = False           # no outbound telemetry
        litellm.suppress_debug_info = True
        try:
            litellm.set_verbose = False
        except Exception:
            pass
        _LITELLM_CONFIGURED = True
    return litellm


class LiteLLMAdapter(ProviderAdapter):
    family = "litellm"

    def _kw(self) -> dict[str, Any]:
        kw: dict[str, Any] = {"timeout": REQUEST_TIMEOUT, "num_retries": MAX_RETRIES}
        if self.api_key:
            kw["api_key"] = self.api_key
        if self.base_url:
            kw["api_base"] = self.base_url
        return kw

    def complete(self, model, system, user, temperature, max_tokens) -> str:
        litellm = _litellm()
        resp = litellm.completion(
            model=self.route or model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            temperature=temperature, max_tokens=max_tokens, **self._kw())
        return resp.choices[0].message.content or ""

    def tool_loop(self, model, system, user, tools, max_turns, temperature,
                  max_tokens, on_event, dispatch) -> str:
        litellm = _litellm()
        route = self.route or model
        kw = self._kw()

        def create(messages, tool_defs):
            extra = {"tools": tool_defs, "tool_choice": "auto"} if tool_defs else {}
            resp = litellm.completion(
                model=route, messages=messages,
                temperature=temperature, max_tokens=max_tokens, **extra, **kw)
            return resp.choices[0].message

        seed = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        return _run_openai_style_loop(create, tools, max_turns, on_event, dispatch, seed)


# --------------------------------------------------------------------------- #
# Native engine — Anthropic (native API).
# --------------------------------------------------------------------------- #
@register
class AnthropicAdapter(ProviderAdapter):
    family = "anthropic"

    def _client(self):
        import anthropic

        kwargs: dict[str, Any] = {"api_key": self.api_key,
                                  "timeout": REQUEST_TIMEOUT, "max_retries": MAX_RETRIES}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return anthropic.Anthropic(**kwargs)

    def complete(self, model, system, user, temperature, max_tokens) -> str:
        resp = self._client().messages.create(
            model=model, max_tokens=max_tokens, temperature=temperature,
            system=system, messages=[{"role": "user", "content": user}])
        return "".join(b.text for b in resp.content if b.type == "text")

    def tool_loop(self, model, system, user, tools, max_turns, temperature,
                  max_tokens, on_event, dispatch) -> str:
        client = self._client()
        tool_defs = [{"name": t.name, "description": t.description,
                      "input_schema": t.input_schema} for t in tools]
        by_name = {t.name: t for t in tools}
        messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
        for _ in range(max_turns):
            resp = client.messages.create(
                model=model, max_tokens=max_tokens, temperature=temperature,
                system=system, messages=messages, tools=tool_defs)
            messages.append({"role": "assistant", "content": [b.model_dump() for b in resp.content]})
            if resp.stop_reason != "tool_use":
                return "".join(b.text for b in resp.content if b.type == "text")
            results = []
            for b in resp.content:
                if b.type == "text" and b.text.strip():
                    on_event({"type": "thought", "text": b.text})
                if b.type == "tool_use":
                    on_event({"type": "tool_call", "tool": b.name, "arguments": b.input})
                    out = dispatch(by_name.get(b.name), b.input)
                    on_event({"type": "tool_result", "tool": b.name, "result": out})
                    results.append({"type": "tool_result", "tool_use_id": b.id,
                                    "content": json.dumps(out)[:60000]})
            messages.append({"role": "user", "content": results})
        # Budget exhausted: force a verdict (no tools) instead of discarding it.
        messages.append({"role": "user", "content": _FORCE_FINAL})
        try:
            resp = client.messages.create(
                model=model, max_tokens=max_tokens, temperature=temperature,
                system=system, messages=messages)
            text = "".join(b.text for b in resp.content if b.type == "text")
            if text.strip():
                return text
        except Exception:
            pass
        return "Reached max turns without a final answer."


# --------------------------------------------------------------------------- #
# Native engine — OpenAI-compatible (OpenAI, Azure, Groq, DeepSeek, Together,
# OpenRouter, Mistral, xAI, Gemini's OpenAI endpoint, Ollama, vLLM, LM Studio).
# --------------------------------------------------------------------------- #
@register
class OpenAIAdapter(ProviderAdapter):
    family = "openai"

    def _client(self):
        from openai import OpenAI

        kwargs: dict[str, Any] = {"api_key": self.api_key or "not-needed",
                                  "timeout": REQUEST_TIMEOUT, "max_retries": MAX_RETRIES}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)

    def complete(self, model, system, user, temperature, max_tokens) -> str:
        resp = self._client().chat.completions.create(
            model=model, temperature=temperature,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}])
        return resp.choices[0].message.content or ""

    def tool_loop(self, model, system, user, tools, max_turns, temperature,
                  max_tokens, on_event, dispatch) -> str:
        client = self._client()

        def create(messages, tool_defs):
            extra = {"tools": tool_defs, "tool_choice": "auto"} if tool_defs else {}
            resp = client.chat.completions.create(
                model=model, temperature=temperature, messages=messages, **extra)
            return resp.choices[0].message

        seed = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        return _run_openai_style_loop(create, tools, max_turns, on_event, dispatch, seed)


# --------------------------------------------------------------------------- #
# Presets — a provider alias -> family, native endpoint, key env vars, default
# model, and the LiteLLM route prefix. `lite` is the LiteLLM provider prefix;
# `base` is the native-SDK endpoint. Local/self-hosted providers are keyless.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Preset:
    family: str
    key_envs: tuple[str, ...] = ()          # env vars tried in order for the API key
    base: str = ""                           # native-SDK endpoint (empty = vendor default)
    default_model: str = ""                  # used when SHERLOCK_LLM_MODEL is unset
    lite: str = ""                           # LiteLLM provider prefix ("" = bare model)
    local_key: str = ""                      # dummy key for keyless local servers
    local: bool = False                      # self-hosted (pass api_base to LiteLLM)


PRESETS: dict[str, Preset] = {
    "anthropic": Preset("anthropic", ("ANTHROPIC_API_KEY",),
                        default_model="claude-sonnet-4-5", lite="anthropic"),
    "openai":     Preset("openai", ("OPENAI_API_KEY",), default_model="gpt-4o", lite=""),
    "azure":      Preset("openai", ("AZURE_OPENAI_API_KEY", "OPENAI_API_KEY"),
                         default_model="gpt-4o", lite="azure", local=True),
    "groq":       Preset("openai", ("GROQ_API_KEY", "OPENAI_API_KEY"),
                         "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "groq"),
    "deepseek":   Preset("openai", ("DEEPSEEK_API_KEY", "OPENAI_API_KEY"),
                         "https://api.deepseek.com/v1", "deepseek-chat", "deepseek"),
    "together":   Preset("openai", ("TOGETHER_API_KEY", "OPENAI_API_KEY"),
                         "https://api.together.xyz/v1",
                         "meta-llama/Llama-3.3-70B-Instruct-Turbo", "together_ai"),
    "openrouter": Preset("openai", ("OPENROUTER_API_KEY", "OPENAI_API_KEY"),
                         "https://openrouter.ai/api/v1", "openai/gpt-4o", "openrouter"),
    "mistral":    Preset("openai", ("MISTRAL_API_KEY", "OPENAI_API_KEY"),
                         "https://api.mistral.ai/v1", "mistral-large-latest", "mistral"),
    "xai":        Preset("openai", ("XAI_API_KEY", "OPENAI_API_KEY"),
                         "https://api.x.ai/v1", "grok-2-latest", "xai"),
    "gemini":     Preset("openai", ("GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY"),
                         "https://generativelanguage.googleapis.com/v1beta/openai/",
                         "gemini-2.0-flash", "gemini"),
    "ollama":     Preset("openai", (), "http://localhost:11434/v1", "llama3.1",
                         "ollama_chat", local_key="ollama", local=True),
    "lmstudio":   Preset("openai", (), "http://localhost:1234/v1", "local-model",
                         "lm_studio", local_key="lm-studio", local=True),
    "vllm":       Preset("openai", ("VLLM_API_KEY",), "http://localhost:8000/v1",
                         "local-model", "hosted_vllm", local_key="EMPTY", local=True),
}

# friendly aliases -> canonical preset name
_ALIASES = {
    "claude": "anthropic", "gpt": "openai", "openai-compatible": "openai",
    "grok": "xai", "google": "gemini", "google-gemini": "gemini",
    "llama": "ollama", "local": "ollama", "lm-studio": "lmstudio",
    "azure-openai": "azure", "open-router": "openrouter", "deep-seek": "deepseek",
}


# --------------------------------------------------------------------------- #
# Resolution — turn settings + env into a ready-to-use adapter.
# --------------------------------------------------------------------------- #
@dataclass
class Resolved:
    name: str                 # provider alias as requested (normalised)
    family: str               # protocol family (anthropic | openai | custom)
    engine: str               # "litellm" | "native"
    adapter: ProviderAdapter  # configured instance
    model: str                # plain model id
    route: str                # LiteLLM-qualified model id (engine == litellm)
    base_url: str
    api_key: str
    available: bool           # True if we have (or don't need) a usable key
    note: str = ""            # human-readable status for diagnostics


def _first_env(names: tuple[str, ...]) -> str:
    for n in names:
        v = os.environ.get(n, "")
        if v:
            return v
    return ""


def _litellm_installed() -> bool:
    return importlib.util.find_spec("litellm") is not None


def _choose_engine() -> str:
    mode = os.environ.get("SHERLOCK_LLM_ENGINE", "auto").strip().lower()
    if mode in ("native", "litellm"):
        return mode
    return "litellm" if _litellm_installed() else "native"


def resolve_provider(provider: str | None = None) -> Resolved:
    """Resolve a provider name to a configured adapter, endpoint, model and key.

    Precedence: explicit args/env override preset defaults. Unknown provider names,
    and custom-registered families, use the native engine (LiteLLM only knows its
    own providers). Otherwise the engine is LiteLLM when available.
    """
    raw = (provider or os.environ.get("SHERLOCK_LLM_PROVIDER")
           or settings.llm_provider or "anthropic").strip().lower()
    name = _ALIASES.get(raw, raw)
    preset = PRESETS.get(name)

    unknown = preset is None
    if unknown:
        preset = Preset("openai", ("OPENAI_API_KEY",))      # assume OpenAI-compatible
        note = f"unknown provider '{raw}', treating as OpenAI-compatible (native)"
    else:
        note = ""

    family = preset.family

    # --- model: explicit SHERLOCK_LLM_MODEL wins, else preset default, else settings
    explicit_model = os.environ.get("SHERLOCK_LLM_MODEL", "")
    model = explicit_model or preset.default_model or settings.llm_model

    # --- base_url: explicit env override wins, else preset default, else settings
    explicit_base = os.environ.get("SHERLOCK_LLM_BASE_URL", "") or settings.openai_base_url
    base_url = explicit_base or preset.base

    # --- api key: provider-specific env vars, then settings fields, then local dummy
    api_key = _first_env(preset.key_envs)
    if not api_key:
        api_key = settings.anthropic_api_key if family == "anthropic" else settings.openai_api_key
    if not api_key and preset.local_key:
        api_key = preset.local_key          # keyless local server

    # --- engine: LiteLLM by default; native for unknown/custom families
    engine = _choose_engine()
    if engine == "litellm" and (unknown or family not in ("anthropic", "openai")):
        engine = "native"
        if not note:
            note = "custom/unknown provider → native engine"

    if engine == "litellm":
        prefix = preset.lite
        route = f"{prefix}/{model}" if prefix else model
        # Only hand LiteLLM an api_base for self-hosted or explicitly-overridden
        # endpoints; hosted providers use LiteLLM's own defaults.
        lite_base = explicit_base or (preset.base if preset.local else "")
        adapter: ProviderAdapter = LiteLLMAdapter(api_key=api_key, base_url=lite_base, route=route)
    else:
        route = ""
        adapter_cls = _REGISTRY.get(family, OpenAIAdapter)
        adapter = adapter_cls(api_key=api_key, base_url=base_url)

    available = bool(api_key)
    if not available and not note:
        keys = " / ".join(preset.key_envs) or "(none)"
        note = f"no API key found (looked for {keys})"
    return Resolved(name=name, family=family, engine=engine, adapter=adapter, model=model,
                    route=route, base_url=base_url, api_key=api_key,
                    available=available, note=note)


def list_providers() -> list[dict[str, Any]]:
    """Describe every known provider and whether it is ready — for `sherlock providers`."""
    out: list[dict[str, Any]] = []
    for pname in PRESETS:
        r = resolve_provider(pname)
        out.append({
            "provider": pname, "family": r.family, "engine": r.engine, "model": r.model,
            "endpoint": r.base_url or "(vendor default)", "ready": r.available,
        })
    return out


# --------------------------------------------------------------------------- #
# Extending with a genuinely new API (not OpenAI-compatible, not in LiteLLM) is
# this small — set SHERLOCK_LLM_ENGINE=native (or it is chosen automatically for a
# custom family):
#
#   @register
#   class MyVendorAdapter(ProviderAdapter):
#       family = "myvendor"
#       def complete(self, model, system, user, temperature, max_tokens) -> str: ...
#       def tool_loop(self, model, system, user, tools, max_turns, temperature,
#                     max_tokens, on_event, dispatch) -> str: ...
#
#   PRESETS["myvendor"] = Preset("myvendor", ("MYVENDOR_API_KEY",), default_model="m1")
#
# No change to the hunt engine, verifier, ledger, reporter or dashboard.
# --------------------------------------------------------------------------- #
