"""Central configuration for Sherlock.

Everything is environment-driven so the whole system is reproducible from a
single `.env` file. See `.env.example` for the knobs.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional at runtime
    pass

REPO_ROOT = Path(__file__).resolve().parent.parent


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


# --- Index names -----------------------------------------------------------
# Per-type log indices keep mappings clean and let the agent scope a hunt to a
# single source when it wants to. The registry / hunt / evidence indices hold
# Sherlock's own state so everything (including provenance) lives in ES.
LOG_INDEX_PREFIX = "sherlock-logs-"
SCHEMA_INDEX = "sherlock-schemas"
CONTRACT_INDEX = "sherlock-schema-contracts"
HUNT_INDEX = "sherlock-hunts"
EVIDENCE_INDEX = "sherlock-evidence"
INGEST_AUDIT_INDEX = "sherlock-ingest-audit"


def log_index(log_type: str) -> str:
    return f"{LOG_INDEX_PREFIX}{log_type}"


@dataclass
class Settings:
    es_url: str = field(default_factory=lambda: _env("SHERLOCK_ES_URL", "http://localhost:9200"))

    # LLM. Provider is 'anthropic' or 'openai' (or any OpenAI-compatible base_url).
    llm_provider: str = field(default_factory=lambda: _env("SHERLOCK_LLM_PROVIDER", "anthropic"))
    llm_model: str = field(default_factory=lambda: _env("SHERLOCK_LLM_MODEL", "claude-sonnet-4-5"))
    llm_temperature: float = field(default_factory=lambda: float(_env("SHERLOCK_LLM_TEMPERATURE", "0.0")))
    llm_max_tokens: int = field(default_factory=lambda: int(_env("SHERLOCK_LLM_MAX_TOKENS", "4096")))
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY", ""))
    openai_api_key: str = field(default_factory=lambda: _env("OPENAI_API_KEY", ""))
    openai_base_url: str = field(default_factory=lambda: _env("OPENAI_BASE_URL", ""))

    # If no usable key is configured, the engine runs in a deterministic offline
    # planner mode so the demo still works end-to-end without credentials. The
    # decision is delegated to the provider layer so every supported provider
    # (incl. keyless local servers like Ollama) is judged consistently.
    def llm_available(self) -> bool:
        from common.providers import resolve_provider  # lazy: avoids import cycle

        return resolve_provider().available

    # Paths
    drop_dir: Path = field(default_factory=lambda: Path(_env("SHERLOCK_DROP_DIR", str(REPO_ROOT / "drop"))))
    data_dir: Path = field(default_factory=lambda: Path(_env("SHERLOCK_DATA_DIR", str(REPO_ROOT / "datasets" / "generated"))))
    reports_dir: Path = field(default_factory=lambda: Path(_env("SHERLOCK_REPORTS_DIR", str(REPO_ROOT / "reports"))))

    # Network
    push_host: str = field(default_factory=lambda: _env("SHERLOCK_PUSH_HOST", "0.0.0.0"))
    stream_syslog_port: int = field(default_factory=lambda: int(_env("SHERLOCK_SYSLOG_PORT", "5514")))
    dashboard_port: int = field(default_factory=lambda: int(_env("SHERLOCK_DASHBOARD_PORT", "8080")))
    mcp_http_port: int = field(default_factory=lambda: int(_env("SHERLOCK_MCP_PORT", "8765")))

    def __post_init__(self) -> None:
        for p in (self.drop_dir, self.data_dir, self.reports_dir):
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
