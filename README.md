# Sherlock — Agentic Threat Hunting on the ELK Stack

**Plain-English hypothesis in → evidence-linked verdict out.**

Sherlock is an AI-assisted threat-hunting platform for SE6014 (Question 1). A user
types a hypothesis in natural language; agentic workflows plan the hunt, query an
Elasticsearch SIEM **only through an MCP tool surface**, gather evidence, and
return an evidenced verdict — where **every claim is tied to the exact query that
produced it**, and any claim that is not is rejected by a verifier before it can
reach the report.

It ships with a self-contained lab: an ELK stack in Docker, agentic ingestion of
14 public ATT&CK-labelled datasets with automatic schema detection, and a live
dashboard to watch a hunt happen.

---

## What it does (mapped to the brief)

| Requirement | Where |
|---|---|
| Ingest via **pull, push, stream** | `ingestion/pull.py`, dashboard `POST /api/ingest/push`, `ingestion/stream.py` |
| **Agentic ingestion** — point at a source, agents do the rest | `ingestion/auto_schema.py` |
| **Auto schema**: inspect → match template → else create, validate, register | `ingestion/auto_schema.py`, `ingestion/schema_registry.py` |
| **≥3 log types** (14 public ATT&CK datasets: Windows Security, Sysmon, PowerShell…) | `datasets/mordor_import.py` |
| **MCP server** exposing search/aggregation/etc. | `mcp_server/server.py`, `mcp_server/tools.py` |
| **Agentic hunt**: plan → query → test → evidenced report | `hunt_engine/` |
| **Completeness/accuracy + anti-hallucination** | `hunt_engine/evidence_ledger.py`, `hunt_engine/verifier.py` |
| **Same hunt twice + compare** | `experiment/run_twice.py` |

---

## Requirements

- **Docker Desktop** (Apple Silicon supported — see notes below)
- **[uv](https://docs.astral.sh/uv/)** for the Python environment
- ~6 GB free for the Docker VM
- *(Optional)* an LLM API key for the LLM engine. **Without a key, Sherlock runs
  its deterministic engine and everything still works end to end.**

## Quick start — 3 steps

```bash
make demo              # 1. START + DATA: ES + Kibana + deps, then download & ingest the datasets
cp .env.example .env   # 2. KEY (optional): add an LLM key — see below; the Scan engine needs none
make dashboard         # 3. RUN: web UI → http://localhost:8080
```

Open **http://localhost:8080** → type a hypothesis → **Run hunt**; or open **Detection
scan** (deterministic, no key needed). **Kibana** for raw pivoting: **http://localhost:5601**.

**2 · LLM key.** One line picks the model. Edit `.env`:

```bash
SHERLOCK_LLM_PROVIDER=deepseek     # or anthropic, openai, groq, gemini, openrouter, ollama, …
DEEPSEEK_API_KEY=sk-...            # the matching *_API_KEY for your chosen provider
```

`.env` is gitignored. **No key? The deterministic Scan still works end-to-end — only the
LLM Hunt is disabled.** List providers and which are ready: `make providers`.

**1 · Data.** `make mordor` (included in `make demo`) pulls the public, MIT-licensed
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) — real
Windows/Sysmon/PowerShell telemetry, each capture labelled with the ATT&CK technique it
ran (~36,700 events across 14 datasets). Auto-downloaded and cached under
`datasets/mordor_cache/`; per-dataset provenance in `docs/DATA_SOURCES.md`.

### CLI

```bash
uv run python -m cli status                                  # cluster + indices
uv run python -m cli hunt "Was a backdoor local account created on this host?"
uv run python -m cli schemas                                 # registered parsers
```

### Supported LLM providers

Each is one `SHERLOCK_LLM_PROVIDER` value; set its key env var in `.env`. Routing uses
**LiteLLM** when installed, else built-in native adapters.

| Provider | Key env var | Notes |
|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | native Claude API |
| `openai` | `OPENAI_API_KEY` | |
| `azure` | `AZURE_OPENAI_API_KEY` | also set `SHERLOCK_LLM_BASE_URL` |
| `groq` | `GROQ_API_KEY` | |
| `deepseek` | `DEEPSEEK_API_KEY` | |
| `together` | `TOGETHER_API_KEY` | |
| `openrouter` | `OPENROUTER_API_KEY` | any model on OpenRouter |
| `mistral` | `MISTRAL_API_KEY` | |
| `xai` | `XAI_API_KEY` | Grok |
| `gemini` | `GEMINI_API_KEY` | Google's OpenAI-compatible endpoint |
| `ollama` / `lmstudio` / `vllm` | *(none — local)* | self-hosted, no key |

`engine: auto` uses the LLM when a key is present; `engine: deterministic` forces
the no-LLM path. Adding a provider with a genuinely different API is a ~40-line
adapter class — the hunt logic never changes (see `common/providers.py`).

**Robustness:** if the chosen LLM provider fails mid-hunt (bad key, network, dead
endpoint, rate-limit), the hunt does **not** crash — it falls back to the
deterministic engine and still returns an evidenced verdict, labelling the fallback
in the report (`meta.engine_fallback`). Tune with `SHERLOCK_LLM_TIMEOUT` (seconds)
and `SHERLOCK_LLM_RETRIES`.

### SIEM schema compatibility + "normalise first" (SE6014 Week 2)

*A detection is only as portable as its schema.* The same incident ships exported in
the **seven schemas the course teaches**, and Sherlock normalises them all onto one
canonical field set so a single query fires across every one. The seven formats are
kept as illustrative fixtures and normalised onto `n_*`; the agreement is proven by a
unit test (no synthetic dataset is ingested):

```bash
uv run pytest tests/test_core.py -k normalise_all_seven_agree
```

| File | Side | Schema |
|---|---|---|
| `cef.log` | producer (wire) | **CEF** — ArcSight |
| `leef.log` | producer (wire) | **LEEF** — IBM QRadar |
| `cim.json` | consumer | **CIM** — Splunk |
| `ecs.json` | consumer | **ECS** — Elastic |
| `ocsf.json` | consumer | **OCSF** |
| `asim.json` | consumer | **ASIM** — MS Sentinel |
| `udm.json` | consumer | **UDM** — Google SecOps |

Each event is normalised onto canonical `n_*` fields (`n_user`, `n_src_ip`,
`n_event_id`, `n_action`, …) using the lecture's field-mapping tables, so **one query
fires identically across all seven schemas**:

```bash
# the SAME canonical query matches the identical event rendered in all seven schemas
n_event_id=4625  AND  n_user=administrator  AND  n_src_ip=203.0.113.66  AND  n_action=failure
```

CEF/LEEF are parsed by deterministic parsers (standardised wire formats); the JSON
schemas by introspection — all with no API key.

**Schema-drift detection** (Week 2, slide 36 — *"drift breaks detections silently"*):
every ingest runs an observed-vs-expected contract check. Rename or drop a field a
detection relies on and the ingest surfaces `drift` (with the missing / added / type-
changed fields) instead of quietly matching nothing. Contracts live in
`sherlock-schema-contracts`; re-accept an intentional change with `schema_drift.rebaseline()`.

### The three ingestion modes

```bash
# PULL — drop a file into the watched directory
uv run python -m ingestion.pull            # in one terminal
cp datasets/generated/sysmon.json drop/    # in another

# PUSH — an endpoint agent posts a batch
curl -X POST "http://localhost:8080/api/ingest/push?log_type=windows" \
     -H 'Content-Type: application/json' --data-binary @datasets/generated/windows_security.json

# STREAM — a continuous syslog-style feed
uv run python -m ingestion.stream                                   # listener
uv run python -m ingestion.stream --send datasets/generated/web_access.log  # producer
```

### Point Claude Desktop at the same MCP server (optional)

The MCP server is a normal stdio server. In Claude Desktop's config:

```json
{ "mcpServers": { "sherlock": {
    "command": "uv",
    "args": ["run", "python", "-m", "mcp_server.server"],
    "cwd": "/absolute/path/to/sherlock"
}}}
```

---

## Architecture (one paragraph)

Logs enter through pull/push/stream and hit a shared **ingestion core**. An
**auto-schema agent** fingerprints each source, reuses a registered parser or
builds one (JSON introspection or a generated regex), validates it against a
sample, and registers it. Parsed events land in per-type Elasticsearch indices.
The **MCP server** exposes search/aggregate/count and friends as read-only tools,
scoped to the log indices and bounded. The **hunt engine** (LLM agent or
deterministic engine) plans a hunt, calls those tools, and records every call in an
**evidence ledger** with the exact reproducible request (`es_request`) and the
number of documents it matched. A **verifier** keeps only findings backed by a
successful query, and a **reducer** derives the final verdict from that verified
evidence plus real coverage — so the engine's self-report never decides the
verdict, and rejected claims genuinely do not count. The **reporter** shows the
verified verdict, every finding's query, and every rejected claim. The
**dashboard** streams the whole thing live. Full detail: `docs/sherlock-spec.md`.

---

## Notes for Apple Silicon (M-series) — problems we hit and fixed

These are baked into the repo; listed so a grader understands the choices.

1. **Elasticsearch SIGILL at JVM start.** ES 8.14+ bundles JDK 22, and JDK 22 /
   ES's own JDK 21.0.2 crash on Apple Silicon under Docker Desktop while probing
   the ARM SVE vector length. **Fix:** `docker/es/Dockerfile` swaps in Temurin
   21.0.12, which disables SVE gracefully. Pinned to ES **8.13.4**.
2. **Indices flip read-only / cluster goes red.** On a full-ish laptop disk ES
   hits the 95% flood-stage watermark. **Fix:** disk-based allocation is disabled
   in `docker-compose.yml` for this local lab.
3. **Memory.** ES heap is capped at 768 MB and Kibana at 512 MB so the stack fits
   a ~6–8 GB Docker VM.

## Repo layout

```
docker-compose.yml   docker/es/       # ELK, patched for Apple Silicon
common/              # settings, ES client, LLM client
datasets/            # deterministic 3-source attack generator
ingestion/           # auto_schema, parsing, ingest core, pull/push/stream
mcp_server/          # MCP tools + stdio server
hunt_engine/         # mcp_client, planner/executor (LLM), heuristic, ledger, verifier, reporter
dashboard/           # FastAPI + single-page SOC console (SSE live trace)
experiment/          # run-the-same-hunt-twice comparison
docs/                # architecture spec, division of labour, experiment results
```
