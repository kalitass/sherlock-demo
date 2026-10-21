# Sherlock — Architecture Specification

| Date | Version | Change |
|------|---------|--------|
| 2026-10-21 | v1.20 | Top-bar environment check. New endpoint **`GET /api/health`** → `{es_ok, llm_ok, llm_provider, llm_model}`: `es_ok` from an ES ping, `llm_ok` from `resolve_provider().available` (is a usable key configured for the active `SHERLOCK_LLM_PROVIDER`). The dashboard shows two status lights in the top bar — **ES** and **LLM** (green when OK, red when not; the LLM pill names the provider, or "off"), polled every 15s. Makes "is my `.env` key wired up / is Elasticsearch reachable" visible at a glance; scan needs no key, so a red LLM light still leaves the deterministic path fully usable. |
| 2026-10-21 | v1.19 | Dashboard & report readability. (1) Evidence links now deep-link into **Kibana Discover** (data view `sherlock-logs-*`, lucene query, wide time window, scoped to the evidence's concrete index via `_index:`), not the raw ES `_search` JSON. New env `SHERLOCK_KIBANA_URL` (default `http://localhost:5601`); `/api/overview` gains a `kibana: {url, data_view_id}` field (resolved/created on demand, `null` when Kibana is unreachable → the UI falls back to the ES `_search` link). (2) Verdict summary (`reduce._summary`) is now human-readable: it no longer dumps the full `mordor_*` index list — it states a source *count* and a technique phrase (names one–two techniques, else "N ATT&CK techniques"). (3) `reporter.build_report` trimmed: Coverage uses counts ("searched N of M") instead of full name lists; Appendix A (evidence ledger) is wrapped in a collapsed `<details>`. (4) Scan KPIs drop the trivial denominators (`X/15`, `X/7` → bare counts). (5) Theme options reduced 4→2 (Graphite, Light). (6) Report tab now renders Markdown→HTML (CSP-safe inline renderer) instead of showing raw `.md`; the `.md` download is unchanged. Verifier/reducer verdict logic unchanged. |
| 2026-10-20 | v1.18 | Public data only. Dropped the hand-synthesised data entirely — the Operation Nightjar generator (`datasets/generate.py`), the canonical-schema scenarios (`datasets/scenarios.py`, the `scn_*` indices incl. `benign`) and the 7-SIEM sample renderer (`datasets/siem_samples.py`). Sherlock now runs solely on public, third-party ATT&CK-labelled telemetry: the OTRF Security-Datasets (`datasets/mordor_import.py`); provenance + citation in new `docs/DATA_SOURCES.md`, and every record keeps `_ingest.source = OTRF/Security-Datasets:<path>`. Consequences: (1) the deterministic scanner (`hunt_engine/heuristic.py`) is re-pointed from the Nightjar `windows/sysmon/web` indices to a corpus sweep of `sherlock-logs-mordor_*` using the raw Windows/Sysmon fields those captures carry (EventID/CommandLine/Image/TargetObject/…), with the kill-chain scenario layer removed (atomic single-technique captures don't compose a chain); (2) the benchmark's false-positive controls move from the synthetic benign day to cross-dataset negatives on real captures (`mshta_exec` asked about brute force, `sam_dump` about scheduled tasks); (3) CLI `seed`/`siem`/`scenario` → one `mordor` command, Makefile updated; (4) the normalization 7-SIEM claim is now backed only by the `test_normalise_all_seven_agree` unit fixture (illustrative format examples), not an ingested synthetic dataset. Synthetic `test_regression.py` removed. |
| 2026-10-20 | v1.17 | Verdict now turns on the DIRECTION OF THE ARGUMENT, not the claim's grammar. New enumerable finding field `supports_hypothesis: true\|false` (does this finding argue the hypothesis AS STATED is true?), emitted by the LLM and orthogonal to `role` (which the verifier keeps using for citation direction: positive→≥1 hit, negative→0 hits). `reduce_verdict` now confirms from verified *addressing* findings with `supports_hypothesis=true` and refutes from those with `supports_hypothesis=false` (default when absent: presence argues for, absence against — so the deterministic engine is unchanged). This replaces the `polarity`-flip (`hypothesis_polarity` is still emitted/reported but no longer flips the verdict — direction is now carried per finding, which removes a double-negation class of bugs). Also dropped the global `any_query_failed` gate on refutation: a stray failed exploratory query no longer blocks a refutation that stands on its own verified absence evidence (the verifier already guarantees those cited queries ran and matched 0). Fixes two failure modes a false-hypothesis benchmark exposed: (1) a benign day wrongly `confirmed` because observations like "all logons succeeded, no failures" were tagged role:positive and read as support; (2) well-evidenced refutations degraded to `inconclusive` by an unrelated failed query. Test `test_reduce_negation_flips`→`test_reduce_direction_from_supports`. |
| 2026-10-20 | v1.16 | Public-dataset accuracy benchmark + hunt scoping. New env `SHERLOCK_LOG_SCOPE` (bare log_type / full index / glob, pinned inside `sherlock-logs-*`) confines a hunt to ONE source: `list_log_types` lists only the scope and `_resolve_index` rejects out-of-scope indices (unset → full namespace, unchanged). `datasets/mordor_import.py` pulls five single-technique, ATT&CK-labelled Windows/Sysmon/PowerShell captures from OTRF Security-Datasets (Mordor) through the normal `ingest_records` auto-schema path (`use_llm=False`, raw PascalCase fields preserved — the agent adapts via `get_field_mapping`), each into its own `sherlock-logs-mordor_<label>` index (cached under gitignored `datasets/mordor_cache/`). `experiment/benchmark.py` scores 20 ground-truth hypotheses (14 distinct ATT&CK techniques across 7 tactics → should confirm, 6 technique-absent / benign → should not), one scoped hunt each, reporting precision/recall/F1/accuracy/false-positive-rate for BOTH the RAW (trust-the-LLM) and HARNESS (evidence-derived) verdicts → `docs/benchmark_results_<model>.md` + `experiment/benchmark_results_<model>.json` (model-tagged via `SHERLOCK_BENCH_TAG`). Companion experiments: `experiment/naive_baseline.py` (same model, harness fully removed — neutral prompt, no verifier/reducer), `experiment/repeatability.py` (same hypothesis run twice, verdict + Jaccard convergence). The 14-technique MANIFEST lives in `datasets/mordor_import.py`. Verifier/reducer/engine logic unchanged. |
| 2026-10-20 | v1.15 | LLM system prompt now states the verifier's contract (rule 7) so the model constructs compliant evidence: each finding is dropped unless every cited query exists, is a query tool, ran OK, and matches the finding's DIRECTION (positive→matched≥1, negative→matched=0); don't cite a 0-hit query under a positive finding or a hit query under an absence; split compound presence+absence claims into two findings. Diagnosed via the ablation: the verifier was rejecting true-but-mis-cited findings (false negatives, e.g. a positive finding citing a 0-hit "after the clear" query) — this reduces those sloppy citations at the source. Verifier/reducer logic unchanged. |
| 2026-10-20 | v1.14 | Deterministic engine is now a pure SCANNER — no natural-language interpretation of the hypothesis anywhere in it. Removed the keyword-relevance machinery (`_tokens`, `BROAD`, per-probe/per-scenario `keywords`, the `relevant` flag): it was the last place the no-LLM path keyword-matched the hypothesis. Now it runs every probe and reports every finding + composed kill-chain, regardless of the hypothesis wording; candidate verdict is about the SCAN (`confirmed`=attack detected, `refuted`=scanned clean, `inconclusive`=could not run). Interpreting a free-text hypothesis is the LLM engine's job (semantic). Coverage keys renamed: `techniques_with_findings`→`techniques_detected`, `hypothesis_relevant_probes`/`relevant_probe_errors`→`probes_ok`/`probe_errors`, new `coverage.mode="scan"`. Consequence: a hypothesis the scan doesn't specifically name (e.g. "ransomware?") against attacked data now returns `confirmed` with the REAL detected techniques, not `inconclusive` — the deterministic path answers "what attacks are present", the LLM path answers the specific hypothesis. |
| 2026-10-19 | v1.13 | Closed the "citation integrity != semantic relevance" gap found by the ablation experiment. Previously the reducer confirmed a hypothesis from ANY verified positive finding, so investigating a FALSE hypothesis ("did ransomware encrypt files?") wrongly returned `confirmed` on the strength of real-but-unrelated findings (the Nightjar C2/brute-force), while the raw LLM correctly judged `refuted`. Fix: the LLM now tags each finding with an enumerable `addresses_hypothesis` (true only if the finding directly tests THIS hypothesis; false for incidental context about other activity), validated in `_sanitize_final`; `reduce_verdict` derives the verdict ONLY from addressing findings (incidental ones remain in the report as context). Result on the false hypothesis: harness verdict moved from wrong `confirmed` to correct/conservative `refuted`/`inconclusive`. Semantic judgement stays the LLM's job (structured field); the deterministic reducer only reads the field. |
| 2026-10-19 | v1.12 | LLM robustness: the tool-use loop no longer discards the whole investigation when the turn budget is exhausted. Previously running out of `max_turns` returned a non-JSON stub ("Reached max turns…") → the verdict defaulted to `inconclusive`, which was the single biggest source of LLM run-to-run divergence (same hypothesis → inconclusive one run, confirmed the next). Now, on budget exhaustion, both loops (`_run_openai_style_loop` and the Anthropic loop) force ONE final tool-less completion instructing the model to emit its verdict from the evidence already gathered. The `create` closures accept an empty tool list to drive that forced call. Measured effect: the same hypothesis went from {inconclusive, inconclusive, confirmed} to {confirmed, confirmed, confirmed}. Added `experiment/ablation.py` (raw-LLM vs evidence-harness comparison) → `docs/ablation_results.md`. |
| 2026-10-19 | v1.11 | Sigma rule migration (`detections/sigma_import.py`, new `detections/` package): import existing SigmaHQ YAML detection rules into the deterministic engine the same way auto-schema onboards a log source — parse (deterministic) → map fields to canonical `n_*` via a deterministic alias table with an LLM fallback for unknown fields → translate selection+condition into one MCP `query_string` (common shapes deterministic; aggregation/correlation flagged `needs_review`, never mis-translated) → validate against ES. Because migrated rules target `n_*`, one rule runs across all 7 normalised SIEM formats at once (verified: a 4625 rule hits 18 docs in each of CEF/LEEF/CIM/ECS/OCSF/ASIM/UDM). New `sherlock sigma` CLI + `make sigma`, three sample rules under `detections/sigma_samples/`, `tests/test_sigma.py`. New dep: `pyyaml`. |
| 2026-10-19 | v1.10 | Deterministic engine reorganised around attack **scenarios** (kill-chains), not just atomic probes. Probes are now reusable *primitives*; a `Scenario` is an ordered set of `Stage`s (each reusing a probe, labelled with its ATT&CK tactic). After the probes run once, each relevant scenario composes the stages that fired into one multi-stage kill-chain finding (`mitre:"kill-chain"`, `technique:<scenario name>`) that narrates the tactic chain and cites every fired stage's evidence; emitted only when ≥2 stages fired. Two scenarios shipped: `hands_on_intrusion`, `web_compromise` (probes reused across both). New result field `coverage.scenarios_detected` (`{scenario,name,stages_present,stages_total,tactics}`). Per-stage findings unchanged, so evidence binding and the verifier/reducer contract are intact. |
| 2026-10-19 | v1.9 | Natural-language understanding is now the LLM's job only — no keyword matching. Removed `_is_negated`/`_NEG` from the reducer and `_NEG_HINTS`/claim-text inference from the verifier. The LLM emits an enumerable `hypothesis_polarity` ("affirmative"\|"negated"), validated in `_sanitize_final`; `reduce_verdict(..., polarity=...)` uses it to decide confirmed↔refuted flips. Finding `role` ("positive"\|"negative") is likewise taken only from the structured field the engine sets (LLM enum / deterministic probes), defaulting to the stricter "positive" when absent — never guessed from wording. Result/`hunt` bundle now carries `hypothesis_polarity` (replaces the internal `negated`). Consequence: the deterministic (no-LLM) engine reads every hypothesis affirmatively; negated-phrased hypotheses require the LLM engine. |
| 2026-10-08 | v1.8 | Third-pass fixes (codex round 3): `_norm_severity` completed — full ladder {informational,low,medium,high,critical,unknown}, string map incl. very-high/error/none/unknown, CEF-correct numeric band (0-3 Low); generated severities made consistent 7-wide (success→low, failure→high). CEF `rt` fallback now actually implemented (`ts_fallback` in `parse_record`), not just advertised. Drift: `get_client()` moved inside `_get`'s try; a failed drift-persist write now returns `persisted:false` + `persist_error`. |
| 2026-10-08 | v1.7 | Second schema-fidelity pass (codex round 2). Mapping fixes: OCSF `n_host`→`dst_endpoint.hostname`, process→`actor.process.*`; ASIM `n_dst_ip`→`TargetIpAddr`, `n_dst_port`→`TargetPortNumber`, `n_process`→`ActingAppName`, `n_cmdline`/`n_sha256`→None; CIM `n_process`→`process`, others→None; UDM process→`principal.process.*`. Data fixes: event times rounded to whole seconds + schema-correct encodings (CEF/LEEF/CIM epoch-ms, OCSF epoch-ms, ECS/UDM RFC3339) so `n_time` is identical across all seven; OCSF `metadata.product` object + `dst_endpoint.hostname`; ASIM `EventStartTime`/`EventEndTime` + schema version 1.0.0. New: `get_path()` resolves flat-dotted OR truly-nested JSON; `_norm_severity()` maps each schema's scale (CEF/LEEF 0-10, OCSF `severity_id` 0-6, ASIM/UDM strings) to one ladder; `detect_schema()`/auto-schema recognise CEF/LEEF after a syslog prefix; CEF parser is escape-aware (trailing `\`), LEEF delimiter 1-4 hex; drift write failures surface as `error`. Stale pre-v1.5 sample files removed. |
| 2026-10-08 | v1.6 | Schema-fidelity corrections after external (codex) review of the 7-schema mock data + mappings: (1) `n_time` now sourced from parsed `@timestamp` — it was silently lost for 6 of 7 schemas; (2) `_norm_action` now EXACT-match, not substring (`"not allowed"` no longer read as success); (3) field-map fixes — CEF event-id← header SignatureID (`cef_sig_id`) + outcome←`outcome`; CIM host←`dest`; ASIM host←`TargetHostname`; UDM host←`target.hostname`, outcome←`extensions.auth.outcome`; wrong-concept mappings (CEF `n_parent`/`n_sha256`, LEEF/CIM/OCSF `n_rule`) set to None; (4) mock data made schema-faithful — OCSF `activity_id=1` (Logon) with outcome in `status`/`status_id`, valid `severity_id`, `category_uid`/`metadata.*`; LEEF 2.0 explicit `x09` delimiter header; CEF outcome in `outcome`; CIM `dest`; ECS `event.category` array + `ecs.version`; ASIM mandatory Authentication fields; UDM principal/target split; 4720/4728 dropped from the SIEM set (logon-only so each is a clean Authentication example). CEF/LEEF parsers now escape-aware + syslog-prefix + LEEF-delimiter aware. Drift surfaces storage errors as status `error`. |
| 2026-10-06 | v1.5 | SIEM schema compatibility + normalisation (SE6014 Week 2): `common/schemas.py` encodes the course's field-mapping tables for all seven famous schemas — producer-side **CEF, LEEF** and consumer-side **CIM, ECS, OCSF, ASIM, UDM** — with `detect_schema()` + `normalise()` onto a canonical `n_*` field set, so one detection/query fires across every schema ("normalise first"). Deterministic CEF/LEEF parsers added (`parser.kind` = `cef`/`leef`); ingestion now auto-detects the schema and writes canonical fields alongside the raw ones. Schema-drift detection (`ingestion/schema_drift.py`, new `sherlock-schema-contracts` index): observed-vs-expected keys & types at ingest, surfaced as `summary.drift` (baseline\|stable\|drift) — Week 2 slide 36. `datasets/siem_samples.py` now emits the incident in all seven schemas; `sherlock siem` shows the schema + drift. |
| 2026-10-06 | v1.4 | Cross-SIEM onboarding demo: `datasets/siem_samples.py` renders the same "Operation Nightjar" incident in 5 popular SIEM export formats (Splunk WinEventLog JSON, Elastic ECS JSON, MS Sentinel SigninLogs JSON, ArcSight CEF text, QRadar LEEF text); new `sherlock siem` CLI + `make siem` onboards them via the standard auto-schema path (JSON by introspection, CEF/LEEF by LLM-built parser). Verified end-to-end with DeepSeek: CEF/LEEF parsed (0.82/0.88), and a DeepSeek hunt on the Splunk index returned `confirmed` 0.95 at 100% integrity. Bug fix: `sherlock-schemas.field_map` mapping set to `enabled:false` (dotted ECS keys like `host.name` were expanding into nested objects and colliding across schemas). Coverage regression test made robust to extra onboarded sources (`coverage.complete` is informational and never gates the verdict). |
| 2026-10-05 | v1.3 | Robustness: LiteLLM is now the **default engine** behind the provider layer (`LiteLLMAdapter`) — inherits LiteLLM's retries, timeouts, `drop_params`, 100+ providers; the hand-rolled Anthropic/OpenAI adapters remain as an automatic fallback (used if LiteLLM is absent or `SHERLOCK_LLM_ENGINE=native`). The agent loop, tool dispatch and evidence-ledger recording stay ours. **Hunt now degrades instead of crashing:** an LLM/provider failure mid-hunt is caught and falls back to the deterministic engine, surfaced as `meta.engine_fallback` + a `warning` event. Native SDK clients now set request timeout + max-retries. New env: `SHERLOCK_LLM_ENGINE` (auto\|litellm\|native), `SHERLOCK_LLM_TIMEOUT` (s), `SHERLOCK_LLM_RETRIES`. `sherlock providers` shows the engine. Public API unchanged. |
| 2026-10-05 | v1.2 | Provider compatibility layer (`common/providers.py`): pluggable `ProviderAdapter` + registry, two families (Anthropic native, OpenAI-compatible) covering 13 presets (openai, azure, groq, deepseek, together, openrouter, mistral, xai, gemini, ollama, lmstudio, vllm). New env: `SHERLOCK_LLM_PROVIDER` accepts any preset/alias, `SHERLOCK_LLM_BASE_URL` overrides the endpoint, `SHERLOCK_LLM_MODEL` blank → provider default; per-provider key env vars (e.g. `GROQ_API_KEY`) auto-detected; local servers are keyless. `llm_available()` now delegates to the resolver. New `sherlock providers` CLI command. Public `LLMClient`/`ToolSpec` API unchanged. |
| 2026-09-30 | v1.1 | Hardening after external review: (1) verified-verdict reducer — the final verdict is derived from verified evidence + coverage, never the engine's self-report; (2) verifier now requires successful **query-tool** evidence and supports negative/absence findings; (3) uniform tool envelope (`ok`, `matched_documents`, `es_request`) — query errors no longer read as zero hits; (4) MCP tools scoped to `sherlock-logs-*` with size/interval/query bounds; (5) coverage computed from the ledger; (6) NDJSON push/stream fixed, schemas below threshold quarantined, idempotent ingestion; (7) LLM output schema-validated, log data marked untrusted, dashboard CSP + output escaping; (8) experiment splits query/result/finding convergence + dataset manifest hash. |
| 2026-09-18 | v1.0 | Initial architecture: ELK backbone, tri-modal ingestion, agentic auto-schema, MCP tool surface, dual-engine hunt (LLM + deterministic), evidence ledger + verifier, dashboard, repeatability experiment. |

---

## 1. Purpose

Sherlock turns a **plain-language threat-hunt hypothesis** into an **evidenced
verdict** at machine speed. It is built so that automation is *trustworthy*: no
claim reaches the report unless it is tied to a reproducible Elasticsearch query
that actually returned supporting data.

Design goals, in priority order:

1. **Evidentiary integrity** — every claim cites the query that produced it.
2. **Coverage** — all sources and the full time window are considered, provably.
3. **Repeatability** — the same hypothesis converges across runs.
4. **Zero-config ingestion** — point at a source; agents parse it.
5. **Observability** — a human can watch and audit the whole hunt.

## 2. Component overview

```
                 ┌──────────── pull (dir watch) ───────────┐
   log sources ──┼──────────── push (HTTP POST) ───────────┼──▶ ingestion core
                 └──────────── stream (syslog UDP) ─────────┘        │
                                                                     ▼
                                                        auto-schema agent
                                                    (fingerprint → reuse |
                                                     LLM/heuristic propose →
                                                     validate → register)
                                                                     │
                                                                     ▼
                                          Elasticsearch  sherlock-logs-{windows,sysmon,web}
                                          + state indices: schemas, hunts, evidence, ingest-audit
                                                                     ▲
                                                                     │  (only via tools)
                                                     ┌──────── MCP server (stdio) ────────┐
                                                     │  list_log_types, get_field_mapping, │
                                                     │  sample_logs, count_logs,           │
                                                     │  search_logs, aggregate, list_schemas│
                                                     └──────────────┬─────────────────────┘
                                                                    │
                          ┌─────────────────── hunt engine ────────┴───────────────────┐
                          │  LLM agent loop  ──or──  deterministic probe battery         │
                          │        │                        │                            │
                          │        ▼                        ▼                            │
                          │   evidence ledger  ◀── records every tool call (DSL + hits)  │
                          │        │                                                     │
                          │        ▼                                                     │
                          │   verifier (reject claims without supporting evidence)       │
                          │        │                                                     │
                          │        ▼                                                     │
                          │   reporter → Markdown verdict + evidence appendix            │
                          └───────────────────────────┬─────────────────────────────────┘
                                                       ▼
                                    dashboard (live SSE trace, verdict, findings, ledger)
                                                       +  Kibana (raw pivoting)
```

## 3. Data model

**Log indices** — one per type (`sherlock-logs-windows|sysmon|web`). Each doc is
normalised to have `@timestamp` (UTC) and `log_type`; other fields come from the
schema's field map. Single shard, zero replicas (single-node lab).

**State indices** (Sherlock's own provenance, so everything lives in ES):

- `sherlock-schemas` — registered parsers, keyed by structural fingerprint.
- `sherlock-hunts` — one doc per hunt: hypothesis, verdict, confidence, coverage,
  verification rate, full report Markdown.
- `sherlock-evidence` — one doc per query executed during a hunt: tool, arguments,
  **exact DSL**, result summary, hit count, digest.
- `sherlock-ingest-audit` — one doc per ingest batch: source, mode, schema, counts.

## 4. Ingestion

All three modes converge on `ingestion/ingest_core.ingest_records()`:
`detect-or-reuse schema → ensure index mapping → parse → bulk index → audit`.

- **Pull** (`ingestion/pull.py`): watches a drop directory; new files are ingested
  and moved to `processed/`.
- **Push** (dashboard `POST /api/ingest/push?log_type=...`): a JSON array or NDJSON
  body from an endpoint agent.
- **Stream** (`ingestion/stream.py`): a UDP syslog listener that buffers and flushes
  in small batches; includes a replay producer for demos.

## 5. Agentic auto-schema (`ingestion/auto_schema.py`)

1. **Fingerprint** the sample (sorted JSON keys, or a normalised text shape).
2. **Reuse** — if a schema with that fingerprint exists, use it (no re-derivation).
3. **Propose** — LLM proposes a parser spec (`{parser, ts_field, ts_format}`); if
   no LLM, a heuristic does (JSON introspection, or the Apache/NGINX *combined*
   log-format regex, or a generic fallback).
4. **Validate** — apply the parser to the sample; require ≥80% parse rate and a
   parseable timestamp. If the LLM proposal fails, fall back to the heuristic.
5. **Derive** the ES field map (types inferred from sample values) and **register**.

This is what lets an analyst "point the system at a source and the agents handle
the rest." The web source is deliberately raw text so the agent must *build* a
parser, not just map JSON keys.

## 6. MCP tool surface (`mcp_server/`)

A stdio MCP server exposes the hunt tools. Any MCP client — Sherlock's engine or
Claude Desktop — drives hunts through it. Every query tool returns the **exact
DSL** it executed under `query_dsl`, which is what the ledger captures.

Tools: `list_log_types`, `get_field_mapping`, `sample_logs`, `count_logs`,
`search_logs`, `aggregate` (terms / date_histogram / cardinality / stats),
`list_schemas`.

The engine's MCP client (`hunt_engine/mcp_client.py`) is a synchronous facade
over the async SDK; it has a `stdio` backend (real MCP) and a `direct` in-process
fallback so a live demo never fails on a transport hiccup.

## 7. Hunt engine (`hunt_engine/`)

Two interchangeable engines produce the **same bundle shape** so everything
downstream (verifier, reporter, dashboard) is engine-agnostic:

- **LLM engine** (`llm_hunt.py`): a tool-use agent loop. The system contract forces
  coverage first, quantitative testing, technique-based thinking, and — critically
  — **evidence citation**: the final verdict is a JSON object whose findings cite
  evidence ids returned by the tools. Temperature 0 for determinism. The loop is
  **hand-rolled on the raw provider SDKs** (no CrewAI/LangChain/agent framework) so
  every tool call is recorded in the evidence ledger and streamed to the dashboard
  under full control — the framework-free choice is deliberate: a black-box agent
  loop cannot be made to satisfy the "no evidence, no claim" contract.

  The engine talks to one abstraction — a `ProviderAdapter` (see §7.4) — so the
  same hunt logic runs on any supported provider.
- **Deterministic engine** (`heuristic.py`): a fixed battery of standard SOC
  detections (brute force, valid-account abuse, web shell/exploitation, encoded
  PowerShell, persistence, log clearing, C2 beaconing), each tagged to MITRE
  ATT&CK. A finding is emitted only when its query returns supporting hits. The
  verdict is decided by matching the hypothesis to the techniques that fired.

### 7.0 SIEM schema compatibility + normalisation (`common/schemas.py`)

Aligned to SE6014 Week 2 ("a detection is only as portable as its schema").
Sherlock recognises the seven schemas the course teaches and maps them onto one
canonical field set:

- **Producer-side wire formats:** CEF (ArcSight), LEEF (IBM QRadar) — parsed by
  deterministic `cef`/`leef` parsers (the formats are standardised, so no LLM is
  needed), not an LLM-guessed regex.
- **Consumer-side normalisation schemas:** CIM (Splunk), ECS (Elastic), OCSF,
  ASIM (MS Sentinel), UDM (Google SecOps).

`detect_schema()` identifies the schema (wire-format prefix, or signature fields);
`normalise()` rewrites each event onto canonical `n_*` fields (`n_user`, `n_src_ip`,
`n_event_id`, `n_action`, …) using the course's field-mapping tables. At ingest the
canonical fields are written **alongside** the raw ones, so a single query or
detection fires identically across all seven schemas — the "normalise first" /
Sigma portability idea, and the migration path when a source's schema differs from
what a rule was written against.

**Schema-drift detection (`ingestion/schema_drift.py`).** Week 2's prescribed
defence against drift that "breaks detections silently": a per-source **contract**
(field→type map, first seen) is stored in `sherlock-schema-contracts`, and every
later ingest compares observed vs expected keys & types. Missing or retyped fields
are surfaced as `summary.drift` (`baseline`/`stable`/`drift`) instead of failing
silently; the baseline is not auto-updated on drift, so the condition keeps
alerting until `rebaseline()` accepts the change.

### 7.1 Evidence ledger (`evidence_ledger.py`)

Every tool call is recorded with a stable id (`E1`, `E2`, …), the exact DSL, a
result summary, a hit count, and a digest. Persisted to `sherlock-evidence`.

### 7.2 Verifier (`verifier.py`) — anti-hallucination

For each finding, the verifier requires that it cite ≥1 evidence id that (a) exists
in the ledger and (b) actually returned hits. Findings that cite nothing, cite a
**non-existent** evidence id (a hallucinated citation), or cite only empty results
are **quarantined** out of the verdict and shown in a "rejected" section. The
report's *evidence-integrity* percentage is `verified / total`.

### 7.3 Reporter (`reporter.py`)

Renders: verdict badge + confidence + integrity, executive summary, coverage,
each verified finding with MITRE mapping and the **inline DSL** behind it, the
rejected-claims section (transparency), recommended actions, and an appendix
listing **every** query that ran.

### 7.4 Provider compatibility layer (`common/providers.py`)

Bring-your-own-model. A `ProviderAdapter` declares two methods — `complete()` and
`tool_loop()` — and the loop orchestration that is Sherlock-specific (evidence
ledger wiring, the SSE event stream, tool dispatch, output sanitisation) stays in
the engine and is provider-agnostic. Only the wire translation lives in the
adapter. Two **engines** implement that contract:

- **LiteLLM engine (default).** One `LiteLLMAdapter` routes to 100+ providers and
  inherits LiteLLM's **retries, per-call timeout, `drop_params`, and fallbacks** —
  this is the robustness baseline. LiteLLM normalises each model *call* only; the
  agent loop, tool dispatch and ledger recording remain ours, so auditability is
  unaffected. Model routing is a provider-qualified id (`groq/llama-3.3-70b-…`).
- **Native engine (fallback / minimal-dependency).** Hand-rolled `Anthropic` and
  `OpenAI`-compatible adapters on the raw vendor SDKs, with request timeout +
  max-retries set. Chosen automatically when LiteLLM is not installed, or forced
  with `SHERLOCK_LLM_ENGINE=native`. A custom-registered family always uses this
  engine (LiteLLM only routes its own providers).

A preset table maps each provider alias to its family, native endpoint, key env
var(s), default model and LiteLLM prefix; local servers (Ollama, LM Studio, vLLM)
are keyless. `resolve_provider()` turns `SHERLOCK_LLM_PROVIDER` (+ optional
`SHERLOCK_LLM_MODEL` / `SHERLOCK_LLM_BASE_URL` / `SHERLOCK_LLM_ENGINE` and the
per-provider key env var) into a configured adapter. Switching provider is one
config line; **adding a brand-new, non-OpenAI API is a ~40-line adapter class plus
one `@register` and a preset — the hunt engine, verifier, ledger, reporter and
dashboard do not change.** `sherlock providers` prints the matrix, engine and
readiness.

**Degrade, don't crash.** If the selected LLM engine fails mid-hunt (bad key,
network, dead endpoint, rate-limit after retries), `run_hunt` catches it and falls
back to the deterministic engine — which needs no external model — so a verdict is
still produced. The fallback is surfaced transparently as `meta.engine_fallback`
and a `warning` event, never silently masked.

## 8. Completeness & accuracy — how they are guaranteed

- **Coverage**: coverage is computed from the ledger, not self-reported. The
  reducer records which indices were actually queried successfully, which sources
  were missed, and whether any query failed. A `refuted` verdict requires complete,
  successful coverage; otherwise the result is `inconclusive`.
- **Verified verdict**: the engine (LLM or heuristic) only proposes a *candidate*
  verdict. `hunt.reduce_verdict` derives the final verdict from the verifier's
  output, so rejected claims genuinely do not count. Presence-claims need a query
  that matched ≥1 document; absence-claims need a query that ran and matched 0;
  hypothesis polarity (negation) is handled explicitly.
- **Accuracy / anti-hallucination**: a finding is verified only if it cites
  evidence that (a) exists in this hunt's ledger, (b) came from a query tool
  (count/search/aggregate), (c) executed successfully, and (d) matches its role.
  A hallucinated citation fails (a); a context-tool citation fails (b); a failed
  query fails (c). All rejections are shown in the report.
- **Reproducibility of evidence**: every query tool returns `es_request` (index +
  body), which the ledger stores and the report shows, so any reader can re-run it.
  A separate `query_digest` (index + DSL, results excluded) makes query-plan
  comparison independent of the data.

## 9. Repeatability experiment (`experiment/run_twice.py`)

Runs the same hypothesis twice and reports verdict agreement, finding-set Jaccard
(over MITRE techniques), evidence-integrity, and query-plan overlap. The
deterministic engine is byte-identical across runs (repeatability ceiling); the
LLM engine's variance is controlled by temperature 0, the coverage-first
contract, and the evidence gate. See `docs/experiment_results.md`.

## 10. Security & scope notes

- Security is **disabled** on ES/Kibana because this is a self-contained local
  lab, not a deployment. Production would enable TLS + auth and put the MCP server
  behind authenticated transport.
- All data is synthetic (generated locally). No live systems are touched.
- The agent has a **read-only** tool surface over the SIEM — it can query but not
  mutate logs — which bounds the blast radius of any agent error.

## 11. Claim–evidence binding: what is and isn't guaranteed

- **Deterministic engine (authoritative):** each finding is *generated from* the
  query that supports it — the claim text and its cited evidence are produced
  together from the same result — so a finding structurally cannot cite unrelated
  evidence. Combined with the verified-verdict reducer, the deterministic verdict
  is evidence-bound end to end. This is the mode to trust for a verdict of record.
- **LLM engine (exploratory):** the model writes free-text claims and chooses which
  evidence ids to cite. Sherlock enforces **citation integrity** (the citation must
  be a real, successful query that matched in the claim's direction) and sanitises
  the output, but it does **not** yet prove the cited query is *semantically about*
  the claim. So the LLM path can, in principle, cite a real-but-off-topic query.
  Treat LLM verdicts as leads to confirm, not as the verdict of record.
- **Next step to close this:** typed assertions — a finding declares
  `predicate + polarity + required_evidence`, and claims are generated from
  structured evidence rather than free text, extending the deterministic engine's
  binding to the LLM path.

## 12. Known limitations / next steps

- The deterministic engine only knows the techniques we encoded; the LLM engine is
  open-ended but costs tokens and adds variance.
- Absence/`refuted` is only asserted for binary detections that ran a clean
  zero-match query; threshold detections (brute force, C2 volume) do not assert
  absence, so a clean run of only those returns `inconclusive`, not `refuted`.
- Single-node ES, no ILM/retention; no auth on the dashboard/MCP transport (lab).
- Exact document counts use `track_total_hits`, which can be expensive on very
  large indices — a per-hunt query budget/timeout is the next hardening step.
- Next: streaming/continuous hunts, typed-assertion findings, a detection-as-code
  regression harness on the deterministic engine, and analyst feedback to tune
  confidence.
