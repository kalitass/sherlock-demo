# Division of Labour & Work Breakdown

> Sherlock is decomposed into five coherent subsystems, one owner each. Every
> member owns code that is independently runnable and testable, so each
> contribution is visible in the repository history and in the demo. Replace the
> bracketed placeholders with real names and matriculation numbers.

| # | Member | Matric. | Role | Owns |
|---|--------|---------|------|------|
| 1 | [Name 1] | [Axxxxxxx] | Platform & Ingestion Lead | ELK stack, tri-modal ingestion |
| 2 | [Name 2] | [Axxxxxxx] | Schema Intelligence Engineer | Agentic auto-schema, registry, parsing |
| 3 | [Name 3] | [Axxxxxxx] | MCP & Tooling Engineer | MCP server + tools, MCP client, LLM client |
| 4 | [Name 4] | [Axxxxxxx] | Agentic Hunt Engineer | Hunt engine, ledger, verifier, reporter |
| 5 | [Name 5] | [Axxxxxxx] | Product, UX & Evaluation Lead | Dashboard, datasets, experiment, report/pitch |

---

## Member 1 — Platform & Ingestion Lead

**Mission.** Stand up a reliable ELK backbone on Apple Silicon and make logs flow
in through all three required modes.

- Elasticsearch + Kibana in Docker; solved the Apple-Silicon JDK SIGILL (Temurin
  swap) and the disk-watermark red-cluster issue.
- Shared ingestion core (schema → mapping → parse → bulk → audit).
- Pull (directory watch), push (HTTP), stream (syslog UDP) ingestion.
- Cluster/index health via `cli status`.

**Files.** `docker-compose.yml`, `docker/es/Dockerfile`, `common/settings.py`,
`common/es.py`, `ingestion/ingest_core.py`, `ingestion/pull.py`,
`ingestion/stream.py`, `Makefile`.

## Member 2 — Schema Intelligence Engineer

**Mission.** Make ingestion "point-and-go", and make detections portable across
SIEMs: the agent decides how to parse any source, and every event is normalised
onto one canonical schema (SE6014 Week 2: "a detection is only as portable as its
schema").

- Fingerprint-based schema reuse; LLM and heuristic parser proposal.
- Validation gate (parse-rate + timestamp) and field-map derivation.
- Schema registry in Elasticsearch, versioned, reusable.
- Deterministic CEF/LEEF parsers and the combined-log-format regex path.
- **Seven-schema compatibility + normalisation** (CEF, LEEF, CIM, ECS, OCSF, ASIM,
  UDM → canonical `n_*` fields) so one query fires across every schema.
- **Schema-drift detection** (observed-vs-expected field contract at ingest).
- **Sigma rule migration** (`detections/sigma_import.py`): import existing SigmaHQ
  YAML detection rules, map their fields to `n_*` (deterministic alias table + LLM
  fallback), translate to one MCP query — so ONE imported rule hunts across all 7
  SIEM formats. Verified: a 4625 rule hit 18 docs in each of the seven.

**Files.** `ingestion/auto_schema.py`, `ingestion/schema_registry.py`,
`ingestion/parsing.py`, `common/schemas.py`, `ingestion/schema_drift.py`,
`datasets/siem_samples.py`, `detections/sigma_import.py`, `detections/sigma_samples/`.

## Member 3 — MCP & Tooling Engineer

**Mission.** Expose the SIEM to agents through a clean, safe MCP tool surface.

- The tool functions (search, aggregate, count, mappings, samples, schemas), each
  returning the exact DSL executed.
- The stdio MCP server (also connectable from Claude Desktop).
- The synchronous MCP client facade with a real-stdio backend and a direct
  fallback.
- The provider-agnostic LLM client + tool-use agent loop, and a **provider
  compatibility layer** (LiteLLM default + native adapters) so any of 13+ providers
  — or a local model — works from one config line, with graceful fallback.
- **Agent-loop robustness**: force a final answer when the tool-call budget is
  exhausted (previously the loop discarded the whole investigation and defaulted to
  inconclusive — the single biggest source of run-to-run divergence).

**Files.** `mcp_server/tools.py`, `mcp_server/server.py`,
`hunt_engine/mcp_client.py`, `common/llm.py`, `common/providers.py`.

## Member 4 — Agentic Hunt Engineer

**Mission.** Turn a hypothesis into an evidenced verdict, and make hallucination
mechanically impossible to publish.

- LLM hunt (coverage-first agent contract, structured verdict).
- **Scenario kill-chain engine**: probes as reusable primitives, composed into
  multi-stage ATT&CK kill-chains (hands-on intrusion, web compromise) that narrate
  the attack story instead of raising isolated alerts.
- Evidence ledger (every query, DSL, hit count, digest).
- Verifier (reject unsupported / hallucinated-citation claims by evidence direction).
- **Verdict reducer with semantic binding**: verdict derived only from verified,
  hypothesis-addressing evidence (`addresses_hypothesis`); LLM-emitted enumerable
  `hypothesis_polarity` — no keyword matching of natural language.
- Reporter (verdict, evidence-linked findings, full appendix) + orchestrator.

**Files.** `hunt_engine/hunt.py`, `hunt_engine/llm_hunt.py`,
`hunt_engine/heuristic.py`, `hunt_engine/evidence_ledger.py`,
`hunt_engine/verifier.py`, `hunt_engine/reporter.py`.

## Member 5 — Product, UX & Evaluation Lead

**Mission.** Make it observable, demoable, evaluated, and sellable.

- The SOC-console dashboard with a live SSE agent trace, verdict card, findings,
  and evidence ledger.
- The deterministic cross-source attack dataset ("Operation Nightjar") and the
  extra test scenarios (benign / password-spray / data-exfil).
- The repeatability experiment and its write-up.
- **The harness ablation experiment** (`experiment/ablation.py`): raw-LLM vs
  evidence-harness — quantifies unsupported/hallucinated claims caught (26% across
  runs) and the verdict correctness the harness adds.
- The project report and the Shark-Tank pitch deck.

**Files.** `dashboard/app.py`, `dashboard/static/index.html`,
`datasets/generate.py`, `datasets/scenarios.py`, `experiment/run_twice.py`,
`experiment/ablation.py`, `docs/*`, `report/*`, `pitch/*`.

---

## Timesheet (indicative, hours)

| Activity | M1 | M2 | M3 | M4 | M5 | Total |
|---|---:|---:|---:|---:|---:|---:|
| Design & architecture (joint) | 4 | 4 | 4 | 4 | 4 | 20 |
| ELK bring-up + Apple-Silicon fixes | 10 | 1 | 1 | – | 1 | 13 |
| Tri-modal ingestion | 9 | 2 | – | – | 1 | 12 |
| Auto-schema + registry + parsing | 1 | 12 | 2 | – | – | 15 |
| MCP server + tools + client + LLM client | 1 | 1 | 13 | 2 | – | 17 |
| Hunt engine + ledger + verifier + reporter | – | – | 3 | 14 | 1 | 18 |
| Dataset scenario design | – | 1 | – | 1 | 7 | 9 |
| Dashboard + observability | 1 | – | 1 | 1 | 11 | 14 |
| Experiment + evaluation | – | 1 | – | 2 | 6 | 9 |
| Report + pitch + demo prep | 2 | 2 | 2 | 2 | 9 | 17 |
| Integration & testing (joint) | 3 | 3 | 3 | 3 | 3 | 15 |
| **Total** | **31** | **27** | **32** | **31** | **43** | **159** |

_Every member contributed to design, integration, and the live demo. Ownership
above indicates the primary author of each subsystem; code review was
cross-member._
