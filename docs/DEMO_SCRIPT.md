# Demo runbook — 5-minute demo + 5-minute pitch

## Before class (once)

```bash
make up            # wait until http://localhost:9200 is green (~1 min)
make seed          # ~5 s; loads 3 log types
make dashboard     # leave running on http://localhost:8080
```

Open two browser tabs: **http://localhost:8080** (Sherlock) and
**http://localhost:5601** (Kibana). Set `engine: deterministic` in the dashboard
dropdown so the demo is instant and can't fail live. (If you have an API key set,
`engine: LLM` shows the agent reasoning in natural language — nice, but slower and
needs network. Deterministic is the safe default for a graded demo.)

## The 5-minute demo (click-by-click)

1. **(0:00) Framing — 20 s.** “Today an analyst hand-loads logs and writes a
   one-off query per hunt. Sherlock takes a hypothesis in plain English and returns
   an evidenced verdict. Watch.”
2. **(0:20) Show ingestion — 40 s.** Point at the four tiles: **6,468 events, 3
   sources, 3 auto-schemas**. “Three different log formats — Windows, Sysmon, and
   raw text web logs — and we wrote **zero** parsers. An agent inspected each
   source, built a parser, validated it, and registered it. The web log is plain
   text; it auto-extracted 12 fields.” (Optional: show the *Ingested sources* table.)
3. **(1:00) Run a hunt — 90 s.** Click the example chip *“An external actor
   brute-forced the administrator account and gained access”*, press **Run hunt**.
   Narrate the **live trace**: “It connects to the SIEM through MCP, runs a coverage
   sweep, then probes technique by technique — brute force, web shell, PowerShell,
   persistence, log clearing, C2 — and each finding streams in with its severity and
   MITRE ID.” End on **VERDICT: CONFIRMED, integrity 100%**.
4. **(2:30) The proof — 60 s.** Scroll to **Findings** and **Evidence ledger**.
   “Here’s the whole kill chain. Every finding cites evidence ids — E2, E3 — and
   over here is the ledger: **every query we ran**, with its hit count. Nothing on
   the left exists without a receipt on the right.”
5. **(3:30) The guardrail — 40 s.** “If the agent ever claimed something it couldn’t
   back with a query, a verifier throws it out before it reaches the report — you’d
   see it in a struck-through *rejected* section. Hallucination isn’t discouraged;
   it’s mechanically blocked.” (Show `uv run python -m tests.test_core` output if
   asked — it proves the verifier rejects a hallucinated citation.)
6. **(4:10) Repeatability — 30 s.** “Run the same hunt twice and the verdict,
   findings, and evidence are identical — Jaccard 1.0. That’s what makes it
   auditable.” (Optionally run `make experiment` beforehand and show the table.)
7. **(4:40) Kibana — 20 s.** Flip to Kibana: “And because it’s the standard ELK
   stack, an analyst can pivot on the same indices by hand any time.”

**Backup if anything hangs:** switch the engine dropdown to `deterministic`, or run
`uv run python -m cli hunt "web shell was used for initial access"` in a terminal —
the CLI prints the same report.

## The 5-minute Shark-Tank pitch

Follow `pitch/GroupX_Pitch.pdf`. Beats:

- **Problem (1 min):** threats at machine speed; hunts are slow and don’t scale;
  and when teams try AI, it hallucinates, so nobody trusts it for a real verdict.
  *The trust gap is the whole problem.*
- **Product (1 min):** hypothesis in, verdict out — and it proves every claim.
- **Why it wins (2 min):** (1) no evidence, no claim — a verifier blocks
  hallucination; (2) zero-config ingestion — agents build the parsers; (3)
  repeatable and auditable — deterministic mode for regulated SOCs.
- **Business + ask (1 min):** MSSPs and enterprise SOCs; per-seat SaaS + volume
  tier + on-prem for air-gapped; asking for a design-partner MSSP and a seed round.

**Likely investor questions & answers**

- *“How is this different from an LLM with a SIEM plugin?”* The evidence ledger +
  verifier. We don’t just let a model query logs; we make every claim provable and
  reject the ones that aren’t.
- *“What if the LLM is wrong?”* It can be wrong in its narrative, never in its
  published findings — an unsupported claim can’t pass the verifier. And a
  deterministic mode needs no model at all.
- *“Moat?”* The schema registry (parsers improve with every source seen), the
  evidence/audit trail as a system of record, and detection-as-code on top of the
  deterministic engine.
- *“Why now?”* MCP standardised how agents use tools; ELK is already in every SOC.
  We’re the trust layer between them.
```
