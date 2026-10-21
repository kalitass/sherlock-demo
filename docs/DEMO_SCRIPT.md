# Demo runbook — 5-minute live demo + presentation

*Threat hunting you can put in front of an auditor: plain-English hypothesis in → evidenced verdict out.*

## Before the session (once)

```bash
make demo          # start ELK + download & ingest the 14 OTRF datasets (~36,700 real events)
make dashboard     # leave running on http://localhost:8080
```

Open two tabs: **http://localhost:8080** (Sherlock) and **http://localhost:5601** (Kibana).

- **No LLM key?** The **Detection scan** (deterministic) runs with no key and is instant —
  the safe default for a graded live demo.
- **With a key** (`.env`: `SHERLOCK_LLM_PROVIDER` + the matching `*_API_KEY`): **Run hunt**
  streams the agent's reasoning live — nicer, but slower and needs network.

## The 5-minute live demo (in order)

1. **Framing — 20 s.** Today an analyst hand-writes a query per hunt; point an LLM at the
   logs instead and it confidently makes things up. Sherlock takes a hypothesis in plain
   English and returns a verdict where **every claim is tied to a query that proves it**.
2. **Data — 30 s.** Show the Overview tiles: **~36,700 real events across 14 public,
   ATT&CK-labelled datasets** (Windows / Sysmon / PowerShell, the OTRF Security-Datasets).
   Every source was **auto-schema'd on ingest — zero hand-written parsers**.
3. **Run a hunt — 90 s.** Type a hypothesis (e.g. *"Was a backdoor local account created on
   this host?"*) and **Run hunt**. Narrate the live trace: connects to ES through **MCP**,
   plans a coverage sweep, then queries technique by technique; each finding streams in with
   its severity and MITRE ID. End on the **verdict + evidence integrity %**.
4. **Proof — 60 s.** Scroll to **Findings** and the **Evidence ledger**: every finding cites
   evidence ids, and the ledger lists **every query that ran** with its hit count. *Nothing on
   the left exists without a receipt on the right.* (Each evidence link opens Kibana Discover.)
5. **Guardrail — 40 s.** A **verifier** drops any claim not backed by a successful query —
   shown in the struck-through *rejected* section. On our benchmark it caught **6%** of the
   model's own claims. Hallucination isn't discouraged; it's **mechanically blocked**.
6. **Reproducibility — 30 s.** Run the same hypothesis twice → the **same verdict every time
   (4/4)**, even though the agent's query path differs each run — because the verdict is
   derived from verified evidence, not the model's wording.
7. **Kibana — 20 s.** It's the standard ELK stack, so an analyst can pivot on the same
   indices by hand any time.

**Backup if anything hangs:** switch the dashboard engine to **Detection scan** (deterministic,
no key), or run `make hunt H="Was a backdoor local account created on this host?"` in a
terminal — same evidenced report.

## Headline numbers (from §6 of the report; DeepSeek, temperature 0)

- **100% accuracy / 0% false-positive rate** on 20 labelled hypotheses (14 ATT&CK techniques, 7 tactics)
- **6%** of LLM claims caught as unsupported; **100%** claim integrity by construction
- **Same verdict on repeated runs (4/4)**; the deterministic scanner detects **15/15** probed techniques

## Presentation

The pitch deck is on **Canva** (14 pages, structured as Part 1–5). The slide→speaker split and
the report-section ownership live in the collaboration repo (`sherlock/docs/DIVISION.md`).
