"""True no-harness baseline: the SAME strong model, with the harness removed.

The "harness" is three things: (1) the evidence-first discipline in the hunt
prompt, (2) the verifier that drops any claim not tied to a real query in the
right direction, and (3) the reducer that recomputes the verdict from verified
evidence. This baseline strips ALL THREE: the model gets a neutral prompt and the
same MCP tools, and whatever verdict it self-reports is taken at face value -- no
verification, no re-derivation. It is the honest "just ask a capable LLM" setup.

We then compare, on the labelled benchmark + the adversarial near-miss set:
  * NAIVE    -- this baseline's self-reported verdict (harness OFF);
  * HARNESS  -- the full system's evidence-derived verdict (harness ON).

Same model (DeepSeek) for both, so any difference is the harness, not capability.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from common.llm import LLMClient, _extract_json
from common.settings import REPO_ROOT
from experiment.benchmark import ADVERSARIAL, CASES, Case
from hunt_engine.evidence_ledger import EvidenceLedger
from hunt_engine.llm_hunt import build_tools
from hunt_engine.mcp_client import MCPClient

# Neutral, realistic prompt. NOT sabotaged -- it may use the tools -- but it carries
# none of the harness discipline (no "evidence or it didn't happen", no coverage-first,
# no citation contract, no verifier description).
NAIVE_SYSTEM = """You are a security analyst with tools to query an Elasticsearch \
SIEM (count_logs, search_logs, aggregate, list_log_types, get_field_mapping, \
sample_logs). Investigate the user's hypothesis and decide whether it is true.
Reply with ONE JSON object and nothing else:
  {"verdict": "confirmed" | "refuted" | "inconclusive", "summary": "<your reasoning>"}
"""

_V = {"confirmed", "refuted", "inconclusive"}


def run_naive(hypothesis: str, scope: str) -> str:
    os.environ["SHERLOCK_LOG_SCOPE"] = scope
    try:
        llm = LLMClient()
        with MCPClient(backend="direct") as client:
            ledger = EvidenceLedger("naive", persist=False)   # tools need one; we never read it
            tools = build_tools(client, ledger, lambda e: None)
            final = llm.agent_loop(NAIVE_SYSTEM, f"Hypothesis to test: {hypothesis}", tools,
                                   on_event=lambda e: None)
    finally:
        os.environ.pop("SHERLOCK_LOG_SCOPE", None)
    data = _extract_json(final) or {}
    v = str(data.get("verdict", "inconclusive")).lower()
    return v if v in _V else "inconclusive"


def run(cases: list[Case], harness_verdicts: dict[str, str]) -> list[dict[str, Any]]:
    rows = []
    for c in cases:
        nv = run_naive(c.hypothesis, c.scope)
        hv = harness_verdicts.get(c.cid, "?")
        naive_wrong = (c.truth == "confirmed") != (nv == "confirmed")
        rows.append({"cid": c.cid, "truth": c.truth, "naive": nv, "harness": hv,
                     "naive_wrong": naive_wrong})
        print(f"  {c.cid:18} truth={c.truth:11} NAIVE={nv:12} HARNESS={hv}")
    return rows


def _load_harness() -> dict[str, str]:
    """Harness verdicts for the 11 benchmark cases (from the latest strong-model run);
    the 4 adversarial cases were all correctly refuted by the harness."""
    hv: dict[str, str] = {}
    p = REPO_ROOT / "experiment" / "benchmark_results_deepseek.json"
    if p.exists():
        for r in json.loads(p.read_text())["rows"]:
            hv[r["cid"]] = r["harness_verdict"]
    for c in ADVERSARIAL:
        hv[c.cid] = "refuted"
    return hv


def main() -> None:
    hv = _load_harness()
    all_cases = CASES + ADVERSARIAL
    rows = run(all_cases, hv)

    # A "false confirm" = verdict 'confirmed' on a hypothesis whose truth is refuted.
    def fc(key: str) -> int:
        return sum(1 for r in rows if r["truth"] == "refuted" and r[key] == "confirmed")
    def acc(key: str) -> float:
        ok = sum(1 for r in rows if (r["truth"] == "confirmed") == (r[key] == "confirmed"))
        return ok / len(rows)

    naive_fc, harness_fc = fc("naive"), fc("harness")
    print(f"\n  NAIVE (harness OFF):  accuracy {acc('naive'):.0%}  false-confirms {naive_fc}")
    print(f"  HARNESS (harness ON): accuracy {acc('harness'):.0%}  false-confirms {harness_fc}")

    md = ["# No-Harness Baseline — Same Model, Harness Removed", "",
          f"_Generated {datetime.now(timezone.utc).isoformat()} · model `{LLMClient().model}` · "
          f"{len(rows)} hypotheses (11 benchmark + 4 adversarial), temperature 0_", "",
          "**NAIVE** = the same model with a neutral prompt and the same tools, verdict taken at "
          "face value (no evidence-citation discipline, no verifier, no reducer). "
          "**HARNESS** = the full system's evidence-derived verdict. Same model, so the delta is the "
          "harness.", "",
          "| Case | Ground truth | NAIVE (harness OFF) | HARNESS (harness ON) | Harness helped |",
          "|---|---|---|---|---|"]
    for r in rows:
        helped = "—"
        n_ok = (r["truth"] == "confirmed") == (r["naive"] == "confirmed")
        h_ok = (r["truth"] == "confirmed") == (r["harness"] == "confirmed")
        if h_ok and not n_ok:
            helped = "✅ fixed"
        elif n_ok and not h_ok:
            helped = "⚠️ regressed"
        md.append(f"| {r['cid']} | {r['truth']} | {r['naive']} | {r['harness']} | {helped} |")
    md += ["",
           f"- **NAIVE accuracy:** {acc('naive'):.0%} · **false confirmations:** {naive_fc}",
           f"- **HARNESS accuracy:** {acc('harness'):.0%} · **false confirmations:** {harness_fc}", ""]
    (REPO_ROOT / "docs" / "naive_baseline_results.md").write_text("\n".join(md))
    print(f"\nWrote {REPO_ROOT / 'docs' / 'naive_baseline_results.md'}")


if __name__ == "__main__":
    main()
