"""Ablation: the LLM hunt WITHOUT the evidence harness vs WITH it.

The assignment asks how hallucination is prevented or detected. This measures it:
we run the LLM engine several times and, for each run, compare

  * RAW  (no harness) -- the model's self-reported verdict and EVERY claim it
    asserted, which is what you would get if you simply trusted the model;
  * HARNESS            -- the verdict re-derived from verified evidence, and only
    the claims whose cited queries actually exist, ran, and matched in the claim's
    direction. Everything else is rejected (hallucinated/unsupported).

Reported: how many claims the model asserted, how many the harness rejected
(the hallucination/over-claim rate), how often the harness changed the verdict,
and concrete examples of the rejected claims with the reason.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common.settings import REPO_ROOT
from hunt_engine.hunt import run_hunt


def _one(hypothesis: str, runs: int) -> list[dict[str, Any]]:
    out = []
    for i in range(runs):
        b = run_hunt(hypothesis, run_label=f"abl-{i+1}", use_llm=True, persist=False)
        r, v = b["result"], b["verification"]
        out.append({
            "raw_verdict": r.get("candidate_verdict"),          # the model's own call
            "claims_asserted": v["n_total"],                    # every finding it produced
            "harness_verdict": r["verdict"],                    # re-derived from evidence
            "verified": v["n_verified"],
            "rejected": v["n_rejected"],
            "integrity": v["verification_rate"],
            "rejected_findings": [(f.get("claim", "")[:70], f.get("reject_reason", ""))
                                  for f in v["rejected_findings"]],
        })
    return out


def _reason_bucket(why: str) -> str:
    w = why.lower()
    if "hallucinated" in w:
        return "fabricated_citation"
    if "context tools" in w:
        return "context_tool_not_query"
    if "failed to execute" in w:
        return "failed_query"
    if "direction" in w:
        return "wrong_direction"
    if "no evidence cited" in w:
        return "no_evidence_cited"
    return "other"


def run_ablation(cases: list[tuple[str, str]], runs: int = 4) -> str:
    """cases: list of (label, hypothesis). Returns a Markdown report (also printed)."""
    md: list[str] = ["# Ablation — Evidence Harness vs Raw LLM",
                     "",
                     f"_Generated {datetime.now(timezone.utc).isoformat()} · {runs} runs per hypothesis_",
                     ""]
    for label, hyp in cases:
        rows = _one(hyp, runs)
        claims = sum(x["claims_asserted"] for x in rows)
        rejected = sum(x["rejected"] for x in rows)
        catch = (rejected / claims) if claims else 0.0
        corrections = sum(1 for x in rows if x["raw_verdict"] != x["harness_verdict"])
        raw_set = sorted({str(x["raw_verdict"]) for x in rows})
        harness_set = sorted({str(x["harness_verdict"]) for x in rows})

        buckets = Counter(_reason_bucket(why) for x in rows for (_, why) in x["rejected_findings"])
        print(f"\n===== {label} =====\n{hyp}")
        print(f"  claims asserted by LLM : {claims}")
        print(f"  rejected by harness    : {rejected}  ({catch:.0%} were unsupported/hallucinated)")
        print(f"  rejection reasons      : {dict(buckets)}")
        print(f"  verdict corrections    : {corrections} / {runs} runs (raw != harness)")
        print(f"  verdict stability      : raw={raw_set}  harness={harness_set}")

        md += [f"## {label}", "", f"**Hypothesis.** {hyp}", "",
               "| Run | RAW verdict (LLM self-report) | Claims asserted | HARNESS verdict | Verified | Rejected | Integrity |",
               "|---|---|---|---|---|---|---|"]
        for i, x in enumerate(rows, 1):
            md.append(f"| {i} | {x['raw_verdict']} | {x['claims_asserted']} | {x['harness_verdict']} | "
                      f"{x['verified']} | {x['rejected']} | {x['integrity']:.0%} |")
        md += ["",
               f"- **Claims the LLM asserted:** {claims}",
               f"- **Claims the harness rejected as unsupported/hallucinated:** {rejected} "
               f"(**{catch:.0%}**)",
               f"- **Rejection reasons:** {dict(buckets)}",
               f"- **Runs where the harness changed the verdict:** {corrections} / {runs}",
               f"- **Verdict stability:** raw = {raw_set} · harness = {harness_set}",
               ""]
        examples = [(c, why) for x in rows for (c, why) in x["rejected_findings"]]
        if examples:
            md += ["**Claims the harness caught (reason):**", ""]
            for c, why in examples[:8]:
                md.append(f"- _{c}_ → {why}")
            md.append("")
            print("  examples of rejected claims:")
            for c, why in examples[:5]:
                print(f"    - {c[:60]} -> {why[:70]}")

    out = REPO_ROOT / "docs" / "ablation_results.md"
    out.write_text("\n".join(md))
    print(f"\nWrote {out}")
    return str(out)


if __name__ == "__main__":
    run_ablation([
        ("TRUE hypothesis (attack really happened)",
         "Was the administrator account brute-forced and used to gain access?"),
        ("FALSE hypothesis (no such attack in the data)",
         "Did ransomware encrypt files across the estate last night?"),
    ], runs=4)
