"""Derive the FINAL verdict and coverage from verified evidence.

The engine (LLM or heuristic) proposes a candidate verdict, but the verdict that
reaches the report is computed here from the verifier's output, the ledger, and
real coverage -- never taken from the model's self-report. This is what makes
"rejected claims do not count toward the verdict" literally true.
"""
from __future__ import annotations

from typing import Any

from hunt_engine.evidence_ledger import EvidenceLedger


def compute_coverage(ledger: EvidenceLedger, engine_coverage: dict[str, Any] | None) -> dict[str, Any]:
    from mcp_server.tools import ALL_LOGS, list_log_types

    try:
        available = [lt["index"] for lt in list_log_types().get("log_types", [])]
    except Exception:
        available = []

    searched: set[str] = set()
    queries_ok = queries_failed = 0
    for e in ledger.entries:
        if not e.is_query_tool:
            continue
        if e.ok:
            queries_ok += 1
        else:
            queries_failed += 1
            continue
        idx = (e.es_request or {}).get("index")
        if not idx or idx == ALL_LOGS or idx.endswith("*"):
            searched.update(available)
        else:
            searched.add(idx)

    missing = [i for i in available if i not in searched]
    cov = dict(engine_coverage or {})
    cov.update({
        "sources_available": [i.replace("sherlock-logs-", "") for i in available],
        "sources_searched": sorted(s.replace("sherlock-logs-", "") for s in searched if s in available),
        "sources_missing": [i.replace("sherlock-logs-", "") for i in missing],
        "queries_ok": queries_ok,
        "queries_failed": queries_failed,
        # Fail-closed: unknown source list (ES error -> available == []) is NOT
        # complete coverage, and any failed query breaks completeness.
        "complete": bool(available) and not missing and queries_failed == 0 and queries_ok > 0,
    })
    return cov


def reduce_verdict(hypothesis: str, candidate: str, verification: dict[str, Any],
                   coverage: dict[str, Any], ledger: EvidenceLedger,
                   hypothesis_covered: bool = True,
                   polarity: str = "affirmative") -> dict[str, Any]:
    verified = verification["verified_findings"]
    # Only findings that DIRECTLY address this hypothesis drive the verdict. A
    # true-but-incidental finding about other activity (addresses_hypothesis=False)
    # stays in the report as context but must not decide an unrelated hypothesis --
    # this closes the "citation integrity != semantic relevance" gap.
    addressing = [f for f in verified if f.get("addresses_hypothesis", True)]
    # The verdict turns on the DIRECTION OF THE ARGUMENT, not on the claim's grammar.
    # `supports_hypothesis` is the enumerable field the LLM emits after reading the
    # hypothesis: true = evidence the hypothesis is TRUE, false = evidence it is
    # FALSE. (It is orthogonal to `role`, which the verifier uses for citation
    # direction.) Understanding the hypothesis is the LLM's job; we only read the
    # field. The deterministic engine cannot read language, so its findings fall back
    # to role (presence argues for, absence argues against).
    confirming = [f for f in addressing if _supports(f)]
    refuting = [f for f in addressing if not _supports(f)]
    any_query_failed = any(e.is_query_tool and not e.ok for e in ledger.entries)

    # A confirmed verdict needs verified evidence FOR the hypothesis; a refuted
    # verdict needs verified evidence AGAINST it (e.g. a matched=0 absence query the
    # verifier already confirmed ran OK). "No findings" is not evidence of absence.
    # A stray failed exploratory query does NOT block a refutation that stands on its
    # own verified evidence -- the verifier already guaranteed those queries ran.
    if not hypothesis_covered:
        verdict, confidence = "inconclusive", 0.4
    elif confirming:
        verdict = "confirmed"
        confidence = round(min(0.95, 0.6 + 0.1 * len(confirming)), 2)
    elif refuting:
        verdict = "refuted"
        confidence = 0.72
    else:
        verdict, confidence = "inconclusive", 0.4

    return {"verdict": verdict, "confidence": confidence, "candidate_verdict": candidate,
            "hypothesis_polarity": polarity, "hypothesis_covered": hypothesis_covered,
            "summary": _summary(verdict, verified, confirming, refuting, verification, coverage,
                                any_query_failed, hypothesis_covered)}


def _supports(f: dict[str, Any]) -> bool:
    """Does this verified finding argue the hypothesis is TRUE? Prefer the LLM's
    enumerable `supports_hypothesis`; fall back to the claim's grammar (a presence
    claim argues for, an absence claim argues against) for the deterministic engine."""
    v = f.get("supports_hypothesis")
    if isinstance(v, bool):
        return v
    return f.get("role", "positive") != "negative"


def _summary(verdict, verified, confirming, refuting, verification, coverage,
             any_query_failed, covered) -> str:
    rej = verification["n_rejected"]
    src = ", ".join(coverage.get("sources_searched") or []) or "no sources"
    tail = f" {rej} candidate claim(s) were rejected by the verifier for lacking evidence." if rej else ""
    if verdict == "confirmed":
        techs = sorted({f.get("technique") or f.get("mitre") or "?" for f in confirming})
        return (f"CONFIRMED on the evidence: {len(confirming)} verified finding(s) argue the "
                f"hypothesis is true, spanning {', '.join(techs) or '?'}. Sources searched: {src}.{tail}")
    if verdict == "refuted":
        return (f"REFUTED: {len(refuting)} verified finding(s) argue against the hypothesis "
                f"(e.g. queries that returned zero matches for the claimed activity) across "
                f"{src}.{tail}")
    if not covered:
        return ("INCONCLUSIVE: no probe or query in this hunt covers the stated hypothesis, so it "
                f"can be neither confirmed nor refuted.{tail}")
    reason = ("one or more queries failed to execute" if any_query_failed
              else "no verified evidence for or against the hypothesis")
    return (f"INCONCLUSIVE: {reason}. A confirmed verdict needs verified presence evidence; a refuted "
            f"verdict needs a verified absence query.{tail}")
