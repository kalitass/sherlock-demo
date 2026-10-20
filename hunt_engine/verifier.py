"""Verification pass -- enforces "no evidence, no claim".

A finding is verified only if it cites evidence that:
  1. exists in this hunt's ledger (no hallucinated citation);
  2. came from a QUERY tool (count/search/aggregate), not a context tool;
  3. actually ran successfully (ok);
  4. matches the finding's role -- a positive finding needs a query that matched
     >=1 document; a negative finding (an absence claim) needs a query that ran
     and matched 0 documents.

Anything else is quarantined out of the verdict and shown in the report's
"rejected" section, so the guardrail is visible.
"""
from __future__ import annotations

from typing import Any

from hunt_engine.evidence_ledger import EvidenceLedger

def _role(f: dict[str, Any]) -> str:
    # The role ("positive" presence vs "negative" absence) is a structured field the
    # engine sets: the LLM emits it (validated enum), the deterministic probes set it
    # explicitly. We never infer it from the claim's wording. A finding that arrives
    # without a valid role defaults to "positive" -- the stricter check (needs >=1 hit).
    role = (f.get("role") or "").lower()
    return role if role in ("positive", "negative") else "positive"


def verify_findings(findings: list[dict[str, Any]], ledger: EvidenceLedger) -> dict[str, Any]:
    verified, rejected = [], []
    for f in findings:
        eids = f.get("evidence_ids") or []
        role = _role(f)
        evs = [(e, ledger.get(e)) for e in eids]
        missing = [e for e, ev in evs if ev is None]
        query_evs = [ev for _, ev in evs if ev is not None and ev.is_query_tool]

        def _matches(ev) -> bool:
            m = ev.matched_documents
            if not isinstance(m, int):
                return False               # unknown match count never supports
            return (m == 0) if role == "negative" else (m > 0)

        # Fail-closed: EVERY cited query must have executed and matched in the
        # finding's direction. One failed/mismatched citation sinks the finding,
        # so a multi-stage "A AND B" claim cannot pass on A alone.
        all_ok = bool(query_evs) and all(ev.ok for ev in query_evs)
        all_support = all_ok and all(_matches(ev) for ev in query_evs)

        reasons = []
        if not eids:
            reasons.append("no evidence cited")
        if missing:
            reasons.append(f"cites non-existent evidence {missing} (hallucinated citation)")
        if eids and not missing and not query_evs:
            reasons.append("cites only context tools, not a query that returns evidence")
        if query_evs and not all(ev.ok for ev in query_evs):
            reasons.append("a cited query failed to execute or returned an unknown result")
        if all_ok and not all_support:
            reasons.append("a cited query did not match in the claim's direction "
                           f"({'expected 0 hits' if role == 'negative' else 'expected >=1 hit'})")

        f = dict(f)
        f["role"] = role
        f["cited_matches"] = {e: (ev.matched_documents if ev else None) for e, ev in evs}
        if not missing and all_support:
            f["verified"] = True
            verified.append(f)
        else:
            f["verified"] = False
            f["reject_reason"] = "; ".join(reasons) or "unsupported"
            rejected.append(f)

    total = len(findings)
    return {
        "verified_findings": verified,
        "rejected_findings": rejected,
        "verification_rate": round(len(verified) / total, 3) if total else 1.0,
        "n_total": total,
        "n_verified": len(verified),
        "n_rejected": len(rejected),
    }
