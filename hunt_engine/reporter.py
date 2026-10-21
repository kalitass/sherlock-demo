"""Render a hunt result into a professional Markdown report.

The verdict shown is the VERIFIED verdict (derived from evidence), not the
engine's self-report; where they differ, both are shown. Every verified finding
carries its MITRE mapping and the exact reproducible request; rejected claims are
listed for transparency; an appendix lists every query with its match count and
whether it succeeded.
"""
from __future__ import annotations

import json
from typing import Any

from hunt_engine.evidence_ledger import EvidenceLedger

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_VERDICT_BADGE = {"confirmed": "🔴 CONFIRMED", "refuted": "🟢 REFUTED", "inconclusive": "🟡 INCONCLUSIVE"}


def _esc(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def build_report(meta: dict[str, Any], result: dict[str, Any],
                 verification: dict[str, Any], ledger: EvidenceLedger) -> str:
    verdict = result.get("verdict", "inconclusive")
    candidate = result.get("candidate_verdict")
    findings = sorted(verification["verified_findings"], key=lambda f: _SEV_ORDER.get(f.get("severity", "low"), 3))
    rejected = verification["rejected_findings"]
    persist = meta.get("evidence_persistence", "enabled")

    L: list[str] = []
    L.append(f"# Threat Hunt Report — {meta['hunt_id']}")
    L.append("")
    L.append(f"> **Verdict: {_VERDICT_BADGE.get(verdict, verdict.upper())}**  ·  "
             f"Confidence {result.get('confidence', 0):.0%}  ·  "
             f"Evidence integrity {verification['verification_rate']:.0%} "
             f"({verification['n_verified']}/{verification['n_total']} candidate claims backed by data)")
    if candidate and candidate != verdict:
        L.append(">")
        L.append(f"> *The engine proposed **{candidate}**; the verified verdict derived from evidence "
                 f"is **{verdict}**. Only the verified verdict is authoritative.*")
    L.append("")
    L.append("| | |")
    L.append("|---|---|")
    L.append(f"| Hypothesis | {_esc(meta['hypothesis'])} |")
    L.append(f"| Run label | `{meta.get('run_label','-')}` |")
    L.append(f"| Engine | `{_esc(result.get('engine','?'))}` |")
    L.append(f"| MCP backend | `{meta.get('mcp_backend','?')}` |")
    L.append(f"| Started / Finished | {meta.get('started_at','-')} → {meta.get('finished_at','-')} |")
    L.append(f"| Queries executed | {len(ledger.entries)} |")
    L.append(f"| Evidence persistence | {persist} |")
    L.append("")

    L.append("## Executive summary")
    L.append("")
    L.append(_p(result.get("summary", "")) or "_No summary produced._")
    L.append("")

    cov = result.get("coverage", {})
    avail = cov.get("sources_available") or []
    searched = cov.get("sources_searched") or []
    missing = cov.get("sources_missing") or []
    det = cov.get("techniques_detected") or []
    L.append("## Coverage")
    L.append("")
    L.append(f"- **Sources searched:** {len(searched)} of {len(avail)} available"
             + ("  ·  complete" if cov.get("complete") else ""))
    if missing:
        L.append(f"- **Not searched:** {', '.join(missing)}")
    L.append(f"- **Queries:** {cov.get('queries_ok', '?')} ok, {cov.get('queries_failed', 0)} failed")
    tw = cov.get("time_window") or {}
    if tw:
        L.append(f"- **Time window:** {str(tw.get('earliest','?'))[:19]} → {str(tw.get('latest','?'))[:19]}")
    if det:
        L.append(f"- **Techniques detected:** {len(det)} — {', '.join(det)}")
    L.append("")

    L.append("## Findings")
    L.append("")
    if not findings:
        L.append("_No verified findings._")
        L.append("")
    for i, f in enumerate(findings, 1):
        L.append(f"### F{i}. {_p(f.get('claim','(no claim)'))}")
        L.append("")
        L.append(f"- **Severity:** {f.get('severity','low').upper()}  ·  "
                 f"**MITRE ATT&CK:** {_p(f.get('mitre','-'))} ({_p(f.get('technique','-'))})  ·  "
                 f"**Role:** {f.get('role','positive')}")
        if f.get("detail"):
            L.append(f"- **Detail:** {_p(f['detail'])}")
        L.append(f"- **Evidence:** {', '.join(f.get('evidence_ids', []))} "
                 f"(matched documents: {f.get('cited_matches', {})})")
        for eid in f.get("evidence_ids", []):
            ev = ledger.get(eid)
            if ev and ev.es_request:
                L.append("")
                L.append(f"  <details><summary>{eid} — reproducible query ({ev.tool}, "
                         f"{ev.matched_documents} matched)</summary>")
                L.append("")
                L.append("  ```json")
                L.append("  " + json.dumps(ev.es_request, indent=2).replace("\n", "\n  "))
                L.append("  ```")
                L.append("  </details>")
        L.append("")

    if rejected:
        L.append("## Claims rejected by the verifier (not counted in the verdict)")
        L.append("")
        L.append("*These candidate claims failed the evidence check and were quarantined. "
                 "Listing them is deliberate: it shows the guardrail working.*")
        L.append("")
        for f in rejected:
            L.append(f"- ~~{_p(f.get('claim','(no claim)'))}~~ — **rejected:** {_p(f.get('reject_reason','unsupported'))}")
        L.append("")

    actions = result.get("recommended_actions") or []
    if actions:
        L.append("## Recommended actions")
        L.append("")
        for a in actions:
            L.append(f"- {_p(a)}")
        L.append("")

    L.append(f"<details><summary><b>Appendix A — Evidence ledger</b> "
             f"({len(ledger.entries)} queries that ran)</summary>")
    L.append("")
    L.append("| ID | Tool | OK | Matched | Summary | Digest |")
    L.append("|----|------|----|---------|---------|--------|")
    for e in ledger.entries:
        L.append(f"| {e.evidence_id} | {e.tool} | {'✓' if e.ok else '✗'} | "
                 f"{e.matched_documents if e.matched_documents is not None else '-'} | "
                 f"{_esc(e.result_summary)[:90]} | `{e.digest}` |")
    L.append("")
    note = ("Full reproducible requests are stored in the `sherlock-evidence` index"
            if persist == "enabled" else
            "Evidence persistence was degraded this run; requests are shown inline above but may not be in ES")
    L.append(f"*{note}; each is also shown inline under its finding.*")
    L.append("")
    L.append("</details>")
    L.append("")
    return "\n".join(L)


def _p(s: Any) -> str:  # paragraph text -- normalise whitespace, keep it markdown-safe
    return str(s).replace("\r", " ").strip()
