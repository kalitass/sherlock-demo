"""Hunt orchestrator -- the public entry point.

run_hunt(hypothesis) sets up the MCP session and evidence ledger, runs either the
LLM agent or the deterministic engine, verifies findings against the ledger,
renders the report, persists everything to Elasticsearch, and returns a bundle
the CLI and dashboard render.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from common.es import ensure_state_indices, index_doc
from common.llm import LLMClient
from common.settings import HUNT_INDEX, settings
from hunt_engine.evidence_ledger import EvidenceLedger
from hunt_engine.heuristic import run_heuristic_hunt
from hunt_engine.llm_hunt import run_llm_hunt
from hunt_engine.mcp_client import MCPClient
from hunt_engine.reduce import compute_coverage, reduce_verdict
from hunt_engine.reporter import build_report
from hunt_engine.verifier import verify_findings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_hunt(
    hypothesis: str,
    run_label: str | None = None,
    use_llm: bool | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    persist: bool = True,
    mcp_backend: str | None = None,
) -> dict[str, Any]:
    on_event = on_event or (lambda e: None)
    hunt_id = "hunt-" + uuid.uuid4().hex[:8]
    run_label = run_label or "run-1"
    if use_llm is None:
        use_llm = LLMClient().available()

    ensure_state_indices()
    ledger = EvidenceLedger(hunt_id, persist=persist)
    started_at = _now()
    on_event({"type": "start", "hunt_id": hunt_id, "hypothesis": hypothesis,
              "engine": "llm" if use_llm else "heuristic", "run_label": run_label})

    with MCPClient(backend=mcp_backend) as client:
        on_event({"type": "mcp", "backend": client.backend_name,
                  "tools": [t.name for t in client.list_tools()]})
        engine_fallback = None
        if use_llm:
            try:
                result = run_llm_hunt(hypothesis, client, ledger, on_event)
            except Exception as e:
                # A provider/network failure must not crash the hunt: degrade to the
                # deterministic engine (needs no external model) and say so plainly.
                engine_fallback = f"{type(e).__name__}: {e}"
                on_event({"type": "warning", "message":
                          f"LLM engine failed ({type(e).__name__}); falling back to the "
                          f"deterministic engine"})
                result = run_heuristic_hunt(hypothesis, client, ledger, on_event)
                result["engine"] = f"heuristic (fallback from llm: {type(e).__name__})"
        else:
            result = run_heuristic_hunt(hypothesis, client, ledger, on_event)
        mcp_backend_used = client.backend_name

    verification = verify_findings(result.get("findings", []), ledger)

    # Derive the FINAL verdict from verified evidence -- never from the engine's
    # self-report. Keep the engine's originals as `candidate_*` for transparency.
    coverage = compute_coverage(ledger, result.get("coverage"))
    reduced = reduce_verdict(hypothesis, result.get("verdict", "inconclusive"), verification,
                             coverage, ledger, result.get("hypothesis_covered", True),
                             polarity=result.get("hypothesis_polarity", "affirmative"))
    result["candidate_verdict"] = result.get("verdict")
    result["candidate_summary"] = result.get("summary")
    result["verdict"] = reduced["verdict"]
    result["confidence"] = reduced["confidence"]
    result["summary"] = reduced["summary"]
    result["coverage"] = coverage
    result["hypothesis_polarity"] = reduced["hypothesis_polarity"]
    finished_at = _now()

    persistence = ("enabled" if persist and ledger.persist_errors == 0
                   else ("degraded" if persist else "disabled"))
    meta = {
        "hunt_id": hunt_id, "hypothesis": hypothesis, "run_label": run_label,
        "started_at": started_at, "finished_at": finished_at,
        "mcp_backend": mcp_backend_used, "llm_available": LLMClient().available(),
        "evidence_persistence": persistence,
        "engine_fallback": engine_fallback,
    }
    report_md = build_report(meta, result, verification, ledger)

    bundle = {
        "meta": meta, "result": result, "verification": verification,
        "report_md": report_md, "evidence": ledger.as_list(),
    }
    on_event({"type": "verdict", "verdict": result.get("verdict"),
              "confidence": result.get("confidence"),
              "verification_rate": verification["verification_rate"],
              "n_findings": verification["n_verified"]})

    if persist:
        _persist_hunt(bundle)
        _write_report(hunt_id, run_label, report_md)
    on_event({"type": "done", "hunt_id": hunt_id})
    return bundle


def _persist_hunt(bundle: dict[str, Any]) -> None:
    meta, result, ver = bundle["meta"], bundle["result"], bundle["verification"]
    try:
        index_doc(HUNT_INDEX, {
            "hunt_id": meta["hunt_id"], "hypothesis": meta["hypothesis"],
            "verdict": result.get("verdict"), "confidence": result.get("confidence"),
            "started_at": meta["started_at"], "finished_at": meta["finished_at"],
            "run_label": meta["run_label"], "report_md": bundle["report_md"],
            "plan": {"engine": result.get("engine")}, "coverage": result.get("coverage"),
            "summary": result.get("summary"),
            "verification_rate": ver["verification_rate"], "n_verified": ver["n_verified"],
            "n_queries": len(bundle["evidence"]),
        }, refresh=True)
    except Exception:
        pass


def _write_report(hunt_id: str, run_label: str, report_md: str) -> Path:
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    path = settings.reports_dir / f"{hunt_id}_{run_label}.md"
    path.write_text(report_md)
    return path
