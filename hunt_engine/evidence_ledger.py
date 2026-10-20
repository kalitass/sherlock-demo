"""Evidence ledger -- the spine of Sherlock's anti-hallucination guarantee.

Every tool call is recorded with a stable evidence id, whether it succeeded
(`ok`), whether it is a query tool that can back a claim (`is_query_tool`), the
honest number of documents its query matched (`matched_documents`), the exact
reproducible request (`es_request`: index + body), a summary, and a digest. The
verifier reads these fields: a finding may only cite query evidence that ran
successfully and whose match count fits the finding's role. Context tools
(list_log_types, mappings, schemas) are recorded but can never support a claim.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from common.es import index_doc
from common.settings import EVIDENCE_INDEX
from mcp_server.tools import QUERY_TOOLS


@dataclass
class Evidence:
    evidence_id: str
    step: int
    tool: str
    arguments: dict[str, Any]
    ok: bool
    is_query_tool: bool
    matched_documents: int | None
    es_request: dict[str, Any] | None
    query_dsl: dict[str, Any] | None
    result_summary: str
    hit_count: int
    sample_hits: list[Any]
    digest: str            # result digest: query + result summary (changes if data changes)
    query_digest: str      # query-plan digest: index + DSL only (stable across data changes)


@dataclass
class EvidenceLedger:
    hunt_id: str
    entries: list[Evidence] = field(default_factory=list)
    persist: bool = True
    persist_errors: int = 0

    def _next_id(self) -> str:
        return f"E{len(self.entries) + 1}"

    def record(self, tool: str, arguments: dict[str, Any], result: Any) -> Evidence:
        eid = self._next_id()
        r = result if isinstance(result, dict) else {}
        ok = r.get("ok") is True            # fail-closed: only an explicit ok:true counts
        is_query = tool in QUERY_TOOLS
        matched = r.get("matched_documents")
        if not isinstance(matched, int) and isinstance(r.get("count"), int):
            matched = r["count"]
        if not isinstance(matched, int) or matched < 0:
            matched = None                  # unknown -> never silently treated as zero
        es_request = r.get("es_request") or (
            {"body": r.get("query_dsl")} if r.get("query_dsl") else None
        )
        hit_count = _display_count(tool, r, matched)
        summary = _summarise(tool, r, ok)
        digest = hashlib.sha1(
            json.dumps({"tool": tool, "req": es_request, "summary": summary}, sort_keys=True, default=str).encode()
        ).hexdigest()[:12]
        query_digest = hashlib.sha1(
            json.dumps({"tool": tool, "req": es_request}, sort_keys=True, default=str).encode()
        ).hexdigest()[:12] if is_query else ""
        ev = Evidence(eid, len(self.entries) + 1, tool, arguments, ok, is_query,
                      matched if isinstance(matched, int) else None,
                      es_request, r.get("query_dsl"), summary, hit_count, _samples(r), digest, query_digest)
        self.entries.append(ev)
        if self.persist:
            self._persist(ev)
        return ev

    def _persist(self, ev: Evidence) -> None:
        try:
            index_doc(EVIDENCE_INDEX, {
                "hunt_id": self.hunt_id, "evidence_id": ev.evidence_id, "step": ev.step,
                "tool": ev.tool, "arguments": ev.arguments, "ok": ev.ok,
                "is_query_tool": ev.is_query_tool, "matched_documents": ev.matched_documents,
                "es_request": ev.es_request, "query_dsl": ev.query_dsl,
                "result_summary": ev.result_summary, "hit_count": ev.hit_count,
                "sample_hits": ev.sample_hits, "digest": ev.digest, "query_digest": ev.query_digest,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            self.persist_errors += 1

    def get(self, evidence_id: str) -> Evidence | None:
        for e in self.entries:
            if e.evidence_id == evidence_id:
                return e
        return None

    def as_list(self) -> list[dict[str, Any]]:
        return [{
            "evidence_id": e.evidence_id, "step": e.step, "tool": e.tool, "arguments": e.arguments,
            "ok": e.ok, "is_query_tool": e.is_query_tool, "matched_documents": e.matched_documents,
            "es_request": e.es_request, "query_dsl": e.query_dsl,
            "result_summary": e.result_summary, "hit_count": e.hit_count,
            "sample_hits": e.sample_hits, "digest": e.digest, "query_digest": e.query_digest,
        } for e in self.entries]


def _display_count(tool: str, r: dict, matched: Any) -> int:
    """A number for the UI only. Never used by the verifier for context tools."""
    if isinstance(matched, int):
        return matched
    if tool == "list_log_types":
        return len(r.get("log_types", []))
    if tool == "list_schemas":
        return len(r.get("schemas", []))
    if tool == "sample_logs":
        return len(r.get("samples", []))
    if tool == "get_field_mapping":
        return len(r.get("fields", {}))
    if "metric_value" in r:
        return int(r.get("metric_value") or 0)
    return 0


def _summarise(tool: str, r: dict, ok: bool) -> str:
    if not ok or "error" in r:
        return f"error: {r.get('error', 'failed')}"
    if tool == "count_logs":
        return f"matched_documents={r.get('matched_documents')}"
    if tool == "search_logs":
        rel = "" if r.get("total_relation", "eq") == "eq" else ">="
        return f"matched_documents={rel}{r.get('matched_documents')} returned={r.get('returned_documents')}"
    if tool == "aggregate":
        res = r.get("result", {})
        if "buckets" in res:
            top = ", ".join(f"{b['key']}={b['count']}" for b in res["buckets"][:5])
            return f"terms({r.get('field')}) matched={r.get('matched_documents')}: {top}"
        if "metric_value" in r:
            return f"{r.get('agg_type')}({r.get('field')})={r.get('metric_value')} matched={r.get('matched_documents')}"
        return f"{r.get('agg_type')}({r.get('field')}) matched={r.get('matched_documents')}"
    if tool == "list_log_types":
        return ", ".join(f"{lt['log_type']}={lt['count']}" for lt in r.get("log_types", []))
    if tool == "list_schemas":
        return ", ".join(s["name"] for s in r.get("schemas", []))
    if tool == "sample_logs":
        return f"{len(r.get('samples', []))} samples from {r.get('index')}"
    if tool == "get_field_mapping":
        return f"{len(r.get('fields', {}))} fields in {r.get('index')}"
    return json.dumps(r, default=str)[:200]


def _samples(r: dict) -> list[Any]:
    if isinstance(r.get("hits"), list):
        return r["hits"][:5]
    res = r.get("result")
    if isinstance(res, dict) and isinstance(res.get("buckets"), list):
        return res["buckets"][:10]
    if "samples" in r:
        return r["samples"][:3]
    return []
