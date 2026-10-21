"""Sherlock dashboard -- observe ingestion, launch hunts, watch the agent work
live, and read the evidenced verdict.

Also hosts the PUSH ingestion endpoint (POST /api/ingest/push) so all three
ingestion modes are exercisable from one process.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import urllib.request
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool
from sse_starlette.sse import EventSourceResponse

from common.es import get_client
from common.settings import HUNT_INDEX, LOG_INDEX_PREFIX, SCHEMA_INDEX, INGEST_AUDIT_INDEX
from ingestion import schema_registry as reg
from ingestion.ingest_core import ingest_records
from hunt_engine.hunt import run_hunt

app = FastAPI(title="Sherlock")
STATIC = Path(__file__).resolve().parent / "static"

# Bound concurrent hunts so a burst of requests cannot exhaust threads / ES / LLM.
MAX_CONCURRENT_HUNTS = 2
_hunt_slots = threading.BoundedSemaphore(MAX_CONCURRENT_HUNTS)
MAX_PUSH_BYTES = 8 * 1024 * 1024

_CSP = ("default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


_KIBANA_URL = os.environ.get("SHERLOCK_KIBANA_URL", "http://localhost:5601")
_DV_PATTERN = f"{LOG_INDEX_PREFIX}*"  # sherlock-logs-*
_kibana_cache: dict[str, Any] = {}


def _kibana_data_view() -> dict[str, Any] | None:
    """Discover (and, on a fresh stack, create) the `sherlock-logs-*` Kibana data
    view, so an evidence row can deep-link into Discover instead of the raw ES
    `_search` JSON. Returns {'url', 'data_view_id'} or None when Kibana is not yet
    reachable (the UI then falls back to the ES link). Only a success is cached, so
    this keeps retrying while Kibana is still booting."""
    if "result" in _kibana_cache:
        return _kibana_cache["result"]
    result = None
    try:
        req = urllib.request.Request(f"{_KIBANA_URL}/api/data_views", headers={"kbn-xsrf": "true"})
        with urllib.request.urlopen(req, timeout=2) as r:
            views = json.loads(r.read()).get("data_view", [])
        dv = next((d for d in views if d.get("title") == _DV_PATTERN), None)
        if dv is None:
            body = json.dumps({"data_view": {"title": _DV_PATTERN, "name": "Sherlock logs",
                                             "timeFieldName": "@timestamp"}}).encode()
            req = urllib.request.Request(
                f"{_KIBANA_URL}/api/data_views/data_view", data=body, method="POST",
                headers={"kbn-xsrf": "true", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                dv = json.loads(r.read()).get("data_view", {})
        if dv and dv.get("id"):
            result = {"url": _KIBANA_URL, "data_view_id": dv["id"]}
    except Exception:
        result = None
    if result is not None:
        _kibana_cache["result"] = result
    return result


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (STATIC / "index.html").read_text()


@app.get("/api/health")
def health() -> JSONResponse:
    """Environment check for the top bar: is Elasticsearch reachable, and is a usable
    LLM provider key configured? Each drives a green/red light in the UI."""
    es_ok = False
    try:
        es_ok = bool(get_client().ping())
    except Exception:
        es_ok = False
    llm_ok, provider, model = False, "?", ""
    try:
        from common.providers import resolve_provider
        r = resolve_provider()
        llm_ok, provider, model = bool(r.available), r.name, r.model
    except Exception:
        pass
    return JSONResponse({"es_ok": es_ok, "llm_ok": llm_ok,
                         "llm_provider": provider, "llm_model": model})


@app.get("/api/overview")
def overview() -> JSONResponse:
    es = get_client()
    log_types = []
    total_events = 0
    for idx in sorted(es.indices.get(index=f"{LOG_INDEX_PREFIX}*", ignore_unavailable=True).keys()):
        cnt = es.count(index=idx)["count"]
        total_events += cnt
        tr = es.search(index=idx, size=0, aggs={"min": {"min": {"field": "@timestamp"}},
                                                "max": {"max": {"field": "@timestamp"}}})
        log_types.append({"index": idx, "log_type": idx.replace(LOG_INDEX_PREFIX, ""), "count": cnt,
                          "earliest": tr["aggregations"]["min"].get("value_as_string"),
                          "latest": tr["aggregations"]["max"].get("value_as_string")})
    schemas = [{"name": s["name"], "log_type": s["log_type"], "parser": s.get("parser", {}).get("kind"),
                "by": s.get("created_by"), "rate": s.get("validation", {}).get("rate"),
                "fields": len(s.get("field_map", {}))} for s in reg.list_schemas()]
    n_hunts = es.count(index=HUNT_INDEX)["count"] if es.indices.exists(index=HUNT_INDEX) else 0
    n_schemas = es.count(index=SCHEMA_INDEX)["count"] if es.indices.exists(index=SCHEMA_INDEX) else 0
    return JSONResponse({"total_events": total_events, "log_types": log_types, "schemas": schemas,
                         "n_hunts": n_hunts, "n_schemas": n_schemas,
                         "kibana": _kibana_data_view()})


@app.get("/api/hunts")
def hunts() -> JSONResponse:
    es = get_client()
    if not es.indices.exists(index=HUNT_INDEX):
        return JSONResponse({"hunts": []})
    res = es.search(index=HUNT_INDEX, size=20, sort=[{"finished_at": "desc"}],
                    _source=["hunt_id", "hypothesis", "verdict", "confidence", "finished_at",
                             "run_label", "verification_rate", "n_verified", "n_queries"])
    return JSONResponse({"hunts": [h["_source"] for h in res["hits"]["hits"]]})


@app.get("/api/hunt/{hunt_id}")
def hunt_detail(hunt_id: str) -> JSONResponse:
    es = get_client()
    res = es.search(index=HUNT_INDEX, query={"term": {"hunt_id": hunt_id}}, size=1)
    hits = res["hits"]["hits"]
    if not hits:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(hits[0]["_source"])


@app.get("/api/hunt/{hunt_id}/report", response_class=PlainTextResponse)
def hunt_report(hunt_id: str) -> str:
    es = get_client()
    res = es.search(index=HUNT_INDEX, query={"term": {"hunt_id": hunt_id}}, size=1)
    hits = res["hits"]["hits"]
    return hits[0]["_source"].get("report_md", "") if hits else "not found"


@app.post("/api/ingest/push")
async def ingest_push(request: Request) -> JSONResponse:
    """PUSH ingestion: an endpoint agent POSTs a batch of log records (JSON array
    or NDJSON body) with ?log_type=..."""
    log_type = request.query_params.get("log_type", "pushed")
    body = await request.body()
    if len(body) > MAX_PUSH_BYTES:
        return JSONResponse({"ok": False, "error": "payload too large"}, status_code=413)
    text = body.decode("utf-8", "replace").strip()
    records: list[Any]
    try:
        parsed = json.loads(text)
        records = parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        records = [ln for ln in text.splitlines() if ln.strip()]
    # Offload the synchronous schema/ES work so it never blocks the event loop.
    summary = await run_in_threadpool(
        ingest_records, log_type, records, "push:http", "push", True, False)
    return JSONResponse(summary)


@app.get("/api/hunt_stream")
async def hunt_stream(request: Request, hypothesis: str, engine: str = "auto"):
    """Run a hunt and stream every agent event over SSE, then a final bundle."""
    use_llm = None if engine == "auto" else (engine == "llm")
    q: "queue.Queue[dict]" = queue.Queue()
    holder: dict[str, Any] = {}

    def worker():
        if not _hunt_slots.acquire(blocking=False):
            q.put({"type": "error", "message": "server busy (max concurrent hunts reached); retry shortly"})
            q.put({"type": "_end"})
            return
        try:
            bundle = run_hunt(hypothesis, use_llm=use_llm, on_event=lambda e: q.put(e))
            holder["bundle"] = bundle
        except Exception as e:  # surface engine errors to the UI
            q.put({"type": "error", "message": f"{type(e).__name__}: {e}"})
        finally:
            _hunt_slots.release()
            q.put({"type": "_end"})

    threading.Thread(target=worker, daemon=True).start()

    async def gen():
        import asyncio
        while True:
            if await request.is_disconnected():
                break
            try:
                e = q.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.05)
                continue
            if e.get("type") == "_end":
                b = holder.get("bundle")
                if b:
                    yield {"event": "complete", "data": json.dumps({
                        "meta": b["meta"], "result": b["result"],
                        "verification": b["verification"], "report_md": b["report_md"],
                        "evidence": b["evidence"]}, default=str)}
                yield {"event": "end", "data": "{}"}
                break
            yield {"event": "message", "data": json.dumps(e, default=str)}

    return EventSourceResponse(gen())
