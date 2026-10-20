"""The hunt tool surface, as plain Python functions.

`mcp_server/server.py` exposes these over MCP; the hunt engine calls them through
an MCP client. Every tool returns a uniform envelope:

  {ok, tool, es_request?, matched_documents?, metric_value?, ... , error?}

Query tools (count_logs / search_logs / aggregate) additionally return the exact
Elasticsearch request they ran under `es_request` (index + body), so every claim
ties to a reproducible query. Only these three tools may back a finding; the rest
are context tools. Inputs are scoped and bounded (index allowlist, size clamps,
interval allowlist, query-string length) so the agent cannot touch Sherlock's own
state indices or issue an unbounded/degenerate query.
"""
from __future__ import annotations

import fnmatch
import os
from typing import Any

from common.es import get_client
from common.settings import LOG_INDEX_PREFIX
from ingestion import schema_registry as reg

ALL_LOGS = f"{LOG_INDEX_PREFIX}*"

# Only these tools produce quantitative evidence that can support a finding.
QUERY_TOOLS = {"count_logs", "search_logs", "aggregate"}

# Bounds
MAX_SEARCH_SIZE = 100
MAX_SAMPLE_SIZE = 50
MAX_TERMS_SIZE = 1000
MAX_QUERY_LEN = 2000
INTERVALS = {"1m", "5m", "10m", "15m", "30m", "1h", "2h", "3h", "6h", "12h", "1d"}


class ToolError(Exception):
    """Raised for a bad/blocked request; surfaced as {ok: False, error}."""


# --- scope & validation ----------------------------------------------------
def _scope() -> str:
    """Optional operator scope so a hunt can be confined to ONE source/case
    (the `SHERLOCK_LOG_SCOPE` knob). May be a bare log_type ("mordor_adduser"), a
    full index, or a glob; it is always pinned inside the log-index namespace.
    Unset -> the full log namespace, i.e. unchanged behaviour. Read live (not at
    import) so a driver can rescope between hunts in one process."""
    s = os.environ.get("SHERLOCK_LOG_SCOPE", "").strip()
    if not s:
        return ALL_LOGS
    return s if s.startswith(LOG_INDEX_PREFIX) else LOG_INDEX_PREFIX + s


def _resolve_index(requested: str | None) -> str:
    """Allow only the log indices. Blocks Sherlock's state indices and '*', and
    enforces the active hunt scope (if any)."""
    scope = _scope()
    if not requested or requested == ALL_LOGS:
        return scope
    if requested == "*" or "," in requested:
        raise ToolError(f"index '{requested}' not allowed; use a sherlock-logs-* index or omit")
    if not requested.startswith(LOG_INDEX_PREFIX):
        raise ToolError(f"index '{requested}' is out of scope; only {LOG_INDEX_PREFIX}* is queryable")
    if scope != ALL_LOGS and not fnmatch.fnmatch(requested, scope):
        raise ToolError(f"index '{requested}' is outside this hunt's scope ({scope})")
    es = get_client()
    if not es.indices.exists(index=requested):
        raise ToolError(f"index '{requested}' does not exist")
    return requested


def _check_qs(qs: str | None) -> str | None:
    if qs is None:
        return None
    if len(qs) > MAX_QUERY_LEN:
        raise ToolError(f"query_string too long ({len(qs)} > {MAX_QUERY_LEN})")
    if qs.strip() in ("*", "*:*", ""):
        raise ToolError("query_string too broad; scope it to fields/values")
    return qs


def _clamp(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


# --- query building --------------------------------------------------------
def _time_filter(start: str | None, end: str | None) -> dict | None:
    if not start and not end:
        return None
    rng: dict[str, Any] = {}
    if start:
        rng["gte"] = start
    if end:
        rng["lte"] = end
    return {"range": {"@timestamp": rng}}


def _build_query(query_string, start, end, filters) -> dict[str, Any]:
    must: list[dict] = []
    if query_string:
        must.append({"query_string": {"query": query_string, "default_operator": "AND"}})
    for k, v in (filters or {}).items():
        must.append({"term": {k: v}})
    tf = _time_filter(start, end)
    filt = [tf] if tf else []
    if not must and not filt:
        return {"match_all": {}}
    return {"bool": {"must": must or [{"match_all": {}}], "filter": filt}}


def _mapping(index: str) -> dict[str, Any]:
    es = get_client()
    try:
        m = es.indices.get_mapping(index=index)
    except Exception:
        return {}
    props: dict[str, Any] = {}
    for idx in m.values():
        props.update(idx.get("mappings", {}).get("properties", {}))
    return props


def _agg_field(index: str, field: str) -> str:
    spec = _mapping(index).get(field, {})
    if spec.get("type") == "text":
        if "keyword" in spec.get("fields", {}):
            return f"{field}.keyword"
        raise ToolError(f"field '{field}' is analysed text with no keyword sub-field; not aggregatable")
    return field


# --- tools -----------------------------------------------------------------
def list_log_types(_: dict | None = None) -> dict[str, Any]:
    es = get_client()
    out = []
    for idx in sorted(es.indices.get(index=_scope(), ignore_unavailable=True).keys()):
        cnt = es.count(index=idx)["count"]
        tr = es.search(index=idx, size=0, aggs={
            "min": {"min": {"field": "@timestamp"}}, "max": {"max": {"field": "@timestamp"}}})
        agg = tr["aggregations"]
        out.append({"index": idx, "log_type": idx.replace(LOG_INDEX_PREFIX, ""), "count": cnt,
                    "earliest": agg["min"].get("value_as_string"), "latest": agg["max"].get("value_as_string")})
    return {"ok": True, "tool": "list_log_types", "log_types": out}


def get_field_mapping(args: dict[str, Any]) -> dict[str, Any]:
    index = _resolve_index(args.get("index"))
    props = _mapping(index)
    return {"ok": True, "tool": "get_field_mapping", "index": index,
            "fields": {k: v.get("type", "object") for k, v in props.items()}}


def sample_logs(args: dict[str, Any]) -> dict[str, Any]:
    es = get_client()
    index = _resolve_index(args.get("index"))
    n = _clamp(args.get("n", 3), 1, MAX_SAMPLE_SIZE, 3)
    res = es.search(index=index, size=n, query={"match_all": {}}, sort=[{"@timestamp": "asc"}],
                    ignore_unavailable=True)
    return {"ok": True, "tool": "sample_logs", "index": index,
            "samples": [h["_source"] for h in res["hits"]["hits"]]}


def count_logs(args: dict[str, Any]) -> dict[str, Any]:
    es = get_client()
    index = _resolve_index(args.get("index"))
    q = _build_query(_check_qs(args.get("query_string")), args.get("start"), args.get("end"), args.get("filters"))
    body = {"query": q}
    cnt = es.count(index=index, query=q, ignore_unavailable=True)["count"]
    return {"ok": True, "tool": "count_logs", "index": index,
            "matched_documents": cnt, "count": cnt,
            "es_request": {"index": index, "body": body}, "query_dsl": body}


def search_logs(args: dict[str, Any]) -> dict[str, Any]:
    es = get_client()
    index = _resolve_index(args.get("index"))
    size = _clamp(args.get("size", 10), 0, MAX_SEARCH_SIZE, 10)
    q = _build_query(_check_qs(args.get("query_string")), args.get("start"), args.get("end"), args.get("filters"))
    sort_dir = args.get("sort", "asc")
    if sort_dir not in ("asc", "desc"):
        sort_dir = "asc"
    body: dict[str, Any] = {"query": q, "size": size, "sort": [{"@timestamp": sort_dir}],
                            "track_total_hits": True}
    if args.get("fields"):
        body["_source"] = [str(f)[:128] for f in args["fields"]][:50]
    res = es.search(index=index, ignore_unavailable=True, **body)
    total = res["hits"]["total"]
    hits = [h["_source"] for h in res["hits"]["hits"]]
    return {"ok": True, "tool": "search_logs", "index": index,
            "matched_documents": total["value"], "total_relation": total.get("relation", "eq"),
            "returned_documents": len(hits), "total": total["value"], "returned": len(hits),
            "hits": hits, "es_request": {"index": index, "body": body}, "query_dsl": body}


def aggregate(args: dict[str, Any]) -> dict[str, Any]:
    es = get_client()
    index = _resolve_index(args.get("index"))
    agg_type = args.get("agg_type", "terms")
    field = args.get("field")
    if not field:
        raise ToolError("aggregate requires 'field'")
    q = _build_query(_check_qs(args.get("query_string")), args.get("start"), args.get("end"), args.get("filters"))
    size = _clamp(args.get("size", 10), 1, MAX_TERMS_SIZE, 10)

    if agg_type == "terms":
        aggs = {"result": {"terms": {"field": _agg_field(index, field), "size": size}}}
    elif agg_type == "date_histogram":
        interval = args.get("interval", "1h")
        if interval not in INTERVALS:
            raise ToolError(f"interval '{interval}' not allowed; use one of {sorted(INTERVALS)}")
        aggs = {"result": {"date_histogram": {"field": field, "fixed_interval": interval}}}
    elif agg_type == "cardinality":
        aggs = {"result": {"cardinality": {"field": _agg_field(index, field)}}}
    elif agg_type == "stats":
        aggs = {"result": {"stats": {"field": field}}}
    else:
        raise ToolError(f"unknown agg_type '{agg_type}'")

    body = {"query": q, "size": 0, "aggs": aggs, "track_total_hits": True}
    res = es.search(index=index, ignore_unavailable=True, **body)
    matched = res["hits"]["total"]["value"]
    result = res["aggregations"]["result"]
    out: dict[str, Any] = {"ok": True, "tool": "aggregate", "index": index, "agg_type": agg_type,
                           "field": field, "matched_documents": matched,
                           "es_request": {"index": index, "body": body}, "query_dsl": body}
    if agg_type in ("terms", "date_histogram"):
        buckets = [{"key": b.get("key_as_string", b["key"]), "count": b["doc_count"]} for b in result["buckets"]]
        out["result"] = {"buckets": buckets}
        out["bucket_count"] = len(buckets)
        out["bucket_doc_count_sum"] = sum(b["count"] for b in buckets)
    elif agg_type == "cardinality":
        out["result"] = result
        out["metric_value"] = int(result.get("value") or 0)
        out["distinct_count"] = out["metric_value"]
    else:  # stats
        out["result"] = result
        out["metric_value"] = int(result.get("count") or 0)
    return out


def list_schemas(_: dict | None = None) -> dict[str, Any]:
    return {"ok": True, "tool": "list_schemas", "schemas": [
        {"name": s["name"], "log_type": s["log_type"], "version": s["version"],
         "parser": s.get("parser", {}).get("kind"), "created_by": s.get("created_by"),
         "fields": list((s.get("field_map") or {}).keys()), "validation": s.get("validation")}
        for s in reg.list_schemas()]}


def call(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    """Dispatch with a uniform ok/error envelope. Both MCP transports use this."""
    spec = TOOLS_BY_NAME.get(name)
    if spec is None:
        return {"ok": False, "tool": name, "error": f"unknown tool '{name}'"}
    try:
        return spec["fn"](arguments or {})
    except ToolError as e:
        return {"ok": False, "tool": name, "error": str(e)}
    except Exception as e:  # pragma: no cover - defensive
        return {"ok": False, "tool": name, "error": f"{type(e).__name__}: {e}"}


TOOLS: list[dict[str, Any]] = [
    {"name": "list_log_types", "fn": list_log_types,
     "description": "List every ingested log source (index), its document count, and its time range. "
                    "Call this first for coverage. Context only: cannot by itself support a finding.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_field_mapping", "fn": get_field_mapping,
     "description": "Return field names and types for a sherlock-logs-* index so you can build correct queries.",
     "input_schema": {"type": "object", "properties": {"index": {"type": "string"}}, "required": ["index"]}},
    {"name": "sample_logs", "fn": sample_logs,
     "description": "Return the first N (<=50) documents of an index to understand its structure.",
     "input_schema": {"type": "object", "properties": {
         "index": {"type": "string"}, "n": {"type": "integer", "default": 3}}, "required": ["index"]}},
    {"name": "count_logs", "fn": count_logs,
     "description": "Count documents matching a Lucene query_string and optional ISO8601 time window. "
                    "Cheap; use it to test a hypothesis quantitatively. Returns matched_documents.",
     "input_schema": {"type": "object", "properties": {
         "index": {"type": "string", "description": "a sherlock-logs-* index; omit for all logs"},
         "query_string": {"type": "string"}, "start": {"type": "string"}, "end": {"type": "string"},
         "filters": {"type": "object"}}}},
    {"name": "search_logs", "fn": search_logs,
     "description": "Search logs with a Lucene query_string, time window, and size (<=100). Returns matching "
                    "documents, matched_documents, and the exact request executed.",
     "input_schema": {"type": "object", "properties": {
         "index": {"type": "string"}, "query_string": {"type": "string"},
         "start": {"type": "string"}, "end": {"type": "string"},
         "size": {"type": "integer", "default": 10}, "sort": {"type": "string", "enum": ["asc", "desc"]},
         "fields": {"type": "array", "items": {"type": "string"}}}}},
    {"name": "aggregate", "fn": aggregate,
     "description": "Aggregate: agg_type terms|date_histogram|cardinality|stats over a field, with optional "
                    "query_string and time window. terms for top-N, date_histogram (interval like '5m'/'1h') "
                    "for spikes/beacons, cardinality for distinct counts. Returns matched_documents plus "
                    "bucket_count / metric_value as appropriate.",
     "input_schema": {"type": "object", "properties": {
         "index": {"type": "string"}, "field": {"type": "string"},
         "agg_type": {"type": "string", "enum": ["terms", "date_histogram", "cardinality", "stats"]},
         "query_string": {"type": "string"}, "start": {"type": "string"}, "end": {"type": "string"},
         "interval": {"type": "string"}, "size": {"type": "integer", "default": 10}}, "required": ["field"]}},
    {"name": "list_schemas", "fn": list_schemas,
     "description": "List registered parsing schemas. Context only: cannot by itself support a finding.",
     "input_schema": {"type": "object", "properties": {}}},
]

TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}
