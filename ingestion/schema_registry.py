"""Schema registry -- stored in Elasticsearch so parsers are reusable across
runs and visible to the agent as first-class state.

A schema describes how to turn a raw record (a JSON object or a text line) into a
normalised document with an `@timestamp`. Schemas are keyed by a structural
`fingerprint` so an identical source is recognised instantly and never re-derived.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from common.es import get_client
from common.settings import SCHEMA_INDEX

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def fingerprint(sample: list[Any], log_type: str = "") -> str:
    """Structural signature of a source, used for reuse detection.

    Includes the log_type, the union of keys across several sample records, and
    each key's value type -- so two sources that merely share a first-record key
    set (but differ in type or log_type) do NOT collide onto one parser.
    """
    if not sample:
        return f"empty:{log_type}"
    first = sample[0]
    if isinstance(first, dict):
        keys: set[str] = set()
        for rec in sample[:8]:
            if isinstance(rec, dict):
                keys.update(rec.keys())

        def _type_of(key: str) -> str:
            # first NON-None value across samples -> so a field that only appears
            # later, or is null in record 1, still gets its real type in the sig.
            for rec in sample[:8]:
                if isinstance(rec, dict) and rec.get(key) is not None:
                    return type(rec[key]).__name__
            return "NoneType"

        typesig = ",".join(f"{k}:{_type_of(k)}" for k in sorted(keys))
        return "json:" + hashlib.sha1(f"{log_type}|{typesig}".encode()).hexdigest()[:16]
    # text: normalise several lines into a coarse shape (digits->#, quoted->Q)
    shapes = []
    for line in sample[:8]:
        s = re.sub(r"\d+", "#", str(line))
        s = re.sub(r'"[^"]*"', "Q", s)
        s = re.sub(r"\[[^\]]*\]", "T", s)
        shapes.append(re.sub(r"\s+", " ", s).strip())
    sig = f"{log_type}|" + "\n".join(sorted(set(shapes)))
    return "text:" + hashlib.sha1(sig.encode()).hexdigest()[:16]


def guess_es_type(field: str, value: Any) -> str:
    lf = field.lower()
    if field == "@timestamp" or lf in ("time", "date") or lf.endswith("_time") or lf.endswith("_at"):
        return "date"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "long"
    if isinstance(value, float):
        return "double"
    if isinstance(value, str):
        if _IP_RE.match(value.strip()):
            return "ip"
        if lf in ("message", "command_line", "query_results", "command", "request", "url") or len(value) > 180:
            return "text"
        return "keyword"
    return "keyword"


def get_by_fingerprint(fp: str) -> dict[str, Any] | None:
    es = get_client()
    if not es.indices.exists(index=SCHEMA_INDEX):
        return None
    res = es.search(index=SCHEMA_INDEX, query={"term": {"fingerprint": fp}}, size=1)
    hits = res["hits"]["hits"]
    return hits[0]["_source"] if hits else None


def list_schemas() -> list[dict[str, Any]]:
    es = get_client()
    if not es.indices.exists(index=SCHEMA_INDEX):
        return []
    res = es.search(index=SCHEMA_INDEX, query={"match_all": {}}, size=100, sort=[{"created_at": "desc"}])
    return [h["_source"] for h in res["hits"]["hits"]]


def register(schema: dict[str, Any]) -> dict[str, Any]:
    es = get_client()
    existing = get_by_fingerprint(schema["fingerprint"])
    schema["version"] = (existing["version"] + 1) if existing else 1
    schema.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    es.index(index=SCHEMA_INDEX, id=schema["fingerprint"], document=schema, refresh="wait_for")
    return schema
