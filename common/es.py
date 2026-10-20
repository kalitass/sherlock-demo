"""Elasticsearch client factory and low-level helpers.

Kept deliberately thin: the MCP tools are the real query surface. This module
only handles connection, index bootstrap, and bulk indexing.
"""
from __future__ import annotations

import time
from typing import Any, Iterable

from elasticsearch import Elasticsearch, helpers

from common.settings import (
    CONTRACT_INDEX,
    EVIDENCE_INDEX,
    HUNT_INDEX,
    INGEST_AUDIT_INDEX,
    SCHEMA_INDEX,
    settings,
)

_client: Elasticsearch | None = None


def get_client() -> Elasticsearch:
    global _client
    if _client is None:
        _client = Elasticsearch(settings.es_url, request_timeout=60, retry_on_timeout=True)
    return _client


def wait_until_ready(timeout: int = 120) -> bool:
    """Block until the cluster answers and is at least yellow."""
    es = get_client()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            health = es.cluster.health()
            if health.get("status") in ("yellow", "green"):
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


# --- Sherlock's own state indices -----------------------------------------
# These hold provenance, not logs. Mappings are permissive on purpose.
_STATE_MAPPINGS: dict[str, dict[str, Any]] = {
    SCHEMA_INDEX: {
        "mappings": {
            "properties": {
                "log_type": {"type": "keyword"},
                "name": {"type": "keyword"},
                "version": {"type": "integer"},
                "fingerprint": {"type": "keyword"},
                "created_at": {"type": "date"},
                "created_by": {"type": "keyword"},
                # Stored metadata only (read from _source, never queried). Disabled
                # so dotted field names (e.g. ECS "host.name") are not expanded into
                # nested objects that collide across schemas.
                "field_map": {"type": "object", "enabled": False},
                "sample": {"type": "object", "enabled": False},
                "validation": {"type": "object", "enabled": False},
                "rationale": {"type": "text"},
            }
        }
    },
    HUNT_INDEX: {
        "mappings": {
            "properties": {
                "hunt_id": {"type": "keyword"},
                "hypothesis": {"type": "text"},
                "verdict": {"type": "keyword"},
                "confidence": {"type": "float"},
                "started_at": {"type": "date"},
                "finished_at": {"type": "date"},
                "run_label": {"type": "keyword"},
                "report_md": {"type": "text"},
                "plan": {"type": "object", "enabled": False},
                "coverage": {"type": "object", "enabled": False},
                "summary": {"type": "text"},
            }
        }
    },
    EVIDENCE_INDEX: {
        "mappings": {
            "properties": {
                "hunt_id": {"type": "keyword"},
                "evidence_id": {"type": "keyword"},
                "step": {"type": "integer"},
                "tool": {"type": "keyword"},
                "arguments": {"type": "object", "enabled": False},
                "query_dsl": {"type": "object", "enabled": False},
                "result_summary": {"type": "text"},
                "hit_count": {"type": "long"},
                "sample_hits": {"type": "object", "enabled": False},
                "digest": {"type": "keyword"},
                "created_at": {"type": "date"},
            }
        }
    },
    INGEST_AUDIT_INDEX: {
        "mappings": {
            "properties": {
                "source": {"type": "keyword"},
                "mode": {"type": "keyword"},
                "log_type": {"type": "keyword"},
                "schema_name": {"type": "keyword"},
                "record_count": {"type": "long"},
                "ok": {"type": "boolean"},
                "detail": {"type": "text"},
                "created_at": {"type": "date"},
            }
        }
    },
    CONTRACT_INDEX: {
        "mappings": {
            "properties": {
                "log_type": {"type": "keyword"},
                "siem_schema": {"type": "keyword"},
                "updated_at": {"type": "date"},
                # field:type maps stored as metadata only (read from _source, never
                # queried) so dotted schema field names are not expanded/collided.
                "contract": {"type": "object", "enabled": False},
                "last_drift": {"type": "object", "enabled": False},
            }
        }
    },
}


def _create_index(index: str, **body: Any) -> None:
    """Create an index, tolerating a concurrent creator (TOCTOU-safe)."""
    es = get_client()
    try:
        es.indices.create(index=index, **body)
    except Exception as e:  # elasticsearch.BadRequestError: resource_already_exists_exception
        if "resource_already_exists" not in str(e):
            raise


def ensure_state_indices() -> None:
    es = get_client()
    for name, body in _STATE_MAPPINGS.items():
        if not es.indices.exists(index=name):
            _create_index(name, **body)


def ensure_log_index(index: str, field_map: dict[str, str] | None = None) -> None:
    """Create a log index. field_map is {field_name: es_type}; @timestamp is
    always a date. Unknown fields fall back to ES dynamic mapping."""
    es = get_client()
    if es.indices.exists(index=index):
        return
    props: dict[str, Any] = {"@timestamp": {"type": "date"}, "log_type": {"type": "keyword"}}
    for fname, ftype in (field_map or {}).items():
        if fname in props:
            continue
        if ftype == "text":
            props[fname] = {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}}
        else:
            props[fname] = {"type": ftype}
    _create_index(index, mappings={"properties": props},
                  settings={"number_of_shards": 1, "number_of_replicas": 0})


def bulk_index(index: str, docs: Iterable[dict[str, Any]], refresh: bool = False) -> int:
    """Bulk index. If a doc carries an '_id', it is used as the ES document id
    (so re-ingesting identical events overwrites rather than duplicating)."""
    es = get_client()

    def _actions():
        for d in docs:
            doc_id = d.pop("_id", None)
            action = {"_index": index, "_source": d}
            if doc_id is not None:
                action["_id"] = doc_id
            yield action

    ok, _ = helpers.bulk(es, _actions(), refresh="wait_for" if refresh else False, stats_only=True)
    return ok


def index_doc(index: str, doc: dict[str, Any], refresh: bool = False) -> None:
    es = get_client()
    es.index(index=index, document=doc, refresh="wait_for" if refresh else False)
