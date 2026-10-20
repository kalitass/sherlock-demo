"""Schema-drift detection — "a detection's health is inseparable from its schema's
health" (SE6014 Week 2, slide 36).

Schema drift breaks detections *silently*: the rule still runs, but a renamed,
dropped or retyped field means it quietly matches nothing. The lecture's prescribed
defence is a **schema contract check at ingest — observed vs expected keys & types**.

This module keeps a per-source contract (the field→type map first seen for a
log_type) in Elasticsearch and, on every later ingest, compares the newly observed
fields against it. Missing or type-changed fields the detections rely on are
surfaced as drift instead of failing silently. The baseline is NOT auto-updated on
drift, so the condition keeps alerting until a human re-baselines it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from common.es import get_client
from common.settings import CONTRACT_INDEX

# Fields that are Sherlock-internal or always-present; never part of a drift check.
_IGNORE = {"@timestamp", "log_type", "_id", "_ingest"}
_SAMPLE = 200


def observed_fields(docs: list[dict[str, Any]]) -> dict[str, str]:
    """field -> python type name, from the first non-null value across a sample."""
    fields: dict[str, str] = {}
    for doc in docs[:_SAMPLE]:
        for k, v in doc.items():
            if k in _IGNORE or k.startswith("n_") or k == "n_schema":
                continue
            if k not in fields and v is not None:
                fields[k] = type(v).__name__
    return fields


class _StorageError(Exception):
    """A real ES read/write failure — distinct from 'no baseline yet', so a broken
    contract store is surfaced as drift status 'error' rather than looking stable."""


def _get(log_type: str) -> dict[str, Any] | None:
    try:
        es = get_client()                    # client construction can also fail
        if not es.indices.exists(index=CONTRACT_INDEX):
            return None
        res = es.get(index=CONTRACT_INDEX, id=log_type, ignore=[404])
        return res["_source"] if res.get("found") else None
    except Exception as e:  # genuine transport/cluster error, not a missing doc
        raise _StorageError(str(e)) from e


def _put(doc: dict[str, Any]) -> None:
    try:
        get_client().index(index=CONTRACT_INDEX, id=doc["log_type"], document=doc, refresh="wait_for")
    except Exception as e:  # a failed baseline write must not look like success
        raise _StorageError(str(e)) from e


def check_drift(log_type: str, docs: list[dict[str, Any]], siem_schema: str = "") -> dict[str, Any]:
    """Compare this batch's fields against the stored contract for `log_type`.

    Returns {status: baseline|stable|drift, missing, type_changed, added}. On first
    sight, records a baseline. On drift, records the drift but keeps the baseline so
    the alert persists until `rebaseline()` is called.
    """
    observed = observed_fields(docs)
    if not observed:
        return {"status": "empty", "missing": [], "type_changed": [], "added": []}

    try:
        prior = _get(log_type)
    except _StorageError as e:
        return {"status": "error", "error": str(e), "missing": [], "type_changed": [], "added": []}
    now = datetime.now(timezone.utc).isoformat()
    if prior is None:
        try:
            _put({"log_type": log_type, "siem_schema": siem_schema, "updated_at": now,
                  "contract": observed, "last_drift": {}})
        except _StorageError as e:
            return {"status": "error", "error": str(e), "missing": [], "type_changed": [], "added": []}
        return {"status": "baseline", "n_fields": len(observed),
                "missing": [], "type_changed": [], "added": []}

    base: dict[str, str] = prior.get("contract", {})
    missing = sorted(k for k in base if k not in observed)
    type_changed = sorted(f"{k}:{base[k]}->{observed[k]}" for k in observed
                          if k in base and observed[k] != base[k])
    added = sorted(k for k in observed if k not in base)
    drifted = bool(missing or type_changed)

    status = "drift" if drifted else "stable"
    result = {"status": status, "missing": missing, "type_changed": type_changed, "added": added}
    if drifted:
        try:
            _put({**prior, "updated_at": prior.get("updated_at"), "last_drift": {
                "at": now, "missing": missing, "type_changed": type_changed, "added": added}})
        except _StorageError as e:          # the finding stands; flag that it was not persisted
            result["persisted"] = False
            result["persist_error"] = str(e)
    return result


def rebaseline(log_type: str, docs: list[dict[str, Any]], siem_schema: str = "") -> dict[str, Any]:
    """Accept the current fields as the new contract (after an intentional change)."""
    observed = observed_fields(docs)
    try:
        _put({"log_type": log_type, "siem_schema": siem_schema,
              "updated_at": datetime.now(timezone.utc).isoformat(),
              "contract": observed, "last_drift": {}})
    except _StorageError as e:
        return {"status": "error", "error": str(e), "n_fields": len(observed)}
    return {"status": "rebaselined", "n_fields": len(observed)}
