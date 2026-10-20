"""Shared ingestion core used by all three modes (pull / push / stream).

Flow for any batch of raw records:
  detect-or-reuse schema  ->  ensure index mapping  ->  parse  ->  bulk index
  ->  write an ingest-audit record (provenance).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common.es import bulk_index, ensure_log_index, index_doc
from common.schemas import detect_schema, normalise
from common.settings import INGEST_AUDIT_INDEX, log_index
from ingestion.auto_schema import detect_and_register
from ingestion.parsing import parse_record
from ingestion.schema_drift import check_drift


def guess_log_type(name: str) -> str:
    n = name.lower()
    if "sysmon" in n:
        return "sysmon"
    if "win" in n or "security" in n or "evtx" in n:
        return "windows"
    if any(k in n for k in ("web", "access", "nginx", "apache", "http")):
        return "web"
    return Path(name).stem.replace(".", "_")


def read_raw_file(path: Path) -> tuple[str, list[Any]]:
    text = path.read_text(errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    log_type = guess_log_type(path.name)
    # NDJSON if every (sampled) line parses as a JSON object.
    def _is_json(ln: str) -> bool:
        try:
            return isinstance(json.loads(ln), dict)
        except Exception:
            return False

    if lines and all(_is_json(ln) for ln in lines[:20]):
        return log_type, [json.loads(ln) for ln in lines]
    return log_type, lines


def _maybe_json(r: Any) -> Any:
    """Turn a JSON-object string into a dict (NDJSON lines arriving over push/
    stream); leave everything else as-is."""
    if isinstance(r, str):
        s = r.strip()
        if s[:1] == "{":
            try:
                v = json.loads(s)
                if isinstance(v, dict):
                    return v
            except Exception:
                pass
    return r


def ingest_records(
    log_type: str, raw_records: list[Any], source: str, mode: str,
    refresh: bool = True, use_llm: bool = True,
) -> dict[str, Any]:
    if not raw_records:
        return {"ok": True, "count_in": 0, "count_indexed": 0, "failures": 0, "detail": "empty batch"}

    raw_records = [_maybe_json(r) for r in raw_records]
    sample = raw_records[: min(200, len(raw_records))]
    schema = detect_and_register(log_type, sample, source=source, use_llm=use_llm)
    registered = schema.get("registered", True)

    # Which of the seven famous SIEM schemas is this? (CEF/LEEF/CIM/ECS/OCSF/ASIM/UDM)
    siem_schema = detect_schema(sample[0]) if sample else None

    docs, failures = [], 0
    drift: dict[str, Any] = {"status": "skipped"}
    index = log_index(log_type)
    if registered:
        ensure_log_index(index, schema.get("field_map"))
        for r in raw_records:
            doc = parse_record(schema, r)
            if doc is None:
                failures += 1
                continue
            # Normalise onto canonical n_* fields so one detection fires across any
            # schema ("normalise first", Week 2). No-op for unknown schemas.
            if siem_schema:
                doc.update(normalise(doc, siem_schema))
            # Deterministic id from the event content -> idempotent ingestion
            # (re-running seed or replaying a file never duplicates events).
            doc_id = hashlib.sha1(
                json.dumps(doc, sort_keys=True, default=str).encode()
            ).hexdigest()
            doc["_ingest"] = {"source": source, "mode": mode, "schema": schema["name"]}
            doc["_id"] = doc_id
            docs.append(doc)
        # Schema-drift contract check (observed vs expected keys & types).
        drift = check_drift(log_type, docs, siem_schema or "")
        indexed = bulk_index(index, docs, refresh=refresh) if docs else 0
    else:
        failures = len(raw_records)
        indexed = 0

    # Honest success: the schema was accepted AND most of the batch parsed.
    batch_rate = indexed / len(raw_records) if raw_records else 0.0
    ok = registered and batch_rate >= 0.8
    detail = ("schema quarantined (validation below threshold)" if not registered
              else f"batch parse rate {batch_rate:.2f}")

    summary = {
        "ok": ok, "index": index, "log_type": log_type, "mode": mode, "source": source,
        "schema_name": schema.get("name"), "schema_reused": schema.get("reused", False),
        "schema_registered": registered, "schema_version": schema.get("version"),
        "parse_rate": schema.get("validation", {}).get("rate"), "batch_parse_rate": round(batch_rate, 3),
        "count_in": len(raw_records), "count_indexed": indexed, "failures": failures,
        "created_by": schema.get("created_by"), "detail": detail,
        "siem_schema": siem_schema, "drift": drift,
    }
    _audit(summary)
    return summary


def ingest_file(path: Path, mode: str = "pull", refresh: bool = True, use_llm: bool = True) -> dict[str, Any]:
    log_type, records = read_raw_file(path)
    return ingest_records(log_type, records, source=str(path), mode=mode, refresh=refresh, use_llm=use_llm)


def _audit(summary: dict[str, Any]) -> None:
    try:
        index_doc(INGEST_AUDIT_INDEX, {
            "source": summary["source"], "mode": summary["mode"], "log_type": summary["log_type"],
            "schema_name": summary["schema_name"], "record_count": summary["count_indexed"],
            "ok": summary["ok"], "detail": f"in={summary['count_in']} failures={summary['failures']} "
                                            f"reused={summary['schema_reused']}",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        pass
