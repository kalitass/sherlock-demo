"""Agentic auto-schema detection.

Given a raw sample from an unknown source, the agent:
  1. fingerprints the source and reuses a registered schema if one matches;
  2. otherwise proposes a parser (LLM-assisted, with a deterministic fallback);
  3. validates the parser against the sample (parse rate + timestamp presence);
  4. derives an ES field mapping and registers the schema for reuse.

This is what lets a user "point the system at a log source and the agents handle
the rest" -- no hand-written parsers.
"""
from __future__ import annotations

import re
from typing import Any

from common.llm import LLMClient
from ingestion import schema_registry as reg
from ingestion.parsing import parse_record

# Deterministic parser for Apache/NGINX "combined" access logs.
CLF_PATTERN = (
    r'^(?P<client_ip>\S+) \S+ (?P<auth_user>\S+) \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

MIN_PARSE_RATE = 0.8
MIN_FIELDS = 2               # a parser that only extracts a timestamp is not a schema
MAX_PATTERN_LEN = 2000
_EPOCH_KEYS = ("epoch", "unixtime", "unix_time", "ts_epoch")


def _safe_regex(pattern: str) -> bool:
    """Reject over-long or non-compiling patterns and obvious catastrophic-
    backtracking shapes (nested unbounded quantifiers)."""
    if not pattern or len(pattern) > MAX_PATTERN_LEN:
        return False
    if re.search(r"\([^)]*[+*]\)[+*]", pattern):     # e.g. (a+)+ / (a*)*
        return False
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def _validate(candidate: dict[str, Any], sample: list[Any]) -> tuple[float, list[dict]]:
    """Parse rate over the WHOLE sample, requiring real field coverage (not just a
    timestamp) so a lazy regex cannot score 100% by grabbing one field."""
    if candidate.get("parser", {}).get("kind") == "regex":
        if not _safe_regex(candidate["parser"].get("pattern", "")):
            return 0.0, []
    parsed = [parse_record(candidate, r) for r in sample]
    good = [p for p in parsed if p is not None
            and len([k for k in p if k not in ("@timestamp", "log_type")]) >= MIN_FIELDS]
    rate = len(good) / len(sample) if sample else 0.0
    return rate, good


def _derive_field_map(parsed: list[dict]) -> dict[str, str]:
    fmap: dict[str, str] = {}
    for doc in parsed[:50]:
        for k, v in doc.items():
            if k in ("@timestamp", "log_type"):
                continue
            fmap.setdefault(k, reg.guess_es_type(k, v))
    return fmap


def _heuristic_propose(log_type: str, sample: list[Any]) -> dict[str, Any]:
    first = sample[0]
    if isinstance(first, dict):
        ts_field = "@timestamp" if "@timestamp" in first else next(
            (k for k in first if "time" in k.lower() or "date" in k.lower() or k.lower() in _EPOCH_KEYS),
            "@timestamp",
        )
        ts_val = first.get(ts_field)
        ts_format = "epoch" if isinstance(ts_val, (int, float)) or (
            isinstance(ts_val, str) and ts_val.strip().isdigit()) else "auto"
        return {
            "parser": {"kind": "json"}, "ts_field": ts_field, "ts_format": ts_format,
            "rationale": f"Records are JSON objects; timestamp field detected as '{ts_field}' "
                         f"(format {ts_format}). Field types inferred from sample values.",
            "created_by": "heuristic",
        }
    # text: recognise standardised SIEM producer wire formats first (CEF/LEEF),
    # then the Apache/NGINX combined log format.
    head = str(first).strip()[:64].upper()
    if "CEF:" in head:
        return {"parser": {"kind": "cef"}, "ts_field": "start", "ts_fallback": "rt", "ts_format": "auto",
                "rationale": "ArcSight CEF wire format (pipe header + key=value extension); "
                             "deterministic parser, event time from 'start' (fallback 'rt').",
                "created_by": "heuristic"}
    if "LEEF:" in head:
        return {"parser": {"kind": "leef"}, "ts_field": "devTime", "ts_format": "auto",
                "rationale": "IBM QRadar LEEF wire format (pipe header + delimited extension); "
                             "deterministic parser, timestamp from the 'devTime' key.",
                "created_by": "heuristic"}
    return {
        "parser": {"kind": "regex", "pattern": CLF_PATTERN}, "ts_field": "timestamp", "ts_format": "clf",
        "rationale": "Records are plain text matching the Apache/NGINX combined log format; "
                     "built a named-group regex and parse the bracketed CLF timestamp.",
        "created_by": "heuristic",
    }


def _llm_propose(llm: LLMClient, log_type: str, sample: list[Any]) -> dict[str, Any] | None:
    preview = "\n".join(str(s)[:500] for s in sample[:5])
    system = (
        "You are a log-parsing engineer. Given raw log records, output a parser spec as JSON with keys: "
        "parser ({kind:'json'} or {kind:'regex', pattern: <python regex with named groups>}), "
        "ts_field (the field/group holding the timestamp), ts_format ('iso'|'clf'|'auto'), and rationale. "
        "For text logs, the regex MUST use named groups and cover the whole line."
    )
    try:
        spec = llm.complete_json(system, f"log_type={log_type}\nrecords:\n{preview}")
        if "parser" in spec and "ts_field" in spec:
            if spec["parser"].get("kind") == "regex" and not _safe_regex(spec["parser"].get("pattern", "")):
                return None            # reject unsafe/over-long LLM regex outright
            spec["created_by"] = "llm"
            return spec
    except Exception:
        pass
    return None


def detect_and_register(
    log_type: str, sample: list[Any], source: str = "unknown", use_llm: bool = True
) -> dict[str, Any]:
    fp = reg.fingerprint(sample, log_type)
    existing = reg.get_by_fingerprint(fp)
    if existing and existing.get("log_type") == log_type:
        # Fast re-validation against the new sample; only reuse if it still parses.
        rate, _ = _validate(existing, sample)
        if rate >= MIN_PARSE_RATE:
            existing["reused"] = True
            existing["registered"] = True
            return existing

    llm = LLMClient()
    candidate = _llm_propose(llm, log_type, sample) if (use_llm and llm.available()) else None

    best = None       # highest-rate proposal seen, even if below threshold
    for proposal in (candidate, _heuristic_propose(log_type, sample)):
        if proposal is None:
            continue
        proposal["log_type"] = log_type
        rate, parsed = _validate(proposal, sample)
        proposal["_rate"], proposal["_parsed"] = rate, parsed
        if best is None or rate > best["_rate"]:
            best = proposal
        if rate >= MIN_PARSE_RATE and parsed:
            break

    rate, parsed = best["_rate"], best["_parsed"]
    best.pop("_rate", None); best.pop("_parsed", None)
    best["field_map"] = _derive_field_map(parsed)
    best["validation"] = {"tested": len(sample), "parsed": len(parsed), "rate": round(rate, 3),
                          "min_required": MIN_PARSE_RATE, "has_timestamp": bool(parsed)}
    best["fingerprint"] = fp
    best["name"] = f"{log_type}-schema"
    best["source"] = source
    best["sample"] = [str(s)[:500] for s in sample[:3]]

    if rate >= MIN_PARSE_RATE and parsed:
        registered = reg.register(best)
        registered["reused"] = False
        registered["registered"] = True
        return registered
    # Below threshold: quarantine -- do NOT register a bad parser for reuse.
    best["reused"] = False
    best["registered"] = False
    return best
