"""SIEM schema compatibility + normalisation — "normalise first" (SE6014 Week 2).

The lecture's thesis: *one event has seven+ spellings* across the famous SIEM
schemas, and *a detection is only as portable as its schema*. This module encodes
the course's own field-mapping tables (Week 2, slides 21-26) for all seven:

  Producer-side (wire format):   CEF (ArcSight), LEEF (IBM QRadar)
  Consumer-side (normalisation): CIM (Splunk), ECS (Elastic), OCSF, ASIM
                                 (MS Sentinel), UDM (Google SecOps)

`detect_schema()` recognises which of the seven an event is in; `normalise()`
rewrites it to ONE canonical field set (prefix `n_`) so a single detection — or a
single hunt query — fires across every schema. This is the "normalise first" /
Sigma portability idea made concrete, and the migration path when a source's
schema differs from what a rule was written against.
"""
from __future__ import annotations

from typing import Any

# Canonical field names Sherlock normalises every schema onto. Kept flat and
# prefixed (`n_`) so they never collide with a source's own fields and are trivial
# to query (ES expands dotted names into objects; flat keeps joins simple).
CANONICAL = [
    "n_time", "n_event_id", "n_host", "n_user",
    "n_src_ip", "n_dst_ip", "n_src_port", "n_dst_port",
    "n_action", "n_rule", "n_severity", "n_url",
    "n_process", "n_parent", "n_cmdline", "n_sha256",
]

# Per-schema source field (or dotted path) for each canonical field. Values are
# taken directly from the Week 2 mapping tables. None = the schema has no native
# field for it (e.g. CEF/LEEF cannot express process lineage — slide 24).
# Field maps corrected against the real schemas after an external review (see
# docs/sherlock-spec changelog). For Authentication events specifically: n_time is
# taken from the parsed `@timestamp` (the native ts field is consumed at parse
# time); mappings flagged as the wrong concept for Authentication are set to None.
SCHEMA_FIELDS: dict[str, dict[str, str | None]] = {
    "cef": {  # ArcSight CEF: event id from header SignatureID; outcome from `outcome`
        "n_time": "@timestamp", "n_event_id": "cef_sig_id", "n_host": "dvchost", "n_user": "duser",
        "n_src_ip": "src", "n_dst_ip": "dst", "n_src_port": "spt", "n_dst_port": "dpt",
        "n_action": "outcome", "n_rule": None, "n_severity": "sev", "n_url": "request",
        "n_process": "dproc", "n_parent": None, "n_cmdline": None, "n_sha256": None,
    },
    "leef": {  # IBM QRadar LEEF: outcome via `cat`; host via `resource`
        "n_time": "@timestamp", "n_event_id": "EventID", "n_host": "resource", "n_user": "usrName",
        "n_src_ip": "src", "n_dst_ip": "dst", "n_src_port": "srcPort", "n_dst_port": "dstPort",
        "n_action": "cat", "n_rule": None, "n_severity": "sev", "n_url": "url",
        "n_process": None, "n_parent": None, "n_cmdline": None, "n_sha256": None,
    },
    "cim": {  # Splunk CIM Authentication: target host is `dest`; process = `process`
        "n_time": "@timestamp", "n_event_id": "signature_id", "n_host": "dest", "n_user": "user",
        "n_src_ip": "src", "n_dst_ip": None, "n_src_port": "src_port", "n_dst_port": "dest_port",
        "n_action": "action", "n_rule": None, "n_severity": "severity", "n_url": "url",
        "n_process": "process", "n_parent": None, "n_cmdline": None, "n_sha256": None,
    },
    "ecs": {  # Elastic Common Schema -- dotted, schema-on-write
        "n_time": "@timestamp", "n_event_id": "event.code", "n_host": "host.name",
        "n_user": "user.name", "n_src_ip": "source.ip", "n_dst_ip": "destination.ip",
        "n_src_port": "source.port", "n_dst_port": "destination.port",
        "n_action": "event.outcome", "n_rule": "rule.name", "n_severity": "event.severity",
        "n_url": "url.full", "n_process": "process.name", "n_parent": "process.parent.name",
        "n_cmdline": "process.command_line", "n_sha256": "process.hash.sha256",
    },
    "ocsf": {  # OCSF Authentication: target = dst_endpoint; actor = initiating process
        "n_time": "@timestamp", "n_event_id": "metadata.event_code", "n_host": "dst_endpoint.hostname",
        "n_user": "user.name", "n_src_ip": "src_endpoint.ip", "n_dst_ip": "dst_endpoint.ip",
        "n_src_port": "src_endpoint.port", "n_dst_port": "dst_endpoint.port",
        "n_action": "status", "n_rule": None, "n_severity": "severity_id",
        "n_url": "http_request.url.url_string", "n_process": "actor.process.name",
        "n_parent": "actor.process.parent_process.name", "n_cmdline": "actor.process.cmd_line",
        "n_sha256": None,
    },
    "asim": {  # Microsoft Sentinel ASIM Authentication: target host is TargetHostname
        "n_time": "@timestamp", "n_event_id": "EventOriginalType", "n_host": "TargetHostname",
        "n_user": "TargetUsername", "n_src_ip": "SrcIpAddr", "n_dst_ip": "TargetIpAddr",
        "n_src_port": "SrcPortNumber", "n_dst_port": "TargetPortNumber",
        "n_action": "EventResult", "n_rule": "RuleName", "n_severity": "EventSeverity",
        "n_url": "TargetUrl", "n_process": "ActingAppName", "n_parent": None,
        "n_cmdline": None, "n_sha256": None,
    },
    "udm": {  # Google SecOps UDM: authenticated system in `target`, client in `principal`
        "n_time": "@timestamp", "n_event_id": "metadata.product_event_type",
        "n_host": "target.hostname", "n_user": "target.user.userid",
        "n_src_ip": "principal.ip", "n_dst_ip": "target.ip",
        "n_src_port": "principal.port", "n_dst_port": "target.port",
        "n_action": "extensions.auth.outcome", "n_rule": "security_result.rule_name",
        "n_severity": "security_result.severity", "n_url": "target.url",
        "n_process": "principal.process.file.full_path", "n_parent": None,
        "n_cmdline": "principal.process.command_line", "n_sha256": "principal.process.file.sha256",
    },
}

SCHEMAS = list(SCHEMA_FIELDS)

# Signature fields that uniquely identify a schema from a parsed record's keys.
# Ordered most-specific first so detection is unambiguous.
_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("udm", ("metadata.event_timestamp", "principal.ip", "target.user.userid")),
    ("ocsf", ("metadata.event_code", "src_endpoint.ip", "class_uid")),
    ("ecs", ("@timestamp", "event.code", "source.ip")),
    ("asim", ("TimeGenerated", "SrcIpAddr", "TargetUsername")),
    ("cim", ("_time", "signature_id", "action")),
    ("cef", ("cef_sig_id", "dvchost", "duser")),
    ("leef", ("devTime", "usrName", "EventID")),
]

# Normalised outcome vocabulary — map each schema's native result token to pass/fail
# by EXACT match (never substring: "not allowed" must not read as success). Auth
# outcomes (Success/Failure/Failed/FAIL) plus firewall verbs for network events.
_FAIL = {"failure", "fail", "failed", "deny", "denied", "block", "blocked"}
_PASS = {"success", "succeeded", "successful", "allow", "allowed", "accept",
         "accepted", "pass", "passed", "permit", "permitted"}


def get_path(record: dict[str, Any], path: str) -> Any:
    """Resolve a field that may be stored as a flat dotted key ("source.ip") OR as a
    truly-nested object ({"source": {"ip": ...}}). Supports both representations so
    the layer normalises real nested ECS/OCSF/UDM JSON as well as the flattened form."""
    if path in record:
        return record[path]
    cur: Any = record
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def detect_schema(record: dict[str, Any] | str, raw: str | None = None) -> str | None:
    """Identify which of the seven SIEM schemas a record is in.

    Text records are recognised by their wire-format prefix (CEF:/LEEF:, after any
    syslog prefix); parsed dicts by the presence of signature fields (flat or
    nested). Returns the schema id or None.
    """
    text = raw if raw is not None else (record if isinstance(record, str) else "")
    if "CEF:" in text[:64]:
        return "cef"
    if "LEEF:" in text[:64]:
        return "leef"
    if not isinstance(record, dict):
        return None
    for schema, sig in _SIGNATURES:
        hits = sum(1 for s in sig if get_path(record, s) is not None)
        if hits >= 2:                       # ≥2 signature fields => confident match
            return schema
    return None


def _norm_action(value: Any) -> str | None:
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in _FAIL:
        return "failure"
    if v in _PASS:
        return "success"
    return v or None


# Canonical severity ladder. Each schema uses a different scale (CEF/LEEF 0-10,
# OCSF severity_id 0-6, ASIM/UDM strings), so severity is normalised per-schema to
# one vocabulary {informational, low, medium, high, critical, unknown} — otherwise a
# cross-schema query on n_severity is meaningless.
_SEV_MAP = {  # string tokens across schemas -> canonical ladder
    "informational": "informational", "info": "informational",
    "low": "low", "medium": "medium", "moderate": "medium",
    "high": "high", "error": "high",
    "critical": "critical", "very-high": "critical", "veryhigh": "critical", "fatal": "critical",
    "none": "unknown", "unknown": "unknown", "unknown_severity": "unknown",
}
# OCSF severity_id (0-6): 0=Unknown,1=Informational,2=Low,3=Medium,4=High,5=Critical,6=Fatal.
_OCSF_SEV = {0: "unknown", 1: "informational", 2: "low", 3: "medium",
             4: "high", 5: "critical", 6: "critical"}


def _norm_severity(value: Any, schema: str) -> Any:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in _SEV_MAP:
        return _SEV_MAP[s]
    try:
        n = int(float(s))
    except (TypeError, ValueError):
        return s or None
    if schema == "ocsf":
        return _OCSF_SEV.get(n, "unknown")
    # numeric 0-10 band (CEF severity scale: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Critical)
    if n <= 3:
        return "low"
    if n <= 6:
        return "medium"
    if n <= 8:
        return "high"
    return "critical"


def normalise(record: dict[str, Any], schema: str) -> dict[str, Any]:
    """Return the canonical `n_*` fields for a parsed record of a known schema.

    A single hunt query on these fields (e.g. n_user + n_src_ip + n_action) then
    fires identically no matter which SIEM exported the event. `n_time` comes from
    the parsed `@timestamp`, since the schema-native timestamp field is consumed at
    parse time.
    """
    fmap = SCHEMA_FIELDS.get(schema)
    if not fmap:
        return {}
    out: dict[str, Any] = {}
    for canon, src in fmap.items():
        if not src or canon == "n_time":
            continue
        val = get_path(record, src)
        if val is None:
            continue
        if canon == "n_action":
            out[canon] = _norm_action(val)
        elif canon == "n_severity":
            out[canon] = _norm_severity(val, schema)
        else:
            out[canon] = val
    ts = record.get("@timestamp")
    if ts is None:
        ts = get_path(record, fmap.get("n_time") or "")
    if ts is not None:
        out["n_time"] = ts
    if out:
        out["n_schema"] = schema
    return out
