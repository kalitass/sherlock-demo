"""Agentic migration of Sigma detection rules into Sherlock.

Sigma (sigmahq.io) is the vendor-neutral YAML standard for detection rules -- the
open SigmaHQ corpus has 3000+ ATT&CK-tagged rules. This brings an existing Sigma
rule into the deterministic engine the SAME way auto-schema onboards a log source:

  1. parse the rule (deterministic);
  2. map its fields to our canonical `n_*` schema -- a deterministic alias table for
     the common Sigma fields, with an LLM proposing a mapping for UNKNOWN fields;
  3. translate the `detection` (selection blocks + condition) into one MCP
     `query_string` -- deterministic for the common selection/condition shapes;
     aggregation/correlation rules are flagged `needs_review`, never silently
     mis-translated;
  4. (caller) validate the query against Elasticsearch before trusting it.

Because the query targets `n_*` fields, ONE migrated rule runs across every SIEM
format we have normalised (CEF/LEEF/CIM/ECS/OCSF/ASIM/UDM) at once: Sigma gives
portability at the QUERY level, our `n_*` gives it at the DATA level.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

# Valid mapping targets -- the canonical fields (keep in sync with common/schemas).
CANONICAL = {
    "n_time", "n_event_id", "n_host", "n_user", "n_src_ip", "n_dst_ip",
    "n_src_port", "n_dst_port", "n_action", "n_rule", "n_severity", "n_url",
    "n_process", "n_parent", "n_cmdline", "n_sha256",
}

# Deterministic alias table: common Sigma field names -> canonical n_* field. This
# is the "heuristic" fast path (like auto-schema's known formats); unknown fields
# fall through to the LLM. Keys are lower-cased.
SIGMA_FIELD_MAP: dict[str, str] = {
    "eventid": "n_event_id", "eventcode": "n_event_id", "event_id": "n_event_id",
    "commandline": "n_cmdline", "command_line": "n_cmdline",
    "image": "n_process", "process": "n_process", "newprocessname": "n_process",
    "processname": "n_process", "sourceimage": "n_process",
    "parentimage": "n_parent", "parentprocessname": "n_parent", "parentcommandline": "n_parent",
    "user": "n_user", "targetusername": "n_user", "subjectusername": "n_user",
    "accountname": "n_user", "username": "n_user", "samaccountname": "n_user",
    "computername": "n_host", "computer": "n_host", "hostname": "n_host",
    "workstation": "n_host", "workstationname": "n_host", "targethostname": "n_host",
    "sourceip": "n_src_ip", "ipaddress": "n_src_ip", "sourcenetworkaddress": "n_src_ip",
    "src_ip": "n_src_ip", "srcip": "n_src_ip", "clientip": "n_src_ip",
    "destinationip": "n_dst_ip", "dst_ip": "n_dst_ip", "destaddress": "n_dst_ip",
    "sourceport": "n_src_port", "srcport": "n_src_port",
    "destinationport": "n_dst_port", "dstport": "n_dst_port",
    "sha256": "n_sha256", "hashes": "n_sha256", "sha256hash": "n_sha256",
    "url": "n_url", "requesturl": "n_url", "uri": "n_url",
    "ruleName": "n_rule",
}

_LEVEL_TO_SEV = {"informational": "low", "low": "low", "medium": "medium",
                 "high": "high", "critical": "critical"}

# Lucene query_string special characters.
_SPECIALS = set('+-&|!(){}[]^"~:\\/ ')


class Unsupported(Exception):
    """The rule uses a shape we will not silently mis-translate (e.g. aggregation)."""


@dataclass
class MigratedRule:
    title: str
    status: str                 # "migrated" | "needs_review"
    query_string: str | None
    mitre: str
    technique: str
    severity: str
    field_map: dict[str, str] = field(default_factory=dict)
    unmapped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    product: str = ""


# --- parsing helpers -------------------------------------------------------
def parse_sigma(text: str) -> dict[str, Any]:
    """Parse a Sigma YAML rule. Multi-document files: take the first detection rule."""
    docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    for d in docs:
        if "detection" in d:
            return d
    return docs[0] if docs else {}


def _esc(v: Any) -> str:
    """Escape a value for an UNQUOTED (wildcard) Lucene term."""
    return "".join(("\\" + ch) if ch in _SPECIALS else ch for ch in str(v))


def _escq(v: Any) -> str:
    """Escape a value for a QUOTED Lucene phrase."""
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def _split_mod(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], [p.lower() for p in parts[1:]]


def _tags_to_attack(tags: list[Any]) -> tuple[str, str]:
    tids: list[str] = []
    tactics: list[str] = []
    for t in tags or []:
        s = str(t)
        if not s.lower().startswith("attack."):
            continue
        v = s.split(".", 1)[1]
        if re.fullmatch(r"t\d{4}(\.\d{3})?", v.lower()):
            tids.append(v.upper())
        else:
            tactics.append(v.replace("_", " ").title())
    mitre = ", ".join(dict.fromkeys(tids)) or "n/a"
    technique = ", ".join(dict.fromkeys(tactics)) or "Sigma rule"
    return mitre, technique


# --- field mapping (deterministic table + LLM fallback) --------------------
def _map_field(name: str, use_llm: bool, llm: Any) -> str | None:
    key = name.lower()
    if key in SIGMA_FIELD_MAP:
        return SIGMA_FIELD_MAP[key]
    if key in CANONICAL:
        return key
    if use_llm and llm is not None and llm.available():
        try:
            out = llm.complete_json(
                "You map a SIEM log field name onto one canonical field. Reply JSON "
                '{"field": "<one of the allowed names, or none>"}.',
                f"Allowed canonical fields: {sorted(CANONICAL)}\nMap this field: {name}")
            cand = str(out.get("field", "")).lower()
            if cand in CANONICAL:
                return cand
        except Exception:
            pass
    return None


def _collect_fields(detection: dict[str, Any]) -> list[str]:
    fields: list[str] = []

    def walk(block: Any) -> None:
        if isinstance(block, list):
            for b in block:
                walk(b)
        elif isinstance(block, dict):
            for k in block:
                fields.append(_split_mod(k)[0])

    for name, block in detection.items():
        if name != "condition":
            walk(block)
    return list(dict.fromkeys(fields))


# --- query building --------------------------------------------------------
def _value_clause(nf: str, mods: list[str], val: Any) -> str:
    if isinstance(val, list):
        op = " AND " if "all" in mods else " OR "
        return "(" + op.join(_value_clause(nf, mods, v) for v in val) + ")"
    if "contains" in mods:
        return f"{nf}:*{_esc(val)}*"
    if "startswith" in mods:
        return f"{nf}:{_esc(val)}*"
    if "endswith" in mods:
        return f"{nf}:*{_esc(val)}"
    if "re" in mods:
        raise Unsupported("regex modifier (|re)")
    if isinstance(val, bool):
        return f"{nf}:{str(val).lower()}"
    if isinstance(val, (int, float)):
        return f"{nf}:{val}"
    return f'{nf}:"{_escq(val)}"'


def _block_clause(block: Any, field_map: dict[str, str]) -> str:
    if isinstance(block, list):
        subs = [c for c in (_block_clause(b, field_map) for b in block) if c]
        return "(" + " OR ".join(subs) + ")" if subs else ""
    clauses = []
    for key, val in block.items():
        fname, mods = _split_mod(key)
        nf = field_map.get(fname.lower())
        if nf is None:                      # unmapped -> skip (status already flagged)
            continue
        clauses.append(_value_clause(nf, mods, val))
    return " AND ".join(c for c in clauses if c)


def _condition_to_query(condition: str, blocks: dict[str, str]) -> str:
    if "|" in condition:                    # a pipe is an aggregation/correlation
        raise Unsupported("aggregation/correlation (pipe) condition")

    def _of(qty: str, sel: str) -> str:
        if sel.lower() == "them":
            names = list(blocks)
        else:
            names = [n for n in blocks if n.startswith(sel.rstrip("*"))]
        if not names:
            raise Unsupported(f"'{qty} of {sel}' matches no selection with a mapped field")
        op = " OR " if qty.lower() in ("1", "any") else " AND "
        return "(" + op.join(f"({blocks[n]})" for n in names) + ")"

    toks = re.findall(r"\(|\)|[\w*]+", condition)
    out: list[str] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        low = t.lower()
        if t in ("(", ")"):
            out.append(t)
        elif low in ("and", "or", "not"):
            out.append(low.upper())
        elif low in ("all", "1", "any") and i + 2 < len(toks) and toks[i + 1].lower() == "of":
            out.append(_of(low, toks[i + 2]))
            i += 2
        elif t in blocks:
            out.append(f"({blocks[t]})")
        else:
            raise Unsupported(f"unresolved token '{t}' in condition")
        i += 1
    return " ".join(out)


# --- the migration ---------------------------------------------------------
def migrate(text: str, use_llm: bool = True, llm: Any = None) -> MigratedRule:
    rule = parse_sigma(text)
    title = str(rule.get("title", "(untitled)"))
    product = str((rule.get("logsource") or {}).get("product", ""))
    mitre, technique = _tags_to_attack(rule.get("tags") or [])
    severity = _LEVEL_TO_SEV.get(str(rule.get("level", "medium")).lower(), "medium")
    detection = rule.get("detection") or {}
    condition = str(detection.get("condition", "")).strip()

    field_map: dict[str, str] = {}
    unmapped: list[str] = []
    for f in _collect_fields(detection):
        nf = _map_field(f, use_llm, llm)
        if nf:
            field_map[f.lower()] = nf
        else:
            unmapped.append(f)

    notes: list[str] = []
    status = "migrated"
    if unmapped:
        status = "needs_review"
        notes.append(f"unmapped fields: {sorted(set(unmapped))}")

    query: str | None = None
    try:
        blocks = {name: _block_clause(block, field_map)
                  for name, block in detection.items() if name != "condition"}
        blocks = {k: v for k, v in blocks.items() if v}
        if not condition:
            raise Unsupported("no condition")
        query = _condition_to_query(condition, blocks)
        if not query.strip():
            raise Unsupported("empty query after translation")
    except Unsupported as e:
        status = "needs_review"
        notes.append(f"query not translated: {e}")
        query = None

    return MigratedRule(title=title, status=status, query_string=query, mitre=mitre,
                        technique=technique, severity=severity, field_map=field_map,
                        unmapped=sorted(set(unmapped)), notes=notes, product=product)


# --- demo / validation against Elasticsearch -------------------------------
SIEM_SCHEMAS = ("cef", "leef", "cim", "ecs", "ocsf", "asim", "udm")


def validate(rule: MigratedRule) -> dict[str, Any]:
    """Run the migrated query via the read-only tools. Returns ok + total matched.
    A rule that validly matches zero is still 'ok' (the query parsed and ran)."""
    from mcp_server.tools import count_logs
    if not rule.query_string:
        return {"ok": False, "reason": "no query (needs_review)"}
    r = count_logs({"query_string": rule.query_string})
    if not (isinstance(r, dict) and r.get("ok")):
        return {"ok": False, "reason": (r or {}).get("error", "query failed")}
    return {"ok": True, "matched": r.get("matched_documents", 0)}


def cross_siem_counts(rule: MigratedRule) -> list[tuple[str, int]]:
    """How many of the normalised SIEM-format indices this one rule hits -- the
    'Sigma rule + n_* normalisation = portable across every SIEM' payoff."""
    from mcp_server.tools import count_logs, list_log_types, LOG_INDEX_PREFIX
    if not rule.query_string:
        return []
    out: list[tuple[str, int]] = []
    for lt in list_log_types().get("log_types", []):
        schema = lt["index"].replace(LOG_INDEX_PREFIX, "")
        if schema not in SIEM_SCHEMAS:
            continue
        r = count_logs({"index": lt["index"], "query_string": rule.query_string})
        if isinstance(r, dict) and r.get("ok"):
            out.append((schema, r.get("matched_documents", 0)))
    return out


def run_demo(paths: list[str], use_llm: bool = False) -> None:
    from common.llm import LLMClient
    llm = LLMClient() if use_llm else None
    for path in paths:
        with open(path) as fh:
            text = fh.read()
        rule = migrate(text, use_llm=use_llm, llm=llm)
        print(f"\n=== {rule.title} ===")
        print(f"  status     : {rule.status}   ({', '.join(rule.notes) or 'clean'})")
        print(f"  att&ck     : {rule.mitre}  ({rule.technique})   severity={rule.severity}")
        print(f"  field map  : " + (", ".join(f"{k}->{v}" for k, v in rule.field_map.items()) or "(none)"))
        print(f"  query (n_*): {rule.query_string or '-- not translated --'}")
        if rule.query_string:
            v = validate(rule)
            print(f"  validate   : ok={v['ok']} matched={v.get('matched', '-')}")
            siem = cross_siem_counts(rule)
            if siem:
                total = sum(n for _, n in siem)
                hit = ", ".join(f"{s}={n}" for s, n in siem)
                print(f"  cross-SIEM : one rule hit {total} docs across {len(siem)} SIEM formats -> {hit}")
