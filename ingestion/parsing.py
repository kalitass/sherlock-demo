"""Apply a registered schema to a raw record -> normalised document.

Pure and tiny so it is trivially testable and identical across all three
ingestion paths (pull / push / stream). Regex parsers must match the WHOLE line
(fullmatch), so a parser that only skims a prefix does not count as a parse.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from dateutil import parser as dtparser

_CLF_STRPTIME = "%d/%b/%Y:%H:%M:%S %z"


def normalise_ts(value: Any, fmt: str = "auto") -> str | None:
    if value is None:
        return None

    # Epoch seconds / milliseconds.
    if fmt in ("epoch", "epoch_ms") or (fmt == "auto" and isinstance(value, (int, float))) \
            or (fmt == "auto" and isinstance(value, str) and value.strip().isdigit()):
        try:
            n = float(value)
            if fmt == "epoch_ms" or n > 1e12:  # ms
                n /= 1000.0
            dt = datetime.fromtimestamp(n, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except (ValueError, OverflowError, OSError):
            return None

    s = str(value).strip().strip("[]")
    try:
        if fmt == "clf":
            dt = datetime.strptime(s, _CLF_STRPTIME)
        else:
            try:
                dt = dtparser.isoparse(s)
            except Exception:
                dt = dtparser.parse(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        return None


def _unescape_cef(v: str) -> str:
    out, esc = [], False
    for ch in v:
        if esc:
            out.append({"n": "\n", "r": "\r"}.get(ch, ch))
            esc = False
        elif ch == "\\":
            esc = True
        else:
            out.append(ch)
    if esc:
        out.append("\\")
    return "".join(out)


def _split_escaped(s: str, sep: str, maxsplit: int) -> list[str]:
    """Split on an UNescaped `sep`, counting backslashes so a literal `\\` before a
    separator (an escaped backslash) still splits there."""
    out, buf, esc, n = [], [], False, 0
    for ch in s:
        if esc:
            buf.append(ch); esc = False
        elif ch == "\\":
            buf.append(ch); esc = True
        elif ch == sep and (maxsplit < 0 or n < maxsplit):
            out.append("".join(buf)); buf = []; n += 1
        else:
            buf.append(ch)
    out.append("".join(buf))
    return out


def _parse_cef(line: str) -> dict[str, Any] | None:
    """ArcSight CEF: 'CEF:ver|vendor|product|devver|sigID|name|sev|ext' (Week 2,
    slide 29). Tolerates a syslog prefix, escaped pipes/equals/backslashes in the
    header, and spaces inside extension values (a new key begins only at an
    unescaped ' key=')."""
    s = str(line)
    i = s.find("CEF:")
    if i < 0:
        return None
    parts = _split_escaped(s[i + 4:], "|", 7)          # ver|vendor|product|devver|sig|name|sev|ext
    if len(parts) < 8:
        return None
    ver, vendor, product, devver, sig, name, sev = (_unescape_cef(p) for p in parts[:7])
    ext = parts[7]
    doc: dict[str, Any] = {"cef_version": ver, "cef_vendor": vendor, "cef_product": product,
                           "cef_device_version": devver, "cef_sig_id": sig, "name": name, "sev": sev}
    doc.update(_cef_extension(ext))
    return doc


def _cef_extension(ext: str) -> dict[str, str]:
    """Split a CEF extension into key=value tokens: a new key starts at an unescaped
    space that is immediately followed by `<word>=`. Values may contain spaces and
    escaped characters (including a trailing backslash)."""
    tokens, buf, esc, i, n = [], [], False, 0, len(ext)
    while i < n:
        ch = ext[i]
        if esc:
            buf.append(ch); esc = False
        elif ch == "\\":
            buf.append(ch); esc = True
        elif ch == " " and re.match(r"[\w.]+=", ext[i + 1:]):
            tokens.append("".join(buf)); buf = []
        else:
            buf.append(ch)
        i += 1
    tokens.append("".join(buf))
    out: dict[str, str] = {}
    for t in tokens:
        k, sep, v = t.partition("=")
        if sep and k.strip():
            out[k.strip()] = _unescape_cef(v)
    return out


def _leef_delim(token: str) -> str | None:
    """Decode a LEEF 2.0 delimiter header field: 'xNN'/'0xNN' (1-4 hex) -> that char,
    or a literal single character."""
    t = token.strip()
    if not t:
        return None
    m = re.fullmatch(r"(?:0x|x)([0-9A-Fa-f]{1,4})", t)
    if m:
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return None
    return t if len(t) == 1 else None


def _parse_leef(line: str) -> dict[str, Any] | None:
    """IBM QRadar LEEF 2.0: 'LEEF:2.0|vendor|product|version|EventID|[delimiter|]ext'.
    Honours the optional delimiter header (default tab) and a syslog prefix."""
    s = str(line)
    i = s.find("LEEF:")
    if i < 0:
        return None
    body = s[i + 5:]                                   # after 'LEEF:'
    fields = body.split("|")
    if len(fields) < 6:
        return None
    ver, vendor, product, version, event_id = fields[:5]
    delim = _leef_delim(fields[5]) if len(fields) >= 7 else None
    ext = "|".join(fields[6:]) if delim is not None else "|".join(fields[5:])
    if delim is None:
        delim = "\t"
    doc: dict[str, Any] = {"leef_version": ver, "leef_vendor": vendor, "leef_product": product,
                           "leef_device_version": version, "EventID": event_id}
    for tok in ext.split(delim):
        k, sep2, v = tok.partition("=")
        if sep2 and k.strip():
            doc[k.strip()] = v.strip()
    return doc


def parse_record(schema: dict[str, Any], raw: Any) -> dict[str, Any] | None:
    kind = schema.get("parser", {}).get("kind", "json")
    ts_field = schema.get("ts_field", "@timestamp")
    ts_format = schema.get("ts_format", "auto")

    if kind == "json":
        doc = raw if isinstance(raw, dict) else _load_json(raw)
        if doc is None:
            return None
        doc = dict(doc)
    elif kind in ("cef", "leef"):                      # producer wire formats (deterministic)
        doc = _parse_cef(str(raw)) if kind == "cef" else _parse_leef(str(raw))
        if doc is None:
            return None
    else:  # regex -- must match the whole line
        pattern = schema["parser"]["pattern"]
        try:
            m = re.fullmatch(pattern, str(raw))
        except re.error:
            return None
        if not m:
            return None
        doc = {k: v for k, v in m.groupdict().items() if v is not None}
        for k in ("status", "size", "bytes", "response_bytes"):
            if k in doc and str(doc[k]).isdigit():
                doc[k] = int(doc[k])

    ts_raw = doc.get(ts_field)
    used_field = ts_field
    if ts_raw is None and schema.get("ts_fallback"):     # e.g. CEF: prefer `start`, fall back to `rt`
        used_field = schema["ts_fallback"]
        ts_raw = doc.get(used_field)
    ts = normalise_ts(ts_raw, ts_format)
    if ts is None:
        return None
    doc["@timestamp"] = ts
    if used_field != "@timestamp":
        doc.pop(used_field, None)
    doc["log_type"] = schema["log_type"]
    return doc


def _load_json(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else None
    except Exception:
        return None
