"""STREAM ingestion: consume a continuous syslog-style feed over UDP.

Lines are buffered and flushed to Elasticsearch in small batches as they arrive,
which is how a syslog relay or message-queue tap would feed the SIEM live.

  uv run python -m ingestion.stream                 # listen (UDP :5514)
  uv run python -m ingestion.stream --send FILE     # replay FILE as a stream

Each UDP datagram is one record. JSON datagrams are ingested as structured
records; plain-text datagrams (e.g. web access lines) are ingested as text.
"""
from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path

from common.settings import settings
from ingestion.ingest_core import ingest_records

FLUSH_EVERY = 200
FLUSH_SECONDS = 2.0


def _log_type_of(line: str) -> str:
    try:
        d = json.loads(line)
        if isinstance(d, dict):
            if "query_name" in d or "process_guid" in d or "parent_image" in d:
                return "sysmon"
            if "event_id" in d or "channel" in d:
                return "windows"
    except Exception:
        pass
    return "web"


def listen() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", settings.stream_syslog_port))
    sock.settimeout(FLUSH_SECONDS)
    print(f"[stream] listening UDP :{settings.stream_syslog_port}")
    buckets: dict[str, list] = {}
    last = time.time()

    def flush():
        nonlocal buckets
        for lt, lines in buckets.items():
            if not lines:
                continue
            try:
                s = ingest_records(lt, lines, source="stream:syslog", mode="stream",
                                   refresh=True, use_llm=False)
                print(f"[stream] flushed {s['count_indexed']} {lt} records (ok={s.get('ok')})")
            except Exception as e:      # one bad bucket must not kill the listener
                print(f"[stream] flush error for {lt}: {e}")
        buckets = {}

    import signal
    def _final(*_):
        print("[stream] shutting down; final flush")
        flush()
        raise SystemExit(0)
    signal.signal(signal.SIGINT, _final)
    signal.signal(signal.SIGTERM, _final)

    while True:
        try:
            data, _ = sock.recvfrom(65535)
            line = data.decode("utf-8", "replace").strip()
            if line:
                buckets.setdefault(_log_type_of(line), []).append(line)
        except socket.timeout:
            pass
        total = sum(len(v) for v in buckets.values())
        if total >= FLUSH_EVERY or (total and time.time() - last > FLUSH_SECONDS):
            flush()
            last = time.time()


def send(path: str, rate: int = 500) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = ("127.0.0.1", settings.stream_syslog_port)
    lines = Path(path).read_text(errors="replace").splitlines()
    print(f"[stream] replaying {len(lines)} lines from {path} at ~{rate}/s")
    for i, ln in enumerate(lines):
        if ln.strip():
            sock.sendto(ln.encode("utf-8"), addr)
        if rate and i % rate == 0:
            time.sleep(1.0)
    print("[stream] done sending")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", help="replay a file over the stream instead of listening")
    ap.add_argument("--rate", type=int, default=500)
    args = ap.parse_args()
    if args.send:
        send(args.send, args.rate)
    else:
        listen()


if __name__ == "__main__":
    main()
