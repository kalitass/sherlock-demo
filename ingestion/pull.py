"""PULL ingestion: watch a drop directory; any file placed there is picked up,
auto-schema'd, ingested, and moved to a processed/ subfolder.

  uv run python -m ingestion.pull           # watch settings.drop_dir
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path

from watchfiles import watch

from common.settings import settings
from ingestion.ingest_core import ingest_file


def process_existing(drop: Path) -> None:
    for f in sorted(drop.glob("*")):
        if f.is_file():
            _handle(f)


def _stable(path: Path, tries: int = 6) -> bool:
    """Return True only once the file size holds steady across two reads, so we
    never ingest a partial write. A file that keeps growing returns False."""
    last = -1
    for _ in range(tries):
        try:
            size = path.stat().st_size
        except OSError:
            return False
        if size == last and size > 0:
            return True
        last = size
        time.sleep(0.3)
    return False


def _handle(path: Path) -> None:
    if not path.is_file() or path.parent.name in ("processed", "failed"):
        return
    if not _stable(path):
        print(f"[pull] {path.name}: still being written, skipping this event")
        return
    try:
        summary = ingest_file(path, mode="pull")
        dest_name = "processed" if summary.get("ok") else "failed"
        print(f"[pull] {path.name}: ok={summary.get('ok')} indexed={summary['count_indexed']} "
              f"failures={summary.get('failures')} type={summary['log_type']} -> {dest_name}/")
        dest = path.parent / dest_name
        dest.mkdir(exist_ok=True)
        shutil.move(str(path), str(dest / path.name))
    except Exception as e:
        print(f"[pull] error on {path.name}: {e}")


def main() -> None:
    drop = settings.drop_dir
    drop.mkdir(parents=True, exist_ok=True)
    print(f"[pull] watching {drop} — drop log files here to ingest")
    process_existing(drop)
    for changes in watch(drop):
        for _, p in changes:
            path = Path(p)
            if path.is_file():
                time.sleep(0.2)  # let the writer finish
                _handle(path)


if __name__ == "__main__":
    main()
