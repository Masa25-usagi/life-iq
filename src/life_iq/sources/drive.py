# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Google Drive for Desktop sync-folder adapter."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional

from .base import AdapterResult, SourceStatus, SourceWindow, make_event
from ..privacy import redact_text


TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".csv", ".json", ".yaml", ".yml", ".toml", ".rtf"}


def _safe_excerpt(path: Path) -> str:
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    # Only a short excerpt is ever placed in a normalized event.
    return redact_text(" ".join(text.split())[:300], max_chars=300)


class DriveAdapter:
    source = "drive"

    def __init__(self, path: Optional[Path] = None, *, output_root: Optional[Path] = None) -> None:
        self.path = Path(path) if path else None
        self.output_root = Path(output_root).resolve() if output_root else None

    def _excluded(self, item: Path) -> bool:
        if any(part.startswith(".") for part in item.relative_to(self.path).parts):
            return True
        relative = item.relative_to(self.path).as_posix()
        if relative == "IMPORTANT_CONTEXT.md" or relative.startswith("knowledge/") or relative.startswith("state/"):
            return True
        if self.output_root:
            try:
                item.resolve().relative_to(self.output_root)
                return True
            except ValueError:
                pass
        return False

    def collect(self, window: SourceWindow, cursor: Optional[str] = None) -> AdapterResult:
        if self.path is None:
            return AdapterResult(status=SourceStatus(self.source, "needs_setup", "Google Drive sync folder is not configured"))
        if not self.path.exists() or not self.path.is_dir():
            return AdapterResult(status=SourceStatus(self.source, "needs_setup", "Google Drive sync folder is unavailable"))
        events = []
        latest = cursor
        for item in sorted(self.path.rglob("*")):
            if not item.is_file() or self._excluded(item):
                continue
            try:
                stat = item.stat()
                modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if not (window.start <= modified < window.end):
                continue
            relative = item.relative_to(self.path).as_posix()
            file_id = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:20]
            source_ref = "%s@%d" % (file_id, stat.st_mtime_ns)
            excerpt = _safe_excerpt(item)
            event_type = "file_created" if stat.st_ctime >= stat.st_mtime - 1 else "file_updated"
            summary = "%s%s" % (redact_text(relative, max_chars=220), " — " + excerpt if excerpt else "")
            latest = max(latest or "", modified.isoformat())
            events.append(
                make_event(
                    source=self.source,
                    source_ref=source_ref,
                    timestamp=modified,
                    event_type=event_type,
                    summary_parts=(summary,),
                    entities=("file:" + redact_text(relative, max_chars=120),),
                    confidence=0.75,
                    metadata={"relative_path": relative, "size": stat.st_size, "extension": item.suffix.lower()},
                )
            )
        return AdapterResult(events=events, status=SourceStatus(self.source, "success", "read-only sync-folder metadata", latest, len(events)))
