"""Crash-safe ingestion cursor and dedupe state."""

from __future__ import annotations

import json
import os
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


STATE_VERSION = 1


class StateError(RuntimeError):
    pass


def _atomic_json_write(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".life-iq-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, str(path))
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


class IngestState:
    """Persist only cursors, safe statuses, and content hashes.

    Source bodies and credentials are intentionally absent from this file.
    ``copy`` is used by the pipeline so a failed artifact write does not move
    a cursor forward.
    """

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        self.data: Dict[str, Any] = data or {
            "version": STATE_VERSION,
            "sources": {},
            "processed_hashes": [],
        }
        self._normalize()

    def _normalize(self) -> None:
        if not isinstance(self.data, dict):
            raise StateError("state must be a JSON object")
        self.data.setdefault("version", STATE_VERSION)
        self.data.setdefault("sources", {})
        self.data.setdefault("processed_hashes", [])
        if not isinstance(self.data["sources"], dict) or not isinstance(self.data["processed_hashes"], list):
            raise StateError("state has invalid sources or processed_hashes")

    @classmethod
    def load(cls, path: Path) -> "IngestState":
        path = Path(path)
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StateError("cannot read ingest state: %s" % exc)
        return cls(data)

    def copy(self) -> "IngestState":
        return IngestState(deepcopy(self.data))

    @property
    def processed_hashes(self):
        return set(str(item) for item in self.data.get("processed_hashes", []))

    def cursor(self, source: str) -> Optional[str]:
        record = self.data["sources"].get(source, {})
        return record.get("cursor") if isinstance(record, dict) else None

    def record_success(self, source: str, cursor: Optional[str], *, observed_at: Optional[datetime] = None, item_count: int = 0) -> None:
        timestamp = observed_at or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        self.data["sources"][source] = {
            "cursor": cursor,
            "last_success_at": timestamp.astimezone(timezone.utc).isoformat(),
            "status": "success",
            "item_count": int(item_count),
        }

    def record_status(self, source: str, status: str, diagnostic: str = "") -> None:
        record = dict(self.data["sources"].get(source, {}))
        record.update({"status": status, "diagnostic": str(diagnostic)[:300]})
        self.data["sources"][source] = record

    def add_hashes(self, hashes: Iterable[str]) -> None:
        existing = self.processed_hashes
        existing.update(str(item) for item in hashes if item)
        self.data["processed_hashes"] = sorted(existing)

    def save(self, path: Path) -> None:
        _atomic_json_write(Path(path), self.data)
