# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Common read-only adapter interfaces."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

from ..privacy import redact_mapping, safe_summary, sensitivity_for
from ..schema import NormalizedEvent, canonical_json, parse_datetime


MAX_CAPTURE_READ_BYTES = 16_000_000
MAX_CAPTURE_RECORDS = 20_000
MAX_CAPTURE_RECEIPT_AGE = timedelta(hours=48)


@dataclass(frozen=True)
class SourceWindow:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "start", parse_datetime(self.start))
        object.__setattr__(self, "end", parse_datetime(self.end))
        if self.end <= self.start:
            raise ValueError("source window end must be after start")


@dataclass
class SourceStatus:
    source: str
    status: str
    diagnostic: str = ""
    cursor: Optional[str] = None
    item_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status,
            "diagnostic": self.diagnostic[:300],
            "cursor": self.cursor,
            "item_count": self.item_count,
        }


@dataclass
class AdapterResult:
    events: List[NormalizedEvent] = field(default_factory=list)
    status: SourceStatus = field(default_factory=lambda: SourceStatus("unknown", "skipped"))


class SourceAdapter(Protocol):
    source: str

    def collect(self, window: SourceWindow, cursor: Optional[str] = None) -> AdapterResult:
        ...


def stable_ref(*parts: Any) -> str:
    """Hash a source reference without writing source paths/body text."""

    return hashlib.sha256(canonical_json(list(parts)).encode("utf-8")).hexdigest()[:24]


def in_window(timestamp: Any, window: SourceWindow) -> bool:
    try:
        parsed = parse_datetime(timestamp)
    except ValueError:
        return False
    return window.start <= parsed < window.end


def explicit_capture_flag(value: Any) -> bool:
    """Interpret capture booleans without treating arbitrary strings as true."""

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "y", "on"}
    return False


def any_capture_flag(record: Mapping[str, Any], keys: Iterable[str]) -> bool:
    return any(explicit_capture_flag(record.get(key)) for key in keys)


def _read_capture_payload(path: Path) -> Tuple[Optional[str], Optional[str], int, Optional[str]]:
    """Read one capture file with a hard cap while hashing the same bytes."""

    digest = hashlib.sha256()
    chunks: List[bytes] = []
    total_bytes = 0
    try:
        if not path.is_file():
            return None, None, 0, "capture path is not a file"
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_CAPTURE_READ_BYTES:
                    return None, None, total_bytes, "capture exceeds safe read limit"
                digest.update(chunk)
                chunks.append(chunk)
        raw = b"".join(chunks)
        return raw.decode("utf-8"), digest.hexdigest(), total_bytes, None
    except (OSError, UnicodeError) as exc:
        return None, None, total_bytes, "capture cannot be read: %s" % type(exc).__name__


def _parse_json_records(path: Path, text: str) -> Tuple[List[Mapping[str, Any]], Optional[str]]:
    if path.suffix.lower() == ".jsonl":
        records = []
        malformed = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if isinstance(value, Mapping):
                    records.append(value)
                else:
                    malformed += 1
            except ValueError:
                malformed += 1
        if len(records) > MAX_CAPTURE_RECORDS:
            return [], "capture exceeds safe record limit"
        return records, "ignored %d malformed capture line(s)" % malformed if malformed else None
    try:
        value = json.loads(text)
    except ValueError:
        return [], "capture is not valid JSON"
    if isinstance(value, Mapping):
        for key in ("records", "messages", "items", "events", "captures"):
            if isinstance(value.get(key), list):
                records = [item for item in value[key] if isinstance(item, Mapping)]
                if len(records) > MAX_CAPTURE_RECORDS:
                    return [], "capture exceeds safe record limit"
                return records, None
        return [value], None
    if isinstance(value, list):
        records = [item for item in value if isinstance(item, Mapping)]
        if len(records) > MAX_CAPTURE_RECORDS:
            return [], "capture exceeds safe record limit"
        return records, None
    return [], "capture JSON must contain an object or array"


def read_json_records(path: Optional[Path]) -> Tuple[List[Mapping[str, Any]], Optional[str]]:
    """Read JSON/JSONL capture records and return safe diagnostics only."""

    if path is None:
        return [], "capture path is not configured"
    path = Path(path)
    if not path.exists():
        return [], "capture path is unavailable"
    if path.is_dir():
        files = sorted(item for item in path.rglob("*") if item.suffix.lower() in (".json", ".jsonl"))
        records: List[Mapping[str, Any]] = []
        errors = 0
        total_bytes = 0
        for item in files:
            try:
                total_bytes += item.stat().st_size
            except OSError:
                return [], "capture directory cannot be inspected"
            if total_bytes > MAX_CAPTURE_READ_BYTES:
                return [], "capture directory exceeds safe read limit"
            loaded, diagnostic = read_json_records(item)
            records.extend(loaded)
            if len(records) > MAX_CAPTURE_RECORDS:
                return [], "capture directory exceeds safe record limit"
            errors += int(bool(diagnostic))
        return records, ("parsed %d capture file(s), %d malformed" % (len(files), errors)) if errors else None
    text, _, _, diagnostic = _read_capture_payload(path)
    if diagnostic:
        return [], diagnostic
    assert text is not None
    return _parse_json_records(path, text)


def read_json_records_with_fingerprint(
    path: Optional[Path],
) -> Tuple[List[Mapping[str, Any]], Optional[str], Optional[str], int]:
    """Read a file once and return records plus the fingerprint of those bytes."""

    if path is None:
        return [], "capture path is not configured", None, 0
    path = Path(path)
    if not path.exists():
        return [], "capture path is unavailable", None, 0
    if path.is_dir():
        records, diagnostic = read_json_records(path)
        return records, diagnostic, None, 0
    text, digest, size, diagnostic = _read_capture_payload(path)
    if diagnostic:
        return [], diagnostic, None, size
    assert text is not None
    records, parse_diagnostic = _parse_json_records(path, text)
    return records, parse_diagnostic, digest, size
    if path.suffix.lower() == ".jsonl":
        records = []
        malformed = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if isinstance(value, Mapping):
                    records.append(value)
                else:
                    malformed += 1
            except ValueError:
                malformed += 1
        if len(records) > MAX_CAPTURE_RECORDS:
            return [], "capture exceeds safe record limit"
        return records, "ignored %d malformed capture line(s)" % malformed if malformed else None
    try:
        value = json.loads(text)
    except ValueError:
        return [], "capture is not valid JSON"
    if isinstance(value, Mapping):
        for key in ("records", "messages", "items", "events", "captures"):
            if isinstance(value.get(key), list):
                records = [item for item in value[key] if isinstance(item, Mapping)]
                if len(records) > MAX_CAPTURE_RECORDS:
                    return [], "capture exceeds safe record limit"
                return records, None
        return [value], None
    if isinstance(value, list):
        records = [item for item in value if isinstance(item, Mapping)]
        if len(records) > MAX_CAPTURE_RECORDS:
            return [], "capture exceeds safe record limit"
        return records, None
    return [], "capture JSON must contain an object or array"


def capture_receipt_path(path: Optional[Path]) -> Optional[Path]:
    if path is None:
        return None
    value = Path(path)
    return value.with_name(value.name + ".receipt.json")


def read_capture_receipt(path: Optional[Path]) -> Optional[Mapping[str, Any]]:
    receipt = capture_receipt_path(path)
    if receipt is None or not receipt.exists():
        return None
    try:
        value = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    return value if isinstance(value, Mapping) else None


def _capture_sha256(path: Path) -> Tuple[Optional[str], int]:
    if not path.exists():
        return None, 0
    try:
        size = path.stat().st_size
        if size > MAX_CAPTURE_READ_BYTES or not path.is_file():
            return None, size
        digest = hashlib.sha256()
        read_bytes = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                read_bytes += len(chunk)
                if read_bytes > MAX_CAPTURE_READ_BYTES:
                    return None, read_bytes
                digest.update(chunk)
        size = read_bytes
    except OSError:
        return None, 0
    return digest.hexdigest(), size


def capture_receipt_status(
    path: Optional[Path],
    source: str,
    *,
    fingerprint: Optional[Tuple[Optional[str], int]] = None,
) -> Optional[SourceStatus]:
    """Require a fresh bridge outcome before treating a live capture as usable."""

    if path is None:
        return None
    receipt = read_capture_receipt(path)
    if receipt is None:
        return SourceStatus(source, "skipped", "capture receipt unavailable; re-import through capture bridge")
    outcome = str(receipt.get("outcome") or "").casefold()
    completed_at = str(receipt.get("completed_at") or "") or None
    diagnostic = str((receipt.get("diagnostics") or [""])[0] or "")[:240]
    try:
        completed = parse_datetime(completed_at)
    except (TypeError, ValueError):
        return SourceStatus(source, "failed", "capture receipt timestamp is invalid", completed_at, 0)
    age = datetime.now(timezone.utc) - completed
    if age < timedelta(minutes=-5) or age > MAX_CAPTURE_RECEIPT_AGE:
        return SourceStatus(source, "skipped", "capture receipt is stale; re-import through capture bridge", completed_at, 0)
    try:
        receipt_path = Path(str(receipt.get("capture_path") or "")).expanduser().resolve()
        expected_path = Path(path).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return SourceStatus(source, "failed", "capture receipt path is invalid", completed_at, 0)
    if receipt_path != expected_path:
        return SourceStatus(source, "failed", "capture receipt path mismatch", completed_at, 0)
    if str(receipt.get("source") or "").strip().casefold() != str(source).strip().casefold():
        return SourceStatus(source, "failed", "capture receipt source mismatch", completed_at, 0)
    if outcome in ("success", "verified_empty"):
        if receipt.get("version") != 2:
            return SourceStatus(source, "failed", "capture receipt lacks content binding; re-import through capture bridge", completed_at, 0)
        recorded_bytes = receipt.get("capture_bytes")
        if not isinstance(recorded_bytes, int) or isinstance(recorded_bytes, bool) or recorded_bytes < 0:
            return SourceStatus(source, "failed", "capture receipt size is invalid", completed_at, 0)
        current_hash, current_bytes = fingerprint if fingerprint is not None else _capture_sha256(expected_path)
        recorded_hash = receipt.get("capture_sha256")
        if outcome == "success":
            if not recorded_hash or current_hash != recorded_hash or current_bytes != recorded_bytes:
                return SourceStatus(source, "failed", "capture receipt content mismatch; re-import through capture bridge", completed_at, 0)
        elif current_hash is not None or current_bytes != recorded_bytes:
            return SourceStatus(source, "failed", "verified-empty capture is not empty", completed_at, 0)
    if outcome == "success":
        return None
    if outcome == "verified_empty":
        return SourceStatus(source, "success", "capture verified empty", completed_at, 0)
    if outcome == "unavailable":
        return SourceStatus(source, "skipped", "capture unavailable" + ((": " + diagnostic) if diagnostic else ""), completed_at, 0)
    if outcome in ("rejected", "failed"):
        return SourceStatus(source, "failed", "capture import " + outcome + ((": " + diagnostic) if diagnostic else ""), completed_at, 0)
    return SourceStatus(source, "failed", "unknown capture receipt outcome", completed_at, 0)


def make_event(
    *,
    source: str,
    source_ref: str,
    timestamp: Any,
    event_type: str,
    summary_parts: Iterable[Any],
    entities: Iterable[Any] = (),
    status: str = "observed",
    confidence: float = 0.5,
    metadata: Optional[Mapping[str, Any]] = None,
) -> NormalizedEvent:
    safe_metadata = redact_mapping(dict(metadata or {}))
    summary = safe_summary(*summary_parts)
    sensitivity = sensitivity_for(summary + " " + json.dumps(safe_metadata, ensure_ascii=False, default=str))
    return NormalizedEvent.build(
        source=source,
        source_ref=source_ref,
        occurred_at=timestamp,
        event_type=event_type,
        summary=summary,
        entities=[safe_summary(entity, max_chars=100) for entity in entities if entity],
        status=status,
        confidence=confidence,
        sensitivity=sensitivity,
        metadata=safe_metadata,
    )
