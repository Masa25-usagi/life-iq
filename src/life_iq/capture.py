# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

"""Safe local capture bridge for browser/app acquisition records.

The bridge accepts records produced by an already-running app/browser or by a
Screenpipe/Vision OCR helper.  It never opens a UI, logs in, navigates a
conversation, or performs an external action.  The bounded acquisition layer
may open LINE ordinary 1:1 chats or group chats with a visible direct mention
under the runbook; that layer must pass only already-visible records here.
Records are validated, redacted, bounded,
filtered, hash-deduplicated, and atomically rewritten to a per-source JSONL
file before an adapter can consume them.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from .privacy import contains_sensitive, redact_text
from .schema import canonical_json, parse_datetime
from .sources.line import is_excluded_line_conversation


# Screenpipe is a local read-only capture source.  It uses the same bridge as
# browser/app captures so its OCR or activity-summary output receives the
# source-spoof, secret-redaction, bounds, dedupe, and atomic-write checks before
# the Screenpipe adapter can consume it.
CAPTURE_SOURCES = ("line", "slack", "x", "discord", "screenpipe")
MAX_CAPTURE_TEXT_CHARS = 1200
MAX_TEXT_CHARS = MAX_CAPTURE_TEXT_CHARS

_SOURCE_ALIASES = {
    "line": "line",
    "line_app": "line",
    "line_browser": "line",
    "slack": "slack",
    "slack_browser": "slack",
    "x": "x",
    "twitter": "x",
    "twitter_browser": "x",
    "discord": "discord",
    "discord_app": "discord",
    "discord_browser": "discord",
    "screenpipe": "screenpipe",
    "screenpipe_app": "screenpipe",
}
_SOURCE_KEYS = ("source", "source_name", "capture_source", "origin_source", "__capture_envelope_source")
_TIMESTAMP_KEYS = ("occurred_at", "timestamp", "created_at", "time", "date")
_BODY_KEYS = (
    "text",
    "message",
    "body",
    "content",
    "ocr_text",
    "transcript",
    "notification_text",
    "tweet_text",
    "snippet",
)
_IDENTITY_KEYS = (
    "id",
    "message_id",
    "event_id",
    "frame_id",
    "chunk_id",
    "post_id",
    "tweet_id",
    "notification_id",
)
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|[_-])(?:password|passwd|passphrase|token|secret|api[_ -]?key|access[_ -]?key|"
    r"refresh[_ -]?token|authorization|credential|auth(?:entication)?(?:[_ -]?(?:code|token))?|otp|"
    r"cookie|session|client[_ -]?secret|oauth(?:[_ -]?(?:code|token|state))?|verification[_ -]?code)(?:$|[_-])"
)
_URL_KEY_RE = re.compile(r"(?i)(?:url|uri|href|link)")
_URL_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|code|state|secret|key|auth|session|sig|signature|password)=)[^&#\s]+"
)
_SERVICE_FIELDS = ("app", "application", "site", "provider", "url", "page_url", "browser_url")
_SERVICE_FIELDS = _SERVICE_FIELDS + ("workspace_url", "team_url")
MAX_CAPTURE_INPUT_BYTES = 2_000_000
MAX_CAPTURE_RECORD_BYTES = 64_000
MAX_CAPTURE_FIELDS = 128
MAX_CAPTURE_LIST_ITEMS = 256
MAX_CAPTURE_NESTING = 8
MAX_CAPTURE_INPUT_RECORDS = 256
MAX_CAPTURE_STORE_BYTES = 8_000_000
MAX_CAPTURE_STORE_RECORDS = 20_000


class CaptureImportError(ValueError):
    """Raised when a capture source or input cannot be handled safely."""


class _RejectedRecord(ValueError):
    pass


class _ExcludedRecord(ValueError):
    pass


def normalize_capture_source(source: Any) -> str:
    value = str(source or "").strip().casefold().replace("-", "_").replace(" ", "_")
    normalized = _SOURCE_ALIASES.get(value)
    if not normalized:
        raise CaptureImportError("unsupported capture source")
    return normalized


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _safe_text(value: Any) -> str:
    if contains_sensitive(value):
        return "[REDACTED]"
    text = redact_text(value, max_chars=MAX_CAPTURE_TEXT_CHARS)
    return _URL_SECRET_RE.sub(r"\1[REDACTED]", text)


def _safe_url(value: Any) -> str:
    text = _safe_text(value)
    try:
        parsed = urlsplit(text)
        if not parsed.scheme or not parsed.netloc:
            return text
        # Keep only the origin/path. Query and fragment are common locations
        # for OAuth codes, state, sessions, and tracking identifiers.
        host = parsed.hostname or ""
        if parsed.port:
            host += ":%d" % parsed.port
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except (TypeError, ValueError):
        return text


def _is_secret_key(key: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key)).casefold()
    return bool(_SECRET_KEY_RE.search(normalized))


def _sanitize_value(value: Any, *, key: str = "") -> Any:
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for raw_key, raw_item in value.items():
            key_text = str(raw_key)
            if _is_secret_key(key_text):
                # Secrets are omitted, rather than retained as a placeholder
                # in the capture store.  Diagnostics never include this key.
                continue
            if _URL_KEY_RE.search(key_text):
                result[key_text] = _safe_url(raw_item)
            else:
                result[key_text] = _sanitize_value(raw_item, key=key_text)
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item, key=key) for item in value]
    if isinstance(value, str):
        return _safe_url(value) if _URL_KEY_RE.search(key) else _safe_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _safe_text(value)


def _validate_capture_shape(value: Any, *, depth: int = 0, field_count: Optional[List[int]] = None) -> None:
    """Reject oversized or unexpectedly deep capture structures before storage."""

    counters = field_count if field_count is not None else [0]
    if depth > MAX_CAPTURE_NESTING:
        raise _RejectedRecord("capture nesting exceeds limit")
    if isinstance(value, Mapping):
        if len(value) > MAX_CAPTURE_FIELDS:
            raise _RejectedRecord("capture field count exceeds limit")
        counters[0] += len(value)
        if counters[0] > MAX_CAPTURE_FIELDS:
            raise _RejectedRecord("capture field count exceeds limit")
        for key, item in value.items():
            if len(str(key)) > 160:
                raise _RejectedRecord("capture field name exceeds limit")
            _validate_capture_shape(item, depth=depth + 1, field_count=counters)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_CAPTURE_LIST_ITEMS:
            raise _RejectedRecord("capture list length exceeds limit")
        for item in value:
            _validate_capture_shape(item, depth=depth + 1, field_count=counters)
    try:
        encoded = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise _RejectedRecord("capture is not JSON-compatible")
    if len(encoded) > MAX_CAPTURE_RECORD_BYTES:
        raise _RejectedRecord("capture record exceeds size limit")


def _record_timestamp(record: Mapping[str, Any], fallback: datetime) -> datetime:
    for key in _TIMESTAMP_KEYS:
        value = record.get(key)
        if value not in (None, ""):
            try:
                return parse_datetime(value)
            except (TypeError, ValueError):
                raise _RejectedRecord("invalid timestamp")
    return fallback


def _record_identity(record: Mapping[str, Any]) -> str:
    for key in _IDENTITY_KEYS:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _record_body(record: Mapping[str, Any]) -> str:
    values = []
    for key in _BODY_KEYS:
        value = record.get(key)
        if value not in (None, ""):
            values.append(str(value))
    return " ".join(values).strip()


def _dedupe_hash(source: str, record: Mapping[str, Any]) -> str:
    payload = dict(record)
    for key in ("capture_hash", "captured_at", "imported_at"):
        payload.pop(key, None)
    if payload.get("timestamp_source") == "capture":
        payload.pop("occurred_at", None)
    return hashlib.sha256((source + "\0" + canonical_json(payload)).encode("utf-8")).hexdigest()


def _source_matches(source: str, record: Mapping[str, Any]) -> bool:
    saw_marker = False
    for key in _SOURCE_KEYS:
        value = record.get(key)
        if value in (None, ""):
            continue
        saw_marker = True
        try:
            if normalize_capture_source(value) != source:
                return False
        except CaptureImportError:
            return False
    return saw_marker


def _service_from_field(value: Any, *, key: str = "") -> Optional[str]:
    """Identify an explicit service marker without guessing from generic Chrome."""

    text = str(value or "").strip().casefold()
    if not text:
        return None
    if key.casefold() in ("url", "page_url", "browser_url", "workspace_url", "team_url"):
        try:
            hostname = (urlsplit(text).hostname or "").casefold()
        except ValueError:
            hostname = ""
        if hostname == "slack.com" or hostname.endswith(".slack.com"):
            return "slack"
        if hostname == "discord.com" or hostname.endswith(".discord.com") or hostname == "discordapp.com":
            return "discord"
        if hostname in ("x.com", "twitter.com") or hostname.endswith(".twitter.com"):
            return "x"
        if hostname == "line.me" or hostname.endswith(".line.me"):
            return "line"
        return None
    if re.search(r"(?<![a-z0-9])line(?![a-z0-9.-])", text) or "ライン" in text:
        return "line"
    if re.search(r"(?<![a-z0-9])slack(?![a-z0-9.-])", text):
        return "slack"
    if re.search(r"(?<![a-z0-9])discord(?![a-z0-9.-])", text):
        return "discord"
    if re.search(r"(?<![a-z0-9])screenpipe(?![a-z0-9.-])", text):
        return "screenpipe"
    if re.search(r"(?<![a-z0-9])twitter(?![a-z0-9.-])", text) or re.search(r"(?<![a-z0-9])x\.com(?![a-z0-9.-])", text) or text in ("x", "twitter"):
        return "x"
    return None


def _capture_service_matches(source: str, record: Mapping[str, Any]) -> bool:
    for key in _SERVICE_FIELDS:
        marker = _service_from_field(record.get(key), key=key)
        if marker and marker != source:
            return False
    return True


def _decode_capture_text(text: str, suffix: str = "") -> Tuple[List[Mapping[str, Any]], int]:
    """Decode one JSON object/array or JSONL text without retaining bad data."""

    stripped = text.strip()
    if not stripped:
        return [], 0
    try:
        value = json.loads(stripped)
    except (TypeError, ValueError):
        value = None
    if isinstance(value, Mapping):
        for key in ("records", "messages", "items", "events", "captures", "data"):
            if isinstance(value.get(key), list):
                envelope_source = next((value.get(source_key) for source_key in _SOURCE_KEYS[:-1] if value.get(source_key) not in (None, "")), None)
                records = []
                for item in value[key]:
                    if isinstance(item, Mapping):
                        record = dict(item)
                        if envelope_source not in (None, ""):
                            record["__capture_envelope_source"] = envelope_source
                        records.append(record)
                return records, sum(1 for item in value[key] if not isinstance(item, Mapping))
        return [value], 0
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)], sum(
            1 for item in value if not isinstance(item, Mapping)
        )
    records: List[Mapping[str, Any]] = []
    malformed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (TypeError, ValueError):
            malformed += 1
            continue
        if isinstance(value, Mapping):
            records.append(value)
        else:
            malformed += 1
    return records, malformed


def _read_jsonl(path: Path) -> Tuple[List[Mapping[str, Any]], int, Optional[str], int]:
    if not path.exists():
        return [], 0, None, 0
    try:
        if path.stat().st_size > MAX_CAPTURE_STORE_BYTES:
            raise CaptureImportError("capture store exceeds retention size limit")
    except OSError as exc:
        raise CaptureImportError("cannot stat capture store: %s" % type(exc).__name__)
    try:
        digest = hashlib.sha256()
        chunks = []
        total_bytes = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_CAPTURE_STORE_BYTES:
                    raise CaptureImportError("capture store exceeds retention size limit")
                digest.update(chunk)
                chunks.append(chunk)
        raw = b"".join(chunks)
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise CaptureImportError("cannot read capture store: %s" % type(exc).__name__)
    records, malformed = _decode_capture_text(text, ".jsonl")
    if len(records) > MAX_CAPTURE_STORE_RECORDS:
        raise CaptureImportError("capture store exceeds retention record limit")
    return records, malformed, digest.hexdigest(), len(raw)


def _capture_fingerprint(path: Path) -> Tuple[Optional[str], int]:
    if not path.exists():
        return None, 0
    digest = hashlib.sha256()
    size = 0
    try:
        if path.stat().st_size > MAX_CAPTURE_STORE_BYTES or not path.is_file():
            return None, path.stat().st_size
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_CAPTURE_STORE_BYTES:
                    raise CaptureImportError("capture store exceeds retention size limit")
                digest.update(chunk)
    except (OSError, ValueError) as exc:
        raise CaptureImportError("cannot fingerprint capture store: %s" % type(exc).__name__)
    return digest.hexdigest(), size


def _atomic_jsonl_write(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".capture-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for record in records:
                json.dump(record, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _jsonl_size(records: Sequence[Mapping[str, Any]]) -> int:
    total = 0
    for record in records:
        total += len(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")) + 1
    return total


def _atomic_json_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".capture-receipt-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def _capture_lock(path: Path):
    """Serialize read/merge/replace for one source without changing data semantics."""

    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True)
class CaptureImportResult:
    source: str
    path: Path
    input_count: int = 0
    accepted_count: int = 0
    duplicate_count: int = 0
    rejected_count: int = 0
    excluded_count: int = 0
    existing_count: int = 0
    outcome: str = ""
    diagnostics: Tuple[str, ...] = field(default_factory=tuple)
    records: Tuple[Mapping[str, Any], ...] = field(default_factory=tuple, repr=False)

    @property
    def status(self) -> str:
        if self.accepted_count or self.duplicate_count:
            return "success"
        if self.rejected_count or self.excluded_count:
            return "rejected"
        if self.outcome:
            return self.outcome
        return "unavailable" if self.input_count == 0 else "skipped"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "path": str(self.path),
            "status": self.status,
            "outcome": self.outcome or self.status,
            "input_count": self.input_count,
            "accepted_count": self.accepted_count,
            "duplicate_count": self.duplicate_count,
            "rejected_count": self.rejected_count,
            "excluded_count": self.excluded_count,
            "existing_count": self.existing_count,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True)
class CaptureStatus:
    source: str
    path: Path
    exists: bool
    bytes: int = 0
    records: int = 0
    malformed_lines: int = 0
    latest_occurred_at: Optional[str] = None
    receipt_status: Optional[str] = None
    receipt_completed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "path": str(self.path),
            "exists": self.exists,
            "bytes": self.bytes,
            "records": self.records,
            "malformed_lines": self.malformed_lines,
            "latest_occurred_at": self.latest_occurred_at,
            "receipt_status": self.receipt_status,
            "receipt_completed_at": self.receipt_completed_at,
        }


class CaptureBridge:
    """Validate and atomically append safe records to per-source live JSONL."""

    def __init__(self, root: Path, paths: Optional[Mapping[str, Path]] = None) -> None:
        self.root = Path(root).expanduser().resolve()
        configured = dict(paths or {})
        self.paths: Dict[str, Path] = {}
        for source in CAPTURE_SOURCES:
            value = configured.get(source)
            if value:
                path = Path(value).expanduser()
                if not path.is_absolute():
                    path = self.root / path
                self.paths[source] = path
            else:
                self.paths[source] = self.root / "captures" / source / "live.jsonl"

    def path_for(self, source: str) -> Path:
        return self.paths[normalize_capture_source(source)]

    def receipt_path_for(self, source: str) -> Path:
        path = self.path_for(source)
        return path.with_name(path.name + ".receipt.json")

    def _write_receipt(
        self,
        source: str,
        path: Path,
        *,
        attempt_id: str,
        started_at: datetime,
        outcome: str,
        input_count: int = 0,
        accepted_count: int = 0,
        duplicate_count: int = 0,
        rejected_count: int = 0,
        excluded_count: int = 0,
        existing_count: int = 0,
        diagnostics: Sequence[str] = (),
        capture_sha256: Optional[str] = None,
        capture_bytes: Optional[int] = None,
    ) -> None:
        completed_at = datetime.now(timezone.utc)
        if capture_bytes is None:
            capture_sha256, capture_bytes = _capture_fingerprint(path)
        _atomic_json_write(
            self.receipt_path_for(source),
            {
                "version": 2,
                "attempt_id": attempt_id,
                "source": source,
                "capture_path": str(path.resolve()),
                "capture_sha256": capture_sha256,
                "capture_bytes": capture_bytes,
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "outcome": outcome,
                "input_count": input_count,
                "accepted_count": accepted_count,
                "duplicate_count": duplicate_count,
                "rejected_count": rejected_count,
                "excluded_count": excluded_count,
                "existing_count": existing_count,
                "diagnostics": [redact_text(item, max_chars=180) for item in diagnostics[:8]],
            },
        )

    def _prepare_record(self, source: str, record: Mapping[str, Any], captured_at: datetime) -> Dict[str, Any]:
        if not isinstance(record, Mapping):
            raise _RejectedRecord("record is not an object")
        record_value = dict(record)
        _validate_capture_shape(record_value)
        if not _source_matches(source, record_value):
            raise _RejectedRecord("source mismatch")
        record_value.pop("__capture_envelope_source", None)
        if not _capture_service_matches(source, record_value):
            raise _RejectedRecord("capture service mismatch")
        if any(_truthy(record_value.get(key)) for key in ("auto_traversed", "opened_unread", "adapter_action")):
            raise _RejectedRecord("unsafe traversal marker")
        if not any(
            record_value.get(key) not in (None, "", [], {})
            for key in _TIMESTAMP_KEYS + _IDENTITY_KEYS + _BODY_KEYS + ("observations", "elements")
        ):
            raise _RejectedRecord("record lacks timestamp or content")
        if source == "line" and is_excluded_line_conversation(record_value):
            raise _ExcludedRecord("LINE account/conversation excluded")
        has_source_timestamp = any(record_value.get(key) not in (None, "") for key in _TIMESTAMP_KEYS)
        occurred = _record_timestamp(record_value, captured_at)
        safe = _sanitize_value(record_value)
        if not isinstance(safe, MutableMapping):
            raise _RejectedRecord("record cannot be sanitized")
        safe["source"] = source
        safe["occurred_at"] = occurred.isoformat()
        safe.setdefault("captured_at", captured_at.isoformat())
        if not has_source_timestamp:
            safe["timestamp_source"] = "capture"
        # Make the bounded body guarantee explicit for consumers and tests.
        for key in _BODY_KEYS:
            if key in safe and safe[key] not in (None, ""):
                safe[key] = _safe_text(safe[key])
        safe["capture_hash"] = _dedupe_hash(source, safe)
        return dict(safe)

    def _read_receipt_payload(self, source: str) -> Optional[Mapping[str, Any]]:
        receipt_path = self.receipt_path_for(source)
        if not receipt_path.exists():
            return None
        try:
            value = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise CaptureImportError("capture receipt is invalid: %s" % type(exc).__name__)
        if not isinstance(value, Mapping):
            raise CaptureImportError("capture receipt is invalid")
        return value

    def _validate_existing_receipt(
        self,
        source: str,
        path: Path,
        receipt: Optional[Mapping[str, Any]],
        capture_sha256: Optional[str],
        capture_bytes: int,
    ) -> None:
        if receipt is None:
            raise CaptureImportError("capture store receipt unavailable; re-import through capture bridge")
        try:
            receipt_path = Path(str(receipt.get("capture_path") or "")).expanduser().resolve()
            expected_path = path.resolve()
        except (OSError, RuntimeError, ValueError):
            raise CaptureImportError("capture receipt path is invalid")
        if receipt_path != expected_path:
            raise CaptureImportError("capture receipt path mismatch")
        if str(receipt.get("source") or "").strip().casefold() != source.casefold():
            raise CaptureImportError("capture receipt source mismatch")
        if receipt.get("version") != 2:
            raise CaptureImportError("capture receipt lacks content binding; re-import through capture bridge")
        if str(receipt.get("outcome") or "").casefold() == "verified_empty":
            raise CaptureImportError("capture store is marked verified empty but contains data")
        if receipt.get("capture_sha256") != capture_sha256 or receipt.get("capture_bytes") != capture_bytes:
            raise CaptureImportError("capture receipt content mismatch; re-import through capture bridge")

    def import_records(
        self,
        source: str,
        records: Iterable[Mapping[str, Any]],
        *,
        captured_at: Optional[Any] = None,
        verified_empty: bool = False,
        malformed_count: int = 0,
    ) -> CaptureImportResult:
        normalized_source = normalize_capture_source(source)
        received_at = parse_datetime(captured_at or datetime.now(timezone.utc))
        path = self.path_for(normalized_source)
        input_list = []
        for index, record in enumerate(records):
            if index >= MAX_CAPTURE_INPUT_RECORDS:
                raise CaptureImportError("capture input exceeds record limit")
            input_list.append(record)
        started_at = datetime.now(timezone.utc)
        attempt_id = uuid.uuid4().hex
        with _capture_lock(path):
            live_store_present = path.exists()
            try:
                existing_receipt = self._read_receipt_payload(normalized_source) if path.exists() else None
                existing_raw, malformed_existing, existing_sha256, existing_bytes = _read_jsonl(path)
                if path.exists():
                    # An empty live file has no prior content to authenticate.
                    # Treat it as an uninitialized store so a first capture can
                    # establish the receipt; non-empty stores still require a
                    # valid content-bound receipt.
                    if existing_bytes or existing_raw or malformed_existing:
                        self._validate_existing_receipt(normalized_source, path, existing_receipt, existing_sha256, existing_bytes)
            except CaptureImportError as exc:
                # Never issue a new receipt for an existing store that failed
                # content validation: doing so would bless tampered bytes for
                # the next import.  The old receipt remains available for the
                # adapters to reject with a content-mismatch diagnostic.
                if not live_store_present:
                    self._write_receipt(normalized_source, path, attempt_id=attempt_id, started_at=started_at, outcome="failed", diagnostics=(str(exc),))
                raise
            if malformed_existing:
                diagnostic = "capture store contains malformed line(s): %d" % malformed_existing
                self._write_receipt(normalized_source, path, attempt_id=attempt_id, started_at=started_at, outcome="failed", diagnostics=(diagnostic,))
                raise CaptureImportError(diagnostic)

            existing: List[Mapping[str, Any]] = []
            hashes = set()
            for record in existing_raw:
                preserved = dict(record)
                capture_hash = str(preserved.get("capture_hash") or _dedupe_hash(normalized_source, preserved))
                if capture_hash in hashes:
                    continue
                hashes.add(capture_hash)
                existing.append(preserved)

            if not input_list:
                if verified_empty and existing_sha256 is not None:
                    raise CaptureImportError("cannot verify empty capture while live store contains data")
                outcome = "verified_empty" if verified_empty else "unavailable"
                result = CaptureImportResult(source=normalized_source, path=path, existing_count=len(existing), outcome=outcome)
                self._write_receipt(normalized_source, path, attempt_id=attempt_id, started_at=started_at, outcome=outcome, existing_count=len(existing), capture_sha256=existing_sha256, capture_bytes=existing_bytes)
                return result

            accepted: List[Mapping[str, Any]] = []
            duplicate_count = 0
            rejected_count = malformed_count
            excluded_count = 0
            diagnostics: List[str] = []
            if malformed_count:
                diagnostics.append("ignored malformed input line(s): %d" % malformed_count)
            for record in input_list:
                try:
                    prepared = self._prepare_record(normalized_source, record, received_at)
                except _ExcludedRecord:
                    excluded_count += 1
                    continue
                except _RejectedRecord as exc:
                    rejected_count += 1
                    diagnostics.append(str(exc))
                    continue
                capture_hash = str(prepared.get("capture_hash", ""))
                if capture_hash in hashes:
                    duplicate_count += 1
                    continue
                hashes.add(capture_hash)
                accepted.append(prepared)

            if accepted:
                merged = list(existing) + accepted
                if len(merged) > MAX_CAPTURE_STORE_RECORDS or _jsonl_size(merged) > MAX_CAPTURE_STORE_BYTES:
                    raise CaptureImportError("capture store retention limit would be exceeded")
                _atomic_jsonl_write(path, merged)
            if excluded_count:
                diagnostics.append("excluded records: %d" % excluded_count)
            if duplicate_count:
                diagnostics.append("duplicate records: %d" % duplicate_count)
            outcome = "success" if accepted or duplicate_count else "rejected"
            safe_diagnostics = tuple(redact_text(item, max_chars=180) for item in diagnostics[:8])
            result = CaptureImportResult(
                source=normalized_source,
                path=path,
                input_count=len(input_list) + malformed_count,
                accepted_count=len(accepted),
                duplicate_count=duplicate_count,
                rejected_count=rejected_count,
                excluded_count=excluded_count,
                existing_count=len(existing),
                outcome=outcome,
                diagnostics=safe_diagnostics,
                records=tuple(accepted),
            )
            self._write_receipt(
                normalized_source,
                path,
                attempt_id=attempt_id,
                started_at=started_at,
                outcome=outcome,
                input_count=result.input_count,
                accepted_count=result.accepted_count,
                duplicate_count=result.duplicate_count,
                rejected_count=result.rejected_count,
                excluded_count=result.excluded_count,
                existing_count=result.existing_count,
                diagnostics=safe_diagnostics,
                capture_sha256=None if accepted else existing_sha256,
                capture_bytes=None if accepted else existing_bytes,
            )
            return result

    def import_text(
        self,
        source: str,
        text: str,
        *,
        suffix: str = ".jsonl",
        captured_at: Optional[Any] = None,
        verified_empty: bool = False,
    ) -> CaptureImportResult:
        raw_text = str(text)
        if len(raw_text.encode("utf-8")) > MAX_CAPTURE_INPUT_BYTES:
            raise CaptureImportError("capture input exceeds size limit")
        records, malformed = _decode_capture_text(raw_text, suffix)
        return self.import_records(source, records, captured_at=captured_at, verified_empty=verified_empty, malformed_count=malformed)

    def import_file(self, source: str, input_path: Path, *, captured_at: Optional[Any] = None, verified_empty: bool = False) -> CaptureImportResult:
        path = Path(input_path)
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_CAPTURE_INPUT_BYTES + 1)
            if len(raw) > MAX_CAPTURE_INPUT_BYTES:
                raise CaptureImportError("capture input exceeds size limit")
            text = raw.decode("utf-8")
        except CaptureImportError:
            raise
        except (OSError, UnicodeError) as exc:
            raise CaptureImportError("cannot read capture input: %s" % type(exc).__name__)
        return self.import_text(source, text, suffix=path.suffix, captured_at=captured_at, verified_empty=verified_empty)

    def import_stdin(self, source: str, *, captured_at: Optional[Any] = None, verified_empty: bool = False) -> CaptureImportResult:
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        try:
            raw = stream.read(MAX_CAPTURE_INPUT_BYTES + 1)
        except (OSError, UnicodeError) as exc:
            raise CaptureImportError("cannot read capture input: %s" % type(exc).__name__)
        if isinstance(raw, bytes):
            if len(raw) > MAX_CAPTURE_INPUT_BYTES:
                raise CaptureImportError("capture input exceeds size limit")
            text = raw.decode("utf-8")
        else:
            text = str(raw)
            if len(text.encode("utf-8")) > MAX_CAPTURE_INPUT_BYTES:
                raise CaptureImportError("capture input exceeds size limit")
        return self.import_text(source, text, suffix=".jsonl", captured_at=captured_at, verified_empty=verified_empty)

    def status(self) -> List[CaptureStatus]:
        result = []
        for source in CAPTURE_SOURCES:
            path = self.path_for(source)
            receipt_status: Optional[str] = None
            receipt_completed_at: Optional[str] = None
            try:
                receipt_value = json.loads(self.receipt_path_for(source).read_text(encoding="utf-8"))
                if isinstance(receipt_value, Mapping):
                    receipt_status = str(receipt_value.get("outcome") or "") or None
                    receipt_completed_at = str(receipt_value.get("completed_at") or "") or None
            except (OSError, UnicodeError, ValueError):
                pass
            if not path.exists():
                result.append(CaptureStatus(source, path, False, receipt_status=receipt_status, receipt_completed_at=receipt_completed_at))
                continue
            records, malformed, _, _ = _read_jsonl(path)
            latest: Optional[datetime] = None
            for record in records:
                for key in ("occurred_at", "captured_at"):
                    try:
                        candidate = parse_datetime(record.get(key)) if record.get(key) else None
                    except (TypeError, ValueError):
                        candidate = None
                    if candidate is not None and (latest is None or candidate > latest):
                        latest = candidate
                    if candidate is not None:
                        break
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            result.append(CaptureStatus(source, path, True, size, len(records), malformed, latest.isoformat() if latest else None, receipt_status, receipt_completed_at))
        return result


def capture_paths_from_config(config: Any) -> Dict[str, Path]:
    return {
        source: Path(getattr(config, "%s_capture_path" % source))
        for source in CAPTURE_SOURCES
        if getattr(config, "%s_capture_path" % source, None) is not None
    }


def import_capture_records(
    root: Path,
    source: str,
    records: Iterable[Mapping[str, Any]],
    *,
    paths: Optional[Mapping[str, Path]] = None,
    captured_at: Optional[Any] = None,
    verified_empty: bool = False,
) -> CaptureImportResult:
    return CaptureBridge(root, paths=paths).import_records(source, records, captured_at=captured_at, verified_empty=verified_empty)


import_captures = import_capture_records


def capture_status(root: Path, *, paths: Optional[Mapping[str, Path]] = None) -> List[CaptureStatus]:
    return CaptureBridge(root, paths=paths).status()


__all__ = [
    "CAPTURE_SOURCES",
    "MAX_CAPTURE_TEXT_CHARS",
    "MAX_TEXT_CHARS",
    "CaptureBridge",
    "CaptureImportError",
    "CaptureImportResult",
    "CaptureStatus",
    "capture_paths_from_config",
    "capture_status",
    "import_capture_records",
    "import_captures",
    "normalize_capture_source",
]
