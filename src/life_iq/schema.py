"""Normalized event schema and deterministic serialization helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple


def parse_datetime(value: Any, default: Optional[datetime] = None) -> datetime:
    """Parse common source timestamps into timezone-aware datetimes.

    A missing timestamp is rejected unless ``default`` is supplied.  The
    pipeline never silently uses the current time for source data, because
    doing so would make reruns non-deterministic.
    """

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, datetime.min.time())
    elif isinstance(value, (int, float)):
        # Gmail's internalDate is milliseconds; other captures commonly use
        # Unix seconds.  Values above 10^11 are unambiguously milliseconds.
        numeric = float(value)
        if numeric > 100000000000:
            numeric /= 1000.0
        parsed = datetime.fromtimestamp(numeric, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            if default is None:
                raise ValueError("timestamp is empty")
            parsed = default
        else:
            # RFC 2822 mail dates are supported without importing a mail
            # parser into the core schema.
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                try:
                    from email.utils import parsedate_to_datetime

                    parsed = parsedate_to_datetime(text)
                except (TypeError, ValueError):
                    if default is None:
                        raise ValueError("unsupported timestamp: %s" % text)
                    parsed = default
    elif value is None and default is not None:
        parsed = default
    else:
        raise ValueError("unsupported timestamp type: %r" % (type(value),))

    if parsed.tzinfo is None:
        # Source captures without an offset are interpreted as UTC.  The
        # configured local timezone is applied by window calculations.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def canonical_json(value: Any) -> str:
    """Return stable compact JSON for hashes and reproducible artifacts."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _clean_entities(values: Iterable[Any]) -> Tuple[str, ...]:
    result = []
    seen = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return tuple(result)


@dataclass(frozen=True)
class NormalizedEvent:
    """A source-independent, privacy-filtered event.

    ``metadata`` is deliberately optional and should contain only safe,
    short fields (for example an app name or a relative file name).  Adapters
    sanitize it before constructing an event.  Raw source bodies never belong
    in this object.
    """

    event_id: str
    occurred_at: datetime
    source: str
    source_ref: str
    event_type: str
    summary: str
    entities: Tuple[str, ...] = field(default_factory=tuple)
    status: str = "observed"
    confidence: float = 0.5
    sensitivity: str = "normal"
    content_hash: str = ""
    importance: float = 0.0
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        occurred = parse_datetime(self.occurred_at)
        object.__setattr__(self, "occurred_at", occurred)
        object.__setattr__(self, "source", str(self.source).strip().lower())
        object.__setattr__(self, "source_ref", str(self.source_ref).strip())
        object.__setattr__(self, "event_type", str(self.event_type).strip().lower() or "observation")
        object.__setattr__(self, "summary", str(self.summary).strip())
        object.__setattr__(self, "entities", _clean_entities(self.entities))
        object.__setattr__(self, "confidence", min(1.0, max(0.0, float(self.confidence))))
        object.__setattr__(self, "importance", min(100.0, max(0.0, float(self.importance))))
        if not self.event_id:
            object.__setattr__(self, "event_id", "%s:%s" % (self.source, self.source_ref))
        if not self.content_hash:
            object.__setattr__(self, "content_hash", self.compute_content_hash())

    @classmethod
    def build(
        cls,
        *,
        occurred_at: Any,
        source: str,
        source_ref: str,
        event_type: str,
        summary: str,
        entities: Iterable[Any] = (),
        status: str = "observed",
        confidence: float = 0.5,
        sensitivity: str = "normal",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "NormalizedEvent":
        source_text = str(source).strip().lower()
        ref_text = str(source_ref).strip()
        return cls(
            event_id="%s:%s" % (source_text, ref_text),
            occurred_at=parse_datetime(occurred_at),
            source=source_text,
            source_ref=ref_text,
            event_type=event_type,
            summary=summary,
            entities=tuple(entities),
            status=status,
            confidence=confidence,
            sensitivity=sensitivity,
            metadata=dict(metadata or {}),
        )

    def hash_payload(self) -> Dict[str, Any]:
        """Payload used for dedupe; excludes generated hash and score."""

        return {
            "occurred_at": self.occurred_at.isoformat(),
            "source": self.source,
            "source_ref": self.source_ref,
            "event_type": self.event_type,
            "summary": self.summary,
            "entities": list(self.entities),
            "status": self.status,
            "confidence": round(self.confidence, 6),
            "sensitivity": self.sensitivity,
        }

    def compute_content_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.hash_payload()).encode("utf-8")).hexdigest()

    def with_importance(self, score: float) -> "NormalizedEvent":
        return replace(self, importance=score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "occurred_at": self.occurred_at.isoformat(),
            "source": self.source,
            "source_ref": self.source_ref,
            "event_type": self.event_type,
            "summary": self.summary,
            "entities": list(self.entities),
            "status": self.status,
            "confidence": round(self.confidence, 6),
            "sensitivity": self.sensitivity,
            "content_hash": self.content_hash,
            "importance": round(self.importance, 4),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NormalizedEvent":
        event = cls(
            event_id=str(data.get("event_id", "")),
            occurred_at=parse_datetime(data.get("occurred_at")),
            source=str(data.get("source", "unknown")),
            source_ref=str(data.get("source_ref", "unknown")),
            event_type=str(data.get("event_type", "observation")),
            summary=str(data.get("summary", "")),
            entities=tuple(data.get("entities") or ()),
            status=str(data.get("status", "observed")),
            confidence=float(data.get("confidence", 0.5)),
            sensitivity=str(data.get("sensitivity", "normal")),
            content_hash=str(data.get("content_hash", "")),
            importance=float(data.get("importance", 0.0)),
            metadata=dict(data.get("metadata") or {}),
        )
        # A persisted hash is trusted only if it matches the canonical event.
        if event.content_hash != event.compute_content_hash():
            object.__setattr__(event, "content_hash", event.compute_content_hash())
        return event


# A short alias keeps integrations that call the type ``Event`` ergonomic.
Event = NormalizedEvent


def normalize_event(data: Mapping[str, Any]) -> NormalizedEvent:
    """Public helper for adapter and test integrations."""

    return NormalizedEvent.from_dict(data)
