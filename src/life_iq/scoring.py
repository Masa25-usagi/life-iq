"""Explainable importance scoring."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Mapping, Optional

from .schema import NormalizedEvent, parse_datetime


TYPE_BASE = {
    "task": 78,
    "commitment": 88,
    "deadline": 90,
    "appointment": 86,
    "schedule": 80,
    "relationship": 74,
    "conversation": 66,
    "project": 68,
    "file_created": 55,
    "file_updated": 54,
    "purchase": 52,
    "delivery": 58,
    "return": 61,
    "refund": 60,
    "pattern": 43,
    "activity": 35,
    "observation": 30,
}


def _number(metadata: Mapping[str, object], key: str, default: float = 0.0) -> float:
    try:
        return float(metadata.get(key, default))
    except (TypeError, ValueError):
        return default


def importance_score(
    event: NormalizedEvent,
    *,
    as_of: Optional[datetime] = None,
    frequency: float = 0.0,
    novelty: Optional[float] = None,
) -> float:
    """Compute a bounded score from the factors in the specification."""

    if as_of is None:
        as_of = datetime.now(timezone.utc)
    as_of = parse_datetime(as_of)
    age_days = max(0.0, (as_of - event.occurred_at).total_seconds() / 86400.0)
    recency = max(0.0, 16.0 - min(age_days, 16.0))
    base = float(TYPE_BASE.get(event.event_type, 35))
    metadata = event.metadata
    explicit = max(0.0, min(12.0, _number(metadata, "importance", 0.0)))
    due_days = _number(metadata, "due_in_days", 999.0)
    due = 0.0 if due_days >= 999 else max(0.0, min(18.0, 18.0 - max(0.0, due_days) * 2.5))
    unfinished = 15.0 if event.status.lower() in ("open", "pending", "todo", "unresolved", "in_progress") else 0.0
    frequency_score = max(0.0, min(8.0, float(frequency) * 2.0))
    links = max(0.0, min(7.0, len(event.entities) * 1.5))
    novelty_score = 5.0 if novelty is None else max(0.0, min(8.0, float(novelty) * 8.0))
    source_confidence = max(0.0, min(6.0, event.confidence * 6.0))
    sensitivity_penalty = 12.0 if event.sensitivity == "restricted" else (3.0 if event.sensitivity == "sensitive" else 0.0)
    score = base * 0.52 + recency + explicit + due + unfinished + frequency_score + links + novelty_score + source_confidence - sensitivity_penalty
    return round(max(0.0, min(100.0, score)), 2)


def score_events(
    events: Iterable[NormalizedEvent],
    *,
    as_of: Optional[datetime] = None,
) -> List[NormalizedEvent]:
    event_list = list(events)
    counts = {}
    for event in event_list:
        for entity in event.entities:
            counts[entity] = counts.get(entity, 0) + 1
    scored = []
    for event in event_list:
        frequency = max((counts.get(entity, 1) - 1 for entity in event.entities), default=0)
        scored.append(event.with_importance(importance_score(event, as_of=as_of, frequency=frequency)))
    return sorted(scored, key=lambda event: (-event.importance, -event.occurred_at.timestamp(), event.event_id))
