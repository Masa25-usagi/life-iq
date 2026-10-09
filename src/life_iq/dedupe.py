"""Deterministic event deduplication."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .schema import NormalizedEvent


@dataclass
class DedupeResult:
    events: List[NormalizedEvent]
    duplicate_count: int = 0


def deduplicate_events(
    events: Iterable[NormalizedEvent], seen_hashes: Optional[Iterable[str]] = None
) -> DedupeResult:
    """Keep first occurrences in deterministic event order.

    Ordering is source-independent and stable across process runs.  Existing
    hashes are omitted so a rerun creates no duplicate artifact lines.
    """

    seen: Set[str] = set(seen_hashes or ())
    ordered = sorted(
        list(events),
        key=lambda event: (event.occurred_at, event.source, event.event_id, event.content_hash),
    )
    unique: List[NormalizedEvent] = []
    duplicates = 0
    for event in ordered:
        if event.content_hash in seen:
            duplicates += 1
            continue
        seen.add(event.content_hash)
        unique.append(event)
    return DedupeResult(events=unique, duplicate_count=duplicates)


@dataclass
class DedupeIndex:
    """Small mutable index used by the state store and tests."""

    hashes: Set[str] = field(default_factory=set)

    def add(self, event: NormalizedEvent) -> bool:
        if event.content_hash in self.hashes:
            return False
        self.hashes.add(event.content_hash)
        return True

    def add_all(self, events: Sequence[NormalizedEvent]) -> int:
        count = 0
        for event in events:
            count += int(self.add(event))
        return count
