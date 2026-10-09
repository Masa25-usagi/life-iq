"""Compatibility exports for the MVP core modules."""

from life_iq.schema import Event, NormalizedEvent, normalize_event
from life_iq.privacy import contains_sensitive, redact_mapping, redact_text, sensitivity_for
from life_iq.dedupe import DedupeIndex, DedupeResult, deduplicate_events
from life_iq.scoring import importance_score, score_events
from life_iq.context import build_context, generate_important_context

__all__ = [
    "Event", "NormalizedEvent", "normalize_event", "contains_sensitive",
    "redact_mapping", "redact_text", "sensitivity_for", "DedupeIndex",
    "DedupeResult", "deduplicate_events", "importance_score", "score_events",
    "build_context", "generate_important_context",
]
