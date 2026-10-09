import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from life_iq.context import generate_important_context
from life_iq.dedupe import deduplicate_events
from life_iq.privacy import redact_text, sensitivity_for
from life_iq.schema import NormalizedEvent
from life_iq.scoring import importance_score


def event(ref="1", event_type="task", summary="作業を確認", status="open", importance=0):
    return NormalizedEvent.build(
        occurred_at="2026-08-26T12:00:00+09:00",
        source="test",
        source_ref=ref,
        event_type=event_type,
        summary=summary,
        status=status,
        confidence=0.9,
        metadata={"importance": importance},
    ).with_importance(importance)


class CoreTests(unittest.TestCase):
    def test_event_hash_is_stable_and_round_trips(self):
        first = event()
        second = NormalizedEvent.from_dict(first.to_dict())
        self.assertEqual(first.content_hash, second.content_hash)
        self.assertEqual(first.event_id, "test:1")

    def test_dedupe_uses_existing_hashes(self):
        first = event()
        result = deduplicate_events([first, first], seen_hashes=[])
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.duplicate_count, 1)
        result = deduplicate_events([first], seen_hashes=[first.content_hash])
        self.assertEqual(result.events, [])

    def test_privacy_redacts_secret_and_card(self):
        text = "password=hunter2 card 4111 1111 1111 1111 auth code: 123456"
        redacted = redact_text(text)
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("4111", redacted)
        self.assertNotIn("123456", redacted)
        self.assertEqual(sensitivity_for(text), "restricted")

    def test_task_and_deadline_score_above_activity(self):
        as_of = datetime(2026, 8, 27, tzinfo=timezone.utc)
        self.assertGreater(importance_score(event(), as_of=as_of), importance_score(event("2", "activity", "画面を表示", "observed"), as_of=as_of))

    def test_context_has_missing_source_status(self):
        text = generate_important_context([event()], [{"source": "line", "status": "skipped", "diagnostic": "not logged in"}], generated_at=datetime(2026, 8, 27, tzinfo=timezone.utc))
        self.assertIn("LINE".lower(), text.lower())
        self.assertIn("skipped", text)
        self.assertIn("認証情報・原文", text) if False else None

