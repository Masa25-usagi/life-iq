# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

import json
import tempfile
import unittest
from pathlib import Path

from life_iq.replies import QueueTransitionError, ReplyCandidate, ReplyCandidateBuilder, ReplyQueue
from life_iq.schema import NormalizedEvent
from life_iq.send_intents import SendIntentError, materialize_send_intent


def make_event(source, ref, summary, metadata):
    return NormalizedEvent.build(
        source=source,
        source_ref=ref,
        occurred_at="2026-08-28T09:00:00+00:00",
        event_type="conversation",
        summary=summary,
        metadata=metadata,
    )


class SendIntentTests(unittest.TestCase):
    def test_materialize_rechecks_and_mark_sent_requires_ui_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue = ReplyQueue(
                root / "state/reply-queue.json",
                root / "knowledge/replies/pending.md",
                root / "state/send-intents",
            )
            candidate = ReplyCandidateBuilder().build(
                [
                    make_event(
                        "line",
                        "line-1",
                        "こんにちは",
                        {"conversation_id": "chat-1", "conversation_name": "友達", "recipient": "友達", "direction": "inbound"},
                    )
                ]
            )[0]
            queue.upsert([candidate])
            approved = queue.approve(candidate.candidate_id)
            intent = materialize_send_intent(queue, approved.candidate_id, materialized_at="2026-08-28T09:10:00Z")
            payload = json.loads(intent.path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "send-ready")
            self.assertEqual(payload["recipient"], approved.recipient)
            self.assertEqual(payload["summary"], approved.original_summary)
            self.assertEqual(payload["body"], approved.proposed_reply)
            self.assertEqual(payload["route"], dict(approved.route))
            self.assertFalse(payload["external_send_enabled"])
            with self.assertRaises(QueueTransitionError):
                queue.mark_sent(approved.candidate_id)
            sent = queue.mark_sent(approved.candidate_id, ui_confirmed=True)
            self.assertEqual(sent.status, "sent")
            self.assertEqual(json.loads(intent.path.read_text(encoding="utf-8"))["status"], "sent")

    def test_pending_blocked_and_x_candidates_cannot_materialize(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue = ReplyQueue(root / "state/reply-queue.json", root / "knowledge/replies/pending.md")
            blocked = ReplyCandidateBuilder().build(
                [
                    make_event(
                        "slack",
                        "risk",
                        "購入代金を支払って",
                        {"conversation_id": "c1", "is_dm": True, "direction": "inbound"},
                    )
                ]
            )[0]
            x_candidate = ReplyCandidate(
                candidate_id="x-1",
                source="x",
                recipient="x",
                conversation="x",
                inbound_id="x-inbound",
                inbound_timestamp="2026-08-28T09:00:00Z",
                original_summary="x",
                proposed_reply="x",
                status="approved",
            )
            queue.upsert([blocked, x_candidate])
            with self.assertRaises(SendIntentError):
                materialize_send_intent(queue, blocked.candidate_id)
            with self.assertRaises(SendIntentError):
                materialize_send_intent(queue, x_candidate.candidate_id)


if __name__ == "__main__":
    unittest.main()
