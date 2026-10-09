# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from life_iq.replies import QueueTransitionError, ReplyCandidateBuilder, ReplyQueue
from life_iq.schema import NormalizedEvent


def make_event(source, ref, at, summary, metadata=None):
    return NormalizedEvent.build(
        source=source,
        source_ref=ref,
        occurred_at=at,
        event_type="conversation",
        summary=summary,
        metadata=metadata or {},
    )


class ReplyCandidateTests(unittest.TestCase):
    def test_line_scope_and_ai_disclosure(self):
        events = [
            make_event("line", "friend", "2026-08-28T09:00:00+09:00", "お元気ですか", {"conversation_id": "c1", "conversation_name": "友達", "conversation_type": "friend", "direction": "inbound"}),
            make_event("line", "group", "2026-08-28T09:01:00+09:00", "みんなへ", {"conversation_id": "c2", "conversation_type": "group", "direction": "inbound"}),
            make_event("line", "official", "2026-08-28T09:02:00+09:00", "告知", {"conversation_id": "c3", "conversation_type": "official_account", "direction": "inbound"}),
            make_event("line", "mentioned", "2026-08-28T09:03:00+09:00", "@本人お願い", {"conversation_id": "c2", "conversation_type": "group", "is_direct_mention": True, "direction": "inbound"}),
        ]
        candidates = ReplyCandidateBuilder(now="2026-08-28T10:00:00+09:00").build(events)
        self.assertEqual({candidate.inbound_id for candidate in candidates}, {"friend", "mentioned"})
        self.assertTrue(all("AI" in candidate.proposed_reply for candidate in candidates))

    def test_slack_dm_and_direct_mention_keep_thread_route(self):
        events = [
            make_event("slack", "dm1", "2026-08-28T09:00:00+09:00", "確認お願いします", {"conversation_id": "D1", "is_dm": True, "scope": "dm", "workspace_name": "学校", "workspace_url": "https://example.slack.com", "recipient": "先生", "direction": "inbound"}),
            make_event("slack", "mention", "2026-08-28T09:01:00+09:00", "@本人レビューをお願いします", {"conversation_id": "C1", "channel_name": "#class", "is_direct_mention": True, "thread_id": "root-1", "workspace_name": "学校", "workspace_url": "https://example.slack.com", "direction": "inbound"}),
            make_event("slack", "broadcast", "2026-08-28T09:02:00+09:00", "@channel 全員確認", {"conversation_id": "C2", "channel_name": "#all", "is_direct_mention": True, "direction": "inbound"}),
        ]
        candidates = ReplyCandidateBuilder().build(events)
        self.assertEqual({candidate.inbound_id for candidate in candidates}, {"dm1", "mention"})
        mention = next(candidate for candidate in candidates if candidate.inbound_id == "mention")
        self.assertEqual(mention.route["thread_id"], "root-1")
        self.assertEqual(mention.thread_info["reply_to_id"], "mention")

    def test_discord_requires_three_mutual_days_and_server_allowlist(self):
        events = []
        for day in (20, 21, 22):
            events.append(make_event("discord", "in-%d" % day, "2026-08-%02dT09:00:00+00:00" % day, "相手の連絡", {"conversation_id": "dm-a", "is_dm": True, "direction": "inbound"}))
            events.append(make_event("discord", "out-%d" % day, "2026-08-%02dT10:00:00+00:00" % day, "自分の返信", {"conversation_id": "dm-a", "is_dm": True, "direction": "outbound"}))
        events.append(make_event("discord", "new", "2026-08-23T09:00:00+00:00", "今日の相談", {"conversation_id": "dm-a", "is_dm": True, "direction": "inbound", "recipient": "相手"}))
        events.append(make_event("discord", "sudden", "2026-08-23T09:00:00+00:00", "突然のDM", {"conversation_id": "dm-b", "is_dm": True, "direction": "inbound"}))
        events.append(make_event("discord", "server", "2026-08-23T10:00:00+00:00", "許可済みサーバー", {"conversation_id": "s1", "server_id": "s-allowed", "scope": "server", "direction": "inbound"}))
        builder = ReplyCandidateBuilder(discord_server_allowlist=["s-allowed"])
        candidates = builder.build(events)
        self.assertEqual({candidate.inbound_id for candidate in candidates}, {"new", "server"})

    def test_x_never_creates_reply_candidate_and_later_self_reply_suppresses(self):
        events = [
            make_event("x", "x1", "2026-08-28T09:00:00+00:00", "返信", {"direction": "inbound"}),
            make_event("slack", "inbound", "2026-08-28T09:00:00+00:00", "返信ください", {"conversation_id": "c", "is_dm": True, "direction": "inbound"}),
            make_event("slack", "outbound", "2026-08-28T09:01:00+00:00", "自分の返信", {"conversation_id": "c", "is_dm": True, "direction": "outbound"}),
        ]
        self.assertEqual(ReplyCandidateBuilder().build(events), [])

    def test_risk_is_blocked_and_normal_approval_is_send_ready_only(self):
        risky = make_event("line", "risk", "2026-08-28T09:00:00+00:00", "購入代金を振り込んで。カード番号を送って", {"conversation_id": "c1", "conversation_type": "friend", "direction": "inbound"})
        normal = make_event("line", "normal", "2026-08-28T09:01:00+00:00", "ありがとう", {"conversation_id": "c2", "conversation_type": "friend", "direction": "inbound"})
        candidates = ReplyCandidateBuilder().build([risky, normal])
        self.assertEqual({candidate.status for candidate in candidates}, {"blocked", "pending"})
        blocked = next(candidate for candidate in candidates if candidate.inbound_id == "risk")
        self.assertIn("financial", blocked.risk_flags)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue = ReplyQueue(root / "state" / "reply-queue.json", root / "knowledge" / "replies" / "pending.md")
            queue.upsert(candidates)
            with self.assertRaises(QueueTransitionError):
                queue.approve(blocked.candidate_id)
            ready = queue.send_ready(queue.approve(next(candidate for candidate in candidates if candidate.inbound_id == "normal")).candidate_id)
            self.assertEqual(ready.to_dict()["status"], "send-ready")
            self.assertTrue((root / "knowledge/replies/pending.md").exists())
            self.assertIn("blocked", (root / "knowledge/replies/pending.md").read_text(encoding="utf-8"))
