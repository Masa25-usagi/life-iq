# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from life_iq.capture import CaptureBridge
from life_iq.sources.base import SourceWindow
from life_iq.sources.discord import DiscordAdapter
from life_iq.sources.drive import DriveAdapter
from life_iq.sources.gmail import GmailAdapter
from life_iq.sources.line import LineAdapter, is_excluded_line_conversation
from life_iq.sources.screenpipe import ScreenpipeAdapter
from life_iq.sources.x import XAdapter
from life_iq.sources.slack import SlackAdapter


WINDOW = SourceWindow("2026-08-26T00:00:00+09:00", "2026-08-27T00:00:00+09:00")


class AdapterTests(unittest.TestCase):
    def test_gmail_export_is_normalized(self):
        result = GmailAdapter(records=[{"id": "m1", "timestamp": "2026-08-26T12:00:00+09:00", "subject": "Amazon 注文", "snippet": "発送予定"}]).collect(WINDOW)
        self.assertEqual(result.status.status, "success")
        self.assertEqual(result.events[0].source_ref, "m1")
        self.assertEqual(result.events[0].event_type, "purchase")

    def test_missing_sources_are_safe(self):
        self.assertEqual(GmailAdapter().collect(WINDOW).status.status, "needs_setup")
        self.assertEqual(ScreenpipeAdapter().collect(WINDOW).status.status, "skipped")
        self.assertEqual(LineAdapter().collect(WINDOW).status.status, "skipped")
        self.assertEqual(DiscordAdapter().collect(WINDOW).status.status, "skipped")

    def test_line_excludes_openchat_and_official_before_output(self):
        records = [
            {"id": "open", "timestamp": "2026-08-26T12:00:00+09:00", "chat_name": "OpenChat 雑談", "text": "秘密"},
            {"id": "official", "timestamp": "2026-08-26T12:01:00+09:00", "conversation_type": "official_account", "text": "告知"},
            {"id": "ok", "timestamp": "2026-08-26T12:02:00+09:00", "conversation_type": "group", "chat_name": "家族", "text": "夕食"},
        ]
        result = LineAdapter(records=records).collect(WINDOW)
        self.assertTrue(is_excluded_line_conversation(records[0]))
        self.assertEqual(len(result.events), 1)
        self.assertNotIn("秘密", " ".join(event.summary for event in result.events))

    def test_line_excludes_business_company_store_accounts_before_output(self):
        records = [
            {"id": "business", "timestamp": "2026-08-26T12:03:00+09:00", "account_type": "business", "text": "企業からの案内"},
            {"id": "company", "timestamp": "2026-08-26T12:04:00+09:00", "is_company_account": True, "text": "会社のお知らせ"},
            {"id": "store", "timestamp": "2026-08-26T12:05:00+09:00", "conversation_type": "store", "text": "店舗キャンペーン"},
            {"id": "ok", "timestamp": "2026-08-26T12:06:00+09:00", "conversation_type": "group", "chat_name": "家族", "text": "夕食"},
        ]
        result = LineAdapter(records=records).collect(WINDOW)
        self.assertTrue(all(is_excluded_line_conversation(record) for record in records[:3]))
        self.assertEqual({event.source_ref for event in result.events}, {"ok"})
        self.assertNotIn("企業からの案内", " ".join(event.summary for event in result.events))

    def test_line_does_not_exclude_friend_message_that_mentions_a_store(self):
        record = {
            "id": "friend-store-chat",
            "timestamp": "2026-08-26T12:07:00+09:00",
            "conversation_type": "friend",
            "chat_name": "友達",
            "text": "この店舗、前のcompanyより良さそう",
        }
        result = LineAdapter(records=[record]).collect(WINDOW)
        self.assertFalse(is_excluded_line_conversation(record))
        self.assertEqual({event.source_ref for event in result.events}, {"friend-store-chat"})

    def test_line_string_false_is_not_direct_mention_evidence(self):
        record = {
            "id": "line-false-mention",
            "timestamp": "2026-08-26T12:08:00+09:00",
            "conversation_type": "friend",
            "chat_name": "友達",
            "direction": "inbound",
            "is_direct_mention": "false",
            "mentions_self": "false",
            "text": "対象外のメンション判定",
        }
        result = LineAdapter(records=[record]).collect(WINDOW)
        self.assertEqual(result.events[0].metadata["is_direct_mention"], False)

    def test_discord_only_self_posted_server_and_dms(self):
        records = [
            {"source": "discord", "id": "self", "server_id": "allowed", "server_name": "Allowed", "is_self": True, "timestamp": "2026-08-26T10:00:00+09:00", "text": "own"},
            {"source": "discord", "id": "allowed-other", "server_id": "allowed", "server_name": "Allowed", "timestamp": "2026-08-26T10:01:00+09:00", "text": "reply"},
            {"source": "discord", "id": "blocked", "server_id": "blocked", "server_name": "Blocked", "timestamp": "2026-08-26T10:02:00+09:00", "text": "not in scope"},
            {"source": "discord", "id": "dm", "is_dm": True, "timestamp": "2026-08-26T10:03:00+09:00", "text": "hello"},
        ]
        result = DiscordAdapter(records=records).collect(WINDOW)
        self.assertEqual({event.source_ref for event in result.events}, {"self", "allowed-other", "dm"})
        self.assertNotIn("not in scope", " ".join(event.summary for event in result.events))

    def test_discord_string_false_is_not_dm_or_membership_evidence(self):
        record = {
            "id": "not-a-dm",
            "server_id": "untrusted",
            "is_dm": "false",
            "has_user_sent": "false",
            "timestamp": "2026-08-26T10:04:00+00:00",
            "text": "対象外",
        }
        result = DiscordAdapter(records=[record]).collect(WINDOW)
        self.assertEqual(result.events, [])

    def test_discord_excluded_app_cannot_make_a_server_eligible(self):
        records = [
            {"id": "spoof", "app": "Other App", "server_id": "s", "is_self": True, "timestamp": "2026-08-26T10:05:00+00:00", "text": "spoof"},
            {"id": "other", "app": "Discord", "server_id": "s", "timestamp": "2026-08-26T10:06:00+00:00", "text": "other user"},
        ]
        result = DiscordAdapter(records=records).collect(WINDOW)
        self.assertEqual(result.events, [])

    def test_drive_reads_metadata_and_short_excerpt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            file = source / "notes.md"
            file.write_text("meeting notes", encoding="utf-8")
            # Set mtime into the requested window.
            stamp = datetime(2026, 8, 26, 12, tzinfo=timezone.utc).timestamp()
            import os
            os.utime(str(file), (stamp, stamp))
            result = DriveAdapter(source, output_root=root / "output").collect(WINDOW)
            self.assertEqual(result.status.status, "success")
            self.assertEqual(len(result.events), 1)
            self.assertIn("notes.md", result.events[0].summary)

    def test_x_excludes_general_timeline_and_keeps_configured_account(self):
        records = [
            {"id": "own", "type": "post", "author_handle": "@example_user", "timestamp": "2026-08-26T08:00:00+09:00", "text": "自分の投稿"},
            {"id": "notification", "type": "notification", "notification_for": "example_user", "timestamp": "2026-08-26T08:01:00+09:00", "text": "返信されました"},
            {"id": "other", "type": "post", "author_handle": "other-user", "general_timeline": True, "timestamp": "2026-08-26T08:02:00+09:00", "text": "一般TL"},
        ]
        result = XAdapter(records=records).collect(WINDOW)
        self.assertEqual({event.source_ref for event in result.events}, {"own", "notification"})
        self.assertNotIn("一般TL", " ".join(event.summary for event in result.events))

    def test_slack_accepts_school_workspace_and_dms_but_requires_membership(self):
        records = [
            {"id": "school", "workspace_name": "学校", "workspace_url": "https://example-school.slack.com", "channel_name": "#class", "is_member": True, "timestamp": "2026-08-26T09:00:00+09:00", "text": "授業連絡"},
            {"id": "dm", "workspace_name": "other", "workspace_url": "https://other.slack.com", "is_dm": True, "timestamp": "2026-08-26T09:01:00+09:00", "text": "DM"},
            {"id": "not-member", "workspace_name": "other", "workspace_url": "https://other.slack.com", "channel_name": "#random", "timestamp": "2026-08-26T09:02:00+09:00", "text": "対象外"},
        ]
        result = SlackAdapter(records=records, workspace_allowlist=["example-school.slack.com", "other.slack.com"]).collect(WINDOW)
        self.assertEqual({event.source_ref for event in result.events}, {"school", "dm"})
        self.assertEqual(result.events[0].metadata["workspace_url"], "https://example-school.slack.com")
        self.assertTrue(result.events[0].metadata["is_school_workspace"])

    def test_slack_strips_oauth_query_from_workspace_url(self):
        records = [{
            "id": "oauth-safe",
            "workspace_url": "https://example.slack.com/client/path?code=secret&state=secret",
            "channel_name": "#class",
            "is_member": True,
            "timestamp": "2026-08-26T09:00:00+09:00",
            "text": "授業連絡",
        }]
        result = SlackAdapter(records=records).collect(WINDOW)
        self.assertEqual(result.events[0].metadata["workspace_url"], "https://example.slack.com/client/path")
        self.assertNotIn("secret", str(result.events[0].metadata))

    def test_slack_accepts_chrome_capture_when_workspace_url_identifies_slack(self):
        record = {
            "source": "slack",
            "app": "Google Chrome",
            "workspace_url": "https://example-school.slack.com",
            "channel_name": "#class",
            "is_member": True,
            "timestamp": "2026-08-26T09:10:00+09:00",
            "text": "Chrome表示の学校Slack",
        }
        result = SlackAdapter(records=[record]).collect(WINDOW)
        self.assertEqual(len(result.events), 1)
        self.assertTrue(result.events[0].metadata["is_school_workspace"])

    def test_service_name_substrings_do_not_cross_identify_apps(self):
        line = LineAdapter(records=[{"id": "line-app", "app": "baseline", "timestamp": "2026-08-26T09:15:00+00:00", "text": "not LINE"}]).collect(WINDOW)
        slack = SlackAdapter(records=[{"id": "slack-host", "workspace_url": "https://evilslack.com", "is_dm": True, "timestamp": "2026-08-26T09:16:00+00:00", "text": "not Slack"}]).collect(WINDOW)
        x = XAdapter(records=[{"id": "x-host", "url": "https://notx.com", "author_handle": "@example_user", "timestamp": "2026-08-26T09:17:00+00:00", "text": "not X"}]).collect(WINDOW)
        self.assertEqual(line.events, [])
        self.assertEqual(slack.events, [])
        self.assertEqual(x.events, [])

    def test_slack_string_false_is_not_scope_evidence(self):
        record = {
            "source": "slack",
            "workspace_url": "https://example-school.slack.com",
            "channel_name": "#class",
            "is_dm": "false",
            "is_member": "false",
            "timestamp": "2026-08-26T09:11:00+09:00",
            "text": "参加証拠なし",
        }
        result = SlackAdapter(records=[record]).collect(WINDOW)
        self.assertEqual(result.events, [])

    def test_screenpipe_rejects_unverified_unknown_scope(self):
        records = [
            {
                "source": "screenpipe",
                "frame_id": "life-iq",
                "app": "Google Chrome",
                "window": "Life IQ",
                "timestamp": "2026-08-26T09:12:00+09:00",
                "text": "bounded",
            },
            {
                "source": "screenpipe",
                "frame_id": "unknown",
                "app": "Google Chrome",
                "window": "対象不明画面",
                "timestamp": "2026-08-26T09:13:00+09:00",
                "text": "unknown",
            },
            {
                "source": "screenpipe",
                "frame_id": "claimed",
                "app": "Unknown App",
                "window": "Unknown Window",
                "scope_verified": True,
                "timestamp": "2026-08-26T09:14:00+09:00",
                "text": "self-claimed scope",
            },
        ]
        result = ScreenpipeAdapter(records=records).collect(WINDOW)
        self.assertEqual({event.source_ref for event in result.events}, {"life-iq"})

    def test_file_capture_requires_bridge_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "captures/slack/live.jsonl"
            record = {
                "source": "slack",
                "workspace_url": "https://example.slack.com",
                "is_dm": True,
                "timestamp": "2026-08-26T09:14:00+09:00",
                "text": "without receipt",
            }
            bridge = CaptureBridge(root)
            bridge.import_records("slack", [record])
            bridge.receipt_path_for("slack").unlink()
            before = SlackAdapter(path=path).collect(WINDOW)
            self.assertEqual(before.status.status, "skipped")
            path.unlink()
            bridge.import_records("slack", [record])
            after = SlackAdapter(path=path).collect(WINDOW)
            self.assertEqual(after.status.status, "success")
            self.assertEqual(len(after.events), 1)

    def test_verified_empty_receipt_is_not_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            CaptureBridge(root).import_text("screenpipe", "", verified_empty=True)
            result = ScreenpipeAdapter(path=root / "captures/screenpipe/live.jsonl").collect(WINDOW)
            self.assertEqual(result.status.status, "success")
            self.assertEqual(result.events, [])
