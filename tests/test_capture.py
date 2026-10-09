# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from life_iq.capture import CaptureBridge, CaptureImportError, MAX_CAPTURE_INPUT_BYTES, MAX_CAPTURE_STORE_BYTES, MAX_CAPTURE_TEXT_CHARS
from life_iq.cli import main
from life_iq.sources.base import SourceWindow


class CaptureBridgeTests(unittest.TestCase):
    def test_import_redacts_bounds_dedupes_and_excludes_line_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge = CaptureBridge(root)
            records = [
                {
                    "source": "line",
                    "id": "friend-1",
                    "timestamp": "2026-08-28T09:00:00+09:00",
                    "text": "受け取りました password=hunter2 " + ("本文 " * 800),
                },
                {
                    "source": "line",
                    "id": "business-1",
                    "timestamp": "2026-08-28T09:01:00+09:00",
                    "is_business_account": True,
                    "text": "保存してはいけない企業本文",
                },
                {
                    "source": "line",
                    "id": "store-1",
                    "timestamp": "2026-08-28T09:02:00+09:00",
                    "conversation_type": "store",
                    "text": "保存してはいけない店舗本文",
                },
                {
                    "source": "slack",
                    "id": "spoof-1",
                    "timestamp": "2026-08-28T09:03:00+09:00",
                    "text": "source mismatch",
                },
                {
                    "id": "spoof-2",
                    "app": "Discord",
                    "timestamp": "2026-08-28T09:04:00+09:00",
                    "text": "service mismatch",
                },
                {
                    "source": "line",
                    "id": "spoof-3",
                    "workspace_url": "https://discord.com/channels/1/2",
                    "timestamp": "2026-08-28T09:05:00+09:00",
                    "text": "service mismatch by workspace URL",
                },
            ]
            first = bridge.import_records("line", records, captured_at="2026-08-28T09:10:00+09:00")
            self.assertEqual(first.accepted_count, 1)
            self.assertEqual(first.excluded_count, 2)
            self.assertEqual(first.rejected_count, 3)
            stored_path = root / "captures/line/live.jsonl"
            stored = [json.loads(line) for line in stored_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]["source"], "line")
            self.assertLessEqual(len(stored[0]["text"]), MAX_CAPTURE_TEXT_CHARS)
            self.assertNotIn("hunter2", stored[0]["text"])
            self.assertNotIn("企業本文", stored_path.read_text(encoding="utf-8"))
            self.assertTrue(stored[0]["capture_hash"])

            second = bridge.import_records("line", records[:1], captured_at="2026-08-28T09:11:00+09:00")
            self.assertEqual(second.accepted_count, 0)
            self.assertEqual(second.duplicate_count, 1)
            self.assertEqual(len(stored_path.read_text(encoding="utf-8").splitlines()), 1)

    def test_import_accepts_json_array_and_rejects_unsafe_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            bridge = CaptureBridge(Path(directory))
            text = json.dumps(
                [
                    {"source": "slack", "id": "ok", "occurred_at": "2026-08-28T09:00:00Z", "text": "表示済み"},
                    {"source": "slack", "id": "unread", "occurred_at": "2026-08-28T09:01:00Z", "opened_unread": True, "text": "開かない"},
                ],
                ensure_ascii=False,
            )
            result = bridge.import_text("slack", text, suffix=".jsonl", captured_at="2026-08-28T09:02:00Z")
            self.assertEqual(result.accepted_count, 1)
            self.assertEqual(result.rejected_count, 1)

    def test_import_rejects_a_mismatched_envelope_source(self):
        with tempfile.TemporaryDirectory() as directory:
            bridge = CaptureBridge(Path(directory))
            text = json.dumps({"source": "x", "records": [{"id": "spoof", "text": "not Slack"}]})
            result = bridge.import_text("slack", text, suffix=".json")
            self.assertEqual(result.accepted_count, 0)
            self.assertEqual(result.rejected_count, 1)

    def test_screenpipe_capture_uses_the_same_safe_bridge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge = CaptureBridge(root)
            result = bridge.import_records(
                "screenpipe",
                [
                    {
                        "source": "screenpipe",
                        "frame_id": 42,
                        "occurred_at": "2026-08-28T09:00:00Z",
                        "app": "Google Chrome",
                        "window": "Life IQ",
                        "text": "visible summary password=hunter2 " + ("本文 " * 800),
                    }
                ],
            )
            self.assertEqual(result.accepted_count, 1)
            stored_path = root / "captures/screenpipe/live.jsonl"
            stored = json.loads(stored_path.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(stored["source"], "screenpipe")
            self.assertLessEqual(len(stored["text"]), MAX_CAPTURE_TEXT_CHARS)
            self.assertNotIn("hunter2", stored["text"])

    def test_missing_service_timestamp_uses_capture_time_but_hashes_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge = CaptureBridge(root)
            record = {"source": "discord", "id": "no-clock", "text": "取得時刻で記録"}
            first = bridge.import_records("discord", [record], captured_at="2026-08-28T09:00:00Z")
            second = bridge.import_records("discord", [record], captured_at="2026-08-28T09:15:00Z")
            self.assertEqual(first.accepted_count, 1)
            self.assertEqual(second.duplicate_count, 1)

    def test_first_import_initializes_an_existing_empty_live_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "captures/discord/live.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text("", encoding="utf-8")
            result = CaptureBridge(root).import_records(
                "discord",
                [{"source": "discord", "id": "first", "is_dm": True, "text": "初回取得"}],
                captured_at="2026-08-28T09:00:00Z",
            )
            self.assertEqual(result.accepted_count, 1)
            receipt = json.loads((path.parent / "live.jsonl.receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["outcome"], "success")

    def test_status_contains_counts_without_source_bodies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge = CaptureBridge(root)
            bridge.import_records("x", [{"source": "x", "id": "x1", "timestamp": "2026-08-28T09:00:00Z", "text": "表示"}])
            statuses = {item.source: item for item in bridge.status()}
            self.assertTrue(statuses["x"].exists)
            self.assertEqual(statuses["x"].records, 1)
            self.assertFalse(statuses["line"].exists)
            self.assertNotIn("表示", json.dumps([item.to_dict() for item in statuses.values()], ensure_ascii=False))

    def test_cli_capture_import_reads_stdin_and_reports_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            config_path.write_text(json.dumps({"paths": {"root": str(root)}}, ensure_ascii=False), encoding="utf-8")
            output = io.StringIO()
            stdin = io.StringIO(json.dumps({"source": "line", "id": "cli-1", "text": "CLI capture"}, ensure_ascii=False))
            import sys

            old_stdin = sys.stdin
            try:
                sys.stdin = stdin
                with redirect_stdout(output):
                    result = main(["--config", str(config_path), "capture-import", "line", "-"])
            finally:
                sys.stdin = old_stdin
            self.assertEqual(result, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["accepted_count"], 1)
            self.assertTrue((root / "captures/line/live.jsonl").exists())

    def test_cli_empty_capture_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            config_path.write_text(json.dumps({"paths": {"root": str(root)}}, ensure_ascii=False), encoding="utf-8")
            import sys

            old_stdin = sys.stdin
            try:
                sys.stdin = io.StringIO("")
                with redirect_stdout(io.StringIO()):
                    result = main(["--config", str(config_path), "capture-import", "line", "-"])
            finally:
                sys.stdin = old_stdin
            self.assertEqual(result, 2)

    def test_empty_import_is_unavailable_and_preserves_existing_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge = CaptureBridge(root)
            bridge.import_records("line", [{"source": "line", "id": "keep", "text": "保持"}], captured_at="2026-08-28T09:00:00Z")
            path = root / "captures/line/live.jsonl"
            before = path.read_text(encoding="utf-8")
            result = bridge.import_text("line", "", suffix=".jsonl")
            self.assertEqual(result.status, "unavailable")
            self.assertEqual(path.read_text(encoding="utf-8"), before)
            receipt = json.loads((root / "captures/line/live.jsonl.receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["outcome"], "unavailable")

    def test_verified_empty_is_explicit_and_does_not_create_live_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = CaptureBridge(root).import_text("slack", "", suffix=".jsonl", verified_empty=True)
            self.assertEqual(result.status, "verified_empty")
            self.assertFalse((root / "captures/slack/live.jsonl").exists())

    def test_source_marker_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            result = CaptureBridge(Path(directory)).import_records("slack", [{"id": "missing-source", "text": "曖昧"}])
            self.assertEqual(result.status, "rejected")
            self.assertEqual(result.rejected_count, 1)

    def test_oversized_nested_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            record = {"source": "screenpipe", "id": "large", "text": "ok", "elements": [{"value": "x" * 1000} for _ in range(100)]}
            result = CaptureBridge(Path(directory)).import_records("screenpipe", [record])
            self.assertEqual(result.status, "rejected")
            self.assertEqual(result.accepted_count, 0)

    def test_high_risk_body_is_redacted_before_capture_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = CaptureBridge(root).import_records(
                "slack",
                [{
                    "source": "slack",
                    "id": "restricted",
                    "timestamp": "2026-08-28T09:00:00Z",
                    "text": "medical diagnosis details",
                }],
            )
            self.assertEqual(result.accepted_count, 1)
            stored = json.loads((root / "captures/slack/live.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(stored["text"], "[REDACTED]")
            self.assertNotIn("diagnosis", (root / "captures/slack/live.jsonl").read_text(encoding="utf-8"))

    def test_nested_high_risk_text_and_bare_jwt_are_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue"
            CaptureBridge(root).import_records(
                "screenpipe",
                [{
                    "source": "screenpipe",
                    "id": "nested-restricted",
                    "timestamp": "2026-08-28T09:00:00Z",
                    "app": "Life IQ",
                    "window": "Life IQ",
                    "elements": [{"text": "diagnosis details", "value": jwt}],
                }],
            )
            stored_text = (root / "captures/screenpipe/live.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("diagnosis", stored_text)
            self.assertNotIn(jwt, stored_text)

    def test_receipt_binds_capture_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge = CaptureBridge(root)
            bridge.import_records("slack", [{
                "source": "slack",
                "id": "bound",
                "timestamp": "2026-08-28T09:00:00Z",
                "is_dm": True,
                "text": "original",
            }])
            path = root / "captures/slack/live.jsonl"
            path.write_text(json.dumps({"source": "slack", "id": "tampered", "text": "changed"}) + "\n", encoding="utf-8")
            from life_iq.sources.slack import SlackAdapter
            result = SlackAdapter(path=path).collect(SourceWindow("2026-08-28T00:00:00Z", "2026-08-29T00:00:00Z"))
            self.assertEqual(result.status.status, "failed")
            self.assertIn("content mismatch", result.status.diagnostic)

    def test_tampered_store_cannot_be_recertified_by_a_followup_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge = CaptureBridge(root)
            bridge.import_records("slack", [{
                "source": "slack",
                "id": "bound",
                "timestamp": "2026-08-28T09:00:00Z",
                "is_dm": True,
                "text": "original",
            }])
            path = root / "captures/slack/live.jsonl"
            receipt_path = bridge.receipt_path_for("slack")
            original_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            path.write_text(json.dumps({"source": "slack", "id": "tampered", "text": "changed"}) + "\n", encoding="utf-8")
            with self.assertRaises(CaptureImportError):
                bridge.import_records("slack", [{
                    "source": "slack",
                    "id": "new",
                    "timestamp": "2026-08-28T09:01:00Z",
                    "is_dm": True,
                    "text": "new",
                }])
            receipt_after = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt_after["capture_sha256"], original_receipt["capture_sha256"])

    def test_stale_receipt_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge = CaptureBridge(root)
            bridge.import_records("slack", [{
                "source": "slack",
                "id": "stale",
                "timestamp": "2026-08-28T09:00:00Z",
                "is_dm": True,
                "text": "old receipt",
            }])
            receipt_path = bridge.receipt_path_for("slack")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["completed_at"] = "2000-01-01T00:00:00+00:00"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            from life_iq.sources.slack import SlackAdapter
            result = SlackAdapter(path=root / "captures/slack/live.jsonl").collect(SourceWindow("2026-08-28T00:00:00Z", "2026-08-29T00:00:00Z"))
            self.assertEqual(result.status.status, "skipped")
            self.assertIn("stale", result.status.diagnostic)

    def test_file_and_stdin_capture_inputs_are_bounded_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "oversized.jsonl"
            input_path.write_bytes(b"x" * (MAX_CAPTURE_INPUT_BYTES + 1))
            with self.assertRaises(CaptureImportError):
                CaptureBridge(root).import_file("slack", input_path)

            import sys
            old_stdin = sys.stdin
            try:
                sys.stdin = io.StringIO("x" * (MAX_CAPTURE_INPUT_BYTES + 1))
                with self.assertRaises(CaptureImportError):
                    CaptureBridge(root).import_stdin("slack")
            finally:
                sys.stdin = old_stdin

    def test_existing_capture_store_has_a_retention_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "captures/slack/live.jsonl"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"x" * (MAX_CAPTURE_STORE_BYTES + 1))
            with self.assertRaises(CaptureImportError):
                CaptureBridge(root).import_records("slack", [{"source": "slack", "id": "new", "text": "new"}])


if __name__ == "__main__":
    unittest.main()
