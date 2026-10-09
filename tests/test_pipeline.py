# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com

import tempfile
import unittest
from pathlib import Path

from life_iq.config import Config
from life_iq.pipeline import LifeIQPipeline
from life_iq.sources.gmail import GmailAdapter
from life_iq.sources.line import LineAdapter


class PipelineTests(unittest.TestCase):
    def test_run_writes_artifacts_and_second_run_dedupes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = Config(root=root, sync_outputs=False)
            adapter = GmailAdapter(records=[{"id": "m1", "timestamp": "2026-08-26T12:00:00+09:00", "subject": "締切", "snippet": "確認", "importance": 1}])
            pipeline = LifeIQPipeline(config, [adapter])
            first = pipeline.run(run_at="2026-08-27T05:00:00+09:00", write_weekly=True)
            self.assertEqual(len(first.events), 1)
            self.assertTrue((root / "knowledge/daily/2026-08-26.md").exists())
            self.assertTrue((root / "knowledge/summaries/weekly/2026-W35.md").exists())
            self.assertTrue((root / "IMPORTANT_CONTEXT.md").exists())
            second = pipeline.run(run_at="2026-08-27T05:00:00+09:00", write_weekly=False)
            self.assertEqual(len(second.events), 0)
            self.assertGreaterEqual(second.duplicate_count, 1)
            state_text = (root / "state/ingest-state.json").read_text(encoding="utf-8")
            self.assertNotIn("締切", state_text)

    def test_pipeline_immediately_upserts_reply_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = Config(root=root, drive_sync_path=root / "not-mounted")
            adapter = LineAdapter(records=[{
                "id": "line-inbound",
                "timestamp": "2026-08-26T12:00:00+09:00",
                "conversation_id": "chat-1",
                "conversation_type": "friend",
                "conversation_name": "友達",
                "direction": "inbound",
                "text": "元気？",
            }])
            result = LifeIQPipeline(config, [adapter]).run(run_at="2026-08-27T05:00:00+09:00", write_weekly=False)
            self.assertEqual(len(result.reply_candidates), 1)
            queue_text = (root / "state/reply-queue.json").read_text(encoding="utf-8")
            self.assertIn("line-inbound", queue_text)
            self.assertIn("AI代理", (root / "knowledge/replies/pending.md").read_text(encoding="utf-8"))
