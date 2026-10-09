import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from life_iq.cli import main
from life_iq.config import Config


class LocalOnlyCliTests(unittest.TestCase):
    def test_local_run_writes_artifacts_without_mirroring_or_summarizer(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "local"
            mirror = base / "mounted-drive"
            mirror.mkdir()
            config = Config(root=root, drive_sync_path=mirror,
                            sync_outputs=True, summarizer_command="must-not-run")
            output = io.StringIO()
            with patch("life_iq.cli.load_config", return_value=config), \
                    patch("life_iq.cli.build_adapters", return_value=[]), \
                    patch("subprocess.run", side_effect=AssertionError("external command")) as command, \
                    redirect_stdout(output):
                self.assertEqual(main(["--local-only", "--no-weekly"]), 0)
            self.assertTrue(json.loads(output.getvalue())["ok"])
            self.assertTrue((root / "IMPORTANT_CONTEXT.md").exists())
            self.assertTrue((root / "state/ingest-state.json").exists())
            self.assertTrue((root / "state/reply-queue.json").exists())
            self.assertTrue(list((root / "knowledge/daily").glob("*.md")))
            self.assertEqual(list(mirror.iterdir()), [])
            command.assert_not_called()
            self.assertTrue(config.sync_outputs)
            self.assertEqual(config.summarizer_command, "must-not-run")

    def test_default_run_keeps_configured_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(root=Path(directory), sync_outputs=True,
                            summarizer_command="configured-hook")
            with patch("life_iq.cli.load_config", return_value=config), \
                    patch("life_iq.cli.build_adapters", return_value=[]), \
                    patch("life_iq.cli.LifeIQPipeline") as pipeline, \
                    redirect_stdout(io.StringIO()):
                pipeline.return_value.run.return_value.to_dict.return_value = {"ok": True}
                pipeline.return_value.run.return_value.ok = True
                self.assertEqual(main([]), 0)
            pipeline.assert_called_once_with(config, [])
            self.assertTrue(config.sync_outputs)

    def test_prepare_accepts_local_only_without_running_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Config(root=Path(directory))
            with patch("life_iq.cli.load_config", return_value=config), \
                    patch("life_iq.cli.prepare_candidates", return_value=(None, [])) as prepare, \
                    patch("life_iq.cli.LifeIQPipeline") as pipeline, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--local-only", "prepare"]), 0)
            self.assertFalse(prepare.call_args[0][0].sync_outputs)
            pipeline.assert_not_called()
