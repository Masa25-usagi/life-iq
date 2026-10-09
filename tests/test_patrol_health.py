import importlib.util
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

spec = importlib.util.spec_from_file_location(
    "patrol_health", Path(__file__).resolve().parents[1] / "tools/patrol_health.py")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class PatrolHealthTests(unittest.TestCase):
    def test_backoff_and_recovery(self):
        state = {}
        for hours in (1, 2, 4, 6, 6):
            item = health.record(state, "slack", "timeout", 100)
            self.assertEqual(item["next_attempt_at"], 100 + hours * 3600)
        health.record(state, "slack", "success", 200)
        self.assertEqual(state["slack"]["failures"], 0)
        self.assertEqual(state["slack"]["next_attempt_at"], 200)
        self.assertEqual(health.record(state, "slack", "timeout", 300)["failures"], 1)

    def test_human_blocker_does_not_retry_hourly(self):
        for outcome in ("permission", "login", "account", "scope"):
            item = health.record({}, "line", outcome, 100)
            self.assertEqual(item["next_attempt_at"], 21700)

    def test_atomic_save(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state/health.json"
            health.save(path, {"slack": {"failures": 1}})
            health.save(path, {"slack": {"failures": 0}})
            self.assertEqual(health.json.loads(path.read_text())["slack"]["failures"], 0)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_interrupted_run_is_recovered_and_cooldown_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.json"
            health.save(path, {"line": {"outcome": "running", "updated_at": 0}})
            command = [sys.executable, str(Path(health.__file__)), "--state", str(path)]
            result = subprocess.run(command + ["plan"], capture_output=True, text=True, check=True)
            item = health.json.loads(result.stdout)["line"]
            self.assertEqual(item["outcome"], "interrupted")
            self.assertFalse(item["due"])
            result = subprocess.run(command + ["begin", "line"], capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_concurrent_begins_preserve_each_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.json"
            command = [sys.executable, str(Path(health.__file__)), "--state", str(path)]
            processes = [
                subprocess.Popen(command + ["begin", source],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for source in ("line", "discord", "slack", "x", "pipeline")
            ]
            results = [process.communicate() for process in processes]
            self.assertTrue(all(process.returncode == 0 for process in processes), results)
            state = health.json.loads(path.read_text())
            self.assertEqual({*state}, {"line", "discord", "slack", "x", "pipeline"})
            self.assertTrue(all(item["outcome"] == "running" for item in state.values()))
