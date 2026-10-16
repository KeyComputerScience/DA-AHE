# SPDX-License-Identifier: MIT
"""An expected nonzero exit is evidence only for the specified budget rejection."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("paper_reproducer", ROOT / "tools/reproduce_paper_evidence.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PaperReproducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "tool.py").write_text("# source\n")
        self.root_patch = patch.object(runner, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def invoke(self, data, side_effect=None):
        value = SimpleNamespace(returncode=2, stdout=json.dumps(data).encode(), stderr=b"")
        with patch.object(runner.subprocess, "run", return_value=value, side_effect=side_effect):
            return runner.execute(self.root / "run", "horizon-6-128-rejected", ["tool.py"], 2)

    def test_expected_budget_rejection_is_retained_as_passed_check(self):
        result = self.invoke({"status": "failed_decoding_horizon_budget", "batches": 6,
                              "max_batches_for_target": 5, "passes_target": False})
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["returncode"], 2)

    def test_validation_failure_does_not_count_as_expected_budget_rejection(self):
        result = self.invoke({"status": "failed_decoding_horizon_validation"})
        self.assertEqual(result["status"], "failed")

    def test_wrong_batch_cannot_relabel_a_different_rejection(self):
        result = self.invoke({"status": "failed_decoding_horizon_budget", "batches": 7,
                              "max_batches_for_target": 5, "passes_target": False})
        self.assertEqual(result["status"], "failed")

    def test_source_drift_during_command_fails(self):
        data = {"status": "failed_decoding_horizon_budget", "batches": 6,
                "max_batches_for_target": 5, "passes_target": False}
        def change(*args, **kwargs):
            (self.root / "tool.py").write_text("# changed during run\n")
            return SimpleNamespace(returncode=2, stdout=json.dumps(data).encode(), stderr=b"")
        self.assertEqual(self.invoke(data, change)["status"], "failed")

    def test_timeout_keeps_partial_raw_output_and_failed_receipt(self):
        error = subprocess.TimeoutExpired(["python", "tool.py"], 300, output=b"partial")
        result = self.invoke({}, error)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["timed_out"])
        self.assertEqual((self.root / "run/execution/horizon-6-128-rejected/stdout.log").read_bytes(),
                         b"partial")


if __name__ == "__main__":
    unittest.main()
