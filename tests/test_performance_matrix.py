"""Plan provenance, configuration loading and orchestration contract tests."""
from copy import deepcopy
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from daahe.replay import load_control_config
from tools import run_performance_matrix as matrix


ROOT = Path(__file__).resolve().parents[1]


class PerformanceMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in ("simulation/performance_matrix.json", "simulation/paper_like_config.json",
                         "simulation/controller_fixture.json", "tools/run_performance_matrix.py",
                         "pyproject.toml", "requirements-dev.txt"):
            self._copy(relative)
        base = self._read("simulation/paper_like_config.json")
        for binding in base["bound_evidence_artifacts"].values():
            self._copy(binding["path"])
        # Minimal source bytes exercise provenance binding; integration tests
        # cover the campaign and export behavior.
        for relative in ("simulation/__init__.py", "simulation/engine.py",
                         "src/daahe/control.py", "tools/run_simulation_campaign.py",
                         "tools/verify_simulation_campaign.py",
                         "tools/export_performance_evaluation.py"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# source identity fixture: " + relative + "\n")

    def _copy(self, relative):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)

    def _read(self, relative):
        return json.loads((self.root / relative).read_text())

    def _write(self, relative, value):
        (self.root / relative).write_bytes(matrix.json_bytes(value))

    def _plan(self, **kwargs):
        return matrix.build_plan(self.root, "matrix", **kwargs)

    def test_default_cartesian_product_and_rank6(self):
        plan = self._plan()
        self.assertEqual(plan["node_counts"], [1000, 2000, 3000, 4000, 5000])
        self.assertEqual(plan["evaluation_seeds"], list(range(1000, 1020)))
        self.assertEqual(len(plan["methods"]), 7)
        self.assertEqual(plan["expected_runs"], 700)
        self.assertEqual([case["expected_runs"] for case in plan["cases"]], [140] * 5)
        for case in plan["cases"]:
            config = case["config"]["content"]
            self.assertEqual(config["cryptographic_parameters"]["module_rank"], 6)
            self.assertEqual(config["protected_ciphertext_bytes"], 7168)
            self.assertEqual(config["evaluation_seeds"], plan["evaluation_seeds"])
            self.assertEqual(config["methods"], plan["methods"])
        self.assertEqual(plan["timing"]["duration_s"], 300)
        self.assertEqual(plan["timing"]["warmup_s"], 30)
        self.assertEqual(plan["timing"]["disturbance_start_s"], 100)
        self.assertEqual(plan["timing"]["disturbance_end_s"], 130)
        self.assertEqual(plan["timing"]["control_interval_s"], 5)

    def test_common_initialization_changes_no_controller_coefficients(self):
        original = self._read("simulation/controller_fixture.json")
        plan = self._plan()
        effective = deepcopy(plan["controller"]["content"])
        self.assertEqual(set(effective["initial_action"].values()), {"nominal"})
        self.assertEqual(effective.pop("initialization_policy"), "common_nominal_synthetic")
        self.assertEqual(original["initial_action"]["dpp"], "fallback")
        effective["initial_action"] = original["initial_action"]
        self.assertEqual(effective, original)
        comparison = plan["comparison"]
        self.assertTrue(comparison["existing_admission_gate_G_preserved"])
        self.assertTrue(comparison["da_additional_robust_drift_gate_preserved"])
        self.assertFalse(comparison["identical_admitted_sets_claimed"])
        self.assertTrue(comparison["dpp_increment_coefficients_identical"])
        self.assertFalse(comparison["action_specific_dpp_calibration_claimed"])
        self.assertFalse(comparison["full_system_certified"])

    def test_smaller_sizes_and_paired_cohort_override(self):
        plan = self._plan(node_counts=[10, 4], seeds=[62, 61], jobs=2, bootstrap_resamples=1000)
        self.assertEqual(plan["node_counts"], [4, 10])
        self.assertEqual(plan["evaluation_seeds"], [61, 62])
        self.assertEqual(plan["expected_runs"], 28)
        for case in plan["cases"]:
            config = case["config"]["content"]
            self.assertLessEqual(config["gateways"], case["nodes"])
            self.assertLessEqual(config["local_contention_domains"], config["gateways"])
            self.assertLessEqual(config["backhaul_contention_domains"], config["gateways"])
            self.assertEqual(case["commands"]["campaign"][-2:], ["--jobs", "2"])
            self.assertEqual(case["commands"]["export"][-2:], ["--bootstrap-resamples", "1000"])

    def test_duration_override_is_explicit_and_valid(self):
        plan = self._plan(duration=30)
        timing = plan["timing"]
        self.assertEqual(timing["duration_scale"], 0.1)
        self.assertEqual(timing["warmup_s"], 3)
        self.assertEqual(timing["disturbance_start_s"], 10)
        self.assertEqual(timing["disturbance_end_s"], 13)
        for case in plan["cases"]:
            config = case["config"]["content"]
            self.assertEqual(config["sample_period_s"], 30)
            self.assertEqual(config["control_interval_s"], 5)
            self.assertEqual(config["drain_s"], 35)

    def test_invalid_overrides_are_rejected(self):
        for kwargs in ({"node_counts": [0]}, {"node_counts": [4, 4]},
                       {"seeds": [1]}, {"seeds": [1, 1]}, {"seeds": [-1, 2]},
                       {"duration": 0}, {"duration": float("nan")},
                       {"duration": float("inf")}, {"jobs": 0},
                       {"bootstrap_resamples": 0}, {"bootstrap_resamples": 1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self._plan(**kwargs)

    def test_non_rank6_configuration_is_rejected(self):
        config = self._read("simulation/paper_like_config.json")
        config["cryptographic_parameters"].update(module_rank=3, n=768, m=768)
        config["protected_ciphertext_bytes"] = 4096
        self._write("simulation/paper_like_config.json", config)
        with self.assertRaises(ValueError):
            self._plan()

    def test_common_nominal_fixture_loads_through_the_actual_loader(self):
        plan = self._plan(node_counts=[10], seeds=[61, 62])
        matrix.write_plan(self.root, plan)
        path = self.root / plan["controller"]["path"]
        loaded = load_control_config(path, allow_synthetic=True)
        self.assertEqual(set(loaded["initial_action"].values()), {"nominal"})
        self.assertEqual(loaded["fallback_id"], "fallback")
        self.assertFalse(loaded["runtime"].strict)
        with self.assertRaisesRegex(ValueError, "requires allow_synthetic"):
            load_control_config(path)

    def test_default_loader_initialization_contract_remains_in_force(self):
        path = self.root / "simulation/controller_fixture.json"
        loaded = load_control_config(path, allow_synthetic=True)
        self.assertEqual(loaded["initial_action"]["dpp"], loaded["fallback_id"])
        changed = self._read("simulation/controller_fixture.json")
        changed["initial_action"]["dpp"] = "nominal"
        self._write("simulation/controller_fixture.json", changed)
        with self.assertRaisesRegex(ValueError, "requires the fallback"):
            load_control_config(path, allow_synthetic=True)

    def test_loader_rejects_ambiguous_or_partial_common_initialization(self):
        original = self._read("simulation/controller_fixture.json")
        cases = []
        for value in (None, "", "common_nominal", True):
            data = deepcopy(original)
            data["initialization_policy"] = value
            cases.append(data)
        partial = deepcopy(original)
        partial["initialization_policy"] = "common_nominal_synthetic"
        cases.append(partial)
        wrong_mode = deepcopy(original)
        wrong_mode["initialization_policy"] = "common_nominal_synthetic"
        wrong_mode["initial_action"] = {method: "nominal" for method in original["initial_action"]}
        wrong_mode["hysteresis"]["mode_actions"]["N"] = "repair"
        cases.append(wrong_mode)
        path = self.root / "simulation/controller_fixture.json"
        for data in cases:
            with self.subTest(data=data["initialization_policy"]):
                self._write("simulation/controller_fixture.json", data)
                with self.assertRaises(ValueError):
                    load_control_config(path, allow_synthetic=True)

    def test_exact_seven_method_product_is_required(self):
        specification = self._read("simulation/performance_matrix.json")
        specification["methods"] = specification["methods"][:-1]
        self._write("simulation/performance_matrix.json", specification)
        with self.assertRaisesRegex(ValueError, "seven-method"):
            self._plan()

    def test_plan_identity_binds_commands_config_and_sources(self):
        first = self._plan()
        self.assertEqual(first, self._plan())
        self.assertEqual(matrix.plan_digest(first), first["plan_sha256"])
        self.assertIn("tools/export_performance_evaluation.py", first["source_hashes"])
        self.assertIn("simulation/performance_matrix.json", first["source_hashes"])
        self.assertIn("pyproject.toml", first["source_hashes"])
        self.assertIn("requirements-dev.txt", first["source_hashes"])
        self.assertTrue(first["runtime"]["python_version"])
        self.assertTrue(first["runtime"]["numpy_distribution_version"])
        altered = deepcopy(first)
        altered["cases"][0]["commands"]["export"][-1] = "1234"
        with self.assertRaisesRegex(ValueError, "plan digest"):
            matrix.validate_source_identity(self.root, altered)
        (self.root / "src/daahe/control.py").write_text("# different source\n")
        with self.assertRaisesRegex(ValueError, "source changed"):
            matrix.validate_source_identity(self.root, first)

    def test_runtime_identity_is_checked_before_execution(self):
        plan = self._plan()
        altered_runtime = {**plan["runtime"], "numpy_distribution_version": "changed"}
        with patch.object(matrix, "runtime_identity", return_value=altered_runtime):
            with self.assertRaisesRegex(ValueError, "runtime identity"):
                matrix.validate_source_identity(self.root, plan)

    def test_outside_repository_and_root_outputs_are_rejected(self):
        for output in (self.root, self.root.parent / "outside-matrix"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                matrix.build_plan(self.root, output)

    def test_freeze_writes_only_inputs_plan_and_source_snapshot(self):
        plan = self._plan(node_counts=[10], seeds=[61, 62])
        with patch.object(matrix.subprocess, "run", side_effect=AssertionError("child process forbidden")):
            matrix.write_plan(self.root, plan)
        matrix.validate_frozen_inputs(self.root, plan)
        self.assertTrue((self.root / "matrix/plan.json").is_file())
        self.assertFalse((self.root / "matrix/manifest.json").exists())
        self.assertFalse((self.root / "matrix/campaigns").exists())
        self.assertNotIn("results", plan)
        with self.assertRaisesRegex(ValueError, "never overwritten"):
            matrix.write_plan(self.root, plan)
        config = self.root / plan["cases"][0]["config"]["path"]
        config.write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "input checksum"):
            matrix.validate_frozen_inputs(self.root, plan)

    def test_plan_only_cli_cannot_launch_campaigns(self):
        with patch.object(matrix, "ROOT", self.root), patch.object(matrix, "execute_plan") as execute:
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                matrix.main(["--output", "matrix", "--node-counts", "10", "--seeds", "61,62",
                             "--bootstrap-resamples", "1000", "--plan-only"])
        execute.assert_not_called()
        reply = json.loads(output.getvalue())
        self.assertEqual(reply["expected_runs"], 14)
        self.assertTrue(reply["plan_only"])
        self.assertFalse((self.root / "matrix/manifest.json").exists())

    def test_execution_order_and_final_manifest_require_all_stages(self):
        plan = self._plan(node_counts=[4, 10], seeds=[61, 62])
        matrix.write_plan(self.root, plan)
        calls = []

        def child(argv, **kwargs):
            calls.append(argv)
            self.assertTrue(kwargs["check"])
            self.assertEqual(kwargs["cwd"], self.root)
            return SimpleNamespace(stdout=json.dumps({"verified_runs": 14,
                                   "independent_raw_recomputation": True,
                                   "deterministic_replay": False}))

        def record(root, current_plan, case, audit):
            self.assertFalse((self.root / "matrix/manifest.json").exists())
            self.assertEqual(audit["verified_runs"], 14)
            return {"nodes": case["nodes"], "verified_runs": 14}

        with patch.object(matrix.subprocess, "run", side_effect=child):
            with patch.object(matrix, "completed_case_record", side_effect=record):
                result = matrix.execute_plan(self.root, plan)
        self.assertEqual([argv[1] for argv in calls],
                         ["tools/run_simulation_campaign.py", "tools/verify_simulation_campaign.py",
                          "tools/export_performance_evaluation.py"] * 2)
        self.assertTrue(all(argv[0] == sys.executable for argv in calls))
        self.assertEqual(result["verified_runs"], 28)
        self.assertTrue(result["completed"])

    def test_failed_verification_prevents_export_and_matrix_results(self):
        plan = self._plan(node_counts=[10], seeds=[61, 62])
        matrix.write_plan(self.root, plan)
        failure = subprocess.CalledProcessError(2, ["verify"])
        with patch.object(matrix.subprocess, "run", side_effect=[SimpleNamespace(stdout=""), failure]) as child:
            with self.assertRaises(subprocess.CalledProcessError):
                matrix.execute_plan(self.root, plan)
        self.assertEqual(child.call_count, 2)
        self.assertFalse((self.root / "matrix/manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
