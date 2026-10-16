# SPDX-License-Identifier: MIT
"""Standard-library checks for faithful evidence-derived manuscript evaluation."""
import csv
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("current_evaluation_test", ROOT / "tools/build_current_evaluation.py")
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


class CurrentEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = evaluation.build_evaluation()

    def checkout(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        names = {record["path"] for record in self.actual["provenance"]["input_files"]}
        names.update(evaluation.SOURCE_FILES)
        for name in names:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        return root

    def rewrite_csv(self, root, change):
        path = root / evaluation.CAMPAIGN / "per-seed.csv"
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            fields, rows = reader.fieldnames, list(reader)
        rows = change(rows)
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def test_all_methods_seeds_unfavorable_outcomes_and_rejected_budget_remain_visible(self):
        result = self.actual
        network = result["network"]
        self.assertEqual(len(network["per_seed"]), 140)
        self.assertEqual(network["seeds"], list(range(1000, 1020)))
        self.assertEqual({row["method"] for row in network["per_seed"]}, set(evaluation.METHODS))
        without_hve = next(row for row in network["methods"] if row["method"] == "without_hve")
        self.assertGreater(without_hve["metrics"]["invalid_acceptance_fraction_per_admitted"]["mean_over_seeds"], 0)
        self.assertEqual(network["recovery"]["right_censored_runs"], 140)
        self.assertEqual(network["recovery"]["observed_recoveries"], 0)
        self.assertEqual(result["aggregate_fidelity"]["admissible_cases"], 54)
        self.assertEqual(result["aggregate_fidelity"]["inadmissible_diagnostic_cases"], 18)
        self.assertEqual([row["passes_target"] for row in result["decoding_horizon"]["budgets"]],
                         [True, False, True])
        self.assertIs(result["physical_measurements"], False)
        self.assertIs(result["original_paper_reproduced"], False)

    def test_units_denominators_and_payload_arithmetic_are_explicit(self):
        data = self.actual
        self.assertEqual(data["parameters"]["k"], 6)
        self.assertEqual(data["payload_structure"]["single_ciphertext_bytes"], 7168)
        self.assertEqual(data["payload_structure"]["raw_two_ciphertext_bytes"], 14336)
        self.assertEqual(data["payload_structure"]["single_payload_only_airtime_ms"], "229.376")
        text = evaluation.markdown(data)
        row = next(row for row in data["network"]["methods"] if row["method"] == "da-ahe")
        delivery = row["metrics"]["valid_delivery_fraction_per_opportunity"]["mean_over_seeds"]
        self.assertIn(f"{100 * delivery:.6f}", text)
        self.assertIn("not an observed recovery time", text)
        self.assertIn("not physical energy", text)
        self.assertIn("not** the fresh CI campaign", text)

    def test_missing_seed_or_method_is_not_silently_dropped(self):
        root = self.checkout()
        self.rewrite_csv(root, lambda rows: rows[1:])
        with self.assertRaisesRegex(ValueError, "missing per-seed"):
            evaluation.build_evaluation(root)

    def test_csv_metric_change_cannot_be_hidden_by_existing_summary(self):
        root = self.checkout()

        def changed(rows):
            rows[0]["valid_delivery_fraction_per_opportunity"] = "0.99"
            return rows

        self.rewrite_csv(root, changed)
        with self.assertRaisesRegex(ValueError, "denominator identities|CSV and summary mean/SD mismatch"):
            evaluation.build_evaluation(root)

    def test_rehashed_summary_change_still_fails_csv_recomputation(self):
        root = self.checkout()
        path = root / evaluation.CAMPAIGN / "summary.json"
        summary = json.loads(path.read_text())
        summary["methods"]["da-ahe"]["metrics"]["valid_delay_mean_s"]["mean_over_seeds"] = 0.45
        path.write_text(json.dumps(summary) + "\n")
        manifest_path = root / evaluation.CAMPAIGN / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["summary_sha256"] = evaluation.sha256(path)
        manifest_path.write_text(json.dumps(manifest) + "\n")
        with self.assertRaisesRegex(ValueError, "CSV and summary mean/SD mismatch"):
            evaluation.build_evaluation(root)

    def test_censored_recovery_cannot_be_rewritten_as_a_completion(self):
        root = self.checkout()

        def changed(rows):
            rows[0]["recovery_completion_s"] = "33.0"
            return rows

        self.rewrite_csv(root, changed)
        with self.assertRaisesRegex(ValueError, "censored recovery was treated as observed"):
            evaluation.build_evaluation(root)

    def test_original_targets_are_never_consumed_and_config_drift_is_disclosed(self):
        root = self.checkout()
        forbidden = root / "experiments/paper_targets.json"
        forbidden.parent.mkdir()
        forbidden.write_text("INVALID JSON: must never be read")
        path = root / "simulation/config.json"
        config = json.loads(path.read_text())
        config["synthetic_review_probe"] = True
        path.write_text(json.dumps(config) + "\n")
        derived = evaluation.build_evaluation(root)
        comparison = derived["network"]["active_config_comparison"]
        self.assertIs(comparison["same_bytes"], False)
        self.assertEqual(comparison["different_top_level_keys"], ["synthetic_review_probe"])
        self.assertEqual(derived["network"]["per_seed"], self.actual["network"]["per_seed"])
        self.assertNotIn("experiments/paper_targets.json",
                         [record["path"] for record in derived["provenance"]["input_files"]])

    def test_rank_three_cannot_return_as_current_parameters(self):
        root = self.checkout()
        path = root / "configs/security_profile.json"
        data = json.loads(path.read_text())
        data["module_rank"] = 3
        path.write_text(json.dumps(data) + "\n")
        with self.assertRaisesRegex(ValueError, "rank-6 tuple"):
            evaluation.build_evaluation(root)

    def test_outputs_are_deterministic_checked_and_never_overwritten(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "derived"
        evaluation.write_outputs(output)
        self.assertEqual(evaluation.check_outputs(output)["status"], "verified_current_evaluation")
        with self.assertRaises(FileExistsError):
            evaluation.write_outputs(output)
        path = output / "CURRENT_RESULTS.md"
        path.write_text(path.read_text() + "invented claim\n")
        with self.assertRaisesRegex(ValueError, "missing or stale"):
            evaluation.check_outputs(output)

    def test_provenance_has_no_workstation_identifiers(self):
        exported = json.dumps(self.actual)
        self.assertNotIn("/Users/", exported)
        self.assertNotIn("/private/", exported)
        for record in (*self.actual["provenance"]["source_files"],
                       *self.actual["provenance"]["input_files"]):
            self.assertFalse(Path(record["path"]).is_absolute())
            self.assertEqual(len(record["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
