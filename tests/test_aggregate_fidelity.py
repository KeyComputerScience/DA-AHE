# SPDX-License-Identifier: MIT
"""Standard-library tests for aggregate fidelity and independent recomputation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("aggregate_fidelity_test", ROOT / "tools/check_aggregate_fidelity.py")
fidelity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fidelity)
PROFILES = {profile.name: profile for profile in fidelity.example_profiles()}


class AggregateFidelityTests(unittest.TestCase):
    def make_bundle(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "bundle"
        result = fidelity.run_experiment(output, seeds=[7], families=["zero"],
                                        batch_sizes=[1, 16], profiles=["pi0", "pi2"])
        self.assertEqual(result["cases"], 4)
        return output

    def test_full_support_integer_lifting_is_reversible_but_not_additive(self):
        impulse = [[1] + [0] * 239, [0] * 240]
        one = fidelity.evaluate_case([impulse], PROFILES["pi0"])
        two = fidelity.evaluate_case([impulse, impulse], PROFILES["pi0"])
        self.assertEqual(one["metrics"]["integer_lifting_aggregation"]["combined"]["squared_error"], 0)
        reconstructed = two["vectors"]["inverse_summed_full_transform"]
        self.assertEqual(reconstructed[0], 0)  # True sum at this location is 2.
        self.assertEqual(reconstructed[2], 1)  # True sum at this location is 0.
        self.assertEqual(two["metrics"]["integer_lifting_aggregation"]["combined"]["squared_error"], 5)

    def test_single_source_has_no_lifting_or_aggregate_vs_individual_error(self):
        for name in ("pi0", "pi1", "pi2"):
            with self.subTest(profile=name):
                case = fidelity.evaluate_case(fidelity.generate_sources("mixed_step_noise", 41, 1), PROFILES[name])
                for error in ("integer_lifting_aggregation", "aggregate_minus_sum_individual"):
                    self.assertEqual(case["metrics"][error]["combined"]["squared_error"], 0)
                self.assertGreater(case["metrics"]["total_selected_quantized_aggregate"]["combined"]["squared_error"], 0)

    def test_attribution_keeps_cross_terms_and_matches_actual_profile_reconstruction(self):
        sources = fidelity.generate_sources("mixed_step_noise", 14, 12)
        profile = PROFILES["pi2"]
        case = fidelity.evaluate_case(sources, profile)
        encoded = [fidelity.encode_channels(source, profile.support, profile.delta_q,
                                           profile.coefficient_bound) for source in sources]
        recovered = fidelity.reconstruct_channels(fidelity.add_vectors(encoded), profile.support, profile.delta_q)
        self.assertEqual(case["vectors"]["inverse_selected_quantized_sum"], list(recovered[0] + recovered[1]))
        attribution = case["attribution"]
        total = case["metrics"]["total_selected_quantized_aggregate"]["combined"]["squared_error"]
        self.assertEqual(total, attribution["total_squared_error"])
        self.assertEqual(total, sum(attribution["component_squared_errors"]) + attribution["twice_pairwise_error_inner_products"])
        self.assertNotEqual(attribution["twice_pairwise_error_inner_products"], 0)

    def test_capacity_exceedances_are_separately_counted_diagnostics(self):
        rows = []
        for name, size, allowed in (("pi0", 16, True), ("pi1", 14, True),
                ("pi1", 16, False), ("pi2", 12, True), ("pi2", 14, False), ("pi2", 16, False)):
            with self.subTest(profile=name, size=size):
                case = fidelity.evaluate_case(fidelity.generate_sources("constant", 1, size), PROFILES[name])
                self.assertIs(case["profile_capacity_admissible"], allowed)
                self.assertIs(case["actual_aggregate_data_no_wrap"], True)
                result = fidelity.summary_records({"profiles": [name], "batch_sizes": [size]}, [case])
                row = result["rows"][0]
                self.assertEqual(row["admissible_cases"], 1 if allowed else 0)
                self.assertEqual(row["inadmissible_diagnostic_cases"], 0 if allowed else 1)
                rows.append(row)
        self.assertEqual(len(rows), 6)

    def test_zero_and_cancelled_reference_prd_are_undefined_even_with_error(self):
        x = fidelity.generate_sources("mixed_step_noise", 4, 1)[0]
        negative = [[-value for value in channel] for channel in x]
        for sources in ([x, negative], fidelity.generate_sources("zero", 4, 16)):
            case = fidelity.evaluate_case(sources, PROFILES["pi0"])
            self.assertEqual(case["vectors"]["true_source_integer_sum"], [0] * 480)
            for metric in case["metrics"].values():
                self.assertIsNone(metric["combined"]["prd_percent"])
                self.assertEqual(metric["combined"]["prd_status"], "undefined_zero_reference_energy")
        measured = fidelity.metrics([1] + [0] * 479, [0] * 480)["combined"]
        self.assertGreater(measured["rmse_integer_counts"], 0)
        self.assertIsNone(measured["prd_percent"])
        with self.assertRaisesRegex(ValueError, "exceeds the profile bound"):
            fidelity.evaluate_case([[[100000] * 240, [100000] * 240]], PROFILES["pi0"])

    def test_integer_signal_generation_is_seeded_and_paired(self):
        for family in fidelity.FAMILIES:
            self.assertEqual(fidelity.generate_sources(family, 13, 12), fidelity.generate_sources(family, 13, 16)[:12])
        smooth = fidelity.generate_sources("smooth_triangle", 1, 1)
        self.assertNotEqual(smooth, fidelity.generate_sources("smooth_triangle", 2, 1))
        self.assertTrue(all(type(value) is int for source in smooth for channel in source for value in channel))

    def test_bundle_recomputes_frozen_source_runs_and_rejects_overwrite(self):
        bundle = self.make_bundle()
        self.assertEqual(fidelity.verify_evidence(bundle)["cases"], 4)
        result = subprocess.run([sys.executable, str(bundle / "source/tools/check_aggregate_fidelity.py"),
                                 "--verify", str(bundle)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        index = json.loads((bundle / "index.json").read_text())
        self.assertIs(index["paper_table_iii_reproduced"], False)
        self.assertIs(index["physical_measurements"], False)
        self.assertTrue(all(not Path(part).is_absolute() for part in index["command"]))
        with self.assertRaises(FileExistsError):
            fidelity.run_experiment(bundle)

    def test_default_matrix_runs_and_recomputes_all_72_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            self.assertEqual(fidelity.run_experiment(output)["cases"], 72)
            self.assertEqual(fidelity.verify_evidence(output)["cases"], 72)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(sum(row["admissible_cases"] for row in summary["rows"]), 54)
            self.assertEqual(sum(row["inadmissible_diagnostic_cases"] for row in summary["rows"]), 18)
            self.assertLess(max(path.stat().st_size for path in output.rglob("*") if path.is_file()), 5_000_000)
            self.assertLess(sum(path.stat().st_size for path in output.rglob("*") if path.is_file()), 20_000_000)
            index = json.loads((output / "index.json").read_text())
            self.assertNotIn("/Users/", json.dumps(index))

    def test_integer_arrays_are_exact_despite_floating_metric_tolerance(self):
        self.assertFalse(fidelity.equal_values([0.0], [0]))
        self.assertFalse(fidelity.equal_values([0.00000000000001], [0]))
        self.assertTrue(fidelity.equal_values(1.0 + 1e-13, 1.0))

    def test_raw_data_changes_fail_hash_validation(self):
        bundle = self.make_bundle()
        record = json.loads((bundle / "index.json").read_text())["cases"][0]
        with (bundle / record["path"]).open("a") as stream:
            stream.write(" ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            fidelity.verify_evidence(bundle)

    def test_rehashed_invented_metric_still_fails_independent_recomputation(self):
        bundle = self.make_bundle()
        record = json.loads((bundle / "index.json").read_text())["cases"][0]
        path = bundle / record["path"]
        data = json.loads(path.read_text())
        data["metrics"]["total_selected_quantized_aggregate"]["combined"]["squared_error"] = 99
        path.write_text(json.dumps(data) + "\n")
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for entry in manifest["files"]:
            if entry["path"] == record["path"]:
                entry.update(size=path.stat().st_size, sha256=fidelity.digest(path))
        manifest_path.write_text(json.dumps(manifest) + "\n")
        with self.assertRaisesRegex(ValueError, "case recomputation mismatch"):
            fidelity.verify_evidence(bundle)


if __name__ == "__main__":
    unittest.main()
