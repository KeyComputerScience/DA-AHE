# SPDX-License-Identifier: MIT
"""Task-risk boundaries and identity/scope rejection; standard-library unittest."""
from contextlib import redirect_stdout
from copy import deepcopy
from fractions import Fraction
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "decoding_horizon_checker", ROOT / "tools/check_decoding_horizon.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class DecodingHorizonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.checkout = Path(self.temporary.name)
        profile = json.loads((ROOT / "configs/security_profile.json").read_text())
        names = [checker.REPORT_PATH, "configs/security_profile.json", profile["security_report"],
                 str(Path(checker.REPORT_PATH).parent / "sampler-cdts.json")]
        for name in names:
            destination = self.checkout / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.report = json.loads((ROOT / checker.REPORT_PATH).read_text())
        self.profile = profile

    def test_real_report_uses_exact_endpoint_and_finite_library(self):
        result = checker.verify(self.checkout, batches=5)
        self.assertEqual(result["configuration_count"], 42)
        self.assertEqual(result["poly_count_maximum"], 2)
        self.assertEqual(result["max_batches_for_target"], 5)
        self.assertIs(result["passes_target"], True)
        self.assertIs(result["conditional_per_fixed_key_guarantee"], False)
        self.assertIs(result["full_system_certified"], False)
        self.assertIs(result["independence_between_batches_assumed"], False)
        self.assertIs(result["proof_reexecuted"], False)
        enclosure = self.report["finite_adaptive_union"]["probability_upper_enclosure"]
        self.assertEqual(Fraction(result["single_batch_upper_exact_rational"]),
                         Fraction(enclosure["upper_exact_rational"]))

    def test_six_batches_exceed_two_to_minus_128_without_independence_assumption(self):
        result = checker.verify(self.checkout, batches=6)
        self.assertIs(result["passes_target"], False)
        self.assertEqual(result["status"], "failed_decoding_horizon_budget")
        self.assertGreater(Fraction(result["horizon_union_upper_exact_rational"]),
                           Fraction(1, 2**128))

    def test_less_strict_target_has_exact_last_passing_integer(self):
        risk = Fraction(1, 2**120)
        last = checker.verify(self.checkout, batches=1458, target_risk=risk)
        following = checker.verify(self.checkout, batches=1459, target_risk=risk)
        self.assertEqual(last["max_batches_for_target"], 1458)
        self.assertIs(last["passes_target"], True)
        self.assertIs(following["passes_target"], False)
        self.assertIs(last["max_batches_passes_exact_comparison"], True)
        self.assertIs(last["next_batch_exceeds_target_exact_comparison"], True)

    def test_fraction_boundary_uses_union_not_rounded_decimal_or_independent_product(self):
        # Independent-product arithmetic would pass, but the justified union budget fails.
        result = checker.horizon_budget(Fraction(1, 10), 3, Fraction(29, 100))
        self.assertEqual(result["max_batches_for_target"], 2)
        self.assertIs(result["passes_target"], False)
        self.assertEqual(result["horizon_union_upper_exact_rational"], "3/10")
        self.assertLess(1 - Fraction(9, 10)**3, Fraction(29, 100))

    def test_budget_can_be_zero_or_smaller_than_one_batch(self):
        zero = checker.horizon_budget(Fraction(1, 10), 0, Fraction(1, 100))
        one = checker.horizon_budget(Fraction(1, 10), 1, Fraction(1, 100))
        self.assertEqual(zero["horizon_union_upper_exact_rational"], "0")
        self.assertEqual(zero["max_batches_for_target"], 0)
        self.assertIs(zero["passes_target"], True)
        self.assertIs(one["passes_target"], False)

    def test_union_bound_saturates_at_one(self):
        result = checker.horizon_budget(Fraction(1, 10), 11, Fraction(9, 10))
        self.assertEqual(result["horizon_union_upper_exact_rational"], "1")
        self.assertEqual(result["uncapped_horizon_union_exact_rational"], "11/10")
        self.assertIs(result["passes_target"], False)

    def test_noninteger_negative_or_boolean_horizon_is_rejected(self):
        for batches in (-1, 1.5, True, "5"):
            with self.subTest(batches=batches):
                with self.assertRaisesRegex(ValueError, "nonnegative integer"):
                    checker.horizon_budget(Fraction(1, 10), batches, Fraction(1, 2))

    def test_invalid_or_inexact_target_is_rejected(self):
        for risk in (Fraction(0), Fraction(1), Fraction(-1, 2), 0.5):
            with self.subTest(risk=risk):
                with self.assertRaisesRegex(ValueError, "exact rational in"):
                    checker.horizon_budget(Fraction(1, 10), 1, risk)

    def test_corrupted_report_hash_is_rejected_before_probability_is_used(self):
        path = self.checkout / checker.REPORT_PATH
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "pinned decoding report hash"):
            checker.verify(self.checkout)

    def test_bound_artifact_identity_is_required(self):
        cases = [(self.profile["security_report"], "selected security report hash"),
                 (str(Path(checker.REPORT_PATH).parent / "sampler-cdts.json"), "sampler CDT hash")]
        for relative, match in cases:
            with self.subTest(artifact=relative):
                path = self.checkout / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(ValueError, match):
                    checker.verify(self.checkout)
                path.write_bytes(original)

    def test_wrong_report_parameters_fail_semantic_validation(self):
        for key, value in (("module_rank", 3), ("n", 768), ("q", 3329)):
            with self.subTest(parameter=key):
                report = deepcopy(self.report)
                report["inputs"][key] = value
                with self.assertRaisesRegex(ValueError, "unsupported decoding parameter tuple"):
                    checker.validate_report(report, self.profile)

    def test_current_profile_cannot_bind_legacy_rank_three_parameters(self):
        path = self.checkout / "configs/security_profile.json"
        profile = deepcopy(self.profile)
        profile.update(module_rank=3, n=768, m=768, ciphertext_bytes=4096)
        path.write_text(json.dumps(profile))
        with self.assertRaisesRegex(ValueError, "profile differs from decoding"):
            checker.verify(self.checkout)

    def test_adaptive_bound_cannot_be_relabelled_as_fixed_key_conditional(self):
        report = deepcopy(self.report)
        report["finite_adaptive_union"]["scope"] = "conditional bound for every fixed key"
        with self.assertRaisesRegex(ValueError, "unsupported adaptive probability scope"):
            checker.validate_report(report, self.profile)

    def test_library_and_shared_key_proof_scope_cannot_be_silently_widened(self):
        cases = [
            (lambda r: r["finite_adaptive_union"].update(configuration_count=3), "42 configurations"),
            (lambda r: r["finite_adaptive_union"].update(poly_count_maximum=3), "polynomial count"),
            (lambda r: r["profiles"][0]["smaller_batch_dominance"].update(verified=False),
             "smaller-batch dominance"),
            (lambda r: r["profiles"][0].update(key_reuse_exponent_inside_mgf=1),
             "shared-key noise accounting"),
            (lambda r: r["profiles"][0]["margin"].update(scaling_remainder=0), "scaling/carry"),
        ]
        for change, match in cases:
            with self.subTest(rejection=match):
                report = deepcopy(self.report)
                change(report)
                with self.assertRaisesRegex(ValueError, match):
                    checker.validate_report(report, self.profile)

    def test_rounded_decimal_is_never_used_for_budget_decisions(self):
        report = deepcopy(self.report)
        upper = checker.validate_report(report, self.profile)
        report["finite_adaptive_union"]["probability_upper_enclosure"]["upper_decimal"] = "0"
        self.assertEqual(checker.validate_report(report, self.profile), upper)

    def test_invalid_exact_risk_text_is_rejected(self):
        for text in ("nan", "Infinity", "1/0"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, "invalid exact rational"):
                    checker.exact_rational(text, "target risk")

    def test_external_artifact_path_is_rejected_without_reading_other_directories(self):
        path = self.checkout / "configs/security_profile.json"
        profile = deepcopy(self.profile)
        profile["security_report"] = "/not/an/allowed/local/artifact.json"
        path.write_text(json.dumps(profile))
        with self.assertRaisesRegex(ValueError, "artifact path must be relative"):
            checker.verify(self.checkout)

    def test_cli_exit_code_matches_budget_without_claiming_system_certificate(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = checker.main(["--root", str(self.checkout), "--batches", "5"])
        self.assertEqual(code, 0)
        self.assertIs(json.loads(output.getvalue())["full_system_certified"], False)
        output = io.StringIO()
        with redirect_stdout(output):
            code = checker.main(["--root", str(self.checkout), "--batches", "6"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "failed_decoding_horizon_budget")


    def test_new_output_records_pass_and_expected_rejection_without_overwrite(self):
        for batches, expected_code in ((5, 0), (6, 2)):
            with self.subTest(batches=batches):
                relative = f"new-evidence/budget-{batches}.json"
                output = io.StringIO()
                with redirect_stdout(output):
                    code = checker.main(["--root", str(self.checkout), "--batches", str(batches),
                                         "--output", relative])
                self.assertEqual(code, expected_code)
                path = self.checkout / relative
                original = path.read_bytes()
                record = json.loads(original)
                self.assertEqual(record, json.loads(output.getvalue()))
                self.assertEqual(record["passes_target"], expected_code == 0)
                with redirect_stdout(io.StringIO()):
                    code = checker.main(["--root", str(self.checkout), "--batches", str(batches),
                                         "--output", relative])
                self.assertEqual(code, 2)
                self.assertEqual(path.read_bytes(), original)

    def test_output_cannot_escape_local_root(self):
        with self.assertRaisesRegex(ValueError, "output path must remain inside root"):
            checker.write_new_record(self.checkout, "../outside-risk-record.json", {})


if __name__ == "__main__":
    unittest.main()
