#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Budget a finite task horizon from the pinned rank-6 decoding union bound.

This consumes an archived outward interval endpoint; it does not rerun Sage or
establish a conditional per-fixed-key, lifetime, or full-system certificate.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = "evidence/independent/decoding/k6-cdt-03/decoding-bound.json"
REPORT_SHA256 = "2be1b88b34bdee74c852fd12c9020c4fed1870a117f4a63ab00d057944991335"
EXPECTED_INPUTS = {
    "module_rank": 6, "ring_degree": 256, "n": 1536,
    "q": 4294967296, "p": 65537, "sigma_key": 3.2, "poly_counts": [1, 2],
}
EXPECTED_PROFILES = {(Fraction("3.2"), 16), (Fraction("3.4"), 14),
                     (Fraction("3.6"), 12)}
PROBABILITY_SCOPE = (
    "joint probability over independently sampled random keygen coefficients and fresh "
    "honest encryption noises for one batch; not a worst-case bound conditioned on "
    "every fixed realized secret key"
)
ADAPTIVE_SCOPE = (
    "one choice from the finite declared profile/size library before fresh batch noise; "
    "joint random-key/history probability, not conditional on observed history or any fixed key"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_rational(value, name):
    """Never turn a rounded float into a probability used for acceptance."""
    require(isinstance(value, str), f"{name} must be an exact rational string")
    try:
        return Fraction(value)
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError(f"invalid exact rational: {name}") from error


def regular_file(root, relative):
    relative = Path(relative)
    require(not relative.is_absolute(), "artifact path must be relative to root")
    path = root / relative
    require(path.resolve().is_relative_to(root), "artifact path escapes root")
    require(path.is_file() and not path.is_symlink(), f"missing regular artifact: {relative}")
    return path


def read_json(root, relative):
    return json.loads(regular_file(root, relative).read_text(encoding="utf-8"))


def file_sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_report(report, profile):
    """Validate the declared bound's tuple/library/scope, without redoing its proof."""
    require(report.get("schema_version") == 1, "unsupported decoding report schema")
    require(report.get("status") == "passed_decoding_tail_bound"
            and report.get("execution_returncode") == 0, "decoding execution did not pass")
    require(report.get("original_paper_evidence") is False,
            "independent decoding report was relabeled")
    require(report.get("source_unchanged_after_run") is True,
            "decoding source changed during execution")
    require(report.get("probability_scope") == PROBABILITY_SCOPE,
            "unsupported decoding probability scope")
    require(report.get("inputs") == EXPECTED_INPUTS, "unsupported decoding parameter tuple")
    expected_profile = {key: value for key, value in EXPECTED_INPUTS.items()
                        if key != "poly_counts"}
    expected_profile.update(m=1536, ciphertext_bytes=7168)
    require(all(profile.get(key) == value for key, value in expected_profile.items()),
            "security profile differs from decoding parameters")
    require(profile.get("full_system_certified") is False,
            "decoding bound cannot establish full-system certification")
    binding = report["security_report_binding"]
    require(binding.get("sha256") == profile.get("security_report_sha256"),
            "decoding/security report hash binding differs")
    require(binding.get("lambda_est_bits") == profile.get("computed_estimator_bits")
            and binding.get("status") == "passed_estimator_threshold",
            "decoding/security estimate binding differs")

    declared_profiles = report["profiles"]
    require(len(declared_profiles) == len(EXPECTED_PROFILES), "unexpected decoding profile count")
    observed_profiles = set()
    for item in declared_profiles:
        maximum = item["batch_size"]
        require(type(maximum) is int and maximum > 0, "invalid profile capacity")
        pair = (Fraction(str(item["sigma_enc"])), maximum)
        require(pair in EXPECTED_PROFILES and pair not in observed_profiles,
                "unsupported or duplicate decoding profile")
        observed_profiles.add(pair)
        require(item.get("passed") is True, "profile decoding bound did not pass")
        require(item.get("key_reuse_exponent_inside_mgf") == maximum
                and item.get("product_terms") == 2 * EXPECTED_INPUTS["n"],
                "shared-key noise accounting differs")
        margin = item["margin"]
        delta = EXPECTED_INPUTS["q"] // EXPECTED_INPUTS["p"]
        carry = (maximum + 1) // 2
        require(margin == {"delta": delta, "scaling_remainder": 1,
                           "carry_abs_upper": carry,
                           "noise_tail_threshold": delta // 2 - carry - 1},
                "decoding scaling/carry margin differs")
        dominance = item["smaller_batch_dominance"]
        require(dominance.get("verified") is True
                and dominance.get("covered_batch_sizes") == [1, maximum]
                and dominance.get("direct_mgf_plus_and_minus_lower_ge_one") is True
                and dominance.get("zero_argument_exact_one") is True,
                "smaller-batch dominance is not verified")
        require(exact_rational(dominance["minimum_nonzero_inner_mgf_lower_exact_rational"],
                               "inner MGF lower endpoint") >= 1,
                "inner MGF lower endpoint is below one")
        checks = item["checks"]
        require(len(checks) == 2 and {check["poly_count"] for check in checks} == {1, 2},
                "unsupported polynomial-count checks")
        for check in checks:
            require(check.get("outward_upper_le_target") is True,
                    "fixed-profile outward bound did not pass")
            require(exact_rational(check["union_bound_log2"]["upper_exact_rational"],
                                   "fixed-profile log2 upper endpoint") <= -128,
                    "fixed-profile bound exceeds its recorded target")

    union = report["finite_adaptive_union"]
    require(union.get("status") == "passed_finite_adaptive_union"
            and union.get("passed") is True, "finite adaptive union did not pass")
    require(union.get("scope") == ADAPTIVE_SCOPE, "unsupported adaptive probability scope")
    count = sum(maximum for _, maximum in observed_profiles)
    require(union.get("configuration_count") == count == 42,
            "finite adaptive library does not contain the declared 42 configurations")
    require(union.get("poly_count_maximum") == 2, "unsupported maximum polynomial count")
    require(union.get("formula")
            == "sum_profile Nmax(profile) * U(profile,Nmax,poly_count_maximum)",
            "unsupported finite-union formula")
    enclosure = union["probability_upper_enclosure"]
    lower = exact_rational(enclosure["lower_exact_rational"], "probability lower endpoint")
    upper = exact_rational(enclosure["upper_exact_rational"], "probability upper endpoint")
    require(0 <= lower <= upper < 1 and upper > 0, "invalid probability enclosure")
    require(upper <= Fraction(1, 2**128), "adaptive union exceeds its recorded risk target")
    return upper


def load_certificate(root=ROOT):
    """Read only local in-tree artifacts; ignore archival absolute execution paths."""
    root = Path(root).resolve()
    report_path = regular_file(root, REPORT_PATH)
    require(file_sha256(report_path) == REPORT_SHA256, "pinned decoding report hash mismatch")
    report = read_json(root, REPORT_PATH)
    profile = read_json(root, "configs/security_profile.json")
    upper = validate_report(report, profile)
    security_path = regular_file(root, profile["security_report"])
    require(file_sha256(security_path) == profile["security_report_sha256"],
            "selected security report hash mismatch")
    security = json.loads(security_path.read_text(encoding="utf-8"))
    expected_security = {key: value for key, value in EXPECTED_INPUTS.items()
                         if key not in {"p", "poly_counts"}}
    expected_security.update(m=1536, plaintext_modulus=65537, ciphertext_bytes=7168)
    require(all(security["inputs"].get(key) == value
                for key, value in expected_security.items()),
            "selected security report parameter mismatch")
    require(security.get("lambda_est_bits") == profile["computed_estimator_bits"],
            "selected security report estimate mismatch")
    cdt_relative = str(Path(REPORT_PATH).parent / "sampler-cdts.json")
    require(file_sha256(regular_file(root, cdt_relative)) == report["sampler_cdt_file_sha256"],
            "archived sampler CDT hash mismatch")
    return upper


def decimal_display(value):
    """Display only; exact Fraction arithmetic makes all budget decisions."""
    with localcontext() as context:
        context.prec = 32
        return str(Decimal(value.numerator) / Decimal(value.denominator))


def horizon_budget(single_batch_upper, batches, target_risk):
    """Union bound B*U; independence across batches is not assumed."""
    require(isinstance(single_batch_upper, Fraction) and 0 < single_batch_upper < 1,
            "single-batch upper bound must be an exact rational in (0,1)")
    require(type(batches) is int and batches >= 0, "batches must be a nonnegative integer")
    require(isinstance(target_risk, Fraction) and 0 < target_risk < 1,
            "target risk must be an exact rational in (0,1)")
    uncapped = batches * single_batch_upper
    bounded = min(Fraction(1), uncapped)
    maximum = target_risk // single_batch_upper
    return {
        "status": "passed_decoding_horizon_budget" if bounded <= target_risk
                  else "failed_decoding_horizon_budget",
        "batches": batches,
        "single_batch_upper_exact_rational": str(single_batch_upper),
        "single_batch_upper_approx": decimal_display(single_batch_upper),
        "horizon_union_upper_exact_rational": str(bounded),
        "horizon_union_upper_approx": decimal_display(bounded),
        "uncapped_horizon_union_exact_rational": str(uncapped),
        "target_risk_exact_rational": str(target_risk),
        "target_risk_approx": decimal_display(target_risk),
        "max_batches_for_target": maximum,
        "passes_target": bounded <= target_risk,
        "max_batches_passes_exact_comparison": maximum * single_batch_upper <= target_risk,
        "next_batch_exceeds_target_exact_comparison":
            (maximum + 1) * single_batch_upper > target_risk,
        "independence_between_batches_assumed": False,
        "conditional_per_fixed_key_guarantee": False,
        "full_system_certified": False,
        "scope": "Finite-horizon joint random-key/history/fresh-noise decoding risk only.",
        "conditions": [
            "Each batch makes one choice from the declared 42 configurations, with at most "
            "two plaintext polynomials, before that batch's fresh encryption noises.",
            "The next batch's honest encryption noises are independent of the past; shared "
            "key coefficients and dependent batch outcomes are allowed.",
            "No source-subset selection after observing current-batch ciphertexts/noises.",
            "The task horizon is a predeclared finite cap on attempts, not only successful "
            "deliveries; noise-regenerating retries and reencryptions consume attempts.",
            "No arbitrary-history conditional, every-fixed-key, unlimited-lifetime, "
            "malicious-ciphertext, network, no-wrap or control guarantee is inferred.",
        ],
    }


def verify(root=ROOT, *, batches=1, target_risk=Fraction(1, 2**128)):
    result = horizon_budget(load_certificate(root), batches, target_risk)
    result.update(report=REPORT_PATH, report_sha256=REPORT_SHA256,
                  configuration_count=42, poly_count_maximum=2,
                  parameters=EXPECTED_INPUTS,
                  proof_reexecuted=False)
    return result


def write_new_record(root, output, result):
    """Exclusive creation only; never replace an existing evidence record."""
    root = Path(root).resolve()
    output = Path(output)
    path = output if output.is_absolute() else root / output
    require(path.resolve().is_relative_to(root), "output path must remain inside root")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(result, sort_keys=True, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--batches", type=int, default=1,
                        help="predeclared cap on fresh-noise batch attempts (default: 1)")
    parser.add_argument("--output", type=Path,
                        help="create a new JSON record inside root; never overwrite an existing file")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--target-bits", type=int,
                        help="target risk 2^-bits (default: 128)")
    target.add_argument("--target-risk", help="exact decimal or fraction, strictly between 0 and 1")
    args = parser.parse_args(argv)
    try:
        if args.target_risk is not None:
            risk = exact_rational(args.target_risk, "target risk")
        else:
            bits = 128 if args.target_bits is None else args.target_bits
            require(1 <= bits <= 4096, "target bits must be between 1 and 4096")
            risk = Fraction(1, 2**bits)
        result = verify(args.root, batches=args.batches, target_risk=risk)
        if args.output is not None:
            write_new_record(args.root, args.output, result)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["passes_target"] else 2
    except (ValueError, KeyError, TypeError, OSError, ZeroDivisionError) as error:
        message = (type(error).__name__ + " while accessing a local artifact or output record"
                   if isinstance(error, OSError) else str(error))
        print(json.dumps({"status": "failed_decoding_horizon_validation", "error": message,
                          "full_system_certified": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
