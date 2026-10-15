# SPDX-License-Identifier: MIT
"""Static-result accounting for the pinned estimator; no Sage dependency.

The fixed upstream coded-BKW implementation may derive more samples from the
original ones via signed sums, increasing Gaussian noise. Its cost['m'] counts
derived samples, not new independent public-key samples. Other attacks retain
the original budget check. Missing upstream fields remain unknown.

Pinned upstream contracts:
https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_bkw.py#L270-L277
https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_parameters.py#L81-L116
"""
from __future__ import annotations

import math
import hashlib
import json
from pathlib import Path


REQUIRED_ATTACKS = (
    "primal_usvp", "primal_bdd", "primal_hybrid", "primal_mitm_hybrid",
    "dual", "dual_hybrid", "coded_bkw",
)


def source_manifest(repo, names):
    """Hash exact tracked file bytes independently of checkout location."""
    root = Path(repo).resolve()
    records = []
    for name in sorted(names):
        path = root / name
        if not path.resolve().is_relative_to(root) or path.is_symlink():
            raise ValueError("upstream source must contain only regular in-tree files")
        data = path.read_bytes()
        records.append({"path": name, "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()})
    digest = hashlib.sha256(json.dumps(records, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    return {"files": records, "manifest_sha256": digest}


def summarize_attacks(records, minimum_bits=None):
    """An incomplete attack set never establishes the full estimated minimum."""
    names = [record["algorithm"] for record in records]
    if len(names) != len(set(names)) or any(name not in REQUIRED_ATTACKS for name in names):
        raise ValueError("duplicate or unrecognized attack identifier")
    if minimum_bits is not None and (not math.isfinite(minimum_bits) or minimum_bits <= 0):
        raise ValueError("threshold must be finite and positive")
    successes = []
    for record in records:
        if record["status"] == "success":
            bits = record.get("log2_rop")
            if bits is None or not math.isfinite(bits):
                raise ValueError("successful attack must have finite log2 operation count")
            successes.append(record)
    complete = len(successes) == len(REQUIRED_ATTACKS)
    minimum = min((record["log2_rop"] for record in successes), default=None)
    passed = complete and minimum >= minimum_bits if minimum_bits is not None else None
    status = "failed_incomplete_attacks" if not complete else (
        "estimate_complete" if minimum_bits is None else
        "passed_estimator_threshold" if passed else "failed_below_threshold")
    return {"status": status, "complete_attack_set": complete,
            "required_attacks": list(REQUIRED_ATTACKS),
            "failed_attacks": [name for name in REQUIRED_ATTACKS
                               if not any(r["algorithm"] == name and r["status"] == "success"
                                          for r in records)],
            "minimum_successful_attack_bits": minimum,
            "minimum_successful_attack": min(successes, key=lambda r: r["log2_rop"])["algorithm"]
                if successes else None,
            "lambda_est_bits": minimum if complete else None,
            "threshold_bits": minimum_bits, "threshold_passed": passed}


def sample_accounting(algorithm, cost, *, original_m=768, original_n=768,
                      original_q=2**32, original_error_stddev=3.2):
    """Validate original/derived sample accounting against pinned upstream rules.

    The amplification heuristic is an estimator assumption, not independent new
    observations. Validate its exact signed-combination count and Gaussian-noise
    multiplier; archive the upstream problem representation for review.
    """
    if type(original_m) is not int or original_m <= 0:
        raise ValueError("positive original independent sample budget required")
    used = cost.get("m")
    report = {"original_independent_samples":original_m, "reported_attack_samples":None,
              "sample_amplification":False, "amplification_terms":None,
              "original_error_stddev":str(original_error_stddev),
              "effective_error_stddev":None, "effective_problem_samples":None,
              "upstream_problem":str(cost.get("problem")) if cost.get("problem") is not None else None}
    if used is None:
        report["status"] = "sample_count_not_reported_by_upstream"
        return report
    if not math.isfinite(float(used)) or used <= 0:
        raise ValueError("attack sample count must be finite and positive")
    report["reported_attack_samples"] = str(used)
    if used <= original_m:
        report.update(status="within_original_sample_budget",
                      effective_problem_samples=str(original_m),
                      effective_error_stddev=str(original_error_stddev))
        return report
    if algorithm != "coded_bkw":
        raise ValueError("attack exceeds original independent sample budget without an audited amplification rule")
    problem = cost.get("problem")
    if problem is None:
        raise ValueError("coded-BKW derived samples require the effective upstream problem")
    if problem.n != original_n or problem.q != original_q:
        raise ValueError("coded-BKW amplification changed the original dimension or modulus")
    budget = int(problem.m)
    if problem.m != budget or budget < used:
        raise ValueError("effective sample budget does not cover the reported attack samples")
    sigma = float(problem.Xe.stddev)
    mean = float(problem.Xe.mean)
    if not math.isfinite(sigma) or mean != 0:
        raise ValueError("expected finite centered Gaussian amplification")
    # Upstream LWEParameters.amplify_m chooses the first k satisfying
    # binomial(m_original,k)*2**k - 1 >= requested_samples, then uses sqrt(k)*sigma.
    # The upstream problem rounds the requested count up, preserving this integer
    # inequality, so the minimal k can be independently checked using integers.
    terms = next((k for k in range(original_m+1)
                  if math.comb(original_m, k)*2**k-1 >= budget), None)
    if terms is None or terms < 1:
        raise ValueError("derived sample budget is unsupported by signed-combination amplification")
    expected_sigma = math.sqrt(terms)*original_error_stddev
    if not math.isclose(sigma, expected_sigma, rel_tol=1e-12, abs_tol=1e-12):
        raise ValueError("effective noise does not match the pinned signed-combination amplification rule")
    report.update(status="audited_upstream_signed_sum_amplification", sample_amplification=True,
                  amplification_terms=terms, effective_problem_samples=str(problem.m),
                  effective_error_stddev=str(problem.Xe.stddev),
                  amplification_rule="binomial(original_m,k)*2**k-1 >= effective_m; sigma_effective=sqrt(k)*sigma_original",
                  assumption="upstream estimator signed-sum heuristic; derived samples are not independent new public-key samples")
    return report
