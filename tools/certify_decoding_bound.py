#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rigorous interval Chernoff bound for the finite reference CDT sampler.

Run with Sage-enabled Python. This certifies only the documented random-key,
honest-encryption decoding event, not security, control, memory or airtime.
"""
import argparse
from fractions import Fraction
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import platform
import sys
import time


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def cdt_counts(radius, cdf, bits=256):
    """Exact probabilities for bisect_right(CDF, uniform integer in [0,2^bits))."""
    if type(radius) is not int or radius < 0 or len(cdf) != 2 * radius + 1:
        raise ValueError("CDT support and CDF length disagree")
    previous = 0
    counts = []
    for boundary in cdf:
        if type(boundary) is not int or not previous <= boundary <= 1 << bits:
            raise ValueError("CDT boundaries must be monotone exact integers in range")
        counts.append(boundary - previous)
        previous = boundary
    if previous != 1 << bits:
        raise ValueError("CDT must cover the whole uniform-integer sample space")
    return tuple(zip(range(-radius, radius + 1), counts))


def decoding_threshold(q, p, batch_size):
    """Conservative margin for the exact centered-round decoder and scaling carry."""
    if type(batch_size) is not int or batch_size < 1:
        raise ValueError("positive integer batch size required")
    if p % 2 != 1 or q % 2 != 0 or q <= p:
        raise ValueError("proof requires odd p and even q greater than p")
    delta, remainder = divmod(q, p)
    if delta % 2 != 1 or remainder != 1:
        raise ValueError("proof requires odd Delta and q-p*Delta=1")
    carry = (batch_size + 1) // 2
    threshold = delta // 2 - carry - 1
    if threshold <= 0:
        raise ValueError("no positive decoding margin")
    return {"delta": delta, "scaling_remainder": remainder,
            "carry_abs_upper": carry, "noise_tail_threshold": threshold}


def tuple_binding(report, *, rank, degree, q, p, sigma_key):
    inputs = report["inputs"]
    expected = {"module_rank": rank, "ring_degree": degree, "q": q, "n": rank * degree,
                "m": rank * degree, "sigma_key": sigma_key}
    for name, value in expected.items():
        if inputs.get(name) != value:
            raise ValueError(f"security report parameter mismatch: {name}")
    if inputs.get("plaintext_modulus", p) != p:
        raise ValueError("security report plaintext modulus mismatch")
    return expected


def interval_record(value):
    lower, upper = value.lower().exact_rational(), value.upper().exact_rational()
    return {"lower_exact_rational": str(lower), "upper_exact_rational": str(upper),
            "lower_decimal": str(value.lower()), "upper_decimal": str(value.upper())}


def certify_profile(key_counts, enc_counts, *, rank, degree, sigma_key, sigma_enc,
                    batch_size, q, p, poly_counts, precision, target_bits, t_factor="1"):
    from sage.all import QQ, RealIntervalField
    field = RealIntervalField(precision)
    def rational(value):
        fraction = Fraction(str(value))
        return QQ(fraction.numerator) / fraction.denominator
    space = QQ(2)**256
    key = [(value, QQ(count) / space) for value, count in key_counts if count]
    enc = [(value, QQ(count) / space) for value, count in enc_counts if count]
    margin = decoding_threshold(q, p, batch_size)
    threshold, n = margin["noise_tail_threshold"], rank * degree
    # A Gaussian variance proxy selects a legal positive t only. It is not a
    # probability assumption: all subsequent sums use the exact finite CDT PMFs.
    proxy_variance = 2 * n * batch_size * rational(sigma_key)**2 * rational(sigma_enc)**2
    proxy_variance += batch_size * rational(sigma_enc)**2
    t = rational(t_factor) * threshold / proxy_variance
    if t <= 0:
        raise ValueError("Chernoff t must be positive")

    @lru_cache(maxsize=None)
    def mgf(argument):
        if argument == 0:
            return field(1)  # Exact PMF normalization, checked by cdt_counts.
        return sum((field(probability) * field(argument * value).exp()
                    for value, probability in enc), field(0))

    g_plus = sum((field(probability) * mgf(t * value)**batch_size
                  for value, probability in key), field(0))
    g_minus = sum((field(probability) * mgf(-t * value)**batch_size
                   for value, probability in key), field(0))
    m_plus, m_minus = mgf(t), mgf(-t)
    inner_mgfs = [mgf(sign * t * value) for value, _ in key for sign in (-1, 1)]
    nonzero_inner = [mgf(sign * t * value) for value, _ in key if value for sign in (-1, 1)]
    dominates = all(value.lower() >= 1 for value in inner_mgfs)
    dominates = dominates and m_plus.lower() >= 1 and m_minus.lower() >= 1
    # Enclose the maximum without assuming exact sampler symmetry.
    maximum = lambda a, b: field(min(a.lower(), b.lower()), max(a.upper(), b.upper()))
    g_max, m_max = maximum(g_plus, g_minus), maximum(m_plus, m_minus)
    checks = []
    for count in poly_counts:
        bound = (field(2 * degree * count).log() + 2 * n * g_max.log()
                 + batch_size * m_max.log() - field(t) * threshold) / field(2).log()
        upper = bound.upper().exact_rational()
        checks.append({"poly_count": count, "union_bound_log2": interval_record(bound),
                       "outward_upper_le_target": bool(upper <= -rational(target_bits)),
                       "target_log2_probability": str(-rational(target_bits))})
    return {"sigma_enc": sigma_enc, "batch_size": batch_size, "margin": margin,
            "t_exact_rational": str(t), "t_selection_proxy_variance": str(proxy_variance),
            "t_factor_exact_rational": str(rational(t_factor)),
            "product_terms": 2 * n, "key_reuse_exponent_inside_mgf": batch_size,
            "smaller_batch_dominance": {"verified": bool(dominates),
                "inner_mgf_checks": len(inner_mgfs), "zero_argument_exact_one": True,
                "minimum_nonzero_inner_mgf_lower_exact_rational": str(min(
                    value.lower().exact_rational() for value in nonzero_inner)) if nonzero_inner else None,
                "direct_mgf_plus_and_minus_lower_ge_one": bool(m_plus.lower() >= 1 and m_minus.lower() >= 1),
                "covered_batch_sizes": [1, batch_size]},
            "g_plus": interval_record(g_plus), "g_minus": interval_record(g_minus),
            "g_max_enclosure": interval_record(g_max), "m_plus": interval_record(m_plus),
            "m_minus": interval_record(m_minus), "m_max_enclosure": interval_record(m_max),
            "checks": checks, "passed": all(row["outward_upper_le_target"] for row in checks)}


def adaptive_union(profile_rows, *, poly_count, precision, target_bits):
    """Finite union over (sigma,N) before fresh batch noises are sampled."""
    from sage.all import QQ, RealIntervalField
    field = RealIntervalField(precision)
    if not all(row["smaller_batch_dominance"]["verified"] for row in profile_rows):
        return {"passed": False, "status": "failed_mgf_dominance_check"}
    total = field(0)
    for row in profile_rows:
        check = next(value for value in row["checks"] if value["poly_count"] == poly_count)
        upper = QQ(check["union_bound_log2"]["upper_exact_rational"])
        total += row["batch_size"] * (field(upper) * field(2).log()).exp()
    log2_bound = total.log() / field(2).log()
    from fractions import Fraction
    target = Fraction(str(target_bits))
    passed = log2_bound.upper().exact_rational() <= -QQ(target.numerator) / target.denominator
    return {"status": "passed_finite_adaptive_union" if passed else "failed_probability_target",
            "passed": bool(passed), "configuration_count": sum(row["batch_size"] for row in profile_rows),
            "poly_count_maximum": poly_count, "probability_upper_enclosure": interval_record(total),
            "log2_failure_upper_enclosure": interval_record(log2_bound),
            "formula": "sum_profile Nmax(profile) * U(profile,Nmax,poly_count_maximum)",
            "scope": "one choice from the finite declared profile/size library before fresh batch noise; joint random-key/history probability, not conditional on observed history or any fixed key",
            "excludes": "selection of source subsets after observing current-batch ciphertext/noise; unlimited lifetime batches"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module-rank", type=int, required=True)
    parser.add_argument("--ring-degree", type=int, default=256)
    parser.add_argument("--q", type=lambda value: int(value, 0), default=2**32)
    parser.add_argument("--p", type=int, default=65537)
    parser.add_argument("--sigma-key", type=float, default=3.2)
    parser.add_argument("--profiles", nargs="+", default=["3.2:16", "3.4:14", "3.6:12"])
    parser.add_argument("--poly-counts", nargs="+", type=int, default=[1, 2])
    parser.add_argument("--precision", type=int, default=256)
    parser.add_argument("--target-bits", type=float, default=128.0)
    parser.add_argument("--t-factor", default="1")
    parser.add_argument("--security-report", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; preserve earlier evidence")
    if args.module_rank < 1 or args.ring_degree < 2 or args.ring_degree & (args.ring_degree - 1):
        parser.error("positive rank and power-of-two degree required")
    if args.precision < 128 or not args.poly_counts or any(value < 1 for value in args.poly_counts):
        parser.error("precision >=128 and positive polynomial counts required")
    if not math.isfinite(args.target_bits) or args.target_bits <= 0:
        parser.error("positive finite probability target required")
    profiles = []
    for text in args.profiles:
        sigma, batch = text.split(":")
        sigma, batch = float(sigma), int(batch)
        if not math.isfinite(sigma) or not 0 < sigma <= 16 or batch < 1:
            parser.error("profiles must contain finite sigma in (0,16] and positive batch")
        profiles.append((sigma, batch))
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from daahe.mlwe import _gaussian_cdt
    from sage.env import SAGE_VERSION
    sources = {str(path.relative_to(root)): sha256(path) for path in
               (root / "src/daahe/mlwe.py", root / "src/daahe/ring.py", Path(__file__).resolve())}
    output = args.output.resolve()
    output.mkdir(parents=True)
    cdts, distributions = {}, {}
    for sigma in sorted({args.sigma_key, *(sigma for sigma, _ in profiles)}):
        radius, cdf = _gaussian_cdt(sigma)
        counts = cdt_counts(radius, cdf)
        data = {"sigma_argument": sigma, "radius": radius, "cdf": list(cdf),
                "sampler_uniform_bits": 256, "counts": [[value, count] for value, count in counts]}
        data["cdf_sha256"] = hashlib.sha256(canonical({"radius": radius, "cdf": list(cdf)})).hexdigest()
        cdts[str(sigma)], distributions[sigma] = data, counts
    write_json(output / "sampler-cdts.json", cdts)
    report = {"schema_version": 1, "status": "in_progress", "provenance": "independent_reproduction",
              "original_paper_evidence": False, "started_at": datetime.now(timezone.utc).isoformat(),
              "command": [sys.executable, *sys.argv], "sage_version": SAGE_VERSION,
              "python_version": platform.python_version(), "interval_precision_bits": args.precision,
              "inputs": {"module_rank": args.module_rank, "ring_degree": args.ring_degree,
                         "n": args.module_rank * args.ring_degree, "q": args.q, "p": args.p,
                         "sigma_key": args.sigma_key, "poly_counts": args.poly_counts},
              "source_sha256": sources, "sampler_cdt_file_sha256": sha256(output / "sampler-cdts.json"),
              "sampler": "actual finite 256-bit integer CDT of daahe.mlwe._gaussian_cdt",
              "target_log2_failure": -args.target_bits, "profiles": [],
              "probability_scope": "joint probability over independently sampled random keygen coefficients and fresh honest encryption noises for one batch; not a worst-case bound conditioned on every fixed realized secret key",
              "excluded_claims": ["confidentiality/security proof", "constant-time implementation",
                  "malicious ciphertext decoding", "lifetime/key reuse union bound across unlimited batches",
                  "control stability", "airtime", "memory", "plaintext data no-wrap"]}
    if args.security_report:
        security = json.loads(args.security_report.read_text())
        tuple_binding(security, rank=args.module_rank, degree=args.ring_degree, q=args.q,
                      p=args.p, sigma_key=args.sigma_key)
        report["security_report_binding"] = {"path": str(args.security_report.resolve()),
            "sha256": sha256(args.security_report), "status": security["status"],
            "lambda_est_bits": security.get("lambda_est_bits"),
            "note": "tuple/hash binding only; security estimator uses its own Gaussian model"}
    started = time.monotonic()
    for sigma, batch in profiles:
        row = certify_profile(distributions[args.sigma_key], distributions[sigma],
            rank=args.module_rank, degree=args.ring_degree, sigma_key=args.sigma_key,
            sigma_enc=sigma, batch_size=batch, q=args.q, p=args.p,
            poly_counts=args.poly_counts, precision=args.precision,
            target_bits=args.target_bits, t_factor=args.t_factor)
        row["key_cdf_sha256"] = cdts[str(args.sigma_key)]["cdf_sha256"]
        row["encryption_cdf_sha256"] = cdts[str(sigma)]["cdf_sha256"]
        report["profiles"].append(row)
        write_json(output / "decoding-bound.json", report)
        print(json.dumps({"sigma": sigma, "N": batch, "passed": row["passed"],
                          "log2_upper": [check["union_bound_log2"]["upper_decimal"] for check in row["checks"]]}), flush=True)
    report["source_unchanged_after_run"] = all(sha256(root / path) == digest for path, digest in sources.items())
    report["finite_adaptive_union"] = adaptive_union(report["profiles"], poly_count=max(args.poly_counts),
        precision=args.precision, target_bits=args.target_bits)
    report["status"] = ("passed_decoding_tail_bound" if all(row["passed"] for row in report["profiles"])
                        and report["finite_adaptive_union"]["passed"]
                        else "failed_probability_target")
    if not report["source_unchanged_after_run"]:
        report["status"] = "failed_source_changed"
    report["elapsed_seconds"] = time.monotonic()-started
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["execution_returncode"] = 0 if report["status"] == "passed_decoding_tail_bound" else 2
    write_json(output / "decoding-bound.json", report)
    write_json(output / "manifest.json", {"provenance": "independent_reproduction",
        "files": {path.name: sha256(path) for path in (output / "decoding-bound.json", output / "sampler-cdts.json")}})
    print(json.dumps({"finite_adaptive_union": report["finite_adaptive_union"],
                      "status": report["status"]}), flush=True)
    return report["execution_returncode"]


if __name__ == "__main__":
    raise SystemExit(main())
