#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify saved finite-CDT record bytes, sampler identity and rational bounds.

This is record verification, not a replacement for the separate fresh Sage
outward-interval computation or a claim about fixed keys or lifetime failures.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from daahe.mlwe import _gaussian_cdt  # noqa: E402


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rational_interval(record):
    lower = Fraction(record["lower_exact_rational"])
    upper = Fraction(record["upper_exact_rational"])
    require(lower <= upper, "reversed rational interval")
    return lower, upper


def verify(directory, *, root=ROOT):
    directory, root = Path(directory).resolve(), Path(root).resolve()
    manifest = json.loads((directory / "manifest.json").read_text())
    for name, expected in manifest["files"].items():
        path = (directory / name).resolve()
        require(path.is_relative_to(directory), "manifest path escapes evidence directory")
        require(digest(path) == expected, "evidence checksum mismatch: " + name)
    report = json.loads((directory / "decoding-bound.json").read_text())
    require(report["status"] == "passed_decoding_tail_bound", "saved decoding computation did not pass")
    require(report["execution_returncode"] == 0, "saved computation has nonzero process exit")
    require(report["source_unchanged_after_run"] is True, "source changed during saved computation")
    require(report["original_paper_evidence"] is False, "independent record mislabels original provenance")
    for name, expected in report["source_sha256"].items():
        path = (root / name).resolve()
        require(path.is_relative_to(root), "source path escapes checkout")
        require(digest(path) == expected, "current source differs from saved computation: " + name)
    security = json.loads((root / "configs/security_profile.json").read_text())
    require(report["security_report_binding"]["sha256"] == security["security_report_sha256"],
            "decoding/security report binding mismatch")
    require(digest(root / security["security_report"]) == security["security_report_sha256"],
            "bound security report checksum mismatch")
    for name in ("module_rank", "ring_degree", "n", "q", "p", "sigma_key"):
        require(report["inputs"][name] == security[name], "decoding/security tuple mismatch: " + name)
    require(report["inputs"]["poly_counts"] == [1, 2], "both one- and two-polynomial paths are required")
    require(Fraction(str(report["target_log2_failure"])) <= -128, "decoding target weakened")
    require(digest(directory / "sampler-cdts.json") == report["sampler_cdt_file_sha256"],
            "sampler file binding mismatch")
    cdts = json.loads((directory / "sampler-cdts.json").read_text())
    required_profiles = {(3.2, 16), (3.4, 14), (3.6, 12)}
    require({(row["sigma_enc"], row["batch_size"]) for row in report["profiles"]} == required_profiles
            and len(report["profiles"]) == 3, "declared profile/size library is incomplete")
    for sigma in (3.2, 3.4, 3.6):
        radius, cdf = _gaussian_cdt(sigma)
        recorded = cdts[str(sigma)]
        require(recorded["radius"] == radius and recorded["cdf"] == list(cdf),
                "saved CDT differs from actual current sampler")
        counts, previous = [], 0
        for value, boundary in zip(range(-radius, radius + 1), cdf, strict=True):
            require(type(boundary) is int and previous <= boundary <= 2**256,
                    "CDT does not define an exact integer probability table")
            counts.append([value, boundary - previous])
            previous = boundary
        require(previous == 2**256 and recorded["counts"] == counts,
                "saved integer probabilities do not match the sampler")
        canonical = json.dumps({"radius": radius, "cdf": list(cdf)}, sort_keys=True,
                               separators=(",", ":")).encode()
        require(recorded["cdf_sha256"] == hashlib.sha256(canonical).hexdigest(), "CDT hash mismatch")
    checked = 0
    for row in report["profiles"]:
        require(row["passed"] and row["smaller_batch_dominance"]["verified"], "profile or dominance check failed")
        require(row["key_cdf_sha256"] == cdts[str(security["sigma_key"])]["cdf_sha256"], "key CDT binding mismatch")
        require(row["encryption_cdf_sha256"] == cdts[str(row["sigma_enc"])]["cdf_sha256"], "encryption CDT binding mismatch")
        require(sorted(check["poly_count"] for check in row["checks"]) == [1, 2], "polynomial path missing")
        for check in row["checks"]:
            _, upper = rational_interval(check["union_bound_log2"])
            require(upper <= -128 and check["outward_upper_le_target"] is True,
                    "saved fixed-profile rational upper bound exceeds target")
            require(Fraction(check["target_log2_probability"]) <= -128, "fixed-profile target weakened")
            checked += 1
    union = report["finite_adaptive_union"]
    require(union["passed"] and union["configuration_count"] == 42 and union["poly_count_maximum"] == 2,
            "finite adaptive union library is incomplete")
    require(rational_interval(union["log2_failure_upper_enclosure"])[1] <= -128,
            "adaptive union rational upper bound exceeds target")
    require(0 <= rational_interval(union["probability_upper_enclosure"])[0]
            <= rational_interval(union["probability_upper_enclosure"])[1] <= Fraction(1, 2**128),
            "adaptive union probability upper bound exceeds target")
    return {"status": "verified_saved_decoding_record", "fixed_profile_checks": checked,
            "finite_adaptive_union_count": 42, "exact_sampler_table_verified": True,
            "source_bytes_verified": True, "original_paper_evidence": False,
            "scope": report["probability_scope"],
            "note": "Record integrity and exact-rational comparisons; fresh Sage interval recomputation is a separate CI step."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
