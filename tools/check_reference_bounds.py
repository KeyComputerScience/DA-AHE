#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Record exact no-wrap arithmetic; do not manufacture missing proof certificates."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from daahe.independent_evidence import source_snapshot, utc_now, write_json
from daahe.profiles import example_profiles


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not already exist")
    records = []
    for profile in example_profiles():
        limit = (65537 - 1) // 2
        lhs = profile.nmax * profile.coefficient_bound
        records.append({"profile": profile.name, "profile_digest": profile.digest,
                        "plaintext_modulus": 65537, "max_batch_size": profile.nmax,
                        "single_node_plain_bound": profile.coefficient_bound,
                        "aggregate_absolute_bound": lhs, "centered_limit": limit,
                        "no_wrap_arithmetic_passed": lhs <= limit,
                        "assumption": "every encoded data coefficient is within the checked profile bound; the encoder rejects out-of-range data",
                        "certified": False,
                        "remaining_gates": ["security estimate", "whole-batch decoding tail",
                                            "decryption noise bound", "full-protocol workspace",
                                            "deployment airtime", "uniform control uncertainty",
                                            "invariant domain and useful fallback bound"]})
    write_json(args.output, {"schema_version": 1, "origin": "independent_reimplementation",
                            "status": "arithmetic_checked_other_gates_pending",
                            "created_utc": utc_now(), "paper_reproduced": False,
                            "profiles": records,
                            "source_snapshot": source_snapshot(Path(__file__).resolve().parents[1])})
    return 0 if all(r["no_wrap_arithmetic_passed"] for r in records) else 2


if __name__ == "__main__":
    raise SystemExit(main())
