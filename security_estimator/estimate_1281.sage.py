#!/usr/bin/env sage -python
"""Recompute the manuscript's fixed long-term M-LWE security estimate.

This script intentionally does not contain 128.1 as an estimator result.  It
computes every attack cost, writes JSON/CSV, and then checks whether the
computed minimum rounds to the manuscript value.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import subprocess
import sys


ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--estimator-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--expected-rounded", type=float, default=128.1)
    return parser.parse_args()


def git_commit(root: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()


def finite_log2(value, oo, sage_log):
    if value is None or value == oo:
        return None
    return float(sage_log(value, 2))


def main() -> int:
    args = parse_args()
    root = args.estimator_root.resolve()
    observed_commit = git_commit(root)
    if observed_commit != ESTIMATOR_COMMIT:
        raise SystemExit(
            f"wrong lattice-estimator commit: {observed_commit}; "
            f"expected {ESTIMATOR_COMMIT}"
        )

    sys.path.insert(0, str(root))
    from estimator import LWE, ND  # pylint: disable=import-outside-toplevel
    from estimator.reduction import ADPS16  # pylint: disable=import-outside-toplevel
    from sage.all import log, oo  # pylint: disable=import-outside-toplevel

    params = LWE.Parameters(
        n=768,
        q=2**32,
        Xs=ND.DiscreteGaussian(3.2),
        Xe=ND.DiscreteGaussian(3.2),
        m=768,
        tag="DA-AHE-long-term",
    )
    results = LWE.estimate(
        params,
        red_cost_model=ADPS16(mode="quantum"),
        red_shape_model="gsa",
        jobs=args.jobs,
        catch_exceptions=True,
        quiet=True,
    )

    rows = []
    for attack, result in sorted(results.items()):
        rop_bits = finite_log2(result.get("rop"), oo, log)
        mem_bits = finite_log2(result.get("mem"), oo, log)
        row = {
            "attack": attack,
            "rop_bits": rop_bits,
            "memory_bits": mem_bits,
            "beta": int(result["beta"]) if result.get("beta") is not None else None,
            "dimension": int(result["d"]) if result.get("d") is not None else None,
            "samples": int(result["m"]) if result.get("m") not in (None, oo) else None,
            "raw": repr(result),
        }
        rows.append(row)

    finite = [row for row in rows if row["rop_bits"] is not None]
    if not finite:
        raise SystemExit("no finite attack estimate was produced")
    minimum = min(finite, key=lambda row: row["rop_bits"])

    args.output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "estimator_commit": observed_commit,
        "sage_version": subprocess.check_output(
            [sys.executable, "-c", "import sage.env; print(sage.env.SAGE_VERSION)"],
            text=True,
        ).strip(),
        "parameters": {
            "ring_degree": 256,
            "module_rank": 3,
            "n": 768,
            "q": 2**32,
            "m": 768,
            "secret_distribution": "DiscreteGaussian(stddev=3.2)",
            "error_distribution": "DiscreteGaussian(stddev=3.2)",
            "reduction_shape": "GSA",
            "core_svp_model": "ADPS16 quantum, 2^(0.265 beta)",
        },
        "attacks": rows,
        "minimum": minimum,
    }
    (args.output_dir / "security_1281.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    with (args.output_dir / "security_1281.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=("attack", "rop_bits", "memory_bits", "beta", "dimension", "samples"),
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row[key] for key in writer.fieldnames})

    print(json.dumps(payload, indent=2, sort_keys=True))
    rounded = round(float(minimum["rop_bits"]), 1)
    if not math.isclose(rounded, args.expected_rounded, abs_tol=0.05):
        print(
            f"ERROR: computed minimum is {rounded:.1f} bits, not "
            f"{args.expected_rounded:.1f} bits; update the manuscript, do not hardcode it.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
