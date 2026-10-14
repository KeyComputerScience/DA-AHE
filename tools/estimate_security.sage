#!/usr/bin/env sage
# SPDX-License-Identifier: MIT
"""Run only on reviewer request; no estimator output is shipped as if measured.

API verified against the official repository at the pinned commit:
https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84
The upstream RC.ADPS16 default is CLASSICAL; quantum mode must be explicit.
"""
import argparse
import contextlib
import csv
import hashlib
import importlib.metadata
import io
import json
import math
import platform
import subprocess
import sys
import traceback
from functools import partial
from pathlib import Path

from sage.all import RR, log, oo
from sage.env import SAGE_VERSION
from estimator_result_adapter import sample_accounting

PINNED_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"


def git(repo, *arguments):
    return subprocess.check_output(["git", "-C", str(repo), *arguments], text=True).strip()


def json_value(value):
    """Keep exact Sage representations; do not overflow huge rop through float."""
    if value is None:
        return None
    return str(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator", type=Path, required=True, help="clean local checkout of the pinned upstream repository")
    parser.add_argument("--output", type=Path, required=True, help="new directory for actual execution logs")
    parser.add_argument("--minimum-bits", type=float, default=float(128.1))
    args = parser.parse_args()
    if not math.isfinite(args.minimum_bits) or args.minimum_bits <= 0:
        parser.error("minimum bits must be finite and positive")
    repo = args.estimator.resolve()
    if git(repo, "rev-parse", "HEAD") != PINNED_COMMIT:
        parser.error("estimator HEAD differs from pinned commit")
    if git(repo, "status", "--porcelain", "--untracked-files=normal"):
        parser.error("estimator repository must be clean, including untracked source files")
    if args.output.exists():
        parser.error("output must not exist; preserve previous evidence instead of overwriting it")
    args.output.mkdir(parents=True)
    sys.path.insert(0, str(repo))
    from estimator import LWE, ND
    from estimator.reduction import ADPS16
    import estimator
    if not Path(estimator.__file__).resolve().is_relative_to(repo):
        raise RuntimeError("imported estimator does not belong to the verified checkout")

    parameters = LWE.Parameters(n=768, q=2**32, Xs=ND.DiscreteGaussian(3.2),
                                Xe=ND.DiscreteGaussian(3.2), m=768, tag="DA-AHE fixed public-key instance")
    quantum = ADPS16(mode="quantum")
    attacks = {
        "primal_usvp": partial(LWE.primal_usvp, red_cost_model=quantum, red_shape_model="gsa"),
        "primal_bdd": partial(LWE.primal_bdd, red_cost_model=quantum, red_shape_model="gsa"),
        "primal_hybrid": partial(LWE.primal_hybrid, mitm=False, babai=False,
                                  red_cost_model=quantum, red_shape_model="gsa"),
        "primal_mitm_hybrid": partial(LWE.primal_hybrid, mitm=True, babai=True,
                                       red_cost_model=quantum, red_shape_model="gsa"),
        "dual": partial(LWE.dual, red_cost_model=quantum),
        "dual_hybrid": partial(LWE.dual_hybrid, red_cost_model=quantum),
        "coded_bkw": LWE.coded_bkw,
    }
    records = []
    capture = io.StringIO()
    for name, attack in attacks.items():
        record = {"algorithm": name, "status": "failed", "rop": None, "log2_rop": None,
                  "beta": None, "lattice_dimension": None, "sample_count": None, "memory": None}
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            print("===", name, "===")
            try:
                cost = attack(parameters)
                print(repr(cost))
                record["full_cost"] = {str(k): json_value(v) for k, v in cost.items()}
                rop = cost.get("rop")
                if rop is None or rop == oo or not rop > 0:
                    raise ValueError("required attack did not produce a finite positive operation count")
                bits = float(log(RR(rop), 2))
                if not math.isfinite(bits):
                    raise ValueError("nonfinite log2 operation count")
                accounting = sample_accounting(name, cost, original_m=int(parameters.m),
                    original_n=int(parameters.n), original_q=int(parameters.q),
                    original_error_stddev=float(parameters.Xe.stddev))
                used_samples = cost.get("m")
                record.update(status="success", rop=str(rop), log2_rop=bits,
                              beta=json_value(cost.get("beta", cost.get("β"))),
                              lattice_dimension=json_value(cost.get("d")), sample_count=json_value(used_samples),
                              memory=json_value(cost.get("mem")),
                              sample_accounting=accounting,
                              full_cost={str(k): json_value(v) for k, v in cost.items()})
            except Exception as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
                traceback.print_exc()
        records.append(record)

    successes = [r for r in records if r["status"] == "success"]
    failed = [r["algorithm"] for r in records if r["status"] != "success"]
    minimum = min((r["log2_rop"] for r in successes), default=None)
    complete = not failed and len(successes) == len(attacks)
    certified = complete and minimum >= args.minimum_bits
    versions = {}
    for dependency in ("numpy", "scipy", "fpylll", "cysignals"):
        try:
            versions[dependency] = importlib.metadata.version(dependency)
        except importlib.metadata.PackageNotFoundError:
            versions[dependency] = None
    report = {
        "schema_version": int(1),
        "status": "passed_estimator_threshold" if certified else "failed_incomplete_attacks" if not complete else "failed_below_threshold",
        "commit": PINNED_COMMIT, "estimator_origin": git(repo, "remote", "get-url", "origin"),
        "sage_version": SAGE_VERSION, "python_version": platform.python_version(), "platform": platform.platform(),
        "dependency_versions": versions,
        "command": sys.argv, "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "inputs": {"n":int(768),"q":int(2**32),"m":int(768),"module_rank":int(3),"ring_degree":int(256),
                   "secret_distribution":"independent centered discrete Gaussian, stddev 3.2",
                   "error_distribution":"independent centered discrete Gaussian, stddev 3.2"},
        "cost_model":"ADPS16(mode='quantum')", "primal_shape_model":"gsa",
        "coded_bkw_cost_model":"upstream coded-BKW native cost; no lattice-reduction model argument",
        "required_attacks":list(attacks), "failed_attacks":failed, "attacks":records,
        "minimum_successful_attack_bits":minimum,
        "lambda_est_bits":minimum if complete else None,
        "threshold_bits":args.minimum_bits, "threshold_passed":certified,
        "scope":"heuristic generic flattened-LWE attack estimate; not a module-specific, implementation, side-channel, or worst-case proof",
        "dynamic_sigma_enc":"not used in fixed public-key security estimate; operational decoding capacity needs separate certificates",
        "sample_accounting":"Original independent budget is 768. Coded-BKW may derive samples using the pinned signed-sum noise amplification rule; raw/effective distributions and counts are recorded separately. Missing upstream counts are unknown, never replaced with 768.",
        "adapter_sha256":hashlib.sha256(Path(__file__).with_name("estimator_result_adapter.py").read_bytes()).hexdigest(),
    }
    (args.output/"security.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    (args.output/"stdout.log").write_text(capture.getvalue(), encoding="utf-8")
    with (args.output/"security.csv").open("w", newline="", encoding="utf-8") as stream:
        columns = ["algorithm","status","rop","log2_rop","beta","lattice_dimension","sample_count","memory","error"]
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    print(json.dumps({"status":report["status"],"failed_attacks":failed,"lambda_est_bits":report["lambda_est_bits"],
                      "evidence_directory":str(args.output.resolve())}, sort_keys=True))
    return int(0) if certified else int(2)


if __name__ == "__main__":
    raise SystemExit(main())
