#!/usr/bin/env sage
# SPDX-License-Identifier: MIT
"""Independently reproduce the pinned generic flattened-LWE estimates.

No paper number is substituted for output. Run with sage -python. Each attack
has an isolated process, a deadline and persistent raw logs. Incomplete sets
never produce lambda_est_bits or establish an optional review threshold.
"""
import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

from estimator_result_adapter import (
    REQUIRED_ATTACKS, sample_accounting, source_manifest, summarize_attacks,
)

PINNED_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def git(repo, *arguments):
    return subprocess.check_output(["git", "-C", str(repo), *arguments], text=True).strip()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def verified_source(repo):
    if git(repo, "rev-parse", "HEAD") != PINNED_COMMIT:
        raise ValueError("estimator HEAD differs from pinned commit")
    if git(repo, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("estimator checkout must be clean, including untracked files")
    names = subprocess.check_output(["git", "-C", str(repo), "ls-files", "-z"]).decode().split("\0")
    manifest = source_manifest(repo, [name for name in names if name])
    manifest.update(commit=PINNED_COMMIT, tree=git(repo, "rev-parse", "HEAD^{tree}"),
                    origin=git(repo, "remote", "get-url", "origin"))
    return manifest


def run_worker(repo, name, output):
    started = time.monotonic()
    record = {"algorithm": name, "status": "failed", "started_at": utc_now(),
              "rop": None, "log2_rop": None, "beta": None, "lattice_dimension": None,
              "sample_count": None, "memory": None}
    try:
        from sage.all import RR, log, oo
        from sage.env import SAGE_VERSION
        sys.path.insert(0, str(repo))
        from estimator import LWE, ND
        from estimator.reduction import ADPS16
        import estimator
        if not Path(estimator.__file__).resolve().is_relative_to(repo):
            raise RuntimeError("imported estimator does not belong to verified checkout")
        parameters = LWE.Parameters(n=768, q=2**32, Xs=ND.DiscreteGaussian(3.2),
                                    Xe=ND.DiscreteGaussian(3.2), m=768,
                                    tag="DA-AHE independent fixed-key estimate")
        quantum = ADPS16(mode="quantum")
        options = {"red_cost_model": quantum, "red_shape_model": "gsa"}
        attacks = {
            "primal_usvp": partial(LWE.primal_usvp, **options),
            "primal_bdd": partial(LWE.primal_bdd, **options),
            "primal_hybrid": partial(LWE.primal_hybrid, mitm=False, babai=False, **options),
            "primal_mitm_hybrid": partial(LWE.primal_hybrid, mitm=True, babai=True, **options),
            "dual": partial(LWE.dual, red_cost_model=quantum),
            "dual_hybrid": partial(LWE.dual_hybrid, red_cost_model=quantum),
            "coded_bkw": LWE.coded_bkw,
        }
        print(f"attack={name}; upstream={PINNED_COMMIT}; sage={SAGE_VERSION}", flush=True)
        print(repr(parameters), flush=True)
        cost = attacks[name](parameters)
        print(repr(cost), flush=True)
        record["full_cost"] = {str(key): str(value) for key, value in cost.items()}
        rop = cost.get("rop")
        if rop is None or rop == oo or not rop > 0:
            raise ValueError("attack did not produce finite positive operation count")
        bits = float(log(RR(rop), 2))
        if not math.isfinite(bits):
            raise ValueError("nonfinite log2 operation count")
        accounting = sample_accounting(name, cost, original_m=int(parameters.m),
            original_n=int(parameters.n), original_q=int(parameters.q),
            original_error_stddev=float(parameters.Xe.stddev))
        stringify = lambda value: str(value) if value is not None else None
        record.update(status="success", rop=str(rop), log2_rop=bits, sage_version=SAGE_VERSION,
                      beta=stringify(cost.get("beta", cost.get("β"))),
                      lattice_dimension=stringify(cost.get("d")),
                      sample_count=stringify(cost.get("m")), memory=stringify(cost.get("mem")),
                      sample_accounting=accounting)
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
        traceback.print_exc()
    record.update(finished_at=utc_now(), elapsed_seconds=time.monotonic()-started)
    write_json(output, record)
    return 0 if record["status"] == "success" else 2


def environment():
    result = {"python_version": platform.python_version(), "executable": sys.executable,
              "platform": platform.platform(), "machine": platform.machine(),
              "distributions": sorted((item.metadata["Name"], item.version)
                                      for item in importlib.metadata.distributions())}
    try:
        from sage.env import SAGE_VERSION
        result["sage_version"] = SAGE_VERSION
    except ImportError:
        result["sage_version"] = None
    metadata = Path(sys.prefix) / "conda-meta"
    result["conda_packages"] = []
    if metadata.is_dir():
        for file in sorted(metadata.glob("*.json")):
            package = json.loads(file.read_text())
            result["conda_packages"].append({key: package.get(key) for key in
                ("name", "version", "build", "subdir", "url", "sha256", "md5")})
    return result


def finalize_source_status(report, repo, expected_digest):
    """Preserve evidence but revoke a result if its source changed during execution."""
    try:
        current = verified_source(repo)
        unchanged = current["manifest_sha256"] == expected_digest
        error = None if unchanged else "tracked upstream source bytes changed during execution"
    except Exception as exc:
        unchanged = False
        error = f"{type(exc).__name__}: {exc}"
    finally:
        report["finished_at"] = utc_now()
    report["source_unchanged_after_run"] = unchanged
    if not unchanged:
        report.update(status="failed_source_changed", source_verification_error=error,
                      lambda_est_bits=None, threshold_passed=False)
    report["execution_returncode"] = 0 if (unchanged and report["complete_attack_set"] and
                                           report["threshold_passed"] is not False) else 2
    return report["execution_returncode"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="new evidence directory; never overwritten")
    parser.add_argument("--minimum-bits", type=float, default=None,
                        help="optional review threshold; never used to generate an estimate")
    parser.add_argument("--attack-timeout", type=float, default=300,
                        help="wall-clock seconds per isolated attack, default 300")
    parser.add_argument("--attacks", nargs="+", choices=REQUIRED_ATTACKS,
                        default=list(REQUIRED_ATTACKS), help="a subset always remains incomplete")
    parser.add_argument("--attack-worker", choices=REQUIRED_ATTACKS, help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    repo = args.estimator.resolve()
    sys.dont_write_bytecode = True
    if args.attack_worker:
        if args.worker_output is None:
            parser.error("worker output required")
        return run_worker(repo, args.attack_worker, args.worker_output)
    if args.output is None:
        parser.error("--output required")
    if not math.isfinite(args.attack_timeout) or args.attack_timeout <= 0:
        parser.error("attack timeout must be finite and positive")
    if args.minimum_bits is not None and (not math.isfinite(args.minimum_bits) or args.minimum_bits <= 0):
        parser.error("minimum bits must be finite and positive")
    if len(set(args.attacks)) != len(args.attacks):
        parser.error("duplicate attacks")
    if args.output.exists():
        parser.error("output exists; preserve evidence and select a new directory")
    try:
        source = verified_source(repo)
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    output = args.output.resolve()
    output.mkdir(parents=True)
    write_json(output / "upstream-source.json", source)
    write_json(output / "environment.json", environment())
    report = {"schema_version": 2, "provenance": "independent_reproduction",
              "original_paper_evidence": False, "started_at": utc_now(),
              "commit": PINNED_COMMIT, "source_manifest_sha256": source["manifest_sha256"],
              "command": [sys.executable, *sys.argv], "attack_timeout_seconds": args.attack_timeout,
              "inputs": {"n": 768, "q": 2**32, "m": 768, "module_rank": 3, "ring_degree": 256,
                         "secret_distribution": "centered DiscreteGaussian(stddev=3.2)",
                         "error_distribution": "centered DiscreteGaussian(stddev=3.2)"},
              "cost_model": "ADPS16(mode='quantum')", "primal_shape_model": "gsa",
              "coded_bkw_cost_model": "upstream native word-operation model; no quantum reduction argument",
              "scope": "heuristic generic flattened-LWE estimates; not a module-specific, side-channel, implementation or worst-case proof",
              "dynamic_sigma_enc": "not part of fixed public-key estimate; no decoding certificate generated",
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "adapter_sha256": hashlib.sha256(Path(__file__).with_name("estimator_result_adapter.py").read_bytes()).hexdigest(),
              "attacks": []}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
    for name in args.attacks:
        record_path = output / f"{name}.json"
        command = [sys.executable, "-u", str(Path(__file__).resolve()), "--estimator", str(repo),
                   "--attack-worker", name, "--worker-output", str(record_path)]
        print(f"Running {name}; log={output/name}.log", flush=True)
        started = time.monotonic()
        with (output / f"{name}.log").open("w", encoding="utf-8") as log_file:
            try:
                process = subprocess.run(command, stdout=log_file, stderr=subprocess.STDOUT,
                                         env=env, timeout=args.attack_timeout, check=False)
                if record_path.exists():
                    record = json.loads(record_path.read_text())
                else:
                    record = {"algorithm": name, "status": "failed",
                              "error": "worker exited without a result"}
                record["process_returncode"] = process.returncode
                if process.returncode != 0 and record["status"] == "success":
                    record.update(status="failed", error="worker result and exit status disagree")
            except subprocess.TimeoutExpired:
                record = {"algorithm": name, "status": "timeout",
                          "error": f"attack exceeded {args.attack_timeout} seconds",
                          "elapsed_seconds": time.monotonic()-started}
        record["raw_log_sha256"] = hashlib.sha256((output / f"{name}.log").read_bytes()).hexdigest()
        write_json(record_path, record)
        report["attacks"].append(record)
        report.update(summarize_attacks(report["attacks"], args.minimum_bits))
        write_json(output / "security.json", report)
        print(f"{name}: {record['status']}; log2_rop={record.get('log2_rop')}", flush=True)
    exit_code = finalize_source_status(report, repo, source["manifest_sha256"])
    write_json(output / "security.json", report)
    with (output / "security.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["algorithm", "status", "rop", "log2_rop", "beta", "lattice_dimension",
                  "sample_count", "memory", "elapsed_seconds", "error"]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report["attacks"])
    with (output / "stdout.log").open("w", encoding="utf-8") as combined:
        for name in args.attacks:
            combined.write(f"=== {name} ===\n")
            combined.write((output / f"{name}.log").read_text())
    print(json.dumps({key: report[key] for key in ("status", "failed_attacks", "lambda_est_bits")}), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
