#!/usr/bin/env python
# SPDX-License-Identifier: MIT
"""Screen explicitly selected module ranks with primal-uSVP only.

A screening success is NOT a complete security estimate or a system certificate.
Run selected candidates with estimate_security_parameters.py, which requires all
seven attacks. Defaults preserve q=2^32, d=256 and Gaussian standard deviation3.2.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from estimate_security_parameters import (
    PINNED_COMMIT, environment, security_parameters, utc_now, verified_source, write_json,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ranks", type=int, nargs="+", default=[4, 5, 6, 7, 8, 9, 10])
    parser.add_argument("--target-bits", type=float, required=True,
                        help="screening target, never substituted for computed cost")
    parser.add_argument("--attack-timeout", type=float, default=180)
    parser.add_argument("--ring-degree", type=int, default=256)
    parser.add_argument("--q", type=lambda value: int(value, 0), default=2**32)
    parser.add_argument("--sigma-key", type=float, default=3.2)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; preserve previous attempts")
    if len(set(args.ranks)) != len(args.ranks):
        parser.error("duplicate rank")
    import math
    if not math.isfinite(args.target_bits) or args.target_bits <= 0:
        parser.error("positive finite target required")
    if not math.isfinite(args.attack_timeout) or args.attack_timeout <= 0:
        parser.error("positive finite timeout required")
    repo = args.estimator.resolve()
    source = verified_source(repo)
    output = args.output.resolve()
    output.mkdir(parents=True)
    write_json(output / "upstream-source.json", source)
    write_json(output / "environment.json", environment())
    report = {"schema_version": 1, "status": "screening_in_progress",
              "provenance": "independent_reproduction", "original_paper_evidence": False,
              "started_at": utc_now(), "target_bits": args.target_bits,
              "screening_attack": "primal_usvp", "commit": PINNED_COMMIT,
              "source_manifest_sha256": source["manifest_sha256"],
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "runner_sha256": hashlib.sha256(Path(__file__).with_name("estimate_security_parameters.py").read_bytes()).hexdigest(),
              "command": [sys.executable, *sys.argv], "candidates": [],
              "scope": "candidate screening only; all seven attacks and implementation/decoding/resource recertification remain required"}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
    for rank in args.ranks:
        candidate = output / f"k{rank}"
        candidate.mkdir()
        args.module_rank, args.n = rank, None
        inputs = security_parameters(args)
        record_path = candidate / "primal_usvp.json"
        command = [sys.executable, "-u", str(Path(__file__).with_name("estimate_security_parameters.py").resolve()),
                   "--estimator", str(repo), "--attack-worker", "primal_usvp", "--worker-output", str(record_path),
                   "--module-rank", str(rank), "--ring-degree", str(args.ring_degree),
                   "--q", str(args.q), "--sigma-key", str(args.sigma_key)]
        print(f"Screening k={rank}, n={inputs['n']}, ciphertext_bytes={inputs['ciphertext_bytes']}", flush=True)
        started = time.monotonic()
        log_path = candidate / "primal_usvp.log"
        with log_path.open("w") as log_file:
            try:
                completed = subprocess.run(command, stdout=log_file, stderr=subprocess.STDOUT,
                                           timeout=args.attack_timeout, env=env, check=False)
                record = json.loads(record_path.read_text()) if record_path.exists() else {
                    "algorithm": "primal_usvp", "status": "failed", "error": "worker exited without result"}
                record["process_returncode"] = completed.returncode
                if completed.returncode and record["status"] == "success":
                    record.update(status="failed", error="worker exit and result disagree")
            except subprocess.TimeoutExpired:
                record = {"algorithm": "primal_usvp", "status": "timeout",
                          "error": f"screening exceeded {args.attack_timeout} seconds"}
        record.update(inputs=inputs, elapsed_seconds=time.monotonic()-started,
                      raw_log_sha256=hashlib.sha256(log_path.read_bytes()).hexdigest())
        record["screening_target_met"] = record["status"] == "success" and record["log2_rop"] >= args.target_bits
        write_json(record_path, record)
        report["candidates"].append(record)
        write_json(output / "screening.json", report)
        print(f"k={rank}: {record['status']}, USVP bits={record.get('log2_rop')}, screening_target_met={record['screening_target_met']}", flush=True)
    qualifying = [r for r in report["candidates"] if r["screening_target_met"]]
    report.update(status="screening_finished_not_certified", finished_at=utc_now(),
                  smallest_screening_candidate_rank=min((r["inputs"]["module_rank"] for r in qualifying), default=None),
                  complete_security_estimate=None, threshold_certified=False)
    try:
        report["source_unchanged_after_run"] = verified_source(repo)["manifest_sha256"] == source["manifest_sha256"]
    except Exception as exc:
        report.update(source_unchanged_after_run=False, source_verification_error=str(exc))
    if not report["source_unchanged_after_run"]:
        report.update(status="failed_source_changed", smallest_screening_candidate_rank=None)
    write_json(output / "screening.json", report)
    return 0 if report["source_unchanged_after_run"] and all(r["status"] == "success" for r in report["candidates"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
