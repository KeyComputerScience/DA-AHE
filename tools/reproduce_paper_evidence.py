#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute the bounded reviewer evidence suite and retain raw outputs/receipts."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from daahe.independent_evidence import bundle_manifest, source_snapshot, verify_bundle  # noqa: E402

EXPECTED_STATUSES = {
    "alignment": "passed_repository_alignment_manuscript_revision_required",
    "claim-index": "passed_paper_evidence_index",
    "fidelity-generate": "executed_synthetic_fidelity",
    "fidelity-recompute": "verified_and_recomputed",
    "horizon-5-128": "passed_decoding_horizon_budget",
    "horizon-6-128-rejected": "failed_decoding_horizon_budget",
    "horizon-300-120": "passed_decoding_horizon_budget",
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def execute(output, name, arguments, expected=0):
    directory = output / "execution" / name
    directory.mkdir(parents=True)
    started = time.monotonic()
    entrypoint_digest = hashlib.sha256((ROOT / arguments[0]).read_bytes()).hexdigest()
    # No shell or document-provided command is executed. The published command
    # uses a portable interpreter name rather than a personal absolute path.
    timed_out = False
    try:
        result = subprocess.run([sys.executable, *arguments], cwd=ROOT,
                                capture_output=True, timeout=300, check=False)
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout, stderr, returncode = error.stdout or b"", error.stderr or b"", None
    (directory / "stdout.log").write_bytes(stdout)
    (directory / "stderr.log").write_bytes(stderr)
    try:
        reported = json.loads(stdout)
        semantic_match = reported["status"] == EXPECTED_STATUSES[name]
        if name.startswith("horizon-"):
            semantic_match = semantic_match and reported["max_batches_for_target"] == (
                1458 if name == "horizon-300-120" else 5)
            semantic_match = semantic_match and reported["batches"] == (
                300 if name == "horizon-300-120" else (6 if expected == 2 else 5))
            semantic_match = semantic_match and reported["passes_target"] is (expected == 0)
        semantic_match = semantic_match and entrypoint_digest == hashlib.sha256(
            (ROOT / arguments[0]).read_bytes()).hexdigest()
    except (ValueError, KeyError, TypeError):
        semantic_match = False
    receipt = {"command": ["python", *arguments], "expected_returncode": expected,
               "returncode": returncode, "timed_out": timed_out,
               "expected_status": EXPECTED_STATUSES[name], "semantic_match": semantic_match,
               "entrypoint_sha256": entrypoint_digest,
               "status": "passed" if returncode == expected and not timed_out and
                         semantic_match else "failed",
               "wall_time_s": time.monotonic() - started,
               "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
               "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
    write_json(directory / "execution.json", receipt)
    return {"step": name, **receipt}


def reproduce(output):
    output = output.resolve()
    if not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("output must be a new directory inside this repository")
    output.mkdir(parents=True)
    snapshot = source_snapshot(ROOT)
    inputs = ["evidence/independent/decoding/k6-cdt-03/decoding-bound.json",
              "evidence/independent/decoding/k6-cdt-03/sampler-cdts.json",
              "evidence/independent/security-parameter-search/selected-k6-full/security.json"]
    input_records = [{"path": name, "sha256": hashlib.sha256((ROOT / name).read_bytes()).hexdigest()}
                     for name in inputs]
    write_json(output / "source-snapshot.json", snapshot)
    write_json(output / "input-snapshot.json", input_records)
    relative = output.relative_to(ROOT).as_posix()
    fidelity = relative + "/fidelity"
    steps = [
        ("alignment", ["tools/check_manuscript_alignment.py"], 0),
        ("claim-index", ["tools/check_paper_evidence.py"], 0),
        ("fidelity-generate", ["tools/check_aggregate_fidelity.py", "--output", fidelity], 0),
        ("fidelity-recompute", ["tools/check_aggregate_fidelity.py", "--verify", fidelity], 0),
        ("horizon-5-128", ["tools/check_decoding_horizon.py", "--batches", "5",
                           "--target-bits", "128"], 0),
        ("horizon-6-128-rejected", ["tools/check_decoding_horizon.py", "--batches", "6",
                                   "--target-bits", "128"], 2),
        ("horizon-300-120", ["tools/check_decoding_horizon.py", "--batches", "300",
                             "--target-bits", "120"], 0),
    ]
    records = []
    for name, arguments, expected in steps:
        records.append(execute(output, name, arguments, expected))
        if records[-1]["status"] != "passed":
            break
    source_unchanged = snapshot == source_snapshot(ROOT)
    inputs_unchanged = all(hashlib.sha256((ROOT / r["path"]).read_bytes()).hexdigest() == r["sha256"]
                           for r in input_records)
    summary = {"schema_version": 1, "origin": "independent_reimplementation",
               "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
               "python_version": sys.version.split()[0],
               "status": "passed" if len(records) == len(steps) and
                         all(r["status"] == "passed" for r in records) and
                         source_unchanged and inputs_unchanged else "failed",
               "source_digest": snapshot["digest"], "source_unchanged": source_unchanged,
               "pinned_inputs_unchanged": inputs_unchanged,
               "steps": records, "paper_reproduced": False,
               "full_system_certified": False,
               "scope": "Fresh synthetic aggregate reconstruction and exact-rational horizon budgeting from the pinned decoding bound; no board, original corpus, or OMNeT++ measurements."}
    write_json(output / "summary.json", summary)
    bundle_manifest(output, output / "manifest.json")
    integrity = verify_bundle(output, output / "manifest.json")
    return {"status": summary["status"], "steps": len(records),
            "byte_integrity": integrity["status"], "paper_reproduced": False,
            "full_system_certified": False, "output": relative}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("runs/paper-evidence"))
    args = parser.parse_args()
    try:
        result = reproduce(args.output if args.output.is_absolute() else ROOT / args.output)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        # Keep failure output inside the explicitly selected repository. Do not
        # dump environment variables, host names or interpreter paths.
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" and result["byte_integrity"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
