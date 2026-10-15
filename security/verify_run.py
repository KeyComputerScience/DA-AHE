#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify preserved security-run arithmetic, attack set, hashes and provenance.

This checks the evidence record. It does not prove the estimator's models or
certify the encryption implementation, module structure, memory or decoding.
"""
import argparse
from decimal import Decimal, localcontext
import hashlib
import json
import math
from pathlib import Path

ATTACKS = {"primal_usvp", "primal_bdd", "primal_hybrid", "primal_mitm_hybrid",
           "dual", "dual_hybrid", "coded_bkw"}
COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"


def verify(path, source_root=None, threshold=None):
    report = json.loads((path / "security.json").read_text())
    source = json.loads((path / "upstream-source.json").read_text())
    environment = json.loads((path / "environment.json").read_text())
    if report["provenance"] != "independent_reproduction" or report["original_paper_evidence"]:
        raise ValueError("unexpected provenance")
    if report["commit"] != COMMIT or source["commit"] != COMMIT:
        raise ValueError("upstream commit mismatch")
    if not report["source_unchanged_after_run"] or report.get("execution_returncode") != 0:
        raise ValueError("execution did not finish successfully with unchanged source")
    records = report["attacks"]
    if len(records) != len(ATTACKS) or {row["algorithm"] for row in records} != ATTACKS:
        raise ValueError("required seven-attack set is incomplete or duplicated")
    computed = []
    for row in records:
        if row["status"] != "success" or row["process_returncode"] != 0:
            raise ValueError("an attack did not succeed")
        rop = Decimal(row["rop"])
        if not rop.is_finite() or rop <= 0:
            raise ValueError("operation count is not finite and positive")
        with localcontext() as context:
            context.prec = 60
            bits = float(rop.ln() / Decimal(2).ln())
        if not math.isclose(bits, row["log2_rop"], rel_tol=0, abs_tol=1e-10):
            raise ValueError("recorded log2 cost differs from operation count")
        log_file = path / (row["algorithm"] + ".log")
        if hashlib.sha256(log_file.read_bytes()).hexdigest() != row["raw_log_sha256"]:
            raise ValueError("raw attack-log checksum mismatch")
        individual = json.loads((path / (row["algorithm"] + ".json")).read_text())
        if individual != row:
            raise ValueError("individual and aggregate attack records differ")
        computed.append(bits)
    minimum = min(computed)
    if not report["complete_attack_set"] or report["failed_attacks"]:
        raise ValueError("complete-set status disagrees with attack outcomes")
    if not math.isclose(minimum, report["lambda_est_bits"], rel_tol=0, abs_tol=1e-10):
        raise ValueError("global minimum differs from computed costs")
    expected = report.get("threshold_bits") if threshold is None else threshold
    if expected is not None and (not math.isfinite(expected) or expected <= 0 or minimum < expected):
        raise ValueError("computed minimum does not meet requested threshold")
    encoded = json.dumps(source["files"], sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    if source["manifest_sha256"] != digest or report["source_manifest_sha256"] != digest:
        raise ValueError("source-manifest checksum mismatch")
    if source_root is not None:
        root = source_root.resolve()
        for row in source["files"]:
            file = root / row["path"]
            if not file.resolve().is_relative_to(root) or file.is_symlink():
                raise ValueError("unsafe source-manifest path")
            data = file.read_bytes()
            if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                raise ValueError("current upstream source differs from archived bytes")
    return {"verification": "passed", "provenance": "independent_reproduction",
            "verified_attack_count": len(records), "computed_minimum_bits": minimum,
            "requested_threshold_bits": expected, "inputs": report["inputs"],
            "sage_version": environment["sage_version"], "commit": COMMIT,
            "source_manifest_sha256": digest,
            "scope": "record arithmetic, completeness and hashes; not an independent cryptographic proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--minimum-bits", type=float)
    args = parser.parse_args()
    print(json.dumps(verify(args.run, args.upstream, args.minimum_bits), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
