#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require successful outcomes for every declared reproduction and performance job.

Coverage applies to the independently specified software and evidence contracts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path


REQUIRED_JOBS = ("source", "functional", "firmware", "replay", "history", "history_linux",
                 "campaign", "performance", "security")
ROOT = Path(__file__).resolve().parents[1]


def validate_claim_scope(path):
    path = Path(path)
    claims = json.loads(path.read_text())
    if claims.get("schema_version") != 2:
        raise ValueError("unsupported current claim-scope schema")
    for field in ("paper_reproduced", "all_manuscript_metrics_verified", "full_system_certified",
                  "original_author_artifacts_restored"):
        if claims.get(field) is not False:
            raise ValueError("unsupported original-paper/full-system claim: " + field)
    board = claims.get("board_evidence")
    if (claims.get("physical_board_measurements_verified") is not False or
            not isinstance(board, dict) or board.get("kind") != "core_build_and_host_validation" or
            board.get("measurement_records") != []):
        raise ValueError("unsupported board measurement claim; scope must match reviewed evidence records")
    if not claims.get("claim_states") or any(row.get("original_paper_verified") is not False
                                             for row in claims["claim_states"]):
        raise ValueError("original-paper claim coverage is missing or overstated")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assess(results):
    if not isinstance(results, dict):
        raise ValueError("GitHub needs results must be an object")
    observed = {name: value.get("result") if isinstance(value, dict) else None
                for name, value in results.items()}
    errors = []
    for name in REQUIRED_JOBS:
        if observed.get(name) != "success":
            errors.append({"job": name, "result": observed.get(name, "missing")})
    unexpected = sorted(set(observed) - set(REQUIRED_JOBS))
    if unexpected:
        errors.append({"unexpected_jobs": unexpected})
    return {
        "schema_version": 1,
        "status": "passed_all_independent_ci_checks" if not errors else "failed_incomplete_ci_coverage",
        "required_jobs": list(REQUIRED_JOBS),
        "job_results": observed,
        "errors": errors,
        "paper_reproduced": False,
        "all_manuscript_metrics_verified": False,
        "physical_board_measurements_verified": False,
        "full_system_certified": False,
        "scope": "Independent implementation, synthetic campaign evidence and declared heuristic/security and decoding models only.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--claims", type=Path, default=ROOT / "evidence/independent/claim-coverage.json")
    parser.add_argument("--validate-claims-only", action="store_true")
    args = parser.parse_args()
    try:
        claim_hash = validate_claim_scope(args.claims)
        if args.validate_claims_only:
            report = {"schema_version": 1, "status": "passed_claim_scope_contract",
                      "paper_reproduced": False, "all_manuscript_metrics_verified": False,
                      "physical_board_measurements_verified": False, "full_system_certified": False}
        else:
            report = assess(json.loads(os.environ["DAAHE_CI_RESULTS"]))
        report["claim_coverage_sha256"] = claim_hash
    except (KeyError, ValueError, TypeError) as exc:
        report = {"schema_version": 1, "status": "failed_invalid_ci_results_or_claim_scope",
                  "errors": [str(exc)], "paper_reproduced": False,
                  "all_manuscript_metrics_verified": False,
                  "physical_board_measurements_verified": False,
                  "full_system_certified": False}
    report["checked_utc"] = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] in ("passed_all_independent_ci_checks", "passed_claim_scope_contract") else 2


if __name__ == "__main__":
    raise SystemExit(main())
