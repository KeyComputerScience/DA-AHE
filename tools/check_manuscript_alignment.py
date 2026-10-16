#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check current parameter/evidence declarations without certifying an unedited PDF."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from daahe.mlwe import DEFAULT_PARAMETERS  # noqa: E402
from estimator_result_adapter import summarize_attacks  # noqa: E402


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(root, relative):
    path = root / relative
    require(not path.is_symlink() and path.is_file(), f"missing regular file: {relative}")
    require(path.resolve().is_relative_to(root.resolve()), "evidence path escapes root")
    return json.loads(path.read_text(encoding="utf-8"))


def verify(root=ROOT):
    root = Path(root).resolve()
    contract = read_json(root, "configs/manuscript_alignment.json")
    profile = read_json(root, "configs/security_profile.json")
    require(contract["schema_version"] == 1, "unsupported alignment contract")
    params = DEFAULT_PARAMETERS
    require(contract["current_parameters"] == asdict(params), "canonical parameter drift")
    expected = {"module_rank": params.k, "ring_degree": params.d, "n": params.n,
                "m": params.n, "q": params.q, "p": params.p, "sigma_key": params.sigma_key,
                "ciphertext_bytes": params.ciphertext_bytes}
    require(all(profile.get(k) == v for k, v in expected.items()), "security profile differs from code")
    require(profile["original_paper_parameters"] is False and
            profile["full_system_certified"] is False, "unsupported certification claim")
    report_path = root / profile["security_report"]
    report = read_json(root, profile["security_report"])
    require(hashlib.sha256(report_path.read_bytes()).hexdigest() == profile["security_report_sha256"],
            "selected security report hash mismatch")
    inputs = report["inputs"]
    mapping = {"p": "plaintext_modulus"}
    require(all(inputs.get(mapping.get(k, k)) == v for k, v in expected.items()),
            "selected security inputs differ from code")
    require(report["commit"] == profile["estimator_commit"], "estimator commit drift")
    require(report["cost_model"] == profile["cost_model"], "cost-model drift")
    require(report.get("original_paper_evidence") is False, "independent evidence relabeled")
    summary = summarize_attacks(report["attacks"], profile["required_estimator_bits"])
    require(summary["complete_attack_set"] and summary["threshold_passed"],
            "selected attack set is incomplete or below threshold")
    require(report["complete_attack_set"] is True and report["failed_attacks"] == [],
            "selected report has failed attacks")
    require(set(profile["attack_set"]) == {r["algorithm"] for r in report["attacks"]},
            "selected attack list drift")
    for attack in report["attacks"]:
        require(attack["inputs"] == inputs, "per-attack input drift")
    minimum = Decimal(str(summary["lambda_est_bits"]))
    for declared in (report["lambda_est_bits"], profile["computed_estimator_bits"],
                     contract["selected_estimator_bits"]):
        require(abs(minimum - Decimal(str(declared))) <= Decimal("0.000001"),
                "declared attack minimum differs from actual records")
    require(contract["required_estimator_bits"] == profile["required_estimator_bits"],
            "required threshold drift")
    rate = contract["payload_arithmetic"]["phy_rate_bps"]
    require(type(rate) is int and rate > 0, "invalid PHY rate")
    airtime = Decimal(params.ciphertext_bytes * 8 * 1000) / Decimal(rate)
    derived = {"single_ciphertext_bytes": params.ciphertext_bytes,
               "raw_two_ciphertext_bytes": 2 * params.ciphertext_bytes,
               "single_payload_airtime_ms": str(airtime),
               "raw_payload_airtime_ms": str(2 * airtime),
               "phy_rate_bps": rate}
    require(contract["payload_arithmetic"] == derived, "payload/airtime arithmetic drift")
    for record in contract["preserved_legacy_records"]:
        legacy = read_json(root, record["path"])
        digest = hashlib.sha256((root / record["path"]).read_bytes()).hexdigest()
        require(digest == record["sha256"], "historical evidence changed: " + record["path"])
        require(legacy["inputs"]["n"] == 768, "legacy input was relabeled")
        usvp = next(r for r in legacy["attacks"] if r["algorithm"] == "primal_usvp")
        require(usvp["status"] == "success" and abs(usvp["log2_rop"] - 51.94) < 1e-6,
                "historical attack result was relabeled")
    claims = read_json(root, "evidence/independent/claim-coverage.json")
    for field in ("paper_reproduced", "all_manuscript_metrics_verified", "full_system_certified"):
        require(claims.get(field) is False, "unsupported original-paper claim: " + field)
    require(claims.get("physical_board_samples") == 0, "board claim requires new reviewed evidence")
    statuses = contract["claim_status"]
    for field in ("original_pdf_modified", "historical_measurements_verified_for_k6",
                  "full_system_certified", "control_certificate_available",
                  "aggregate_physical_sum_exact"):
        require(statuses.get(field) is False, "unsupported manuscript claim: " + field)
    require(statuses.get("durable_source_emission_required") is True, "one-time emission missing")
    return {"status": "passed_repository_alignment_manuscript_revision_required",
            "manuscript_aligned": False, "full_system_certified": False,
            "ciphertext_bytes": params.ciphertext_bytes, "estimated_bits": float(minimum),
            "original_pdf_sha256": contract["original_pdf"]["sha256"],
            "scope": "Declared parameters, preserved records and arithmetic only; no experiments rerun."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--require-manuscript-aligned", action="store_true",
                        help="fail while the original PDF has not been revised and checked")
    args = parser.parse_args()
    try:
        result = verify(args.root)
        print(json.dumps(result, sort_keys=True))
        return 2 if args.require_manuscript_aligned else 0
    except (ValueError, KeyError, TypeError, OSError, StopIteration) as error:
        print(json.dumps({"status": "failed_repository_alignment", "error": str(error),
                          "manuscript_aligned": False, "full_system_certified": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
