#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a deterministic rank-6 evaluation from executed independent evidence.

Only the explicit published inputs below are consumed. This is a derived report,
not a new network run, original-paper reproduction or physical measurement.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
from daahe.mlwe import DEFAULT_PARAMETERS  # noqa: E402
import check_aggregate_fidelity as fidelity  # noqa: E402
import check_decoding_horizon as horizon  # noqa: E402
from estimator_result_adapter import summarize_attacks  # noqa: E402

METHODS = ("da-ahe", "dpp", "hys", "without_markov", "without_intdb2",
           "without_route_repair", "without_hve")
METRICS = ("accepted_delivery_fraction_per_admitted", "invalid_acceptance_fraction_per_admitted",
           "modeled_cpu_energy_j_all_run", "modeled_radio_tx_energy_j_all_run",
           "observed_residual_loss_fraction", "source_admission_fraction", "valid_delay_mean_s",
           "valid_delay_p95_s", "valid_delivery_fraction_per_admitted",
           "valid_delivery_fraction_per_opportunity", "wire_bytes_per_source_opportunity_all_run")
CAMPAIGN = "evidence/independent/campaign-report"
FIDELITY = "evidence/independent/aggregate-fidelity/run-01"
HORIZON = "evidence/independent/decoding-horizon/run-01"
CAMPAIGN_SOURCE = "ba9749ce35d4b401afabae8e333aaedc1521dfcedd7d7b35f44affc4cc8f579a"
SOURCE_FILES = ("tools/build_current_evaluation.py", "tools/check_aggregate_fidelity.py",
                "tools/check_decoding_horizon.py", "tools/estimator_result_adapter.py",
                "src/daahe/__init__.py", "src/daahe/mlwe.py", "src/daahe/ring.py",
                "src/daahe/signal.py", "src/daahe/profiles.py")
OUTPUT_NAMES = ("current-results.json", "CURRENT_RESULTS.md")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular_file(root, relative):
    require(isinstance(relative, str) and "\\" not in relative, "invalid relative input path")
    parts = PurePosixPath(relative)
    require(not parts.is_absolute() and all(p not in ("", ".", "..") for p in relative.split("/")),
            "unsafe relative input path")
    path = root / relative
    require(path.resolve().is_relative_to(root), "input escapes repository")
    for ancestor in (path, *path.parents):
        if ancestor == root:
            break
        require(not ancestor.is_symlink(), "input symlink forbidden")
    require(path.is_file(), "required public input missing: " + relative)
    return path


def near(left, right):
    return (left is None and right is None) or (
        type(left) in (int, float) and type(right) in (int, float)
        and math.isfinite(left) and math.isfinite(right)
        and math.isclose(left, right, rel_tol=1e-11, abs_tol=1e-12))


def csv_boolean(value):
    require(value in ("True", "False"), "invalid CSV boolean")
    return value == "True"


def network_results(read_json, read_path, profile):
    summary = read_json(CAMPAIGN + "/summary.json")
    manifest = read_json(CAMPAIGN + "/manifest.json")
    config = read_json(CAMPAIGN + "/config.json")
    active_config = read_json("simulation/config.json")
    controller_path = read_path(CAMPAIGN + "/controller.json")
    require(manifest.get("completed") is True and manifest.get("source_digest") == CAMPAIGN_SOURCE,
            "published campaign identity/completion differs")
    require(sha256(read_path(CAMPAIGN + "/summary.json")) == manifest["summary_sha256"],
            "published summary hash mismatch")
    require(sha256(read_path(CAMPAIGN + "/config.json")) == manifest["effective_config_sha256"],
            "published effective config hash mismatch")
    require(sha256(controller_path) == manifest["controller_sha256"], "published controller hash mismatch")
    require(set(manifest["methods"]) == set(config["methods"]) == set(summary["methods"]) == set(METHODS),
            "all seven methods must be retained")
    seeds = summary["paired_evaluation_seeds"]
    require(seeds == list(range(1000, 1020)) == manifest["evaluation_seeds"] == config["evaluation_seeds"],
            "the complete published 20-seed cohort is required")
    expected = {(seed, method) for seed in seeds for method in METHODS}
    require(len(manifest["runs"]) == 140 and
            {(r["seed"], r["method"]) for r in manifest["runs"]} == expected,
            "published completion manifest is not the full 140-case matrix")
    for label, cfg in (("published", config), ("active", active_config)):
        params = cfg["cryptographic_parameters"]
        require(all(params.get(k) == profile[k] for k in
                    ("module_rank", "ring_degree", "n", "m", "q", "p", "sigma_key"))
                and cfg["protected_ciphertext_bytes"] == 7168, label + " network tuple is not selected rank-6")
    for role in ("security_profile", "security_report", "decoding_report"):
        binding = manifest["bound_artifacts"][role]
        require(sha256(read_path(binding["path"])) == binding["sha256"], "published security binding drift")
    with read_path(CAMPAIGN + "/per-seed.csv").open(newline="", encoding="utf-8") as stream:
        raw_rows = list(csv.DictReader(stream))
    rows, seen = [], set()
    for raw in raw_rows:
        key = int(raw["seed"]), raw["method"]
        require(key in expected and key not in seen, "unexpected/duplicate per-seed row")
        seen.add(key)
        metrics = {}
        for name in METRICS:
            value = float(raw[name]) if raw[name] != "" else None
            require(value is None or (math.isfinite(value) and value >= 0), "invalid per-seed metric")
            if value is not None and ("fraction" in name or name == "observed_residual_loss_fraction"):
                require(value <= 1, "fraction exceeds one")
            metrics[name] = value
        denominator_fields = ("accepted_delivery_fraction_per_admitted", "observed_residual_loss_fraction",
            "valid_delivery_fraction_per_admitted", "invalid_acceptance_fraction_per_admitted",
            "source_admission_fraction", "valid_delivery_fraction_per_opportunity")
        if all(metrics[name] is not None for name in denominator_fields):
            accepted, loss, valid, invalid, admission, opportunity = (metrics[name] for name in denominator_fields)
            require(near(accepted + loss, 1.0) and near(valid + invalid, accepted)
                    and near(admission * valid, opportunity), "per-seed denominator identities differ")
        censored = csv_boolean(raw["recovery_right_censored"])
        completion = None if raw["recovery_completion_s"] == "" else float(raw["recovery_completion_s"])
        require(not censored or completion is None, "censored recovery was treated as observed")
        certified = csv_boolean(raw["all_decisions_certified"])
        require(certified is False, "published synthetic decisions relabeled as certified")
        rows.append({"seed": key[0], "method": key[1], "metrics": metrics,
                     "recovery_right_censored": censored, "recovery_completion_s": completion,
                     "all_decisions_certified": certified})
    require(seen == expected and len(rows) == 140, "missing per-seed rows")
    rows.sort(key=lambda row: (row["seed"], METHODS.index(row["method"])))
    by_key = {(row["seed"], row["method"]): row for row in rows}
    methods = []
    for method in METHODS:
        selected = [row for row in rows if row["method"] == method]
        recorded = summary["methods"][method]
        require(set(recorded["metrics"]) == set(METRICS), "unreported or extra campaign metric")
        for name in METRICS:
            values = [row["metrics"][name] for row in selected if row["metrics"][name] is not None]
            stats = recorded["metrics"][name]
            require(stats["seeds_with_defined_metric"] == len(values) and
                    near(stats["mean_over_seeds"], statistics.fmean(values) if values else None) and
                    near(stats["sd_over_seeds"], statistics.stdev(values) if len(values) > 1 else None),
                    "CSV and summary mean/SD mismatch: " + method + "/" + name)
            if method != "da-ahe":
                paired = summary["paired_differences"][method][name]
                expected_deltas = [{"seed": seed, "difference": by_key[(seed, method)]["metrics"][name]
                                   - by_key[(seed, "da-ahe")]["metrics"][name]} for seed in seeds
                                  if by_key[(seed, method)]["metrics"][name] is not None
                                  and by_key[(seed, "da-ahe")]["metrics"][name] is not None]
                require(len(paired["per_seed"]) == len(expected_deltas) and
                        all(a["seed"] == b["seed"] and near(a["difference"], b["difference"])
                            for a, b in zip(paired["per_seed"], expected_deltas)), "paired per-seed differences drift")
                deltas = [item["difference"] for item in expected_deltas]
                require(paired["direction"] == "method minus da-ahe" and
                        near(paired["mean_difference"], statistics.fmean(deltas) if deltas else None) and
                        near(paired["sd_difference"], statistics.stdev(deltas) if len(deltas) > 1 else None),
                        "paired difference summary drift")
        censored = sum(row["recovery_right_censored"] for row in selected)
        require(censored == recorded["recovery_right_censored_seeds"] == 20 and
                recorded["recovery_no_excursion_seeds"] == 0, "published censoring record differs")
        methods.append({"method": method, **recorded})
    return {"scope": "Previously published independent rank-6 synthetic campaign, identified by its frozen completion manifest; this is not the fresh CI campaign currently executing and is not original-paper reproduction.",
            "verification_scope": "CSV/summary/config/completion-manifest crosschecks; this report builder does not rerun the network or independently replay the companion raw archive.",
            "seeds": seeds, "method_order": list(METHODS), "run_count": len(rows),
            "published_source_digest": manifest["source_digest"],
            "config": {key: config[key] for key in ("nodes", "gateways", "duration_s", "drain_s",
                        "control_interval_s", "protected_fraction", "disturbance", "recovery")},
            "active_config_comparison": {"same_bytes": sha256(read_path("simulation/config.json")) == sha256(read_path(CAMPAIGN + "/config.json")),
                "same_json": active_config == config,
                "different_top_level_keys": sorted(k for k in set(active_config) | set(config)
                                                   if active_config.get(k) != config.get(k))},
            "denominators": {
                "valid_delivery_fraction_per_opportunity": "Valid delivered reports / all raw source reporting opportunities in the configured measurement window.",
                "source_admission_fraction": "Admitted reports / all raw source reporting opportunities; sampling suppression/controller stops remain visible.",
                "observed_residual_loss_fraction": "One minus accepted delivery / admitted reports; invalid acceptance can misleadingly reduce this observed loss.",
                "invalid_acceptance_fraction_per_admitted": "Invalid accepted reports / admitted reports; retained explicitly for without_hve.",
                "valid_delay_mean_s": "Mean source-to-sink delay among valid delivered reports; not all offered reports.",
                "energy": "Modeled CPU and radio-transmit joules over the complete run; assumed costs, no receive/listen/OS/full-protocol or physical energy measurement.",
                "wire": "Complete-run transmitted bytes / all raw source opportunities, including protocol/model accounting; not just ciphertext payload.",
                "statistics": "Equal-weight means and sample SD across 20 paired seeds; packets/nodes are not independent statistical repetitions."},
            "recovery": {"right_censored_runs": 140, "observed_recoveries": 0,
                "observation_end_s": config["duration_s"] + config["drain_s"],
                "censor_interval_from_disturbance_s": config["duration_s"] + config["drain_s"] - config["disturbance"]["start_s"],
                "scope": "All runs right-censored; the configured observation interval is not an observed recovery time and must not be averaged as one."},
            "methods": methods, "per_seed": rows,
            "paired_differences": summary["paired_differences"]}


def build_evaluation(root=ROOT):
    root = Path(root).resolve()
    inputs = {}
    sources = [{"path": name, "size": regular_file(root, name).stat().st_size,
                "sha256": sha256(regular_file(root, name))} for name in SOURCE_FILES]

    def read_path(name):
        path = regular_file(root, name)
        record = {"path": name, "size": path.stat().st_size, "sha256": sha256(path)}
        require(name not in inputs or inputs[name] == record, "input changed during evaluation")
        inputs[name] = record
        return path

    def read_json(name):
        return json.loads(read_path(name).read_text(encoding="utf-8"))

    def bundle_inputs(prefix):
        manifest = read_json(prefix + "/manifest.json")
        require(manifest.get("algorithm") == "SHA256", "invalid bundle algorithm")
        for record in manifest["files"]:
            path = read_path(prefix + "/" + record["path"])
            require(path.stat().st_size == record["size"] and sha256(path) == record["sha256"],
                    "bundle hash mismatch: " + prefix + "/" + record["path"])

    params = DEFAULT_PARAMETERS
    require((params.k, params.d, params.n, params.q, params.p, params.sigma_key, params.ciphertext_bytes)
            == (6, 256, 1536, 2**32, 65537, 3.2, 7168), "evaluation requires the selected rank-6 tuple")
    profile = read_json("configs/security_profile.json")
    require(all(profile.get(k) == v for k, v in {"module_rank": 6, "ring_degree": 256,
                "n": 1536, "m": 1536, "q": 2**32, "p": 65537, "sigma_key": 3.2,
                "ciphertext_bytes": 7168}.items()) and profile["full_system_certified"] is False,
            "security profile is not the selected uncertified rank-6 tuple")
    security = read_json(profile["security_report"])
    require(sha256(read_path(profile["security_report"])) == profile["security_report_sha256"],
            "selected security report hash mismatch")
    estimate = summarize_attacks(security["attacks"], profile["required_estimator_bits"])
    require(estimate["complete_attack_set"] and estimate["threshold_passed"] and
            near(estimate["lambda_est_bits"], profile["computed_estimator_bits"]) and
            near(estimate["lambda_est_bits"], security["lambda_est_bits"]), "selected security result differs")
    network = network_results(read_json, read_path, profile)
    bundle_inputs(FIDELITY)
    fidelity_check = fidelity.verify_evidence(root / FIDELITY)
    fidelity_summary = read_json(FIDELITY + "/summary.json")
    admissible = sum(row["admissible_cases"] for row in fidelity_summary["rows"])
    diagnostic = sum(row["inadmissible_diagnostic_cases"] for row in fidelity_summary["rows"])
    require(fidelity_check["cases"] == 72 and admissible == 54 and diagnostic == 18,
            "declared fidelity matrix/capacity classification differs")
    bundle_inputs(HORIZON)
    upper = horizon.load_certificate(root)
    read_path(horizon.REPORT_PATH)
    read_path(str(PurePosixPath(horizon.REPORT_PATH).parent / "sampler-cdts.json"))
    budgets = []
    for filename, batches, bits in (("budget-5-128.json", 5, 128),
                ("budget-6-128-rejected.json", 6, 128), ("budget-300-120.json", 300, 120)):
        recorded = read_json(HORIZON + "/" + filename)
        computed = horizon.verify(root, batches=batches, target_risk=Fraction(1, 2**bits))
        require(recorded == computed, "horizon record differs from exact recomputation")
        budgets.append({"target_bits": bits, **computed})
    for record in (*sources, *inputs.values()):
        path = regular_file(root, record["path"])
        require(path.stat().st_size == record["size"] and sha256(path) == record["sha256"],
                "source or input changed during evaluation")
    input_records = sorted(inputs.values(), key=lambda record: record["path"])
    return {"schema_version": 1, "origin": "derived_executed_independent_evaluation",
            "original_paper_reproduced": False, "physical_measurements": False,
            "full_system_certified": False, "parameters": asdict(params),
            "security": {"estimated_minimum_bits": estimate["lambda_est_bits"],
                "required_bits": profile["required_estimator_bits"], "estimator_commit": profile["estimator_commit"],
                "cost_model": profile["cost_model"], "scope": profile["scope"],
                "attacks": [{"algorithm": record["algorithm"], "estimated_bits": record["log2_rop"]}
                            for record in security["attacks"]]},
            "network": network,
            "aggregate_fidelity": {"cases": 72, "admissible_cases": admissible,
                "inadmissible_diagnostic_cases": diagnostic, "summary": fidelity_summary,
                "verification": fidelity_check, "scope": fidelity.SCOPE},
            "payload_structure": {"single_ciphertext_bytes": 7168, "raw_two_ciphertext_bytes": 14336,
                "sensitive_ciphertext_payload_reduction_fraction": 0.5, "phy_rate_bps": 250000,
                "single_payload_only_airtime_ms": str(Decimal(7168 * 8 * 1000) / Decimal(250000)),
                "raw_payload_only_airtime_ms": str(Decimal(14336 * 8 * 1000) / Decimal(250000)),
                "scope": "Same-rank mathematical payload comparison and ideal PHY lower bound only; not measured latency, full-protocol traffic reduction or energy savings."},
            "decoding_horizon": {"single_batch_exact_upper": str(upper), "budgets": budgets,
                "scope": "Finite predeclared attempt budget over joint random-key/history/fresh-noise probability; no every-fixed-key, conditional-history, unlimited-lifetime, network or control guarantee. Sage proof is consumed, not reexecuted here."},
            "provenance": {"input_files": input_records, "source_files": sources,
                "input_fingerprint": hashlib.sha256(canonical(input_records)).hexdigest(),
                "source_fingerprint": hashlib.sha256(canonical(sources)).hexdigest(),
                "scope": "Relative public paths and SHA256 only. No workstation paths, usernames, hostnames, environment variables or original target files are consumed or exported."}}


def markdown(data):
    network = data["network"]
    lines = ["# Current independent rank-6 evaluation", "",
        "This generated report replaces unsupported manuscript experiment claims with the available executed independent evidence. It does not modify the original PDF or claim original-paper reproduction, physical-board measurements or full-system certification.", "",
        "The network table describes the **previously published** 20-seed independent synthetic campaign. It is **not** the fresh CI campaign currently executing. Rebuilding this report recomputes CSV statistics and evidence checks; it does not rerun the network.", "",
        "Parameters: k=6, d=256, n=m=1536, q=2^32, p=65537, sigma_key=3.2; single ciphertext 7,168 bytes. The seven-attack heuristic minimum is %.3f bits under the pinned estimator model; it is not a universal security proof." % data["security"]["estimated_minimum_bits"], "",
        "## Complete network comparison", "",
        "All seven methods and all 20 paired seeds (1000–1019), including failed deliveries, are retained. All 140 per-seed rows and all recorded metrics/paired differences are public in [current-results.json](current-results.json). Means below give equal weight to seeds.", "",
        "| Method | Valid delivery / opportunity (%) | Admission / opportunity (%) | Observed loss / admitted (%) | Invalid acceptance / admitted (%) | Mean valid delay (s) | Modeled CPU energy (J/run) | Modeled TX energy (J/run) | Wire bytes / opportunity | Recovery right-censored |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for method in network["methods"]:
        metrics = method["metrics"]
        names = ("valid_delivery_fraction_per_opportunity", "source_admission_fraction",
                 "observed_residual_loss_fraction", "invalid_acceptance_fraction_per_admitted",
                 "valid_delay_mean_s", "modeled_cpu_energy_j_all_run", "modeled_radio_tx_energy_j_all_run",
                 "wire_bytes_per_source_opportunity_all_run")
        values = [metrics[name]["mean_over_seeds"] for name in names]
        displays = ["undefined" if value is None else f"{value * 100 if i < 4 else value:.6f}"
                    for i, value in enumerate(values)]
        lines.append("| " + method["method"] + " | " + " | ".join(displays)
                     + f" | {method['recovery_right_censored_seeds']}/20 |")
    cfg = network["config"]
    lines += ["", f"Configuration: {cfg['nodes']} sensors, {cfg['gateways']} gateways, {cfg['duration_s']:g} s generation plus {cfg['drain_s']:g} s drain, {cfg['control_interval_s']:g} s control interval. Current simulator config matches the archived config byte-for-byte: {network['active_config_comparison']['same_bytes']}. This equality does not make the historical and fresh executions the same run.", "",
        "Denominators matter: delivery and admission use all raw source opportunities; observed loss and invalid acceptance use admitted reports. Mean valid delay conditions on valid delivery. Lower admitted-only loss can result from suppression or invalid acceptance. without_hve retains its invalid-acceptance result, and without_route_repair retains its identical recorded outcomes; no route-repair benefit is inferred.", "",
        "Energy is modeled CPU and radio-transmit energy over the complete run, not physical energy or complete protocol energy. Receive/listen, OS and other omitted costs are not silently added. Wire bytes include the model's complete-run accounting per raw opportunity. Packets/nodes are not independent statistical repetitions; no new significance claim is made.", "",
        f"All 140 recoveries are right-censored at the configured {network['recovery']['observation_end_s']:g} s observation end. The {network['recovery']['censor_interval_from_disturbance_s']:g} s interval from disturbance onset is a censoring interval, **not an observed recovery time**.", "",
        "## Aggregate-domain fidelity", "",
        "The executed synthetic matrix contains 72 cases: **54 capacity-admissible and 18 inadmissible diagnostics**. Diagnostic rows remain visible and are not pooled into admitted results. Integer lifting, selection and quantization increments are separated as vectors with their cross terms; RMSE components must not be added. These arbitrary integer-count signals do not reproduce the original Table III or physical sensor units.", "",
        "| Profile | N | Admissible cases | Diagnostic cases | Aggregate RMSE (integer counts) | Aggregate PRD mean (%) | Aggregate minus summed individual RMSE |",
        "|---|---:|---:|---:|---:|---:|---:|"]
    for row in data["aggregate_fidelity"]["summary"]["rows"]:
        total = row["metrics"]["total_selected_quantized_aggregate"]
        difference = row["metrics"]["aggregate_minus_sum_individual"]
        prd = "undefined" if total["case_prd_mean_percent"] is None else f"{total['case_prd_mean_percent']:.6f}"
        lines.append(f"| {row['profile']} | {row['batch_size']} | {row['admissible_cases']} | {row['inadmissible_diagnostic_cases']} | {total['case_rmse_mean_integer_counts']:.6f} | {prd} | {difference['case_rmse_mean_integer_counts']:.6f} |")
    lines += ["", "PRD is null/undefined whenever the true aggregate reference energy is zero, including cancellation. No PRD pass threshold is used to certify the manuscript. Full raw cases, signal definitions, frozen source and recomputation are in evidence/independent/aggregate-fidelity/run-01.", "",
        "## Structure and finite-horizon arithmetic", "",
        "At fixed rank 6, two ciphertext payloads (14,336 bytes) become one (7,168 bytes): a 50% sensitive ciphertext payload reduction. At 250 kbps, ideal payload-only airtimes are 458.752 ms and 229.376 ms. These are structural arithmetic/lower bounds, not full-protocol communication or measured latency/energy savings.", "",
        "| Predeclared fresh-noise batch-attempt cap | Target risk | Exact union-budget decision |",
        "|---:|---:|---|"]
    for budget in data["decoding_horizon"]["budgets"]:
        lines.append(f"| {budget['batches']} | 2^-{budget['target_bits']} | {'passes' if budget['passes_target'] else 'rejected'} |")
    lines += ["", "The rejected 6-attempt/2^-128 budget is retained. The horizon is an attempt cap, not a number of successful deliveries or seconds. Shared keys and dependence across batches are allowed under the stated fresh-noise/preauthorization assumptions. This is joint random-key/history/noise arithmetic, not an every-fixed-key, arbitrary conditional-history, unlimited-lifetime, network or controller certificate. The Sage bound is consumed without rerunning its proof.", "",
        "## Provenance and reproduction", "",
        "current-results.json binds every consumed public input and every report-builder dependency by relative path, byte size and SHA256. The archived network summary/config/controller and completion manifest are crosschecked against all 140 CSV rows; the report builder does not itself replay the full companion raw network archive.", "",
        "Generate into a new directory: `python tools/build_current_evaluation.py --output-dir <new-dir>`. Check installed generated files: `python tools/build_current_evaluation.py --check`. Both outputs are deterministic; overwriting prior evidence is refused.", "",
        "Input fingerprint: `" + data["provenance"]["input_fingerprint"] + "`.", "",
        "Source fingerprint: `" + data["provenance"]["source_fingerprint"] + "`.", ""]
    return "\n".join(lines)


def render_outputs(root=ROOT):
    data = build_evaluation(root)
    return {OUTPUT_NAMES[0]: json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n",
            OUTPUT_NAMES[1]: markdown(data)}


def write_outputs(output_dir, root=ROOT):
    outputs = render_outputs(root)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    for name, content in outputs.items():
        with (output_dir / name).open("x", encoding="utf-8") as handle:
            handle.write(content)
    return {"status": "generated_current_evaluation", "network_runs": 140, "fidelity_cases": 72,
            "original_paper_reproduced": False}


def check_outputs(output_dir, root=ROOT):
    outputs = render_outputs(root)
    for name, expected in outputs.items():
        path = Path(output_dir) / name
        require(path.is_file() and not path.is_symlink() and path.read_text(encoding="utf-8") == expected,
                "generated output missing or stale: " + name)
    return {"status": "verified_current_evaluation", "network_runs": 140, "fidelity_cases": 72,
            "original_paper_reproduced": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output-dir", type=Path, help="new directory for both generated files")
    action.add_argument("--check", type=Path, nargs="?", const=ROOT / "experiments",
                        help="check generated outputs; defaults to experiments/")
    args = parser.parse_args(argv)
    try:
        result = check_outputs(args.check) if args.check else write_outputs(args.output_dir)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError, ZeroDivisionError) as error:
        print(json.dumps({"status": "failed_current_evaluation", "error_type": type(error).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
