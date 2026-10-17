#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute independent exploration, fit training models, and audit heldout errors.

This is service-model calibration, not physical calibration or uniform coverage.
Existing historical evidence and controller safety parameters are never edited.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shutil
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from daahe.calibration import calibrate_bundle, read_trace, validate_seed_split  # noqa: E402
from daahe.calibration_trace import (ANNOTATION_NAMES, SCENARIOS, ScheduledExplorationPolicy, causal_hmm_predictions,
                                    coverage, extract_transitions, prediction_report, write_trace)  # noqa: E402
from daahe.control import ControlModel  # noqa: E402
from daahe.safety import Action  # noqa: E402
from simulation.engine import Simulator  # noqa: E402
from simulation.exogenous import generate_exogenous, load_config, validate_bound_artifacts, validate_config  # noqa: E402
from simulation.io import JsonlWriter, digest, file_hash, read_jsonl, source_hashes, write_json  # noqa: E402

DEFAULT_SPLIT = {"training": [20000, 20001, 20002], "holdout": [21000, 21001],
                 "evaluation": [22000, 22001]}
SCOPE = ("Executed independent two-hop service-model identification; configured operational-stage labels, "
         "modeled CPU/communication, and separately executed synthetic integer signal probes. "
         "No physical-board data, uniform true-process coverage, or deployment certification.")


def utc():
    return datetime.now(timezone.utc).isoformat()


def scenario_config(base, scenario, seed):
    """Prespecified perturbations, retained explicitly; no result-driven tuning."""
    config = json.loads(json.dumps(base))
    config["methods"], config["evaluation_seeds"], config["calibration_seeds"] = ["da-ahe"], [seed], []
    changes = {
        "normal": {"affected_gateway_fraction": 0.0, "disturbed_ber": base["disturbance"]["baseline_ber"]},
        "congestion": {"affected_gateway_fraction": 0.0, "disturbed_ber": base["disturbance"]["baseline_ber"]},
        "local_impairment": {"affected_gateway_fraction": 0.35, "disturbed_ber": 0.0005},
        "global_impairment": {"affected_gateway_fraction": 1.0, "disturbed_ber": 0.0005},
        "severe_loss": {"affected_gateway_fraction": 1.0, "disturbed_ber": 0.003},
    }
    if scenario not in changes:
        raise ValueError("unknown prespecified scenario")
    config["disturbance"].update(changes[scenario])
    if scenario == "congestion":
        config["backhaul_contention_domains"] = 1
        config["local_contention_domains"] = max(1, min(config["gateways"], 15))
    config["calibration_scenario"] = scenario
    config["calibration_scope"] = SCOPE
    return validate_config(config)


def capture_case(base, template_path, partition, seed, scenario, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    began, started = time.monotonic(), utc()
    config = scenario_config(base, scenario, seed)
    write_json(destination / "config.json", config)
    generate_exogenous(config, seed, destination / "inputs")
    simulator = Simulator(config, seed, "da-ahe", destination / "inputs", destination / "raw", template_path)
    phase = (seed + SCENARIOS.index(scenario)) % 3
    simulator.policy = ScheduledExplorationPolicy(simulator.policy, phase)
    simulator.run()
    # Packet audit has already recomputed every generated simulator summary.
    epochs = list(read_jsonl(destination / "raw/epochs.jsonl.gz"))
    events = list(read_jsonl(destination / "raw/events.jsonl.gz"))
    traffic = list(read_jsonl(destination / "inputs/traffic.jsonl.gz"))
    rows, probes, diagnostics = extract_transitions(
        epochs, events, traffic, config, seed=seed, scenario=scenario, actions=simulator.policy.actions,
        delay_threshold=simulator.policy.data["params"].delay_threshold,
        loss_threshold=simulator.policy.data["loss_threshold"])
    write_trace(destination / "transitions.csv", rows)
    with JsonlWriter(destination / "signal-cases.jsonl.gz") as writer:
        for probe in probes:
            writer.write(probe)
    write_json(destination / "transition-diagnostics.json", diagnostics)
    files = {str(path.relative_to(destination)): file_hash(path) for path in sorted(destination.rglob("*")) if path.is_file()}
    receipt = {"partition": partition, "seed": seed, "scenario": scenario, "started_utc": started,
               "finished_utc": utc(), "elapsed_s": time.monotonic() - began, "rows": len(rows),
               "exploration_phase": phase, "exploration_order": ["nominal", "repair", "fallback"],
               "coverage": coverage(rows, sorted(simulator.policy.actions)), "files": files,
               "operational_labels_available_online": False, "scope": SCOPE,
               "completed": True}
    write_json(destination / "receipt.json", receipt)
    return receipt


def run(args):
    destination = args.output.resolve()
    if destination.exists():
        raise ValueError("output exists; prior evidence is never overwritten")
    if args.jobs < 1 or args.nodes < 1:
        raise ValueError("jobs and nodes must be positive")
    split = {partition: [int(v) for v in getattr(args, partition + "_seeds").split(",")]
             for partition in DEFAULT_SPLIT}
    if any(len(set(values)) != len(values) for values in split.values()):
        raise ValueError("duplicate seed in partition")
    validate_seed_split(*split.values())
    if any(set(values).intersection(range(1000, 1020)) for values in split.values()):
        raise ValueError("historical evaluation seeds 1000–1019 cannot calibrate this controller")
    base = load_config(args.config)
    base["nodes"] = args.nodes
    base["gateways"] = min(base["gateways"], args.nodes)
    for field in ("local_contention_domains", "backhaul_contention_domains"):
        base[field] = min(base[field], base["gateways"])
    validate_config(base)
    validate_bound_artifacts(base, ROOT)
    template = args.controller or (ROOT / base["controller_config"])
    template = Path(template).resolve()
    template_data = json.loads(template.read_text())
    actions = tuple(Action.from_dict(value) for value in template_data["actions"])
    original = {"kappa_z": template_data["model"]["kappa_z"],
                "gamma": template_data["parameters"]["gamma"], "beta": template_data["parameters"]["beta"],
                "zcert_max": template_data["model"]["zcert_max"]}
    if original != {"kappa_z": 0.3, "gamma": 0.1, "beta": 0.02, "zcert_max": [100, 500, 1]}:
        raise ValueError("reference kappa/gamma/beta/domain changed; this campaign does not tune safety gates")
    destination.mkdir(parents=True)
    shutil.copyfile(template, destination / "input-controller.json")
    shutil.copyfile(args.config, destination / "original-config.json")
    write_json(destination / "input-config.json", base)
    hashes = source_hashes(ROOT)
    for relative in ("tools/run_controller_calibration.py",):
        hashes[relative] = file_hash(ROOT / relative)
    for relative, sha in hashes.items():
        target = destination / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    plan = {"schema_version": 1, "scope": SCOPE, "base_seed_split": split, "nodes": args.nodes,
            "scenarios": list(SCENARIOS), "source_hashes": hashes, "source_digest": digest(hashes),
            "input_paths": {"controller": "input-controller.json", "original_config": "original-config.json", "effective_config": "input-config.json"},
            "controller_input_sha256": file_hash(template), "input_config_sha256": file_hash(destination / "input-config.json"),
            "original_config_sha256": file_hash(destination / "original-config.json"),
            "operational_annotation_names": ANNOTATION_NAMES,
            "annotation_rule": "congestion annotation 1 throughout its reduced-domain case; other nonnormal annotations during [disturbance.start,disturbance.end); baseline input annotation 0 outside; not measured latent truth or recovery",
            "exploration": "whole actions cycle nominal/repair/fallback at every observation boundary; phase=(seed+scenario_index)%3; no labels or future outcomes read",
            "cost_definition": "CPU execution overlap per offered opportunity; next-window conditional accepted delay/loss/noise telemetry; separate maximum-capacity synthetic signal probe relative L2",
            "empty_outcome_rule": "Retain simulator zero-observation defaults and flag empty windows; do not reinterpret zeros as measured reliable delivery",
            "window_response_scope": "CPU execution and completed-window telemetry can include queued reports from earlier actions; this is system window response, not isolated instantaneous action cost",
            "label_lag_scope": "Labels annotate input exposure at the cutoff while y_t summarizes its preceding window; exposure labels are not observed hidden states",
            "safety_parameters_unchanged": original, "sparse_transition_threshold": 3,
            "ridge_regularization": 0.001, "dirichlet_strength": 5.0,
            "fit_options": {"kappa_z": original["kappa_z"], "zcert_max": original["zcert_max"],
                            "sparse_threshold": 3, "regularization": 0.001, "dirichlet_strength": 5.0,
                            "variance_floor": 1e-8, "delay_threshold": template_data["parameters"]["delay_threshold"],
                            "loss_threshold": template_data["loss_threshold"]},
            "tasks": [{"partition": part, "seed": seed, "scenario": scenario}
                      for part, seeds in split.items() for seed in seeds for scenario in SCENARIOS],
            "started_utc": utc(), "python_version": platform.python_version(), "platform": platform.system(),
            "machine": platform.machine(),
            "reproduction_argv": ["python", "source/tools/run_controller_calibration.py", "--config", "input-config.json",
                                  "--controller", "input-controller.json", "--output", "replay/controller-calibration",
                                  "--nodes", str(args.nodes), "--jobs", str(args.jobs),
                                  *[v for part in split for v in ("--" + part + "-seeds", ",".join(map(str, split[part])))]],
            "completed": False, "cases": []}
    write_json(destination / "plan.json", plan)
    plan["plan_sha256"] = file_hash(destination / "plan.json")
    write_json(destination / "manifest.json", plan)
    tasks = [(part, seed, scenario) for part, seeds in split.items() for seed in seeds for scenario in SCENARIOS]
    try:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures = {pool.submit(capture_case, base, destination / "input-controller.json", part, seed, scenario,
                                   destination / "cases" / part / f"seed-{seed}" / scenario): (part, seed, scenario)
                       for part, seed, scenario in tasks}
            for future in as_completed(futures):
                part, seed, scenario = futures[future]
                receipt = future.result()
                plan["cases"].append({"partition": part, "seed": seed, "scenario": scenario,
                                      "receipt_sha256": file_hash(destination / "cases" / part / f"seed-{seed}" / scenario / "receipt.json")})
                plan["cases"].sort(key=lambda value: (value["partition"], value["seed"], value["scenario"]))
                write_json(destination / "manifest.json", plan)
                print(f"[{len(plan['cases'])}/{len(tasks)}] {part} seed={seed} scenario={scenario} rows={receipt['rows']}", flush=True)
        traces, exclusions = {}, {}
        for part, seeds in split.items():
            traces[part], exclusions[part] = [], {"empty_outcome_windows": 0, "empty_delay_windows": 0, "no_opportunity_windows": 0}
            for seed in seeds:
                for scenario in SCENARIOS:
                    case = destination / "cases" / part / f"seed-{seed}" / scenario
                    traces[part].extend(read_trace(case / "transitions.csv"))
                    for diag in json.loads((case / "transition-diagnostics.json").read_text()):
                        exclusions[part]["empty_outcome_windows"] += diag["empty_outcome_window"]
                        exclusions[part]["empty_delay_windows"] += diag["empty_delay_window"]
                        exclusions[part]["no_opportunity_windows"] += not diag["included"]
            write_trace(destination / f"{part}.csv", traces[part])
        coverage_report = {part: coverage(rows, sorted(a.id for a in actions)) for part, rows in traces.items()}
        report = {"schema_version": 1, "scope": SCOPE, "base_seed_split": split,
                  "coverage": coverage_report, "observation_coverage": exclusions,
                  "physical_measurements": False, "uniform_state_bounds_proven": False,
                  "certified": False, "calibration_complete": False}
        write_json(destination / "calibration-report.json", report)
        bundle = calibrate_bundle(
            traces["training"], traces["holdout"], actions,
            evaluation_seeds=sorted({row.seed for row in traces["evaluation"]}),
            nominal_transitions=template_data["model"]["transitions"],
            kappa_z=original["kappa_z"], zcert_max=original["zcert_max"],
            sparse_threshold=3, delay_threshold=template_data["parameters"]["delay_threshold"],
            loss_threshold=template_data["loss_threshold"])
        model = ControlModel.from_dict(bundle["model"])
        controller = json.loads(json.dumps(template_data))
        controller.update(model=bundle["model"], dpp_violation_models=bundle["dpp_violation_models"],
                          calibration_metadata={**bundle["calibration_metadata"], "base_seed_split": split,
                                                "scope": SCOPE, "plan_sha256": file_hash(destination / "plan.json"),
                                                "trace_sha256": {part: file_hash(destination / f"{part}.csv") for part in traces}},
                          status="empirical_calibrated_service_model", online_adaptation=False,
                          description="Controller model fitted on independent training trajectories and heldout empirical residuals",
                          warning="Empirical residual maxima are not uniform true-process bounds; original resource admission evidence is not promoted by this fit.")
        kernel_rows = {}
        for action in actions:
            bounds = []
            for regime in range(5):
                subset = [r for r in traces["holdout"] if r.action_id == action.id and r.regime == regime]
                frequencies = [sum(r.next_regime == j for r in subset) / len(subset) for j in range(5)] if subset else None
                bounds.append(sum(abs(x - y) for x, y in zip(frequencies, model.transitions[action.id][regime]))
                              if frequencies is not None else 2.0)
            kernel_rows[action.id] = bounds
        controller["certificate_assumptions"] = {
            "scope": "declared_model_only", "posterior_l1_bound": 2.0,
            "kernel_row_l1_bounds": kernel_rows,
            "source": "Posterior uses exact simplex diameter; kernel rows use heldout empirical frequencies in declared-model scope, not true-kernel uniform bounds",
            "true_process_state_error_coverage_proven": False,
            "state_error_scope": "declared fitted prediction balls only; radii from finite holdout observations"}
        write_json(destination / "controller.json", controller)
        online = []
        for part, seeds in split.items():
            for seed in seeds:
                for scenario in SCENARIOS:
                    case = destination / "cases" / part / f"seed-{seed}" / scenario
                    records, stats = causal_hmm_predictions(list(read_jsonl(case / "raw/epochs.jsonl.gz")),
                                                           read_trace(case / "transitions.csv"), model)
                    with JsonlWriter(case / "fitted-hmm-predictions.jsonl.gz") as writer:
                        for record in records:
                            writer.write(record)
                    online.append({"partition": part, "seed": seed, "scenario": scenario,
                                   "prediction_sha256": file_hash(case / "fitted-hmm-predictions.jsonl.gz"), **stats})
        report.update(calibration_complete=True, model_digest=model.digest(),
                      controller_sha256=file_hash(destination / "controller.json"),
                      prediction_errors={part: prediction_report(rows, model, bundle["dpp_violation_models"],
                                                                 template_data["parameters"]["delay_threshold"],
                                                                 template_data["loss_threshold"])
                                         for part, rows in traces.items()},
                      causal_hmm_case_predictions=online, model_metadata=bundle["model"]["metadata"],
                      fit_status="completed_empirical_fit_not_certification")
        write_json(destination / "calibration-report.json", report)
        changed = [relative for relative, expected in hashes.items()
                   if not (ROOT / relative).is_file() or file_hash(ROOT / relative) != expected]
        if changed:
            raise ValueError("live source changed during capture/fit; evidence cannot bind execution: " + ", ".join(changed))
        plan.update(completed=True, finished_utc=utc(), fit_status=report["fit_status"],
                    source_unchanged_after_run=True,
                    outputs_sha256={name: file_hash(destination / name) for name in
                                    ("plan.json", "original-config.json", "input-controller.json", "input-config.json", "controller.json",
                                     "training.csv", "holdout.csv", "evaluation.csv", "calibration-report.json")})
        write_json(destination / "manifest.json", plan)
        return 0
    except Exception as exc:
        plan.update(completed=False, finished_utc=utc(), failure_type=type(exc).__name__, failure=str(exc))
        write_json(destination / "manifest.json", plan)
        report_path = destination / "calibration-report.json"
        failure_report = json.loads(report_path.read_text()) if report_path.exists() else {"scope": SCOPE}
        failure_report.update(calibration_complete=False, certified=False, failure_type=type(exc).__name__, failure=str(exc))
        write_json(report_path, failure_report)
        (destination / "failure.txt").write_text(traceback.format_exc())
        print(f"Calibration evidence retained; fit failed: {exc}", file=sys.stderr)
        return 2


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, default=ROOT / "simulation/config.json")
    p.add_argument("--controller", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--nodes", type=int, default=3000)
    p.add_argument("--jobs", type=int, default=2)
    for part, seeds in DEFAULT_SPLIT.items():
        p.add_argument(f"--{part}-seeds", default=",".join(map(str, seeds)))
    return p


if __name__ == "__main__":
    try:
        raise SystemExit(run(parser().parse_args()))
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
