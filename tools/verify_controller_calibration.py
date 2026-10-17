#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recompute a calibration bundle; distinguish integrity from certificate validity.

The compact publication contains fitted inputs, epochs and signal vectors.
--raw-root additionally checks and re-extracts every network/input byte.
Verified hashes and recomputation do not authenticate physical measurements.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(root, name):
    require(isinstance(name, str) and name and "\\" not in name, "invalid bundle path")
    pure = PurePosixPath(name)
    require(not pure.is_absolute() and all(p not in ("", ".", "..") for p in name.split("/")),
            "unsafe bundle path: " + name)
    path = root / name
    require(path.resolve().is_relative_to(root.resolve()), "path escapes bundle")
    for ancestor in (path, *path.parents):
        if ancestor == root:
            break
        require(not ancestor.is_symlink(), "symlink forbidden: " + name)
    return path


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read(root, name):
    return json.loads(safe_path(root, name).read_text(encoding="utf-8"))


def check_hash(root, name, expected):
    require(isinstance(expected, str) and len(expected) == 64, "invalid checksum")
    require(sha(safe_path(root, name)) == expected, "checksum mismatch: " + name)


def verify_bytes(root, raw_root=None):
    manifest, plan = read(root, "manifest.json"), read(root, "plan.json")
    require(manifest["completed"] and manifest["source_unchanged_after_run"], "incomplete capture")
    require(manifest["plan_sha256"] == sha(root / "plan.json"), "immutable plan mismatch")
    for name, expected in manifest["outputs_sha256"].items():
        check_hash(root, name, expected)
    for name, expected in plan["source_hashes"].items():
        check_hash(root, "source/" + name, expected)
    check_hash(root, "original-config.json", plan["original_config_sha256"])
    check_hash(root, "input-config.json", plan["input_config_sha256"])
    check_hash(root, "input-controller.json", plan["controller_input_sha256"])
    expected_cases = {(c["partition"], c["seed"], c["scenario"]) for c in plan["tasks"]}
    actual_cases = [(c["partition"], c["seed"], c["scenario"]) for c in manifest["cases"]]
    require(len(actual_cases) == len(set(actual_cases)) and set(actual_cases) == expected_cases,
            "case product differs from immutable plan")
    raw_commitments = {}
    for case in manifest["cases"]:
        directory = f"cases/{case['partition']}/seed-{case['seed']}/{case['scenario']}"
        check_hash(root, directory + "/receipt.json", case["receipt_sha256"])
        receipt = read(root, directory + "/receipt.json")
        require(receipt["completed"] and receipt["seed"] == case["seed"] and
                receipt["partition"] == case["partition"] and receipt["scenario"] == case["scenario"],
                "case receipt identity differs from plan")
        for name, expected in receipt["files"].items():
            relative = directory + "/" + name
            if safe_path(root, relative).is_file():
                check_hash(root, relative, expected)
            elif raw_root is None:
                require(name.startswith(("raw/", "inputs/")), "missing published input: " + relative)
            if name.startswith(("raw/", "inputs/")):
                raw_commitments[relative] = expected
            if raw_root is not None:
                check_hash(raw_root, relative, expected)
    publication = root / "publication-index.json"
    if publication.is_file():
        index = read(root, "publication-index.json")
        require(index["committed_raw_sha"] == raw_commitments, "raw commitments differ from receipts")
        for name, expected in index["published_paths"].items():
            check_hash(root, name, expected)
        present = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
                   and "__pycache__" not in p.parts and p.name != "publication-index.json"}
        require(present == set(index["published_paths"]), "unindexed or missing publication bytes")
    return plan, manifest


def recompute(root, raw_root=None):
    plan, manifest = verify_bytes(root, raw_root)
    # The parent process audits all frozen source bytes before this fresh process imports them.
    sys.path[:0] = [str(root / "source/src"), str(root / "source")]
    from daahe.calibration import calibrate_bundle, read_trace, validate_seed_split
    from daahe.calibration_trace import (causal_hmm_predictions, coverage, extract_transitions,
                                         prediction_report, signal_probe)
    from daahe.control import ControlModel
    from daahe.controller_certificate import verify_saved_report
    from daahe.safety import Action
    from simulation.io import digest, read_jsonl

    require(digest(plan["source_hashes"]) == plan["source_digest"], "source digest mismatch")
    split = plan["base_seed_split"]
    validate_seed_split(*(split[p] for p in ("training", "holdout", "evaluation")))
    traces = {p: read_trace(root / (p + ".csv")) for p in split}
    for part, rows in traces.items():
        require({r.seed.split("/")[0] for r in rows} == {str(v) for v in split[part]},
                "trace seeds differ from declared partition")
    template, controller, report = (read(root, n) for n in
                                   ("input-controller.json", "controller.json", "calibration-report.json"))
    require(report["calibration_complete"] and report["certified"] is False and
            report["uniform_state_bounds_proven"] is False and report["physical_measurements"] is False,
            "calibration report overstates its evidence scope")
    actions = tuple(Action.from_dict(a) for a in template["actions"])
    fitted = calibrate_bundle(traces["training"], traces["holdout"], actions,
                              evaluation_seeds=sorted({r.seed for r in traces["evaluation"]}),
                              nominal_transitions=template["model"]["transitions"], **plan["fit_options"])
    require(fitted["model"] == controller["model"], "refitted controller differs")
    require(fitted["dpp_violation_models"] == controller["dpp_violation_models"], "refitted DPP differs")
    require(controller["calibration_metadata"]["plan_sha256"] == sha(root / "plan.json"), "fit plan binding differs")
    for part in traces:
        check_hash(root, part + ".csv", controller["calibration_metadata"]["trace_sha256"][part])
    for field in ("parameters", "runtime", "actions", "certificates", "fallback_id"):
        require(template[field] == controller[field], "calibration changed safety field: " + field)
    model = ControlModel.from_dict(controller["model"])
    require(model.kappa_z == .3 and tuple(model.zcert_max) == (100, 500, 1), "changed model contraction/domain")
    require(model.bound_kind == "empirical" and not controller["runtime"]["strict"], "unsupported certificate promotion")
    assumptions = controller["certificate_assumptions"]
    require(assumptions["posterior_l1_bound"] == 2 and assumptions["scope"] == "declared_model_only",
            "unsupported posterior or certificate scope")
    for action in actions:
        bounds = []
        for regime in range(5):
            subset = [r for r in traces["holdout"] if r.action_id == action.id and r.regime == regime]
            frequencies = [sum(r.next_regime == j for r in subset) / len(subset) for j in range(5)] if subset else None
            bounds.append(sum(abs(x - y) for x, y in zip(frequencies, model.transitions[action.id][regime]))
                          if frequencies is not None else 2.0)
        require(bounds == assumptions["kernel_row_l1_bounds"][action.id], "heldout kernel discrepancy differs")
    collected, causal_stats = {p: [] for p in split}, []
    raw_verified = 0
    for case in manifest["cases"]:
        directory = f"cases/{case['partition']}/seed-{case['seed']}/{case['scenario']}"
        path = root / directory
        config = read(root, directory + "/config.json")
        rows = read_trace(path / "transitions.csv")
        collected[case["partition"]].extend(rows)
        probes = list(read_jsonl(path / "signal-cases.jsonl.gz"))
        require(len(probes) == len(rows), "missing signal probes")
        action_map = {a.id: a for a in actions}
        for probe in probes:
            expected = signal_probe(case["seed"], case["scenario"], probe["epoch"], action_map[probe["action_id"]])
            require(expected == probe, "signal transform/reconstruction differs")
        epochs = list(read_jsonl(path / "raw/epochs.jsonl.gz"))
        records, stats = causal_hmm_predictions(epochs, rows, model)
        require(records == list(read_jsonl(path / "fitted-hmm-predictions.jsonl.gz")), "causal HMM predictions differ")
        causal_stats.append({"partition": case["partition"], "seed": case["seed"], "scenario": case["scenario"],
                             "prediction_sha256": sha(path / "fitted-hmm-predictions.jsonl.gz"), **stats})
        if raw_root is not None:
            raw_case = raw_root / directory
            extracted, actual_probes, diagnostics = extract_transitions(
                epochs, list(read_jsonl(raw_case / "raw/events.jsonl.gz")),
                list(read_jsonl(raw_case / "inputs/traffic.jsonl.gz")), config,
                seed=case["seed"], scenario=case["scenario"], actions=action_map,
                delay_threshold=plan["fit_options"]["delay_threshold"], loss_threshold=plan["fit_options"]["loss_threshold"])
            require(extracted == rows and actual_probes == probes, "network-to-fit extraction differs")
            require(diagnostics == read(root, directory + "/transition-diagnostics.json"), "window diagnostics differ")
            from simulation.audit import recompute_run
            require(recompute_run(raw_case / "raw", config) == read(raw_root, directory + "/raw/summary.json"),
                    "independent packet audit differs")
            raw_verified += 1
    for part, rows in traces.items():
        ordering = lambda r: (r.seed, r.time_s)
        require(sorted(rows, key=ordering) == sorted(collected[part], key=ordering), "partition CSV/case rows differ")
        require(coverage(rows, sorted(action_map)) == report["coverage"][part], "coverage differs")
        require(prediction_report(rows, model, fitted["dpp_violation_models"],
                                  plan["fit_options"]["delay_threshold"], plan["fit_options"]["loss_threshold"])
                == report["prediction_errors"][part], "prediction diagnostics differ")
    key = lambda c: (c["partition"], c["seed"], c["scenario"])
    require(sorted(causal_stats, key=key) == sorted(report["causal_hmm_case_predictions"], key=key), "causal HMM scores differ")
    certificate = read(root, "controller-certificate.json")
    verification = verify_saved_report(controller, certificate)
    require(verification["matches_recomputation"], "certificate report differs from exact recomputation")
    return {"status": "verified_calibration_bundle", "cases": len(manifest["cases"]),
            "rows": {p: len(r) for p, r in traces.items()}, "fit_recomputed": True,
            "causal_hmm_recomputed": True, "signal_reconstruction_recomputed": True,
            "certificate_recomputed": True, "certificate_status": certificate["status"],
            "raw_cases_reextracted": raw_verified, "raw_network_audit": "verified" if raw_root else "committed_hashes_only",
            "scope": "executed declared service model and empirical fit", "full_system_certified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--raw-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.bundle.resolve()
    raw = args.raw_root.resolve() if args.raw_root else None
    try:
        if args.worker:
            result = recompute(root, raw)
        else:
            verify_bytes(root, raw)
            command = [sys.executable, str(Path(__file__).resolve()), str(root), "--worker"]
            if raw:
                command += ["--raw-root", str(raw)]
            child = subprocess.run(command, check=True, capture_output=True, text=True)
            result = json.loads(child.stdout)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(json.dumps({"status": "failed_calibration_audit", "error": detail, "full_system_certified": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
