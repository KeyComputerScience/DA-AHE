#!/usr/bin/env python3
"""Freeze and sequentially execute paired synthetic campaigns at several sizes.

The plan is an input/provenance artifact. A matrix result manifest is emitted
only after every campaign, independent raw audit and evaluation export succeeds.
Existing engine and historical campaign sources are not changed.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
from importlib import metadata
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from simulation.exogenous import validate_bound_artifacts, validate_config  # noqa: E402
from simulation.io import digest, file_hash, source_hashes  # noqa: E402


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _positive_integer(value, name, *, minimum=1):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _integers(values, name, *, minimum=0, count=1):
    if not isinstance(values, (list, tuple)) or len(values) < count:
        raise ValueError(f"{name} requires at least {count} values")
    if any(type(value) is not int or value < minimum for value in values):
        raise ValueError(f"{name} must contain integers >= {minimum}")
    if len(set(values)) != len(values):
        raise ValueError(name + " must contain unique values")
    return sorted(values)


def _relative(root, path):
    path = Path(path)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("matrix paths must remain inside the repository root") from exc
    if not relative.parts:
        raise ValueError("the repository root itself cannot be a matrix output")
    return relative.as_posix()


def _read(root, relative):
    return json.loads((root / _relative(root, relative)).read_text(encoding="utf-8"))


def plan_digest(plan):
    return digest({key: value for key, value in plan.items() if key != "plan_sha256"})


def runtime_identity():
    try:
        numpy_version = metadata.version("numpy")
    except metadata.PackageNotFoundError as exc:
        raise ValueError("NumPy distribution metadata is required for runtime provenance") from exc
    return {"python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "numpy_distribution_version": numpy_version,
            "platform_family": sys.platform, "machine_architecture": platform.machine(),
            "byteorder": sys.byteorder,
            "scope": "Replay comparisons are scoped to the preserved source/configuration and recorded runtime."}


def build_plan(root, output, *, spec_path="simulation/performance_matrix.json",
               node_counts=None, seeds=None, duration=None, jobs=None,
               bootstrap_resamples=None):
    """Build a complete deterministic plan without writing or executing anything."""
    root = Path(root).resolve()
    output = _relative(root, output)
    spec_path = _relative(root, spec_path)
    input_hashes = {spec_path: file_hash(root / spec_path)}
    spec = _read(root, spec_path)
    if spec.get("schema_version") != 1 or spec.get("kind") != "independent_synthetic_performance_matrix":
        raise ValueError("unsupported performance matrix specification")
    base_path = _relative(root, spec["base_config"])
    controller_path = _relative(root, spec["controller_fixture"])
    input_hashes.update({path: file_hash(root / path) for path in (base_path, controller_path)})
    base = validate_config(_read(root, base_path))
    validate_bound_artifacts(base, root)
    if _relative(root, base["controller_fixture"]) != controller_path:
        raise ValueError("base configuration and specification use different controllers")
    if (base["cryptographic_parameters"]["module_rank"] != 6 or
            base["cryptographic_parameters"]["ring_degree"] != 256 or
            base["protected_ciphertext_bytes"] != 7168):
        raise ValueError("performance matrix requires the released rank-6/7168-byte configuration")
    methods = list(spec["methods"])
    if methods != base["methods"] or len(methods) != 7:
        raise ValueError("matrix must preserve the complete seven-method comparison")
    sizes = _integers(spec["node_counts"] if node_counts is None else node_counts,
                      "node counts", minimum=1)
    evaluation_seeds = _integers(spec["evaluation_seeds"] if seeds is None else seeds,
                                "evaluation seeds", count=2)
    workers = _positive_integer(spec["jobs"] if jobs is None else jobs, "jobs")
    resamples = _positive_integer(spec["bootstrap_resamples"] if bootstrap_resamples is None
                                  else bootstrap_resamples, "bootstrap resamples", minimum=2)
    selected_duration = spec["duration_s"] if duration is None else duration
    if (isinstance(selected_duration, bool) or not isinstance(selected_duration, (int, float)) or
            not math.isfinite(selected_duration) or selected_duration <= 0):
        raise ValueError("duration must be finite and positive")
    if not 0 <= spec["warmup_s"] < spec["disturbance_start_s"] < spec["disturbance_end_s"] < spec["duration_s"]:
        raise ValueError("invalid default warmup/disturbance timing")
    scale = selected_duration / spec["duration_s"]
    original_controller = _read(root, controller_path)
    controller = deepcopy(original_controller)
    initial = spec["common_initial_action"]
    action_ids = [row["id"] for row in controller["actions"]]
    if initial != "nominal" or initial not in action_ids:
        raise ValueError("the common initial action must be the existing nominal row")
    if spec.get("initialization_policy") != "common_nominal_synthetic":
        raise ValueError("common nominal initialization requires its explicit synthetic policy")
    if set(controller["initial_action"]) != {"da-ahe", "dpp", "hys"}:
        raise ValueError("unexpected controller initialization schema")
    if controller["runtime"]["strict"] or controller["status"] != "synthetic_unvalidated":
        raise ValueError("this matrix requires the explicit synthetic controller fixture")
    controller["initial_action"] = {name: initial for name in original_controller["initial_action"]}
    controller["initialization_policy"] = spec["initialization_policy"]
    models = controller["dpp_violation_models"]
    if set(models) != set(action_ids):
        raise ValueError("DPP increment model does not cover exactly the action rows")
    identical_c = len({digest(models[name]) for name in action_ids}) == 1
    controller_output = f"{output}/inputs/controller-common-init.json"
    controller_sha = hashlib.sha256(json_bytes(controller)).hexdigest()

    hashes = source_hashes(root)
    additional = [spec_path, base_path, controller_path,
                  "tools/run_performance_matrix.py", "tools/export_performance_evaluation.py",
                  "pyproject.toml", "requirements-dev.txt"]
    additional.extend(binding["path"] for binding in base["bound_evidence_artifacts"].values())
    for path in additional:
        relative = _relative(root, path)
        hashes[relative] = file_hash(root / relative)
    if any(hashes[path] != expected for path, expected in input_hashes.items()):
        raise ValueError("specification/configuration/controller changed while planning")
    hashes = dict(sorted(hashes.items()))
    cases = []
    for nodes in sizes:
        config = deepcopy(base)
        config.update(nodes=nodes, evaluation_seeds=evaluation_seeds, methods=methods,
                      duration_s=float(selected_duration), metric_start_s=spec["warmup_s"] * scale,
                      control_interval_s=spec["control_interval_s"], controller_fixture=controller_output)
        config["gateways"] = min(base["gateways"], nodes)
        for field in ("local_contention_domains", "backhaul_contention_domains"):
            config[field] = min(base[field], config["gateways"])
        config["disturbance"]["start_s"] = spec["disturbance_start_s"] * scale
        config["disturbance"]["end_s"] = spec["disturbance_end_s"] * scale
        validate_config(config)
        config_path = f"{output}/inputs/nodes-{nodes}/config.json"
        campaign = f"{output}/campaigns/nodes-{nodes}"
        export = f"{output}/exports/nodes-{nodes}"
        verification = f"{output}/verification/nodes-{nodes}.json"
        commands = {
            "campaign": ["python", "tools/run_simulation_campaign.py", "--config", config_path,
                         "--output", campaign, "--jobs", str(workers)],
            "verify": ["python", "tools/verify_simulation_campaign.py", campaign,
                       "--jobs", str(workers)],
            "export": ["python", "tools/export_performance_evaluation.py", campaign,
                       "--output", export, "--bootstrap-resamples", str(resamples)],
        }
        cases.append({"nodes": nodes, "expected_runs": len(evaluation_seeds) * len(methods),
                      "config": {"path": config_path, "content": config,
                                 "sha256": hashlib.sha256(json_bytes(config)).hexdigest(),
                                 "digest": digest(config)},
                      "campaign": campaign, "export": export, "verification": verification,
                      "commands": commands})
    plan = {
        "schema_version": 1, "kind": "performance_matrix_plan",
        "output": output, "matrix_specification": {"path": spec_path, "sha256": file_hash(root / spec_path)},
        "measurement_scope": spec["measurement_scope"],
        "node_counts": sizes, "evaluation_seeds": evaluation_seeds, "methods": methods,
        "expected_runs": sum(case["expected_runs"] for case in cases),
        "jobs": workers, "bootstrap_resamples": resamples,
        "runtime": runtime_identity(),
        "source_hashes": hashes, "source_digest": digest(hashes),
        "bound_evidence_artifacts": base["bound_evidence_artifacts"],
        "controller": {"path": controller_output, "content": controller, "sha256": controller_sha,
                       "original_path": controller_path, "original_sha256": file_hash(root / controller_path)},
        "comparison": {
            "common_initial_action": initial,
            "initial_action_by_method": {method: initial for method in methods},
            "original_initial_action": original_controller["initial_action"],
            "controller_change": "Initial actions are set to nominal and initialization_policy is explicitly common_nominal_synthetic; all other fixture fields are preserved.",
            "candidate_library_shared": True, "existing_admission_gate_G_preserved": True,
            "da_additional_robust_drift_gate_preserved": True,
            "admission_gate_scope": "Adaptive feedback uses the existing G checks. Initialization and the fixed nominal without_markov policy retain the original Policy.choose behavior.",
            "ablation_scope": "Service mechanisms change without recalibration of the shared synthetic controller model.",
            "identical_admitted_sets_claimed": False,
            "dpp_increment_coefficients_identical": identical_c,
            "action_specific_dpp_calibration_claimed": False,
            "controller_coefficients": "existing synthetic uncalibrated fixture",
            "full_system_certified": False,
        },
        "timing": {"duration_s": float(selected_duration), "warmup_s": spec["warmup_s"] * scale,
                   "disturbance_start_s": spec["disturbance_start_s"] * scale,
                   "disturbance_end_s": spec["disturbance_end_s"] * scale,
                   "control_interval_s": spec["control_interval_s"],
                   "duration_scale": scale, "override_policy": spec["timing_override_policy"]},
        "gateway_policy": spec["gateway_policy"],
        "command_convention": "argv arrays, repository-root cwd, python token resolved to the current interpreter",
        "cases": cases,
    }
    plan["plan_sha256"] = plan_digest(plan)
    return plan


def validate_source_identity(root, plan):
    if plan_digest(plan) != plan["plan_sha256"]:
        raise ValueError("plan digest mismatch")
    if runtime_identity() != plan["runtime"]:
        raise ValueError("runtime identity differs from the matrix plan")
    for relative, expected in plan["source_hashes"].items():
        if file_hash(Path(root) / relative) != expected:
            raise ValueError("source changed after planning: " + relative)


def _write_new(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def write_plan(root, plan):
    root = Path(root).resolve()
    validate_source_identity(root, plan)
    output = root / plan["output"]
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output must be empty; existing evidence is never overwritten")
    output.mkdir(parents=True, exist_ok=True)
    _write_new(root / plan["controller"]["path"], json_bytes(plan["controller"]["content"]))
    for case in plan["cases"]:
        _write_new(root / case["config"]["path"], json_bytes(case["config"]["content"]))
    for relative, expected in plan["source_hashes"].items():
        data = (root / relative).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("source changed while freezing plan: " + relative)
        _write_new(output / "source" / relative, data)
    _write_new(output / "plan.json", json_bytes(plan))


def validate_frozen_inputs(root, plan):
    root = Path(root)
    if (root / plan["output"] / "plan.json").read_bytes() != json_bytes(plan):
        raise ValueError("frozen plan bytes differ from the execution plan")
    for item in [plan["controller"], *(case["config"] for case in plan["cases"])]:
        if file_hash(root / item["path"]) != item["sha256"]:
            raise ValueError("frozen input checksum mismatch: " + item["path"])
    for relative, expected in plan["source_hashes"].items():
        if file_hash(root / plan["output"] / "source" / relative) != expected:
            raise ValueError("frozen source checksum mismatch: " + relative)


def completed_case_record(root, plan, case, audit):
    """Require actual, audited campaign outputs before constructing a result row."""
    root = Path(root)
    campaign = root / case["campaign"]
    manifest = json.loads((campaign / "manifest.json").read_text())
    if not manifest.get("completed") or len(manifest["runs"]) != case["expected_runs"]:
        raise ValueError("campaign has not completed the expected run product")
    if manifest["methods"] != plan["methods"] or manifest["evaluation_seeds"] != plan["evaluation_seeds"]:
        raise ValueError("campaign cohort differs from the matrix plan")
    if (manifest["effective_config_sha256"] != case["config"]["sha256"] or
            file_hash(campaign / "config.json") != case["config"]["sha256"] or
            manifest["controller_sha256"] != plan["controller"]["sha256"] or
            file_hash(campaign / "controller.json") != plan["controller"]["sha256"]):
        raise ValueError("campaign configuration/controller differs from the matrix plan")
    expected_campaign_sources = {path: plan["source_hashes"][path] for path in source_hashes(root)}
    if (manifest["source_hashes"] != expected_campaign_sources or
            manifest["source_digest"] != digest(expected_campaign_sources) or
            audit.get("source_digest") != manifest["source_digest"]):
        raise ValueError("campaign source differs from the matrix plan")
    if (audit.get("verified_runs") != case["expected_runs"] or
            audit.get("independent_raw_recomputation") is not True):
        raise ValueError("independent raw verification did not cover the expected run product")
    export = root / case["export"]
    export_files = sorted(path for path in export.rglob("*") if path.is_file())
    if not export_files:
        raise ValueError("evaluation exporter produced no files")
    if any(path.is_symlink() for path in export.rglob("*")):
        raise ValueError("export artifacts must not contain symlinks")
    return {"nodes": case["nodes"], "verified_runs": audit["verified_runs"],
            "campaign": case["campaign"], "export": case["export"],
            "campaign_manifest_sha256": file_hash(campaign / "manifest.json"),
            "campaign_summary_sha256": file_hash(campaign / "summary.json"),
            "verification_sha256": file_hash(root / case["verification"]),
            "independent_raw_recomputation": True,
            "deterministic_replay": bool(audit.get("deterministic_replay")),
            "export_files": {path.relative_to(export).as_posix(): file_hash(path) for path in export_files}}


def execute_plan(root, plan):
    root = Path(root).resolve()
    validate_source_identity(root, plan)
    validate_frozen_inputs(root, plan)
    records = []
    for case in plan["cases"]:
        validate_source_identity(root, plan)
        validate_frozen_inputs(root, plan)
        for stage in ("campaign", "verify", "export"):
            argv = list(case["commands"][stage])
            argv[0] = sys.executable
            result = subprocess.run(argv, cwd=root, check=True, text=True,
                                    capture_output=(stage == "verify"))
            if stage == "verify":
                audit = json.loads(result.stdout)
                _write_new(root / case["verification"], json_bytes(audit))
        records.append(completed_case_record(root, plan, case, audit))
    validate_source_identity(root, plan)
    validate_frozen_inputs(root, plan)
    manifest = {"schema_version": 1, "kind": "completed_performance_matrix",
                "completed": True, "plan_sha256": plan["plan_sha256"],
                "plan_file_sha256": file_hash(root / plan["output"] / "plan.json"),
                "source_digest": plan["source_digest"], "expected_runs": plan["expected_runs"],
                "runtime": plan["runtime"],
                "verified_runs": sum(row["verified_runs"] for row in records),
                "measurement_scope": plan["measurement_scope"],
                "comparison": plan["comparison"], "results": records}
    _write_new(root / plan["output"] / "manifest.json", json_bytes(manifest))
    return manifest


def _comma_integers(value):
    try:
        return [int(part) for part in value.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use comma-separated integers") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New or empty repository subdirectory")
    parser.add_argument("--spec", type=Path, default=Path("simulation/performance_matrix.json"))
    parser.add_argument("--node-counts", type=_comma_integers, help="Positive unique sizes; defaults to 1000,...,5000")
    parser.add_argument("--seeds", type=_comma_integers, help="At least two unique paired seeds; defaults to 1000,...,1019")
    parser.add_argument("--duration", type=float, help="Generation seconds; scales warmup/disturbance times, retains other timings")
    parser.add_argument("--jobs", type=int, help="Workers within each sequential size campaign")
    parser.add_argument("--bootstrap-resamples", type=int, help="Exporter resamples >=2; default 100000")
    parser.add_argument("--plan-only", action="store_true", help="Freeze plan, sources and inputs without launching child commands")
    args = parser.parse_args(argv)
    try:
        plan = build_plan(ROOT, args.output, spec_path=args.spec, node_counts=args.node_counts,
                          seeds=args.seeds, duration=args.duration, jobs=args.jobs,
                          bootstrap_resamples=args.bootstrap_resamples)
        write_plan(ROOT, plan)
        if not args.plan_only:
            execute_plan(ROOT, plan)
    except (ValueError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        parser.exit(2, str(exc) + "\n")
    print(json.dumps({"plan_sha256": plan["plan_sha256"], "expected_runs": plan["expected_runs"],
                      "node_counts": plan["node_counts"], "plan_only": args.plan_only}, sort_keys=True))


if __name__ == "__main__":
    main()
