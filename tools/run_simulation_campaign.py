#!/usr/bin/env python3
"""Run explicitly synthetic, independent paired closed-loop packet experiments."""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from simulation import STATUS  # noqa: E402
from simulation.audit import paired_campaign_summary  # noqa: E402
from simulation.engine import run_one  # noqa: E402
from simulation.exogenous import generate_exogenous, load_config, validate_bound_artifacts, validate_config  # noqa: E402
from simulation.io import digest, file_hash, source_hashes, write_json  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "simulation/config.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", help="Explicit comma-separated evaluation-seed override (saved in effective config)")
    parser.add_argument("--methods", help="Explicit comma-separated method override (saved in effective config)")
    parser.add_argument("--nodes", type=int, help="Explicit small-smoke-test override; not the 3000-node campaign")
    parser.add_argument("--jobs", type=int, default=1, help="Independent worker processes; does not change paired inputs")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("jobs must be a positive integer")
    config = load_config(args.config)
    if args.seeds is not None:
        config["evaluation_seeds"] = [int(seed) for seed in args.seeds.split(",")]
    if args.methods is not None:
        config["methods"] = args.methods.split(",")
    if args.nodes is not None:
        config["nodes"] = args.nodes
        config["gateways"] = min(config["gateways"], args.nodes)
        config["local_contention_domains"] = min(config["local_contention_domains"], config["gateways"])
        config["backhaul_contention_domains"] = min(config["backhaul_contention_domains"], config["gateways"])
    validate_config(config)
    validate_bound_artifacts(config, ROOT)
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("output must be empty; existing evidence is never overwritten")
    output.mkdir(parents=True, exist_ok=True)
    controller = (ROOT / config["controller_fixture"]).resolve()
    if not controller.is_file():
        parser.error("controller fixture does not exist")
    write_json(output / "config.json", config)
    shutil.copyfile(controller, output / "controller.json")
    bound_artifacts = {}
    for name, binding in config["bound_evidence_artifacts"].items():
        path = ROOT / binding["path"]
        if file_hash(path) != binding["sha256"]:
            raise ValueError("bound cryptographic evidence checksum mismatch: " + name)
        target = output / "bound_artifacts" / (name + ".json")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        bound_artifacts[name] = {"file": str(target.relative_to(output)), **binding}
    hashes = source_hashes(ROOT)
    # Preserve an executable source snapshot separate from generated evidence.
    for relative in hashes:
        target = output / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    manifest = {"schema_version": 1, "status": STATUS, "config_digest": digest(config),
                "input_config_sha256": file_hash(args.config),
                "effective_config_sha256": file_hash(output / "config.json"),
                "controller_sha256": file_hash(output / "controller.json"),
                "source_hashes": hashes, "source_digest": digest(hashes),
                "bound_artifacts": bound_artifacts,
                "methods": config["methods"], "evaluation_seeds": config["evaluation_seeds"],
                "calibration_seeds": config["calibration_seeds"],
                "measurement_label": "independent synthetic workload; does not reproduce manuscript network results",
                "paired_design": "All methods reuse each seed's frozen topology, traffic opportunities, disturbance trace, and counter-based channel streams.",
                "completed": False, "runs": []}
    write_json(output / "manifest.json", manifest)
    summaries = []
    total = len(config["evaluation_seeds"]) * len(config["methods"])
    done = 0
    began = time.monotonic()
    for seed in config["evaluation_seeds"]:
        exogenous = output / "exogenous" / f"seed-{seed}"
        generate_exogenous(config, seed, exogenous)
    tasks = [(seed, method) for seed in config["evaluation_seeds"] for method in config["methods"]]
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = {}
        for seed, method in tasks:
            run_dir = output / "runs" / f"seed-{seed}" / method
            future = executor.submit(run_one, config, seed, method,
                                     output / "exogenous" / f"seed-{seed}", run_dir,
                                     output / "controller.json")
            futures[future] = (seed, method, run_dir)
        for future in as_completed(futures):
            seed, method, run_dir = futures[future]
            summary = future.result()
            run_manifest = json.loads((run_dir / "manifest.json").read_text())
            run_manifest["source_digest"] = manifest["source_digest"]
            write_json(run_dir / "manifest.json", run_manifest)
            summaries.append(summary)
            manifest["runs"].append({"seed": seed, "method": method,
                                     "directory": str(run_dir.relative_to(output)),
                                     "manifest_sha256": file_hash(run_dir / "manifest.json"),
                                     "summary_sha256": file_hash(run_dir / "summary.json")})
            manifest["runs"].sort(key=lambda row: (row["seed"], row["method"]))
            done += 1
            write_json(output / "manifest.json", manifest)
            print(f"[{done}/{total}] seed={seed} method={method} "
                  f"admitted={summary['raw_counts']['reports'].get('admitted', 0)} "
                  f"valid={summary['raw_counts']['reports'].get('delivered_valid', 0)} "
                  f"elapsed_s={time.monotonic() - began:.1f}", flush=True)
    write_json(output / "summary.json", paired_campaign_summary(summaries, config["methods"]))
    manifest["summary_sha256"] = file_hash(output / "summary.json")
    manifest["completed"] = True
    write_json(output / "manifest.json", manifest)
    print(f"Completed {total} independent experimental runs: {output}", flush=True)


if __name__ == "__main__":
    main()
