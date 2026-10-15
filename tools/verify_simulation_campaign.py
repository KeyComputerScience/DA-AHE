#!/usr/bin/env python3
"""Independently rederive raw counts/paired summaries; optional deterministic rerun."""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
from itertools import repeat
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from simulation.audit import paired_campaign_summary, recompute_run  # noqa: E402
from simulation.engine import run_one  # noqa: E402
from simulation.exogenous import read_exogenous, validate_bound_artifacts, validate_config  # noqa: E402
from simulation.io import digest, file_hash  # noqa: E402

RAW_FILES = frozenset({"events.jsonl.gz", "packets.jsonl.gz", "reports.jsonl.gz", "epochs.jsonl.gz"})


def _require_all_raw_files(raw_files):
    if not isinstance(raw_files, dict) or set(raw_files) != RAW_FILES:
        raise ValueError("run manifest must list exactly all four raw gzip files")


def _recompute_runs(run_dirs, config, jobs):
    """Preserve input ordering while parallelizing independent raw-log audits."""
    if jobs == 1:
        for run_dir in run_dirs:
            yield recompute_run(run_dir, config)
    else:
        with ProcessPoolExecutor(max_workers=jobs) as executor:
            yield from executor.map(recompute_run, run_dirs, repeat(config))


def _replay_run(payload):
    """Rerun one case in isolation; exact bytes and source identity remain mandatory."""
    config, campaign, run, run_manifest, source_hashes = payload
    _require_all_raw_files(run_manifest.get("raw_files"))
    for relative, expected in source_hashes.items():
        if file_hash(ROOT / relative) != expected:
            raise ValueError("local source differs from recorded source; use the preserved source snapshot")
    with tempfile.TemporaryDirectory(prefix="daahe-network-replay-") as temporary:
        run_one(config, run["seed"], run["method"],
                campaign / "exogenous" / f"seed-{run['seed']}", temporary,
                campaign / "controller.json")
        for name, expected in run_manifest["raw_files"].items():
            if file_hash(Path(temporary) / name) != expected:
                raise ValueError(f"deterministic replay mismatch: seed={run['seed']} method={run['method']} file={name}")
    return True


def _replay_runs(validated_runs, config, campaign, source_hashes, jobs):
    payloads = [(config, campaign, run, run_manifest, source_hashes)
                for run, _, run_manifest in validated_runs]
    if jobs == 1:
        for payload in payloads:
            _replay_run(payload)
    else:
        with ProcessPoolExecutor(max_workers=jobs) as executor:
            for _ in executor.map(_replay_run, payloads):
                pass


def verify(campaign, *, replay=False, jobs=1):
    if type(jobs) is not int or jobs < 1:
        raise ValueError("jobs must be a positive integer")
    campaign = Path(campaign).resolve()
    manifest = json.loads((campaign / "manifest.json").read_text())
    config = validate_config(json.loads((campaign / "config.json").read_text()))
    if not manifest["completed"]:
        raise ValueError("campaign is incomplete")
    if digest(config) != manifest["config_digest"]:
        raise ValueError("configuration digest mismatch")
    if file_hash(campaign / "config.json") != manifest["effective_config_sha256"]:
        raise ValueError("effective configuration checksum mismatch")
    if file_hash(campaign / "controller.json") != manifest["controller_sha256"]:
        raise ValueError("controller snapshot checksum mismatch")
    for name, binding in manifest["bound_artifacts"].items():
        if file_hash(campaign / binding["file"]) != binding["sha256"]:
            raise ValueError("bound cryptographic evidence snapshot checksum mismatch: " + name)
        expected = config["bound_evidence_artifacts"][name]
        if binding["path"] != expected["path"] or binding["sha256"] != expected["sha256"]:
            raise ValueError("cryptographic evidence snapshot differs from configuration binding")
    validate_bound_artifacts(config, campaign,
        {name: campaign / binding["file"] for name, binding in manifest["bound_artifacts"].items()})
    for relative, expected in manifest["source_hashes"].items():
        if file_hash(campaign / "source" / relative) != expected:
            raise ValueError("source snapshot checksum mismatch: " + relative)
    if digest(manifest["source_hashes"]) != manifest["source_digest"]:
        raise ValueError("source digest mismatch")
    expected_pairs = {(seed, method) for seed in config["evaluation_seeds"] for method in config["methods"]}
    pairs = [(run["seed"], run["method"]) for run in manifest["runs"]]
    if len(pairs) != len(set(pairs)) or set(pairs) != expected_pairs:
        raise ValueError("campaign does not contain exactly the paired seed/method product")
    exogenous = {}
    for seed in config["evaluation_seeds"]:
        _, _, _, item = read_exogenous(campaign / "exogenous" / f"seed-{seed}")
        exogenous[seed] = item["exogenous_digest"]
    summaries = []
    validated_runs = []
    for run in manifest["runs"]:
        run_dir = campaign / run["directory"]
        if file_hash(run_dir / "manifest.json") != run["manifest_sha256"]:
            raise ValueError("run manifest checksum mismatch")
        if file_hash(run_dir / "summary.json") != run["summary_sha256"]:
            raise ValueError("run summary checksum mismatch")
        run_manifest = json.loads((run_dir / "manifest.json").read_text())
        _require_all_raw_files(run_manifest.get("raw_files"))
        if run_manifest["exogenous_digest"] != exogenous[run["seed"]]:
            raise ValueError("unpaired exogenous trace")
        if run_manifest["source_digest"] != manifest["source_digest"] or run_manifest["controller_sha256"] != manifest["controller_sha256"]:
            raise ValueError("run source/controller identity mismatch")
        validated_runs.append((run, run_dir, run_manifest))
    raw_results = _recompute_runs([item[1] for item in validated_runs], config, jobs)
    for (run, run_dir, run_manifest), recomputed in zip(validated_runs, raw_results, strict=True):
        if recomputed != json.loads((run_dir / "summary.json").read_text()):
            raise ValueError("summary does not match independently recomputed raw outcomes")
        summaries.append(recomputed)
    recomputed = paired_campaign_summary(summaries, config["methods"])
    if recomputed != json.loads((campaign / "summary.json").read_text()):
        raise ValueError("paired campaign summary mismatch")
    if file_hash(campaign / "summary.json") != manifest["summary_sha256"]:
        raise ValueError("paired campaign summary checksum mismatch")
    if replay:
        _replay_runs(validated_runs, config, campaign, manifest["source_hashes"], jobs)
    return {"verified_runs": len(pairs), "independent_raw_recomputation": True,
            "deterministic_replay": replay, "source_digest": manifest["source_digest"],
            "status": manifest["status"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--replay", action="store_true", help="Rerun all seed/method pairs and compare raw gzip hashes")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallelize independent raw-log audits and exact deterministic replays")
    args = parser.parse_args()
    print(json.dumps(verify(args.campaign, replay=args.replay, jobs=args.jobs), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
