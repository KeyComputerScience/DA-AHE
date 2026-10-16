#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export paired campaign statistics, publication tables, and five evidence-based panels."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import shutil
import statistics
import sys
import tempfile

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from simulation import METHODS, STATUS  # noqa: E402
from simulation.audit import paired_campaign_summary  # noqa: E402
from simulation.io import digest, file_hash, read_jsonl, write_json  # noqa: E402

# Directions describe each estimand; admission and acceptance are not integrity guarantees.
METRICS = {
    "accepted_delivery_fraction_per_admitted": ("Accepted / admitted", "%", 100, "higher"),
    "invalid_acceptance_fraction_per_admitted": ("Invalid accepted / admitted", "%", 100, "lower"),
    "modeled_cpu_energy_j_all_run": ("Modeled CPU energy", "J/run", 1, "lower"),
    "modeled_radio_tx_energy_j_all_run": ("Modeled radio TX energy", "J/run", 1, "lower"),
    "observed_residual_loss_fraction": ("Observed loss / admitted", "%", 100, "lower"),
    "source_admission_fraction": ("Admission / opportunity", "%", 100, "contextual"),
    "valid_delay_mean_s": ("Conditional valid delay", "s", 1, "lower"),
    "valid_delay_p95_s": ("Per-seed valid delay p95", "s", 1, "lower"),
    "valid_delivery_fraction_per_admitted": ("Valid / admitted", "%", 100, "higher"),
    "valid_delivery_fraction_per_opportunity": ("Valid / opportunity", "%", 100, "higher"),
    "wire_bytes_per_source_opportunity_all_run": ("Wire bytes / opportunity", "bytes", 1, "lower"),
}
FIELDS = ("seed", "method", *METRICS, "recovery_right_censored",
          "recovery_completion_s", "all_decisions_certified")
FIGURES = ("revised-DA_energy_comparison", "revised-packetC", "revised-MarkovR",
           "revised-baseline", "revised-ablationA")
BOUND_ROLES = frozenset({"decoding_report", "security_profile", "security_report"})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    def duplicate_checked(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=duplicate_checked,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("nonfinite JSON value: " + value)))


def local_path(root, relative):
    require(isinstance(relative, str) and relative and "\\" not in relative,
            "invalid campaign-relative path")
    path = Path(relative)
    require(not path.is_absolute() and all(x not in ("", ".", "..")
                                          for x in relative.split("/")), "unsafe input path")
    result = root / path
    require(result.resolve().is_relative_to(root), "input path escapes campaign")
    require(not any(p.is_symlink() for p in (result, *result.parents)
                    if p != root and p.is_relative_to(root)),
            "input symlink forbidden")
    return result


def number(value, label, *, optional=False):
    if value == "" and optional:
        return None
    require(isinstance(value, str) and value.strip() == value and value != "",
            "missing or malformed numeric cell: " + label)
    try:
        result = float(value)
    except ValueError as error:
        raise ValueError("malformed numeric cell: " + label) from error
    require(math.isfinite(result) and result >= 0, "nonfinite or negative metric: " + label)
    return result


def boolean(value):
    require(value in ("True", "False"), "invalid CSV boolean")
    return value == "True"


def near(a, b):
    return a is b if a is None or b is None else (
        type(a) in (int, float) and type(b) in (int, float)
        and math.isfinite(a) and math.isfinite(b)
        and math.isclose(a, b, rel_tol=1e-11, abs_tol=1e-12))


def sha256_text(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value)


def read_rows(path, seeds, methods):
    expected = {(seed, method) for seed in seeds for method in methods}
    rows, seen = [], set()
    with Path(path).open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames is not None and len(reader.fieldnames) == len(FIELDS)
                and set(reader.fieldnames) == set(FIELDS), "per-seed CSV schema differs")
        for raw in reader:
            require(set(raw) == set(FIELDS) and all(v is not None for v in raw.values()),
                    "missing or extra CSV cell")
            try:
                seed = int(raw["seed"])
            except ValueError as error:
                raise ValueError("invalid seed") from error
            require(str(seed) == raw["seed"], "invalid seed encoding")
            key = seed, raw["method"]
            require(key in expected and key not in seen, "unexpected or duplicate seed/method")
            seen.add(key)
            metrics = {name: number(raw[name], name, optional=True) for name in METRICS}
            for name, value in metrics.items():
                if value is not None and METRICS[name][1] == "%":
                    require(value <= 1, "fraction exceeds one")
            require(all(metrics[name] is not None for name in (
                "modeled_cpu_energy_j_all_run", "modeled_radio_tx_energy_j_all_run",
                "wire_bytes_per_source_opportunity_all_run")), "missing complete-run cost")
            admitted_names = ("accepted_delivery_fraction_per_admitted",
                              "observed_residual_loss_fraction",
                              "valid_delivery_fraction_per_admitted",
                              "invalid_acceptance_fraction_per_admitted")
            values = [metrics[name] for name in admitted_names]
            require(all(v is None for v in values) or all(v is not None for v in values),
                    "inconsistent undefined admitted denominator")
            if all(v is not None for v in values):
                accepted, loss, valid, invalid = values
                require(near(accepted + loss, 1) and near(valid + invalid, accepted),
                        "admitted-denominator identities differ")
                admission = metrics["source_admission_fraction"]
                opportunity = metrics["valid_delivery_fraction_per_opportunity"]
                require(admission is not None and opportunity is not None
                        and near(admission * valid, opportunity),
                        "opportunity-denominator identity differs")
            else:
                require(metrics["source_admission_fraction"] in (None, 0)
                        and metrics["valid_delivery_fraction_per_opportunity"] in (None, 0),
                        "undefined admitted denominator despite positive admission")
            delay = [metrics["valid_delay_mean_s"], metrics["valid_delay_p95_s"]]
            require(all(v is None for v in delay) or all(v is not None for v in delay),
                    "inconsistent undefined delay")
            if delay[0] is None:
                require(metrics["valid_delivery_fraction_per_opportunity"] in (None, 0),
                        "missing delay despite valid delivery")
            else:
                require(metrics["valid_delivery_fraction_per_opportunity"] not in (None, 0),
                        "delay present without valid delivery")
            censored = boolean(raw["recovery_right_censored"])
            completion = number(raw["recovery_completion_s"], "recovery", optional=True)
            require(not censored or completion is None, "censored recovery has a completion")
            require(boolean(raw["all_decisions_certified"]) is False,
                    "synthetic campaign relabeled as certified")
            rows.append({"seed": seed, "method": key[1], "metrics": metrics,
                         "recovery_right_censored": censored,
                         "recovery_completion_s": completion, "all_decisions_certified": False})
    require(seen == expected and len(rows) == len(expected), "missing paired CSV rows")
    return sorted(rows, key=lambda row: (row["seed"], methods.index(row["method"])))


def rows_from_summaries(summaries):
    return [{"seed": s["seed"], "method": s["method"], "metrics": s["metrics"],
             "recovery_right_censored": s["recovery"]["right_censored"],
             "recovery_completion_s": s["recovery"]["recovery_completion_s"],
             "all_decisions_certified": s["all_decisions_certified"]} for s in summaries]


def write_rows(path, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({**{k: row[k] for k in FIELDS if k not in METRICS}, **row["metrics"]})


def validate_summary(rows, summary, methods):
    audit_rows = [{**row, "recovery": {
        "right_censored": row["recovery_right_censored"],
        "status": "right_censored" if row["recovery_right_censored"] else (
            "observed_recovery" if row["recovery_completion_s"] is not None
            else "no_observed_excursion")}} for row in rows]
    expected = paired_campaign_summary(audit_rows, methods)
    require(summary.get("status") == STATUS
            and summary.get("paired_evaluation_seeds") == expected["paired_evaluation_seeds"]
            and set(summary.get("methods", {})) == set(methods), "summary matrix differs")
    for method in methods:
        actual, desired = summary["methods"][method], expected["methods"][method]
        require(set(actual["metrics"]) == set(METRICS), "summary metric schema differs")
        for name in METRICS:
            require(set(actual["metrics"][name]) == set(desired["metrics"][name])
                    and all(near(actual["metrics"][name][key], value)
                            for key, value in desired["metrics"][name].items()),
                    "CSV and summary statistics differ: " + method + "/" + name)
        for key in ("recovery_right_censored_seeds", "recovery_no_excursion_seeds"):
            require(actual[key] == desired[key], "recovery availability differs")
    require(set(summary.get("paired_differences", {})) == set(expected["paired_differences"]),
            "paired difference method schema differs")
    for method, metrics in expected["paired_differences"].items():
        require(set(summary["paired_differences"][method]) == set(metrics),
                "paired difference metric schema differs")
        for name, desired in metrics.items():
            actual = summary["paired_differences"][method][name]
            require(actual["direction"] == desired["direction"]
                    and len(actual["per_seed"]) == len(desired["per_seed"])
                    and all(a["seed"] == b["seed"] and near(a["difference"], b["difference"])
                            for a, b in zip(actual["per_seed"], desired["per_seed"], strict=True))
                    and near(actual["mean_difference"], desired["mean_difference"])
                    and near(actual["sd_difference"], desired["sd_difference"]),
                    "paired CSV/summary differences disagree")


def load_campaign(campaign):
    root = Path(campaign).resolve()
    documents = {name: read_json(local_path(root, name + ".json"))
                 for name in ("manifest", "config", "controller", "summary")}
    manifest, config = documents["manifest"], documents["config"]
    require(manifest.get("schema_version") == config.get("schema_version") == 1
            and manifest.get("completed") is True and manifest.get("status") == STATUS
            and config.get("protocol_model_version") == 2, "invalid campaign schema/status")
    seeds, methods = config.get("evaluation_seeds"), config.get("methods")
    require(isinstance(seeds, list) and len(seeds) >= 2
            and all(type(s) is int and s >= 0 for s in seeds) and len(set(seeds)) == len(seeds),
            "at least two distinct declared paired seeds are required")
    require(isinstance(methods, list) and all(isinstance(m, str) for m in methods)
            and "da-ahe" in methods and len(set(methods)) == len(methods)
            and set(methods) <= set(METHODS), "invalid declared method matrix")
    require(manifest.get("evaluation_seeds") == seeds and manifest.get("methods") == methods,
            "manifest/config matrix mismatch")
    require(type(config.get("nodes")) is int and config["nodes"] > 0, "invalid node count")
    for name, field in (("config", "effective_config_sha256"),
                        ("controller", "controller_sha256"), ("summary", "summary_sha256")):
        require(file_hash(root / (name + ".json")) == manifest.get(field), name + " hash mismatch")
    require(digest(config) == manifest.get("config_digest"), "config digest mismatch")
    calibration = config.get("calibration_seeds", [])
    require(isinstance(calibration, list) and all(type(s) is int for s in calibration)
            and not set(calibration).intersection(seeds)
            and manifest.get("calibration_seeds", []) == calibration,
            "calibration/evaluation seed declarations differ or overlap")
    hashes = manifest.get("source_hashes")
    require(isinstance(hashes, dict) and hashes and digest(hashes) == manifest.get("source_digest"),
            "source identity mismatch")
    source_snapshot_count = 0
    for name, value in hashes.items():
        path = local_path(root / "source", name)
        require(sha256_text(value), "invalid source hash")
        if path.exists():
            require(file_hash(path) == value, "source snapshot hash mismatch")
            source_snapshot_count += 1
    expected = {(s, m) for s in seeds for m in methods}
    runs = manifest.get("runs", [])
    require(isinstance(runs, list) and all(isinstance(r, dict) for r in runs),
            "invalid manifest run schema")
    keys = [(r.get("seed"), r.get("method")) for r in runs]
    require(len(keys) == len(expected) and len(set(keys)) == len(keys) and set(keys) == expected,
            "manifest does not contain exactly the declared seed/method product")
    require(all(sha256_text(r.get("manifest_sha256")) and sha256_text(r.get("summary_sha256"))
                for r in runs), "invalid run artifact hash declaration")
    directories = [local_path(root, r["directory"]) for r in runs]
    require(len(set(directories)) == len(directories), "duplicate run directory")
    present = [(p / "manifest.json").is_file() for p in directories]
    require(all(present) or not any(present), "partial run provenance directory set")
    summaries, run_manifests, exogenous = [], {}, {}
    bindings = manifest.get("bound_artifacts", {})
    configured_bindings = config.get("bound_evidence_artifacts", {})
    require(set(bindings) == set(configured_bindings), "bound artifact declaration differs")
    if all(present):
        require(set(bindings) == BOUND_ROLES,
                "campaign run snapshots require all three bound evidence roles")
    verified_bound_artifacts = {}
    for name, binding in bindings.items():
        expected_binding = configured_bindings[name]
        require(binding.get("path") == expected_binding.get("path")
                and binding.get("sha256") == expected_binding.get("sha256")
                and sha256_text(binding.get("sha256")), "bound artifact identity differs")
        snapshot = local_path(root, binding["file"])
        available = snapshot if snapshot.is_file() else local_path(ROOT, binding["path"])
        if all(present):
            require(snapshot.is_file(), "missing campaign bound artifact snapshot: " + name)
        if available.is_file():
            require(file_hash(available) == binding["sha256"], "bound artifact hash mismatch: " + name)
            verified_bound_artifacts[name] = {
                "sha256": binding["sha256"],
                "location": "campaign_snapshot" if available == snapshot else "repository_artifact"}
    if all(present):
        for run, directory in zip(runs, directories, strict=True):
            require(file_hash(directory / "manifest.json") == run["manifest_sha256"]
                    and file_hash(directory / "summary.json") == run["summary_sha256"],
                    "run manifest/summary hash mismatch")
            rm, rs = read_json(directory / "manifest.json"), read_json(directory / "summary.json")
            require((rm["seed"], rm["method"]) == (run["seed"], run["method"])
                    and (rs["seed"], rs["method"]) == (run["seed"], run["method"])
                    and rm["source_digest"] == manifest["source_digest"]
                    and rm["controller_sha256"] == manifest["controller_sha256"]
                    and rm["config_digest"] == rs["config_digest"] == manifest["config_digest"]
                    and rm["exogenous_digest"] == rs["exogenous_digest"], "run identity mismatch")
            old = exogenous.setdefault(run["seed"], rm["exogenous_digest"])
            require(old == rm["exogenous_digest"], "unpaired exogenous identity")
            summaries.append(rs)
            run_manifests[(run["seed"], run["method"])] = (directory, rm)
    csv_path = local_path(root, "per-seed.csv")
    if csv_path.is_file():
        rows = read_rows(csv_path, seeds, methods)
        if summaries:
            wanted = {(r["seed"], r["method"]): r for r in rows_from_summaries(summaries)}
            require(all(row == wanted[(row["seed"], row["method"])] for row in rows),
                    "CSV disagrees with run summaries")
    else:
        require(summaries, "report bundle requires per-seed.csv")
        # Apply the same CSV schema/finite/denominator checks to derived rows.
        with tempfile.TemporaryDirectory(prefix="daahe-export-schema-") as temporary:
            temporary_csv = Path(temporary) / "per-seed.csv"
            write_rows(temporary_csv, rows_from_summaries(summaries))
            rows = read_rows(temporary_csv, seeds, methods)
    seeds = sorted(seeds)
    validate_summary(rows, documents["summary"], methods)
    onset, horizon = config["disturbance"]["start_s"], config["duration_s"] + config["drain_s"]
    require(math.isfinite(onset) and math.isfinite(horizon) and 0 <= onset <= horizon,
            "invalid recovery observation horizon")
    for row in rows:
        value = row["recovery_completion_s"]
        require(value is None or onset <= value <= horizon, "recovery outside observation horizon")
    provenance = {
        "input_kind": "campaign_run_snapshots" if summaries else "campaign_report_bundle",
        "source_digest": manifest["source_digest"], "config_digest": manifest["config_digest"],
        "input_sha256": {name: file_hash(root / name) for name in
                         ("manifest.json", "config.json", "controller.json", "summary.json")},
        "per_seed_origin": "input_csv" if csv_path.is_file() else "bound_run_summaries",
        "paired_run_count": len(rows), "run_snapshot_count": len(summaries),
        "source_snapshot_count": source_snapshot_count, "source_declared_count": len(hashes),
        "bound_artifact_declared_count": len(bindings),
        "verified_bound_artifacts": verified_bound_artifacts,
        "validation_scope": "Snapshot and paired-summary consistency; event-level audit uses verify_simulation_campaign.",
        "checks": ["declared_matrix", "snapshot_hashes", "source_digest_binding",
                   "CSV_schema_and_denominators", "summary_and_paired_difference_consistency"],
    }
    if csv_path.is_file():
        provenance["input_sha256"]["per-seed.csv"] = file_hash(csv_path)
    if summaries:
        provenance["checks"].extend(["run_identity_hashes", "paired_exogenous_identity"])
    return {**documents, "rows": rows, "seeds": seeds, "methods": methods,
            "run_manifests": run_manifests, "provenance": provenance}


def validate_epochs(epochs):
    """Validate the recorded engine/policy observation and action fields used by feedback panels."""
    require(epochs and all(isinstance(r, dict) and type(r.get("time_s")) in (int, float)
                           and math.isfinite(r["time_s"]) for r in epochs), "invalid epoch times")
    require(epochs[0]["time_s"] == 0 and all(a["time_s"] < b["time_s"]
            for a, b in zip(epochs, epochs[1:])), "invalid epoch chronology")
    previous = 0
    for row in epochs:
        require(row.get("observation_cutoff_s") == row["time_s"]
                and row.get("observation_start_s") == previous, "invalid epoch observation window")
        previous = row["time_s"]
        for field, length in (("telemetry", 7), ("state", 3)):
            values = row.get(field)
            require(isinstance(values, list) and len(values) == length
                    and all(type(x) in (int, float) and math.isfinite(x) and x >= 0 for x in values),
                    "invalid epoch " + field)
        belief = row.get("belief")
        require(belief is None or (isinstance(belief, list) and len(belief) == 5
                and all(type(x) in (int, float) and math.isfinite(x) and 0 <= x <= 1 for x in belief)
                and near(sum(belief), 1)), "invalid recorded belief")
        require(type(row.get("accepted_reports")) is int and row["accepted_reports"] >= 0,
                "invalid epoch accepted-report count")
        decision = row.get("decision")
        require(isinstance(decision, dict) and "action" in decision
                and decision.get("certified") is False and row.get("certified") is False,
                "invalid synthetic epoch decision")
        action = decision["action"]
        require(action is None or (isinstance(action, dict)
                and type(action.get("batch_size")) is int and action["batch_size"] > 0),
                "invalid recorded selected batch size")


def paired_statistics(rows, seeds, methods, *, resamples=100000, bootstrap_seed=20261016,
                      metric_specs=METRICS):
    require(type(resamples) is int and resamples >= 2, "bootstrap resamples must be at least two")
    require(type(bootstrap_seed) is int and bootstrap_seed >= 0, "invalid bootstrap seed")
    by_key = {(row["seed"], row["method"]): row for row in rows}
    require(len(seeds) >= 2 and len(set(seeds)) == len(seeds)
            and len(by_key) == len(rows) == len(seeds) * len(methods)
            and set(by_key) == {(s, m) for s in seeds for m in methods}, "invalid paired matrix")
    indices = np.random.Generator(np.random.PCG64(bootstrap_seed)).integers(
        0, len(seeds), size=(resamples, len(seeds)), dtype=np.int32)
    result = {method: {} for method in methods}
    def interval(values):
        return [float(x) for x in np.quantile(values, [0.025, 0.975], method="linear")]
    for name, (label, unit, scale, direction) in metric_specs.items():
        boot, means = {}, {}
        for method in methods:
            values = [by_key[(seed, method)]["metrics"][name] for seed in seeds]
            defined = sum(value is not None for value in values)
            record = {"label": label, "unit": unit, "display_scale": scale,
                      "preferred_direction": direction, "n_total": len(seeds),
                      "n_defined": defined, "per_seed": values, "mean": None, "sd": None,
                      "percentile_ci_95": None}
            if defined != len(seeds):
                record["status"] = "withheld_undefined_seed_metric"
            else:
                vector = np.asarray(values, dtype=float)
                require(np.isfinite(vector).all(), "nonfinite bootstrap metric")
                boot[method] = vector[indices].mean(axis=1)
                means[method] = statistics.fmean(values)
                record.update(status="complete_paired_seeds", mean=means[method],
                              sd=statistics.stdev(values), percentile_ci_95=interval(boot[method]))
            result[method][name] = record
        for method in methods:
            record = result[method][name]
            paired = {"direction": "method minus da-ahe", "mean_difference": None,
                      "difference_percentile_ci_95": None, "ratio_of_means": None,
                      "ratio_percentile_ci_95": None}
            if method not in boot or "da-ahe" not in boot:
                paired["status"] = "withheld_undefined_paired_metric"
            else:
                paired.update(status="complete_paired_seeds",
                              mean_difference=means[method] - means["da-ahe"],
                              difference_percentile_ci_95=interval(boot[method] - boot["da-ahe"]))
                if means["da-ahe"] == 0:
                    paired["ratio_status"] = "undefined_zero_reference"
                elif np.any(boot["da-ahe"] == 0):
                    paired.update(ratio_status="undefined_bootstrap_zero_reference",
                                  ratio_of_means=means[method] / means["da-ahe"])
                else:
                    paired.update(ratio_status="complete_paired_seeds",
                                  ratio_of_means=means[method] / means["da-ahe"],
                                  ratio_percentile_ci_95=interval(boot[method] / boot["da-ahe"]))
            record["paired_to_da_ahe"] = paired
    return result, {"unit": "paired seed", "seed_count": len(seeds),
                    "resamples": resamples, "generator": "numpy.PCG64", "numpy_version": np.__version__,
                    "seed": bootstrap_seed,
                    "index_sha256": hashlib.sha256(indices.tobytes()).hexdigest(),
                    "interval": "two-sided percentile 95%, linear quantiles",
                    "pairing": "one shared seed-index matrix for all methods and metrics",
                    "ratio_estimand": "ratio of seed means, not mean of seed ratios",
                    "undefined_policy": "retain every seed; withhold incomplete paired estimands"}


def recovery_summary(data, *, resamples=100000, bootstrap_seed=20261016):
    config, rows = data["config"], data["rows"]
    onset, end = config["disturbance"]["start_s"], config["duration_s"] + config["drain_s"]
    methods = {}
    for method in data["methods"]:
        subset = [row for row in rows if row["method"] == method]
        methods[method] = {
            "observed_recovery": sum(r["recovery_completion_s"] is not None for r in subset),
            "right_censored": sum(r["recovery_right_censored"] for r in subset),
            "no_observed_excursion": sum(not r["recovery_right_censored"]
                                         and r["recovery_completion_s"] is None for r in subset),
            "per_seed": [{"seed": r["seed"], "right_censored": r["recovery_right_censored"],
                          "completion_s": r["recovery_completion_s"],
                          "elapsed_from_onset_s": None if r["recovery_completion_s"] is None
                          else r["recovery_completion_s"] - onset} for r in subset]}
    complete = all(m["observed_recovery"] == len(data["seeds"]) for m in methods.values())
    result = {"status": "all_observed" if complete else "withheld_incomplete_recovery_stratum",
            "observation_end_s": end, "disturbance_onset_s": onset,
            "censor_interval_from_onset_s": end - onset, "methods": methods,
            "statistics": None,
            "scope": "Censoring intervals and no-excursion cases are not observed recovery times."}
    if complete:
        recovery_rows = [{**r, "metrics": {
            "recovery_elapsed_s": r["recovery_completion_s"] - onset}} for r in rows]
        stats, _ = paired_statistics(recovery_rows, data["seeds"], data["methods"],
            resamples=resamples, bootstrap_seed=bootstrap_seed,
            metric_specs={"recovery_elapsed_s": ("Observed recovery from onset", "s", 1, "lower")})
        result["statistics"] = {m: stats[m]["recovery_elapsed_s"] for m in data["methods"]}
    return result


def make_tables(result):
    methods, stats = result["methods"], result["statistics"]
    md = ["# Paired campaign performance", "",
          f"Independent synthetic model; {len(result['seeds'])} paired seeds; "
          f"{len(methods)} methods. Values are seed means ± sample SD. Intervals are "
          "paired-seed percentile bootstrap 95% intervals, not certification or significance claims.", ""]
    tex = ["% Requires amsmath. Values are independent synthetic campaign estimates."]
    for name, (label, unit, scale, direction) in METRICS.items():
        md += [f"## {label} ({unit}; preferred direction: {direction})", "",
               "| Method | Defined seeds | Mean ± SD | 95% interval | Ratio to DA-AHE [95% interval] |",
               "|---|---:|---:|---:|---:|"]
        tex += [r"\begin{table*}[t]\centering\small",
                "\\caption{" + label.replace("%", r"\%") + " (" + unit.replace("%", r"\%")
                + f"); {len(result['seeds'])} paired seeds. Mean, sample SD and percentile 95\\% interval.}}",
                r"\begin{tabular}{lrrrrr}\hline",
                r"Method & Defined & Mean & SD & CI low & CI high\\\hline"]
        for method in methods:
            item = stats[method][name]
            if item["mean"] is None:
                mean_sd, ci, ratio = "withheld", "withheld", "withheld"
                cells = ["--"] * 4
            else:
                lo, hi = item["percentile_ci_95"]
                mean_sd = f"{item['mean'] * scale:.6g} ± {item['sd'] * scale:.6g}"
                ci = f"[{lo * scale:.6g}, {hi * scale:.6g}]"
                pair = item["paired_to_da_ahe"]
                ratio = "undefined" if pair["ratio_of_means"] is None else f"{pair['ratio_of_means']:.6g}"
                if pair["ratio_percentile_ci_95"] is not None:
                    ratio += " [" + ", ".join(f"{x:.6g}" for x in pair["ratio_percentile_ci_95"]) + "]"
                cells = [f"{x * scale:.6g}" for x in (item["mean"], item["sd"], lo, hi)]
            md.append(f"| {method} | {item['n_defined']}/{item['n_total']} | {mean_sd} | {ci} | {ratio} |")
            tex.append(method.replace("_", r"\_") + " & " + str(item["n_defined"])
                       + " & " + " & ".join(cells) + r"\\")
        md.append("")
        tex += [r"\hline\end{tabular}\end{table*}", ""]
    md += ["## Recovery availability", "", "| Method | Observed | Right-censored | No excursion |",
           "|---|---:|---:|---:|"]
    for method, item in result["recovery"]["methods"].items():
        md.append(f"| {method} | {item['observed_recovery']} | {item['right_censored']} | "
                  f"{item['no_observed_excursion']} |")
    md += ["", result["recovery"]["scope"], "",
           "Delay conditions on valid delivery. Accepted delivery includes invalid acceptance; "
           "report it with valid delivery. Energy covers modeled CPU and TX, not board energy. "
           "Admission has no unconditional preferred direction. Evidence coverage is not a forgery rate."]
    return "\n".join(md) + "\n", "\n".join(tex) + "\n"


def make_figures(data, result, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 9,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "pdf.fonttype": 42})
    methods, stats = result["methods"], result["statistics"]
    n = len(result["seeds"])
    captions = {}
    def bars(ax, metric, selected=methods):
        label, unit, scale, _ = METRICS[metric]
        for i, method in enumerate(selected):
            item = stats[method][metric]
            if item["mean"] is None:
                ax.text(i, 0, f"undefined\n{item['n_defined']}/{n}", ha="center", va="bottom")
                continue
            lo, hi = item["percentile_ci_95"]
            mean = item["mean"]
            ax.bar(i, mean * scale, color=plt.get_cmap("tab10")(methods.index(method) % 10),
                   edgecolor="black", linewidth=.5)
            ax.vlines(i, lo * scale, hi * scale, color="black")
            ax.hlines([lo * scale, hi * scale], i - .08, i + .08, color="black")
        ax.set_xticks(range(len(selected)), [m.replace("without_", "w/o ").replace("_", " ")
                                             for m in selected], rotation=30, ha="right")
        ax.set_ylabel(f"{label} ({unit})")
        ax.grid(axis="y", alpha=.2)
    def save(fig, name, caption):
        fig.suptitle(f"Independent synthetic campaign; n={n} paired seeds", fontsize=10)
        fig.tight_layout()
        fig.savefig(output / (name + ".pdf"), bbox_inches="tight",
                    metadata={"Title": caption, "Creator": "DA-AHE performance exporter",
                              "CreationDate": None, "ModDate": None})
        plt.close(fig)
        captions[name + ".pdf"] = caption
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    for ax, metric in zip(axes, ("modeled_cpu_energy_j_all_run", "modeled_radio_tx_energy_j_all_run")):
        bars(ax, metric)
    save(fig, FIGURES[0], "Complete-run modeled CPU and transmit energy; seed-bootstrap 95% intervals.")
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    bars(axes[0], "observed_residual_loss_fraction")
    bars(axes[1], "valid_delivery_fraction_per_opportunity")
    save(fig, FIGURES[1], "Admitted-only observed loss and valid deliveries per offered opportunity.")

    coverage = {method: {"metric_rows": n, "run_snapshots": 0, "epoch_files": 0} for method in methods}
    epoch_example = None
    for (seed, method), (directory, manifest) in data["run_manifests"].items():
        coverage[method]["run_snapshots"] += 1
        epoch = directory / "epochs.jsonl.gz"
        if epoch.is_file():
            require(file_hash(epoch) == manifest.get("raw_files", {}).get("epochs.jsonl.gz"),
                    "epoch evidence hash mismatch")
            coverage[method]["epoch_files"] += 1
            if method == "da-ahe" and seed == min(result["seeds"]):
                epoch_example = (seed, epoch)
    if epoch_example is None:
        fig, ax = plt.subplots(figsize=(8, 3.8))
        x = np.arange(len(methods))
        for offset, key in enumerate(("metric_rows", "run_snapshots", "epoch_files")):
            ax.bar(x + (offset - 1) * .25, [coverage[m][key] for m in methods], .25,
                   label=key.replace("_", " "))
        ax.set_xticks(x, methods, rotation=30, ha="right")
        ax.set_ylabel("Evidence files / paired seed rows")
        ax.legend()
        feedback = {"kind": "evidence_coverage", "coverage": coverage}
        caption = "Manifest-bound evidence coverage; no feedback trajectory is inferred from summary metrics."
    else:
        seed, path = epoch_example
        epochs = list(read_jsonl(path))
        validate_epochs(epochs)
        times = [row["time_s"] for row in epochs]
        fig, axes = plt.subplots(2, 2, figsize=(9, 5.5))
        for index, label in ((0, "Queue fraction"), (1, "Observed loss fraction")):
            axes[0, 0].plot(times, [r["telemetry"][index] for r in epochs], label=label)
        axes[0, 0].legend(fontsize=7)
        axes[0, 1].plot(times, [r["telemetry"][2] if r["accepted_reports"] else np.nan for r in epochs])
        axes[0, 1].set_ylabel("Accepted-report delay (s; gaps for empty windows)")
        filtered = [row for row in epochs if row.get("belief") is not None]
        for regime in range(5):
            axes[1, 0].plot([r["time_s"] for r in filtered],
                            [r["belief"][regime] for r in filtered], label=f"Regime {regime + 1}")
        axes[1, 0].set_ylabel("Recorded posterior belief")
        axes[1, 0].legend(fontsize=6, ncol=2)
        selected = [r for r in epochs if r["decision"].get("action") is not None]
        axes[1, 1].step([r["time_s"] for r in selected],
                        [r["decision"]["action"]["batch_size"] for r in selected], where="post")
        axes[1, 1].set_ylabel("Selected batch-size cap")
        for ax in axes.flat:
            ax.set_xlabel("Time (s)")
        feedback = {"kind": "recorded_epoch_example", "seed": seed, "sha256": file_hash(path),
                    "selection_rule": "smallest declared evaluation seed", "coverage": coverage}
        axes[0, 0].set_title(f"Recorded DA-AHE seed {seed}")
        caption = f"Recorded DA-AHE epoch observations for smallest declared seed {seed}; not a seed mean or hidden-state trace."
    save(fig, FIGURES[2], caption)
    result["feedback_panel"] = feedback

    base = [m for m in methods if m in ("da-ahe", "dpp", "hys")]
    fig, axes = plt.subplots(1, 3, figsize=(10, 3.8))
    bars(axes[0], "valid_delay_mean_s", base)
    bars(axes[1], "observed_residual_loss_fraction", base)
    if result["recovery"]["statistics"] is not None:
        for i, method in enumerate(base):
            item = result["recovery"]["statistics"][method]
            axes[2].bar(i, item["mean"])
            axes[2].vlines(i, *item["percentile_ci_95"], color="black")
        axes[2].set_xticks(range(len(base)), base)
        axes[2].set_ylabel("Observed recovery from onset (s)")
    else:
        bottom = np.zeros(len(base))
        for key in ("observed_recovery", "right_censored", "no_observed_excursion"):
            values = np.asarray([result["recovery"]["methods"][m][key] for m in base])
            axes[2].bar(base, values, bottom=bottom, label=key.replace("_", " "))
            bottom += values
        axes[2].set_ylabel("Recovery availability (seed count)")
        axes[2].legend(fontsize=6)
    save(fig, FIGURES[3], "Complete-policy baseline outcomes and retained recovery censoring; no isolated belief-effect claim.")
    ablations = [m for m in methods if m == "da-ahe" or m.startswith("without_")]
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.8))
    for ax, metric in zip(axes, ("valid_delivery_fraction_per_opportunity", "valid_delay_mean_s",
                                "invalid_acceptance_fraction_per_admitted")):
        bars(ax, metric, ablations)
    save(fig, FIGURES[4], "Ablation service tradeoffs and modeled invalid acceptance; coverage is not a cryptographic forgery probability.")
    result["figure_captions"] = captions


def export_campaign(campaign, output, *, resamples=100000, bootstrap_seed=20261016, figures=True):
    data = load_campaign(campaign)
    output = Path(output).resolve()
    require(not output.exists(), "output must be a new directory")
    require(not output.is_relative_to(Path(campaign).resolve()), "output must be separate from input evidence")
    stats, bootstrap = paired_statistics(data["rows"], data["seeds"], data["methods"],
                                         resamples=resamples, bootstrap_seed=bootstrap_seed)
    result = {"schema_version": 1, "measurement_scope": "independent synthetic service model",
              "nodes": data["config"]["nodes"], "seeds": data["seeds"], "methods": data["methods"],
              "provenance": data["provenance"], "bootstrap": bootstrap, "statistics": stats,
              "recovery": recovery_summary(data, resamples=resamples, bootstrap_seed=bootstrap_seed),
              "interpretation": {"delay": "conditional on valid delivery, equally weighted seed means",
                  "p95": "mean of per-seed percentiles, not pooled packet percentile",
                  "energy": "modeled full-run CPU and transmit joules; no physical measurement",
                  "acceptance": "accepted delivery includes invalid acceptance; retain validity denominator",
                  "comparison": "complete policies; initialization, predictors and admission determine attribution",
                  "inference": "bootstrap uncertainty is not certification or an automatic significance claim"},
              "exporter_sha256": file_hash(Path(__file__))}
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=output.name + ".", dir=output.parent))
    try:
        if figures:
            make_figures(data, result, temporary)
        md, tex = make_tables(result)
        (temporary / "tables.md").write_text(md)
        (temporary / "table.tex").write_text(tex)
        write_rows(temporary / "per-seed.csv", data["rows"])
        write_json(temporary / "summary.json", result)
        write_json(temporary / "export-manifest.json", {
            "schema_version": 1, "input_provenance": data["provenance"],
            "outputs": {p.name: file_hash(p) for p in sorted(temporary.iterdir())}})
        temporary.rename(output)
    except BaseException:
        shutil.rmtree(temporary)
        raise
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap-resamples", type=int, default=100000)
    parser.add_argument("--bootstrap-seed", type=int, default=20261016)
    args = parser.parse_args()
    result = export_campaign(args.campaign, args.output, resamples=args.bootstrap_resamples,
                             bootstrap_seed=args.bootstrap_seed)
    print(json.dumps({"output": str(args.output), "paired_seeds": len(result["seeds"]),
                      "methods": len(result["methods"]), "bootstrap": result["bootstrap"]}, indent=2))


if __name__ == "__main__":
    main()
