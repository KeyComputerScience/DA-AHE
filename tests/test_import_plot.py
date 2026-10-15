# SPDX-License-Identifier: MIT
"""Analytic interface fixtures only; not measured results. Execution receipts are recorded separately."""
import csv
from dataclasses import replace
import importlib.util
import json
from pathlib import Path

import pytest

from daahe.statistics import (MetricRow, load_metrics_csv, summarize,
                              validate_experiment_matrix, write_metrics_csv)


def tool(name):
    path = Path(__file__).resolve().parents[1] / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"daahe_test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def analytic_inputs(tmp_path, *, delivered=True):
    events, telemetry, metadata = (tmp_path/name for name in ("events.csv", "telemetry.csv", "metadata.json"))
    with events.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["packet_id", "created_s", "delivered_s", "aggregate_id", "hve_available"])
        writer.writerow(["analytic-unit-1", 40, 40.1 if delivered else "", "analytic-aggregate" if delivered else "", "true" if delivered else ""])
    with telemetry.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["time_s", "queue_utilization", "residual_plr"])
        # These analytic rows assert only the interval-counting convention.
        writer.writerows((time, 0.1, 0.0) for time in range(100, 301))
    metadata.write_text(json.dumps({
        "schema_version":1, "run_id":"analytic-only", "method":"da-ahe", "nodes":3000, "seed":1,
        "simulator":"OMNeT++ 6.0 / INET 4.4", "measurement_unit":"application_report",
        "event_export_complete":True, "warmup_s":30, "duration_s":300, "disturbance_s":100,
        "normal_queue_threshold":0.2, "normal_plr_threshold":0.01,
        "trace_sha256":"a"*64, "configuration_sha256":"b"*64, "calibration_sha256":"c"*64,
        "loss_observation_boundary":"window_endpoint_loss", "delivery_cutoff_s":300, "drain_s":0,
        "telemetry_timestamp_semantics":"interval_end"}))
    return events, telemetry, metadata


def row(method="da-ahe", seed=1):
    return MetricRow(f"analytic-{method}-{seed}", method, 3000, seed, 10+seed,
                     0.01, 5.0, False, 1.0, 30, 300, 100, 30, 300,
                     f"{seed:064x}", "b"*64, "c"*64, "OMNeT++ 6.0 / INET 4.4", "application_report")


def test_interval_end_recovery_requires_five_full_post_onset_intervals(tmp_path):
    result, provenance = tool("import_omnet").import_external_run(*analytic_inputs(tmp_path))
    assert result.recovery_s == 5.0
    assert result.latency_ms == pytest.approx(100)
    assert provenance["loss_observation_boundary"] == "window_endpoint_loss"
    assert provenance["drain_s"] == 0


def test_wholly_undelivered_seed_preserves_plr_and_undefined_metric_reason(tmp_path):
    result, provenance = tool("import_omnet").import_external_run(*analytic_inputs(tmp_path, delivered=False))
    assert result.residual_plr == 1
    assert result.latency_ms is result.hve_coverage is None
    assert provenance["undefined_metrics"] == {"latency_ms":"no delivered units", "hve_coverage":"no delivered aggregates"}
    output = tmp_path/"metrics.csv"
    write_metrics_csv([result], output)
    assert load_metrics_csv(output) == [result]


def test_delivered_unit_without_aggregate_id_fails_closed(tmp_path):
    events, telemetry, metadata = analytic_inputs(tmp_path)
    events.write_text("packet_id,created_s,delivered_s,aggregate_id,hve_available\nanalytic-unit,40,41,,false\n")
    with pytest.raises(ValueError, match="each delivered unit"):
        tool("import_omnet").import_external_run(events, telemetry, metadata)


def test_missing_loss_boundary_declaration_is_rejected(tmp_path):
    events, telemetry, metadata = analytic_inputs(tmp_path)
    data = json.loads(metadata.read_text())
    del data["loss_observation_boundary"]
    metadata.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="window_endpoint_loss"):
        tool("import_omnet").import_external_run(events, telemetry, metadata)


def test_no_success_seed_deletion_when_one_paired_latency_is_undefined():
    rows = [row(method, seed) for method in ("da-ahe", "dpp") for seed in (1,2)]
    rows[-1] = replace(rows[-1], residual_plr=1.0, latency_ms=None, hve_coverage=None)
    summary = summarize(rows, expected_seeds=2, resamples=16)
    for group in summary["groups"]:
        assert group["n"] == 2
        assert group["raw"]["latency_ms"]["status"] == "blocked_undefined_paired_metric"
        assert "mean" in group["raw"]["residual_plr"]
    assert summary["groups"][1]["raw"]["residual_plr"]["mean"] == pytest.approx(0.505)
    with pytest.raises(ValueError, match="blocked or undefined"):
        tool("plot_results").extract_plot_rows(summary, metric="latency_ms")


def test_stats_output_enters_plot_directly_for_raw_and_normalized_results():
    rows = [row(method, seed) for method in ("da-ahe", "dpp") for seed in (1,2)]
    summary = summarize(rows, expected_seeds=2, resamples=16)
    plot = tool("plot_results")
    raw = plot.extract_plot_rows(summary, nodes=3000, metric="latency_ms")
    normalized = plot.extract_plot_rows(summary, nodes=3000, metric="latency_ms", normalized=True)
    assert [r["label"] for r in raw] == ["da-ahe", "dpp"]
    assert raw[0]["mean"] == 11.5
    assert normalized[0]["mean"] == normalized[0]["low"] == normalized[0]["high"] == 1
    summary["groups"].append({**summary["groups"][0], "nodes":5000})
    with pytest.raises(ValueError, match="select --nodes"):
        plot.extract_plot_rows(summary)


def test_experiment_matrix_rejects_missing_runs_and_seed_overlap():
    rows = [row(method, seed) for method in ("da-ahe", "dpp") for seed in (1,2)]
    matrix = {"schema_version":1, "methods":["da-ahe", "dpp"], "node_counts":[3000],
              "evaluation_seeds":[1,2], "calibration_seeds":[3], "expected_runs":4}
    assert validate_experiment_matrix(rows, matrix)["observed_runs"] == 4
    with pytest.raises(ValueError, match="missing="):
        validate_experiment_matrix(rows[:-1], matrix)
    with pytest.raises(ValueError, match="seeds overlap"):
        validate_experiment_matrix(rows, {**matrix, "calibration_seeds":[1]})
