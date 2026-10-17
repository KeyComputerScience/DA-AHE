"""Ablation estimands, paired uncertainty, censoring and immutable export."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest

from simulation.ablation_analysis import (
    DEFAULT_METHODS, analyze_ablation, kaplan_meier, manuscript_caption,
)

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    config = {"nodes": 3000, "evaluation_seeds": [3, 4, 5, 6],
              "disturbance": {"start_s": 30.}, "duration_s": 90., "drain_s": 35.}
    rows = [{"seed": seed, "method": method,
             "metrics": {"observed_residual_loss_fraction": .1 + index * .01 + seed * .001},
             "recovery_right_censored": True, "recovery_completion_s": None}
            for seed in config["evaluation_seeds"]
            for index, method in enumerate(DEFAULT_METHODS)]
    return rows, config


def analyze(rows=None, config=None, **kwargs):
    defaults, settings = fixture()
    return analyze_ablation(defaults if rows is None else rows,
        settings if config is None else config, expected_seed_count=4,
        resamples=100, bootstrap_seed=27, **kwargs)


def test_constant_paired_difference_has_constant_ci_with_variable_means():
    result = analyze()
    delta = result["statistics"]["without_markov"]["report_loss_fraction"]["paired_difference"]
    assert delta["mean"] == pytest.approx(.01)
    assert delta["ci95"] == pytest.approx([.01, .01])
    assert result["statistics"]["da-ahe"]["report_loss_fraction"]["ci95"][0] < (
        result["statistics"]["da-ahe"]["report_loss_fraction"]["ci95"][1])
    assert result["bootstrap"]["pairing"].startswith("one index bank")


def test_all_censored_is_zero_events_but_undefined_observed_time():
    result = analyze()
    for method in DEFAULT_METHODS:
        recovery = result["recovery"][method]
        assert recovery["n_events"] == 0 and recovery["n_right_censored"] == 4
        assert recovery["observed_conditional_mean_s"] is None
        assert recovery["kaplan_meier"]["rmst_s"] == 95.
        stats = result["statistics"][method]
        assert stats["recovery_event_fraction"]["mean"] == 0.
        assert stats["recovery_observed_conditional_mean_s"]["ci95"] is None
        assert stats["recovery_rmst_s"]["ci95"] == [95., 95.]


def test_no_excursion_is_separate_from_recovery_and_survival_risk_set():
    rows, config = fixture()
    for row in rows:
        row["recovery_right_censored"] = False
    result = analyze(rows, config)
    rec = result["recovery"]["da-ahe"]
    assert rec["n_no_excursion"] == 4 and rec["n_events"] == 0
    assert rec["kaplan_meier"]["rmst_s"] is None
    assert result["statistics"]["da-ahe"]["recovery_observed_conditional_mean_s"]["mean"] is None


def test_observed_recovery_duration_uses_onset_and_excludes_censored():
    rows, config = fixture()
    for row in rows:
        if row["seed"] == 3:
            row.update(recovery_right_censored=False, recovery_completion_s=45.)
    result = analyze(rows, config)
    rec = result["recovery"]["da-ahe"]
    assert rec["observed_conditional_mean_s"] == 15.
    assert rec["n_right_censored"] == 3 and rec["event_fraction_all_seed_runs"] == .25
    assert result["statistics"]["da-ahe"]["recovery_observed_conditional_mean_s"]["ci95"] is None


def test_km_tied_event_and_censor_use_common_risk_set():
    result = kaplan_meier([(5., True), (5., False), (10., True)], 12.)
    assert result["survival_steps"][0]["at_risk"] == 3
    assert result["survival_steps"][0]["survival"] == pytest.approx(2/3)
    assert result["rmst_s"] == pytest.approx(5 + 5 * 2/3)
    with pytest.raises(ValueError, match="identifiable"):
        kaplan_meier([(5., False), (7., False)], 12.)


@pytest.mark.parametrize("change", ["duplicate", "missing", "unknown", "wrong_count"])
def test_incomplete_or_misdeclared_seed_matrices_fail(change):
    rows, config = fixture()
    if change == "duplicate":
        rows.append(deepcopy(rows[0]))
    elif change == "missing":
        rows.pop()
    elif change == "unknown":
        rows[0]["method"] = "other"
    else:
        config["evaluation_seeds"].append(9)
    with pytest.raises(ValueError):
        analyze(rows, config)


def test_undefined_denominator_withholds_estimand_without_dropping_seed():
    rows, config = fixture()
    rows[0]["metrics"]["observed_residual_loss_fraction"] = None
    row = analyze(rows, config)["statistics"]["da-ahe"]["report_loss_fraction"]
    assert row["mean"] is None and row["ci95"] is None
    assert row["n_defined"] == 3 and row["n_total"] == 4
    assert len(row["per_seed"]) == 4


def test_frame_loss_never_falls_back_to_report_loss_and_conserves_frames():
    rows, config = fixture()
    with pytest.raises(ValueError, match="frame counts"):
        analyze(rows, config, metrics=["fragment_loss_fraction"])
    frames = {(r["seed"], r["method"]): {
        "measurement_unit": "network_frame", "counting_policy": "terminal_after_retries",
        "frames_offered": 10, "frames_lost": 2, "frames_delivered": 7, "frames_unresolved": 1}
        for r in rows}
    result = analyze(rows, config, metrics=["fragment_loss_fraction"], frame_metrics=frames)
    assert result["statistics"]["da-ahe"]["fragment_loss_fraction"]["mean"] == .2
    frames[3, "da-ahe"]["frames_delivered"] = 8
    with pytest.raises(ValueError, match="denominator"):
        analyze(rows, config, metrics=["fragment_loss_fraction"], frame_metrics=frames)


def test_hve_panel_reports_declared_capability_not_detection():
    result = analyze()
    assert result["statistics"]["without_hve"]["hve_enabled_coverage"]["mean"] == 0.
    assert result["statistics"]["da-ahe"]["hve_enabled_coverage"]["mean"] == 1.
    assert "not attack detection" in result["statistics"]["da-ahe"]["hve_enabled_coverage"]["denominator"]
    assert "not an attack-detection rate" in manuscript_caption(result)


def exporter():
    path = ROOT / "tools/export_ablation_evaluation.py"
    spec = importlib.util.spec_from_file_location("ablation_export_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_archived_export_preserves_inputs_and_rejects_existing_directory(tmp_path):
    module = exporter()
    source = ROOT / "evidence/independent/campaign-report"
    before = {p.name: module.file_hash(p) for p in source.iterdir() if p.is_file()}
    args = module.parser().parse_args([str(source), "--output", str(tmp_path/"export"),
                                      "--bootstrap-resamples", "100", "--figures",
                                      "--performance-table", "--metrics",
                                      "valid_delivery_fraction_per_opportunity",
                                      "valid_delay_mean_s",
                                      "invalid_acceptance_fraction_per_admitted"])
    result = module.export(args)
    assert result["provenance"]["complete_input_row_count"] == 140
    assert result["provenance"]["selected_row_count"] == 100
    assert result["provenance"]["excluded_methods"] == ["dpp", "hys"]
    out = tmp_path/"export"
    manifest = json.loads((out/"export-manifest.json").read_text())
    assert (out/"ablation-bars.pdf").read_bytes().startswith(b"%PDF")
    table = json.loads((out/"performance-costs.json").read_text())
    tex = (out/"performance-costs.tex").read_text()
    assert table["methods"] == ["da-ahe", "dpp", "hys", "without_markov",
                               "without_intdb2", "without_route_repair", "without_hve"]
    assert table["bootstrap"]["index_sha256"] == result["bootstrap"]["index_sha256"]
    assert table["recovery_counts"]["right_censored"] == 140
    assert "All 140 recovery records are right-censored" in tex
    assert "DPP" in tex and "HYS" in tex
    assert table["statistics"]["da-ahe"]["valid_delay_mean_s"]["percentile_ci_95"] == (
        result["statistics"]["da-ahe"]["valid_delay_mean_s"]["ci95"])
    caption = (out/"ablation-caption.txt").read_text()
    assert "Delay is conditional on valid delivery" in caption
    assert "not a cryptographic forgery probability" in caption
    assert "HVE coverage" not in caption
    assert all(module.file_hash(out/name) == digest
               for name, digest in manifest["output_sha256"].items())
    assert before == {p.name: module.file_hash(p) for p in source.iterdir() if p.is_file()}
    with pytest.raises(ValueError, match="already exists"):
        module.export(args)
