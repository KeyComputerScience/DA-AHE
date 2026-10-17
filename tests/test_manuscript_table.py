# SPDX-License-Identifier: MIT
"""Analytic checks of the compact table's estimands and evidence statements."""
from copy import deepcopy
import json

import pytest

from simulation.ablation_analysis import analyze_ablation
from tools.manuscript_table import build_performance_table


def table_campaign(methods=("da-ahe", "dpp", "without_route_repair")):
    seeds, rows = [61, 62], []
    for index, seed in enumerate(seeds):
        for method in methods:
            offset = 2. if method == "dpp" else 0.
            rows.append({
                "seed": seed, "method": method,
                "metrics": {
                    "valid_delay_mean_s": (1., 7.)[index] + offset,
                    "modeled_cpu_energy_j_all_run": (1., 3.)[index],
                    "modeled_radio_tx_energy_j_all_run": (2., 6.)[index],
                    "wire_bytes_per_source_opportunity_all_run": (100., 300.)[index]},
                "recovery_right_censored": True, "recovery_completion_s": None})
    return {"rows": rows, "seeds": seeds, "methods": list(methods),
            "config": {"nodes": 17, "evaluation_seeds": seeds,
                       "duration_s": 20., "drain_s": 5., "disturbance": {"start_s": 5.}},
            "provenance": {"input_kind": "analytic_test_fixture", "input_sha256": {}}}


def test_table_retains_all_methods_and_equal_seed_weight_without_mutation():
    campaign = table_campaign()
    before = deepcopy(campaign)
    result = build_performance_table(campaign, resamples=128)
    summary, tex = result["summary"], result["latex"]
    assert campaign == before
    assert summary["methods"] == ["da-ahe", "dpp", "without_route_repair"]
    assert summary["statistics"]["da-ahe"]["valid_delay_mean_s"]["mean"] == 4.
    assert r"\shortstack{$4.000$\\$[1.000, 7.000]$}" in tex
    assert r"\shortstack{$200$\\$[100, 300]$}" in tex
    assert all(label in tex for label in ("DA-AHE", "DPP", "Without route repair"))
    assert "128 shared resamples of 2 paired seeds" in tex
    assert "right-censored runs / all runs" in tex
    assert summary["recovery_counts"] == {
        "observed_recovery": 0, "right_censored": 6, "no_observed_excursion": 0, "total": 6}
    assert summary["recovery"]["statistics"] is None
    assert "All 6 recovery records are right-censored at t=25 s (20 s after" in tex
    assert "no observed-recovery mean" in tex
    assert "does not establish a route-repair benefit" in tex
    assert "trigger" not in tex
    json.dumps(summary, allow_nan=False)


def test_table_bootstrap_matches_ablation_index_bank_and_delay_estimand():
    campaign = table_campaign(methods=("da-ahe", "without_route_repair"))
    table = build_performance_table(campaign, resamples=128, bootstrap_seed=8675309)["summary"]
    figure = analyze_ablation(campaign["rows"], campaign["config"],
        methods=campaign["methods"], metrics=("valid_delay_mean_s",),
        expected_seed_count=2, resamples=128, bootstrap_seed=8675309)
    assert table["bootstrap"]["index_sha256"] == figure["bootstrap"]["index_sha256"]
    for method in campaign["methods"]:
        table_delay = table["statistics"][method]["valid_delay_mean_s"]
        figure_delay = figure["statistics"][method]["valid_delay_mean_s"]
        assert table_delay["mean"] == figure_delay["mean"]
        assert table_delay["percentile_ci_95"] == figure_delay["ci95"]


def test_mixed_recovery_strata_are_not_relabeled_as_all_censored():
    campaign = table_campaign(methods=("da-ahe", "dpp"))
    campaign["rows"][0].update(recovery_right_censored=False, recovery_completion_s=10.)
    campaign["rows"][1].update(recovery_right_censored=False, recovery_completion_s=None)
    result = build_performance_table(campaign, resamples=32)
    assert result["summary"]["recovery_counts"] == {
        "observed_recovery": 1, "right_censored": 2, "no_observed_excursion": 1, "total": 4}
    assert "1 observed recoveries, 2 right-censored records and 1 records without" in result["latex"]
    assert "All 4 recovery records are right-censored" not in result["latex"]
    assert "does not estimate an unconditional mean recovery time" in result["latex"]
    assert result["summary"]["recovery"]["statistics"] is None


def test_fully_observed_recoveries_preserve_elapsed_times():
    campaign = table_campaign(methods=("da-ahe", "dpp"))
    for row in campaign["rows"]:
        row.update(recovery_right_censored=False,
                   recovery_completion_s=10. if row["seed"] == 61 else 15.)
    result = build_performance_table(campaign, resamples=32)
    assert "All 4 recovery records have observed recoveries" in result["latex"]
    assert "no observed-recovery mean" not in result["latex"]
    assert "$0/2$" in result["latex"]
    assert result["summary"]["recovery"]["statistics"]["da-ahe"]["mean"] == 7.5


def test_undefined_delay_retains_seed_count_and_does_not_show_partial_mean():
    campaign = table_campaign(methods=("da-ahe", "dpp"))
    campaign["rows"][1]["metrics"]["valid_delay_mean_s"] = None
    result = build_performance_table(campaign, resamples=32)
    item = result["summary"]["statistics"]["dpp"]["valid_delay_mean_s"]
    assert item["mean"] is None and item["percentile_ci_95"] is None
    assert item["per_seed"] == [None, 9.]
    assert r"\shortstack{--\\$1/2$ defined}" in result["latex"]
    assert "retains its defined-seed count" in result["latex"]


def test_repair_equality_note_requires_exact_per_seed_outcomes():
    campaign = table_campaign()
    row = next(row for row in campaign["rows"] if row["method"] == "without_route_repair")
    row["metrics"]["valid_delay_mean_s"] += .00001
    result = build_performance_table(campaign, resamples=32)
    assert result["summary"]["route_repair_matches_table_records"] is False
    assert "identical archived" not in result["latex"]


@pytest.mark.parametrize("mutation", [
    lambda campaign: campaign["rows"].pop(),
    lambda campaign: campaign["rows"].append(deepcopy(campaign["rows"][0])),
])
def test_table_rejects_missing_or_duplicate_paired_rows(mutation):
    campaign = table_campaign()
    mutation(campaign)
    with pytest.raises(ValueError, match="invalid paired matrix"):
        build_performance_table(campaign, resamples=32)
