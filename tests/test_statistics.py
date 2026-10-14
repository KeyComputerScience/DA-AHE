# SPDX-License-Identifier: MIT
"""Authored but not executed; fixtures are analytic unit-test values, not paper data."""
from dataclasses import replace

import pytest

from daahe.statistics import MetricRow, paired_bootstrap, summarize, validate_rows, load_metrics_csv, write_metrics_csv


def row(method="da-ahe", seed=1):
    return MetricRow(f"{method}-{seed}", method, 3000, seed, 10.0+seed, .001, 20.0,
                     False, 1.0, 30.0, 300.0, 100.0, 30.0, 300.0,
                     f"{seed:064x}", "a"*64, "b"*64, "OMNeT++ 6.0 / INET 4.4", "network_packet")


def test_ratio_of_means_is_not_mean_of_ratios():
    result = paired_bootstrap([4,12], [1,7], resamples=128)
    assert result["estimate"] == 2.0
    assert result["estimate"] != pytest.approx((4/1+12/7)/2)


def test_bootstrap_resamples_preserve_pairing():
    result = paired_bootstrap([2,14,38], [1,7,19], resamples=128)
    assert result["estimate"] == result["ci_low"] == result["ci_high"] == 2.0


def test_raw_metrics_and_self_normalized_metrics_are_separate():
    rows = [row(seed=s) for s in range(1,21)]
    summary = summarize(rows, resamples=128)
    group = summary["groups"][0]
    assert group["raw"]["latency_ms"]["mean"] == 20.5
    assert group["normalized_to_da_ahe"]["latency_ms"]["estimate"] == 1.0
    assert group["normalized_to_da_ahe"]["latency_ms"]["ci_low"] == 1.0
    assert group["normalized_to_da_ahe"]["latency_ms"]["ci_high"] == 1.0


def test_default_requires_twenty_independent_seed_rows():
    with pytest.raises(ValueError, match="20 identical paired seeds"):
        summarize([row(seed=s) for s in range(1,20)], resamples=16)


def test_reject_unpaired_duplicate_missing_and_mismatched_provenance():
    base = [row(seed=s) for s in (1,2)]
    with pytest.raises(ValueError, match="duplicate"):
        validate_rows(base + [base[0]])
    with pytest.raises(ValueError, match="identical paired seeds"):
        summarize(base+[row("dpp",1)], expected_seeds=2, resamples=16)
    with pytest.raises(ValueError, match="missing reference or requested methods"):
        summarize(base, expected_seeds=2, required_methods=["da-ahe","dpp"], resamples=16)
    changed = replace(row("dpp",2), trace_sha256="f"*64)
    with pytest.raises(ValueError, match="unmatched trace_sha256"):
        summarize(base+[row("dpp",1),changed], expected_seeds=2, resamples=16)


@pytest.mark.parametrize("change", [
    {"latency_ms":float("nan")}, {"residual_plr":float("inf")},
    {"recovery_s":float("nan")}, {"residual_plr":1.01},
    {"measured_window_start_s":29.0}, {"warmup_s":0.0},
    {"recovery_censored":True,"recovery_s":200.0},
])
def test_reject_invalid_or_warmup_contaminated_rows(change):
    with pytest.raises(ValueError):
        validate_rows([replace(row(), **change)])


def test_censored_recovery_is_retained_and_whole_paired_stratum_withheld():
    rows = [row("da-ahe",s) for s in (1,2)] + [row("dpp",s) for s in (1,2)]
    rows[-1] = replace(rows[-1], recovery_s=None, recovery_censored=True)
    result = summarize(rows, expected_seeds=2, resamples=16)
    for group in result["groups"]:
        assert group["raw"]["recovery_s"]["status"] == "blocked_censored"
        assert group["normalized_to_da_ahe"]["recovery_s"]["status"] == "blocked_censored"
    assert result["groups"][1]["recovery_censored_count"] == 1
    assert result["groups"][1]["raw"]["recovery_s"]["observed"][-1] is None


def test_csv_roundtrip_preserves_censoring_and_fraction_units(tmp_path):
    source = replace(row(), recovery_s=None, recovery_censored=True)
    path = tmp_path/"metrics.csv"
    write_metrics_csv([source], path)
    assert load_metrics_csv(path) == [source]


def test_zero_reference_does_not_create_infinite_ratio():
    rows = [replace(row(seed=s), residual_plr=0.0) for s in (1,2)]
    group = summarize(rows, expected_seeds=2, resamples=16)["groups"][0]
    assert group["normalized_to_da_ahe"]["residual_plr"]["status"] == "undefined_zero_reference"
