# SPDX-License-Identifier: MIT
"""Paired ablation estimands with explicit denominators and recovery censoring.

This module summarizes supplied seed records. Report loss, terminal frame loss,
verification capability, and injected-invalid acceptance are separate estimands.
One seed-index bank is shared by all method means and paired differences.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import math
import statistics

import numpy as np

DEFAULT_METHODS = ("da-ahe", "without_markov", "without_intdb2",
                   "without_route_repair", "without_hve")
DEFAULT_METRICS = ("report_loss_fraction", "recovery_event_fraction",
                   "hve_enabled_coverage")
METHOD_LABELS = {"da-ahe": "DA-AHE", "dpp": "DPP", "hys": "HYS",
                 "without_markov": "Without Markov", "without_intdb2": "Without IntDb2",
                 "without_route_repair": "Without route repair", "without_hve": "Without HVE"}


@dataclass(frozen=True)
class MetricSpec:
    label: str
    unit: str
    display_scale: float
    denominator: str
    preferred_direction: str
    source: str | None = None


METRIC_SPECS = {
    "report_loss_fraction": MetricSpec("Unaccepted reports / admitted reports", "%", 100.,
        "admitted application reports; accepted includes valid and invalid reports", "lower",
        "observed_residual_loss_fraction"),
    "fragment_loss_fraction": MetricSpec("Terminal frame loss / offered frames", "%", 100.,
        "unique terminal network frames after retries; never application reports or TX attempts", "lower"),
    "valid_delivery_fraction_per_admitted": MetricSpec("Valid / admitted reports", "%", 100.,
        "admitted application reports", "higher", "valid_delivery_fraction_per_admitted"),
    "accepted_delivery_fraction_per_admitted": MetricSpec("Accepted / admitted reports", "%", 100.,
        "admitted application reports", "contextual", "accepted_delivery_fraction_per_admitted"),
    "invalid_acceptance_fraction_per_admitted": MetricSpec("Invalid accepted / admitted reports", "%", 100.,
        "admitted application reports; modeled invalidity labels, not forgery probability", "lower",
        "invalid_acceptance_fraction_per_admitted"),
    "valid_delivery_fraction_per_opportunity": MetricSpec("Valid / offered reports", "%", 100.,
        "all source reporting opportunities, including sampling suppression", "higher",
        "valid_delivery_fraction_per_opportunity"),
    "valid_delay_mean_s": MetricSpec("Conditional valid-report delay", "s", 1.,
        "valid delivered application reports within each seed", "lower", "valid_delay_mean_s"),
    "modeled_cpu_energy_j_all_run": MetricSpec("Modeled CPU energy", "J/run", 1.,
        "complete seed run; configured CPU service costs", "lower", "modeled_cpu_energy_j_all_run"),
    "modeled_radio_tx_energy_j_all_run": MetricSpec("Modeled radio-TX energy", "J/run", 1.,
        "complete seed run; transmitted wire bits", "lower", "modeled_radio_tx_energy_j_all_run"),
    "recovery_event_fraction": MetricSpec("Observed recovery events / all seed runs", "%", 100.,
        "all paired seed runs; no-excursion runs remain separately identified", "contextual"),
    "recovery_rmst_s": MetricSpec("Restricted mean time without observed recovery", "s", 1.,
        "runs with an observed excursion, restricted to the declared common follow-up horizon", "lower"),
    "recovery_observed_conditional_mean_s": MetricSpec("Recovery time | observed recovery", "s", 1.,
        "observed recovery events only; censored and no-excursion runs excluded", "contextual"),
    "hve_enabled_coverage": MetricSpec("HVE-enabled configuration coverage", "%", 100.,
        "seed-run configurations; capability enabled, not attack detection", "capability"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def finite(value, label, *, optional=False):
    if value is None and optional:
        return None
    require(type(value) in (int, float) and math.isfinite(value), "nonfinite/nonnumeric " + label)
    require(value >= 0, "negative " + label)
    return float(value)


def paired_matrix(rows, methods, seeds, expected_seed_count):
    """Require exactly the selected Cartesian product, with no seed deletion."""
    require(methods and len(set(methods)) == len(methods) and "da-ahe" in methods,
            "distinct methods including da-ahe are required")
    require(all(isinstance(m, str) and m in METHOD_LABELS for m in methods), "unknown method")
    require(len(seeds) >= 2 and len(set(seeds)) == len(seeds)
            and all(type(s) is int and s >= 0 for s in seeds), "invalid paired seed set")
    require(type(expected_seed_count) is int and expected_seed_count >= 2
            and len(seeds) == expected_seed_count, "unexpected paired seed count")
    expected = {(s, m) for s in seeds for m in methods}
    by_key = {}
    for row in rows:
        require(isinstance(row, dict) and type(row.get("seed")) is int
                and isinstance(row.get("method"), str), "invalid seed/method record")
        key = row["seed"], row["method"]
        require(key in expected and key not in by_key, "unexpected/duplicate seed-method record")
        require(isinstance(row.get("metrics"), dict), "missing supplied metric mapping")
        by_key[key] = row
    require(set(by_key) == expected, "incomplete method/seed Cartesian product")
    return by_key


def kaplan_meier(observations, horizon_s):
    """KM survivor and RMST; event/censor ties use the same pre-event risk set."""
    tau = finite(horizon_s, "RMST horizon")
    require(tau > 0, "RMST horizon must be positive")
    observations = list(observations)
    if not observations:
        return {"status": "undefined_no_excursion_risk_set", "n_at_risk_initial": 0,
                "horizon_s": tau, "rmst_s": None, "survival_steps": []}
    for time, event in observations:
        finite(time, "follow-up time")
        require(type(event) is bool, "recovery event flag must be boolean")
    times = sorted({time for time, _ in observations if time <= tau})
    risk, survivor, previous, area, steps = len(observations), 1., 0., 0., []
    for time in times:
        area += (time - previous) * survivor
        events = sum(t == time and event for t, event in observations)
        censored = sum(t == time and not event for t, event in observations)
        survivor *= 1. - events / risk
        steps.append({"time_s": time, "at_risk": risk, "events": events,
                      "censored": censored, "survival": survivor})
        risk -= events + censored
        previous = time
    require(previous >= tau or survivor == 0. or risk > 0,
            "RMST horizon exceeds identifiable follow-up")
    area += (tau - previous) * survivor
    return {"status": "defined", "n_at_risk_initial": len(observations),
            "horizon_s": tau, "rmst_s": area, "survival_steps": steps}


def recovery_observations(by_key, methods, seeds, config, horizon_s=None):
    onset = finite(config.get("disturbance", {}).get("start_s"), "disturbance onset")
    duration = finite(config.get("duration_s"), "duration")
    drain = finite(config.get("drain_s", 0.), "drain interval")
    follow_up = duration + drain - onset
    require(follow_up > 0, "recovery observation horizon must follow disturbance onset")
    tau = follow_up if horizon_s is None else finite(horizon_s, "RMST horizon")
    require(0 < tau <= follow_up, "RMST horizon must lie inside common administrative follow-up")
    output = {}
    for method in methods:
        records = []
        for seed in seeds:
            row = by_key[seed, method]
            censored, completion = row.get("recovery_right_censored"), row.get("recovery_completion_s")
            require(type(censored) is bool, "recovery_right_censored must be boolean")
            if censored:
                require(completion is None, "censored recovery cannot contain a completion time")
                status, elapsed, event = "right_censored", follow_up, False
            elif completion is None:
                status, elapsed, event = "no_observed_excursion", None, False
            else:
                completion = finite(completion, "recovery completion")
                require(onset <= completion <= duration + drain,
                        "recovery completion outside observation interval")
                status, elapsed, event = "observed_recovery", completion - onset, True
            records.append({"seed": seed, "status": status, "event": event,
                            "elapsed_from_onset_s": elapsed,
                            "administrative_follow_up_s": follow_up})
        eligible = [(r["elapsed_from_onset_s"], r["event"]) for r in records
                    if r["status"] != "no_observed_excursion"]
        observed = [r["elapsed_from_onset_s"] for r in records if r["event"]]
        output[method] = {
            "n_total": len(seeds), "n_events": len(observed),
            "n_right_censored": sum(r["status"] == "right_censored" for r in records),
            "n_no_excursion": sum(r["status"] == "no_observed_excursion" for r in records),
            "event_fraction_all_seed_runs": len(observed) / len(seeds),
            "observed_conditional_mean_s": statistics.fmean(observed) if observed else None,
            "observed_conditional_mean_denominator": "observed recovery events only",
            "per_seed": records, "kaplan_meier": kaplan_meier(eligible, tau),
        }
    return output, {"disturbance_onset_s": onset, "observation_end_s": duration + drain,
                    "administrative_follow_up_s": follow_up, "rmst_horizon_s": tau,
                    "time_origin": "disturbance onset", "risk_set": "observed-excursion runs only",
                    "rmst_interpretation": "restricted mean time without observed recovery, not mean recovery time"}


def _frame_loss(row, extra):
    supplied = extra
    if supplied is None:
        counts = row.get("ablation_counts", {}).get("network_frames")
        if counts is not None:
            supplied = {"measurement_unit": counts.get("unit"),
                        "counting_policy": counts.get("counting_policy"),
                        **{f"frames_{key}": counts.get(key)
                           for key in ("offered", "lost", "delivered", "unresolved")}}
    require(isinstance(supplied, dict), "fragment loss requires supplied terminal frame counts")
    require(supplied.get("measurement_unit") == "network_frame"
            and supplied.get("counting_policy") == "terminal_after_retries",
            "frame metric requires network_frame / terminal_after_retries semantics")
    offered, lost = supplied.get("frames_offered"), supplied.get("frames_lost")
    delivered, unresolved = supplied.get("frames_delivered"), supplied.get("frames_unresolved")
    require(all(type(v) is int and v >= 0 for v in
                (offered, lost, delivered, unresolved))
            and lost + delivered + unresolved == offered,
            "invalid terminal frame numerator/denominator")
    return lost / offered if offered else None


def _interval(values):
    if values is None or not np.isfinite(values).all():
        return None
    return [float(x) for x in np.quantile(values, [.025, .975], method="linear")]


def analyze_ablation(rows, config, *, methods=DEFAULT_METHODS, metrics=DEFAULT_METRICS,
                     expected_seed_count=20, resamples=100000, bootstrap_seed=20261017,
                     rmst_horizon_s=None, frame_metrics=None, hve_capabilities=None):
    """Summarize the exact selected matrix; preserve undefined and censored rows."""
    methods, metrics = tuple(methods), tuple(metrics)
    require(metrics and len(set(metrics)) == len(metrics) and set(metrics) <= set(METRIC_SPECS),
            "distinct supported metrics are required")
    require(type(resamples) is int and resamples >= 2, "bootstrap resamples must be at least two")
    require(type(bootstrap_seed) is int and bootstrap_seed >= 0, "invalid bootstrap RNG seed")
    seeds = config.get("evaluation_seeds")
    require(isinstance(seeds, list), "configuration must declare evaluation_seeds")
    seeds = sorted(seeds)
    by_key = paired_matrix(rows, methods, seeds, expected_seed_count)
    if frame_metrics is not None:
        require(set(frame_metrics) == set(by_key), "frame counts must match every selected seed/method")
    capabilities = ({m: m != "without_hve" for m in methods}
                    if hve_capabilities is None else hve_capabilities)
    require(isinstance(capabilities, dict) and set(capabilities) == set(methods)
            and all(type(v) is bool for v in capabilities.values()),
            "HVE capability declaration must exactly match selected methods")
    recovery, recovery_scope = recovery_observations(by_key, methods, seeds, config, rmst_horizon_s)
    indices = np.random.Generator(np.random.PCG64(bootstrap_seed)).integers(
        0, len(seeds), size=(resamples, len(seeds)), dtype=np.int32)
    selected = tuple(dict.fromkeys((*metrics, "recovery_event_fraction", "recovery_rmst_s",
                                   "recovery_observed_conditional_mean_s")))
    result = {m: {} for m in methods}
    for metric in selected:
        spec, boots = METRIC_SPECS[metric], {}
        for method in methods:
            recs = recovery[method]["per_seed"]
            values = []
            if metric == "recovery_rmst_s":
                mean = recovery[method]["kaplan_meier"]["rmst_s"]
                # RMST is a survival functional, not an average of censored durations.
                values = [r["elapsed_from_onset_s"] for r in recs]
                if mean is None:
                    boot = np.full(resamples, np.nan)
                elif recovery[method]["n_events"] == 0:
                    present = np.asarray([v is not None for v in values], dtype=int)
                    boot = np.where(present[indices].sum(axis=1) > 0,
                                    recovery_scope["rmst_horizon_s"], np.nan)
                else:
                    boot = np.asarray([kaplan_meier(
                        [(recs[int(i)]["elapsed_from_onset_s"], recs[int(i)]["event"])
                         for i in ix if recs[int(i)]["elapsed_from_onset_s"] is not None],
                        recovery_scope["rmst_horizon_s"])["rmst_s"] for ix in indices], dtype=float)
            elif metric == "recovery_observed_conditional_mean_s":
                values = [r["elapsed_from_onset_s"] if r["event"] else None for r in recs]
                mean = recovery[method]["observed_conditional_mean_s"]
                observed = np.asarray([v is not None for v in values], dtype=int)
                totals = np.asarray([0. if v is None else v for v in values])[indices].sum(axis=1)
                counts = observed[indices].sum(axis=1)
                boot = np.divide(totals, counts, out=np.full(resamples, np.nan), where=counts > 0)
            else:
                for seed, rec in zip(seeds, recs, strict=True):
                    row = by_key[seed, method]
                    if metric == "recovery_event_fraction":
                        value = float(rec["event"])
                    elif metric == "hve_enabled_coverage":
                        value = float(capabilities[method])
                    elif metric == "fragment_loss_fraction":
                        value = _frame_loss(row, None if frame_metrics is None else frame_metrics[seed, method])
                    else:
                        require(spec.source in row["metrics"], "missing supplied metric: " + str(spec.source))
                        value = finite(row["metrics"][spec.source], metric, optional=True)
                        if value is not None and spec.unit == "%":
                            require(value <= 1., "fraction exceeds one: " + metric)
                    values.append(value)
                mean = statistics.fmean(values) if all(v is not None for v in values) else None
                boot = (np.asarray(values, dtype=float)[indices].mean(axis=1) if mean is not None
                        else np.full(resamples, np.nan))
            boots[method] = boot
            ci = _interval(boot)
            result[method][metric] = {
                **asdict(spec), "mean": mean, "ci95": ci,
                "n_total": len(seeds), "n_defined": sum(v is not None for v in values),
                "per_seed": values,
                "per_seed_value_role": ("event_or_censor_follow_up_for_survival"
                    if metric == "recovery_rmst_s" else "supplied_or_derived_seed_estimand"),
                "status": "defined" if mean is not None and ci is not None else (
                    "undefined_estimand" if mean is None else "ci_undefined_resample_denominator"),
            }
        reference = result["da-ahe"][metric]["mean"]
        for method in methods:
            record = result[method][metric]
            mean = record["mean"]
            record["paired_difference"] = {
                "estimand": "method minus da-ahe", "reference_method": "da-ahe",
                "mean": mean - reference if mean is not None and reference is not None else None,
                "ci95": _interval(boots[method] - boots["da-ahe"]),
                "seed_count": len(seeds),
            }
    return {"schema_version": 1, "methods": list(methods), "seeds": seeds,
        "node_count": config.get("nodes"), "selected_metrics": list(metrics),
        "statistics": result, "recovery": recovery, "recovery_scope": recovery_scope,
        "bootstrap": {"unit": "paired seed", "resamples": resamples, "seed": bootstrap_seed,
            "confidence": .95, "interval": "pointwise two-sided percentile; linear quantiles",
            "generator": "numpy.PCG64", "numpy_version": np.__version__,
            "seed_count": len(seeds), "index_dtype": "little-endian int32",
            "index_sha256": hashlib.sha256(indices.astype("<i4").tobytes(order="C")).hexdigest(),
            "pairing": "one index bank shared across all methods, metrics and paired differences"},
        "capability_declaration": {"hve_enabled_by_method": capabilities,
            "scope": "configured verification capability, not measured attack detection or cryptographic security"},
        "interpretation": {
            "loss": "Application report loss and terminal frame loss have separate counts and denominators.",
            "missing": "Undefined seed metrics retain their records and withhold the complete paired estimand.",
            "recovery": "No-excursion runs are separate; censored durations are not observed recovery times.",
            "intervals": "Empirical percentile CIs can be degenerate for constant samples; they are not simultaneous bands.",
            "validity": "Injected-invalid acceptance and HVE capability are not cryptographic detection probabilities."}}


def manuscript_caption(result):
    labels = "; ".join(METRIC_SPECS[m].label for m in result["selected_metrics"])
    return (f"Ablation comparison at {result['node_count']} source nodes: {labels}. "
            f"Bars show equally weighted means over {len(result['seeds'])} paired seeds; "
            f"error bars show pointwise 95% percentile-bootstrap confidence intervals from "
            f"{result['bootstrap']['resamples']:,} shared seed resamples. "
            "Application-report loss uses admitted reports, whereas terminal-frame loss, when supplied, "
            "uses unique offered frames after retries. Recovery-event fractions count events over all seed runs; "
            "RMST uses excursion-eligible runs and the stated follow-up horizon, with no-excursion cases separate. "
            "HVE coverage identifies an enabled verification capability, not an attack-detection rate.")
