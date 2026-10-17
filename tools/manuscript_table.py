# SPDX-License-Identifier: MIT
"""Build the manuscript's compact performance table from a validated campaign.

The table and its machine-readable companion retain the same paired-seed
estimands as the performance exporter. Recovery counts are availability data;
censoring follow-up is never substituted for a recovery duration.
"""
from __future__ import annotations

from copy import deepcopy

from simulation.ablation_analysis import METHOD_LABELS
from tools.export_performance_evaluation import (
    METRICS, paired_statistics, recovery_summary,
)


TABLE_METRICS = (
    "valid_delay_mean_s",
    "modeled_cpu_energy_j_all_run",
    "modeled_radio_tx_energy_j_all_run",
    "wire_bytes_per_source_opportunity_all_run",
)
TABLE_PRECISION = dict(zip(TABLE_METRICS, (3, 3, 3, 0), strict=True))


def _latex_escape(value):
    replacements = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%",
                    "$": r"\$", "#": r"\#", "_": r"\_", "{": r"\{",
                    "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}"}
    return "".join(replacements.get(char, char) for char in str(value))


def _cell(item, precision):
    if item["mean"] is None or item["percentile_ci_95"] is None:
        return (r"\shortstack{--\\$" + str(item["n_defined"]) + "/"
                + str(item["n_total"]) + r"$ defined}")
    lower, upper = item["percentile_ci_95"]
    return (r"\shortstack{$" + f"{item['mean']:.{precision}f}" + r"$\\$["
            + f"{lower:.{precision}f}, {upper:.{precision}f}" + r"]$}")


def _matching_repair_records(campaign):
    if not {"da-ahe", "without_route_repair"} <= set(campaign["methods"]):
        return False
    by_key = {(row["seed"], row["method"]): row for row in campaign["rows"]}
    for seed in campaign["seeds"]:
        reference, variant = (by_key[seed, method] for method in
                              ("da-ahe", "without_route_repair"))
        if any(reference["metrics"][metric] != variant["metrics"][metric]
               for metric in TABLE_METRICS):
            return False
        if any(reference[field] != variant[field] for field in
               ("recovery_right_censored", "recovery_completion_s")):
            return False
    return True


def build_performance_table(campaign, *, resamples=100000, bootstrap_seed=20261017):
    """Return LaTeX and JSON-ready evidence for a ``load_campaign`` result.

    Every campaign method is retained, even when a companion ablation figure
    selects fewer methods. The resampling bank depends only on the shared seeds
    and explicit bootstrap settings, preserving pairing with that figure.
    """
    methods, seeds = list(campaign["methods"]), list(campaign["seeds"])
    statistics, bootstrap = paired_statistics(
        campaign["rows"], seeds, methods, resamples=resamples,
        bootstrap_seed=bootstrap_seed,
        metric_specs={metric: METRICS[metric] for metric in TABLE_METRICS})
    recovery = recovery_summary(campaign, resamples=resamples, bootstrap_seed=bootstrap_seed)
    totals = {name: sum(record[name] for record in recovery["methods"].values())
              for name in ("observed_recovery", "right_censored", "no_observed_excursion")}
    total_records = len(seeds) * len(methods)
    repair_matches = _matching_repair_records(campaign)
    nodes = campaign["config"]["nodes"]
    caption = (
        f"Archived {nodes:,}-source-node conditional delay and modeled costs under the "
        "independent synthetic service model. Entries are equally weighted seed means "
        "with pointwise 95% percentile-bootstrap confidence intervals from "
        f"{resamples:,} shared resamples of {len(seeds)} paired seeds. "
        "The recovery column gives right-censored runs / all runs.")
    notes = [
        "Delay is conditional on valid delivery. CPU and radio-TX costs cover the "
        "complete modeled run and are not physical-board measurements. Wire bytes "
        "are normalized by all source reporting opportunities, including suppressed reports."]
    end, follow_up = recovery["observation_end_s"], recovery["censor_interval_from_onset_s"]
    if totals["right_censored"] == total_records:
        notes.append(
            f"All {total_records} recovery records are right-censored at t={end:g} s "
            f"({follow_up:g} s after disturbance onset); no observed-recovery mean "
            "or recovery-time ranking is available.")
    elif totals["observed_recovery"] == total_records:
        notes.append(
            f"All {total_records} recovery records have observed recoveries. "
            "The recovery column reports censoring counts rather than durations.")
    else:
        notes.append(
            f"Recovery outcomes comprise {totals['observed_recovery']} observed recoveries, "
            f"{totals['right_censored']} right-censored records and "
            f"{totals['no_observed_excursion']} records without an observed excursion. "
            f"Administrative follow-up ends at t={end:g} s ({follow_up:g} s after "
            "disturbance onset). Censoring intervals and no-excursion cases are not "
            "observed recovery times; this table does not estimate an unconditional "
            "mean recovery time.")
    if any(item["mean"] is None for metrics in statistics.values() for item in metrics.values()):
        notes.append("An undefined seed metric withholds the complete paired mean and "
                     "interval; the cell retains its defined-seed count.")
    if repair_matches:
        notes.append("DA-AHE and Without route repair have identical archived delay, cost "
                     "and recovery records; this comparison does not establish a route-repair benefit.")
    latex = [
        r"\begin{table*}[tbh]", r"\centering", r"\small",
        r"\caption{" + _latex_escape(caption) + "}",
        r"\label{tab:performance_costs}", r"\begin{tabular}{lrrrrr}", r"\hline",
        r"Method & \shortstack{Conditional valid\\delay (s)} & "
        r"\shortstack{Modeled CPU\\(J/run)} & \shortstack{Modeled radio TX\\(J/run)} & "
        r"\shortstack{Wire bytes /\\source opportunity} & "
        r"\shortstack{Recovery right-\\censored (runs)}\\", r"\hline"]
    for method in methods:
        cells = [_latex_escape(METHOD_LABELS.get(method, method))]
        cells.extend(_cell(statistics[method][metric], TABLE_PRECISION[metric])
                     for metric in TABLE_METRICS)
        cells.append(f"${recovery['methods'][method]['right_censored']}/{len(seeds)}$")
        latex.append(" & ".join(cells) + r"\\")
    latex.extend([r"\hline", r"\end{tabular}", r"\par\smallskip",
                  r"\begin{minipage}{\textwidth}\footnotesize",
                  _latex_escape(" ".join(notes)), r"\end{minipage}", r"\end{table*}", ""])
    summary = {
        "schema_version": 1,
        "measurement_scope": "independent synthetic service model",
        "nodes": nodes, "methods": methods, "seeds": seeds,
        "selected_metrics": list(TABLE_METRICS),
        "statistics": statistics, "bootstrap": bootstrap,
        "recovery": recovery,
        "recovery_counts": {**totals, "total": total_records},
        "route_repair_matches_table_records": repair_matches,
        "provenance": deepcopy(campaign["provenance"]),
        "caption": caption, "notes": notes,
        "interpretation": {
            "delay": "conditional on valid delivery; equally weighted seed means",
            "costs": "complete-run modeled CPU/TX; no physical-board measurements",
            "wire": "complete-run wire bytes / all source reporting opportunities",
            "recovery": "availability counts, not substituted recovery durations",
            "undefined": "retain every seed and withhold incomplete paired estimands"},
    }
    return {"latex": "\n".join(latex), "summary": summary}
