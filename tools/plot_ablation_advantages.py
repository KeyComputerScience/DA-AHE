#!/usr/bin/env python3
"""Plot paired-seed service efficiency, packing and aggregate validity."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import MultipleLocator

METHODS = ("da-ahe", "without_markov", "without_intdb2",
           "without_route_repair", "without_hve")
LABELS = ("DA-AHE", "Fixed\nnominal", "w/o\nIntDb2",
          "w/o route\nrepair", "w/o HVE")
RED = "#b51f39"
GRAY = "#a6a6a6"


def interval(values):
    return [float(x) for x in np.quantile(values, [.025, .975], method="linear")]


def summarize(csv_path, config_path, resamples, seed):
    config = json.loads(config_path.read_text())
    with csv_path.open(newline="") as stream:
        records = list(csv.DictReader(stream))
    declared_methods = config["methods"]
    seeds = sorted(config["evaluation_seeds"])
    by_key = {(int(r["seed"]), r["method"]): r for r in records}
    expected = {(s, m) for s in seeds for m in declared_methods}
    if len(by_key) != len(records) or set(by_key) != expected:
        raise ValueError("CSV must contain the complete declared paired seed/method matrix")
    if resamples < 2 or seed < 0:
        raise ValueError("Invalid bootstrap settings")
    n = config["nodes"]
    if n <= 0:
        raise ValueError("Source-node count must be positive")
    if config["sample_period_s"] != config["duration_s"]:
        raise ValueError("CPU normalization requires one source opportunity per node")
    if any(r["recovery_right_censored"] != "True" or r["recovery_completion_s"] != ""
           for r in records):
        raise ValueError("This figure's recovery statement requires all records to be right-censored")
    indices = np.random.Generator(np.random.PCG64(seed)).integers(
        0, len(seeds), size=(resamples, len(seeds)), dtype=np.int32)
    vectors, statistics, boot = {}, {}, {}
    for method in METHODS:
        rows = [by_key[s, method] for s in seeds]
        valid = np.array([float(r["valid_delivery_fraction_per_opportunity"]) for r in rows])
        cpu = np.array([float(r["modeled_cpu_energy_j_all_run"]) for r in rows])
        invalid = np.array([float(r["invalid_acceptance_fraction_per_admitted"]) for r in rows])
        if np.any(valid <= 0) or not np.isfinite(np.r_[valid, cpu, invalid]).all():
            raise ValueError("Finite costs and positive valid-delivery denominators are required")
        vectors[method] = {
            "cpu_mj_per_valid_report": 1000 * cpu / (n * valid),
            "valid_delivery_percent": 100 * valid,
            "invalid_acceptance_percent": 100 * invalid,
        }
        statistics[method], boot[method] = {}, {}
        for metric, values in vectors[method].items():
            resampled = values[indices].mean(axis=1)
            boot[method][metric] = resampled
            statistics[method][metric] = {
                "mean": float(values.mean()), "ci95": interval(resampled),
                "per_seed": values.tolist(), "n": len(seeds),
            }
    cpu_metric = "cpu_mj_per_valid_report"
    cpu_da = statistics["da-ahe"][cpu_metric]["mean"]
    cpu_fixed = statistics["without_markov"][cpu_metric]["mean"]
    cpu_reduction = 100 * (1 - cpu_da / cpu_fixed)
    reduction_boot = 100 * (1 - boot["da-ahe"][cpu_metric] / boot["without_markov"][cpu_metric])
    delivery_metric = "valid_delivery_percent"
    delivery_gain = statistics["da-ahe"][delivery_metric]["mean"] - (
        statistics["without_intdb2"][delivery_metric]["mean"])
    params = config["cryptographic_parameters"]
    rank, degree, q = params["module_rank"], params["ring_degree"], params["q"]
    if rank != 6 or degree != 256 or q != 2**32:
        raise ValueError("Packing comparison requires the declared rank-6, degree-256, q=2^32 tuple")
    packed_bytes = (rank + 1) * degree * 4
    summary = {
        "nodes": n, "seeds": seeds, "methods": list(METHODS),
        "statistics": statistics,
        "advantages": {
            "cpu_reduction_vs_fixed_percent": {"mean": cpu_reduction, "ci95": interval(reduction_boot)},
            "delivery_gain_vs_without_intdb2_pp": {
                "mean": delivery_gain,
                "ci95": interval(boot["da-ahe"][delivery_metric] -
                                 boot["without_intdb2"][delivery_metric])},
            "protected_ciphertext_payload_reduction_percent": 50.0,
        },
        "packing": {"rank": rank, "degree": degree, "q": q,
                    "raw_polynomials": 2, "packed_polynomials": 1,
                    "raw_ciphertext_bytes": 2 * packed_bytes,
                    "packed_ciphertext_bytes": packed_bytes,
                    "scope": "protected ciphertext only; ticket, MAC, headers and retries are additional"},
        "bootstrap": {"resamples": resamples, "seed": seed,
                      "unit": "paired seed", "generator": "numpy.PCG64",
                      "index_sha256": hashlib.sha256(indices.astype("<i4").tobytes()).hexdigest()},
        "recovery": {"right_censored": len(records), "total": len(records),
                     "observation_end_s": config["duration_s"] + config["drain_s"]},
        "metric_definitions": {
            "cpu_mj_per_valid_report": "Per-seed 1000 * modeled CPU joules / (nodes * valid/opportunity), then seed mean",
            "valid_delivery_percent": "100 * valid deliveries / all source opportunities",
            "invalid_acceptance_percent": "100 * modeled invalid accepted reports / admitted reports",
            "reduction": "One minus ratio of mean per-seed normalized CPU costs; paired seed bootstrap",
        },
        "input_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in (csv_path, config_path)},
    }
    return summary


def bars(ax, summary, metric, limit, step, decimals):
    values = [summary["statistics"][m][metric]["mean"] for m in METHODS]
    bounds = [summary["statistics"][m][metric]["ci95"] for m in METHODS]
    x = np.arange(len(METHODS))
    colors = [RED, GRAY, GRAY, GRAY, GRAY]
    artists = ax.bar(x, values, width=.62, color=colors, edgecolor="#333333",
                     linewidth=.55, zorder=3)
    for i, artist in enumerate(artists):
        if i:
            artist.set_hatch(("", "//", "..", "xx", "\\\\")[i])
        low, high = bounds[i]
        ax.errorbar(i, values[i],
                    yerr=[[max(0, values[i] - low)], [max(0, high - values[i])]],
                    fmt="none", capsize=2.2, elinewidth=.8, capthick=.8,
                    ecolor="#111111", zorder=4)
        if values[i] == 0:
            ax.plot(i, 0, "o", ms=3.5, markeredgewidth=.8,
                    markerfacecolor="white", markeredgecolor=colors[i],
                    clip_on=False, zorder=5)
        ax.text(i, max(values[i], high) + limit * .025, f"{values[i]:.{decimals}f}",
                ha="center", va="bottom", fontsize=8,
                color=RED if i == 0 else "#222222",
                fontweight="bold" if i == 0 else "normal")
    ax.set_xticks(x, LABELS, fontsize=7.2)
    ax.set_ylim(0, limit)
    ax.yaxis.set_major_locator(MultipleLocator(step))
    ax.grid(axis="y", color="#dedede", linewidth=.55, zorder=0)
    ax.set_axisbelow(True)
    return artists


def plot(summary, output):
    plt.rcParams.update({
        "font.family": "DejaVu Serif", "font.size": 8.5,
        "axes.labelsize": 8.5, "axes.titlesize": 9.3,
        "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.linewidth": .65, "pdf.fonttype": 42, "ps.fonttype": 42,
        "mathtext.fontset": "dejavuserif",
    })
    fig, axes = plt.subplots(2, 2, figsize=(7.16, 4.65))
    fig.subplots_adjust(left=.083, right=.985, bottom=.105, top=.935,
                        wspace=.28, hspace=.65)
    a, b, c, d = axes.flat
    bars(a, summary, "cpu_mj_per_valid_report", 1.4, .3, 3)
    a.set_title("(a) Adaptive policy: service efficiency", fontweight="bold", pad=9)
    a.set_ylabel("Modeled CPU cost /\nvalid report (mJ)")
    reduction = summary["advantages"]["cpu_reduction_vs_fixed_percent"]["mean"]
    a.text(.5, .94, f"{reduction:.1f}% lower than fixed nominal",
           transform=a.transAxes, ha="center", va="top", color=RED,
           fontweight="bold", fontsize=8.3)

    packing = summary["packing"]
    payload = [packing["raw_ciphertext_bytes"] / 1024,
               packing["packed_ciphertext_bytes"] / 1024]
    b.bar([0, 1], payload, width=.53, color=[GRAY, RED],
          edgecolor="#333333", linewidth=.55, zorder=3)
    for i, value in enumerate(payload):
        b.text(i, value + .35, f"{value:.0f} KiB",
               ha="center", fontsize=8, fontweight="bold" if i else "normal",
               color=RED if i else "#222222")
    b.set_xticks([0, 1], ["Raw\n2 polynomials", "DA-AHE packing\n1 polynomial"])
    b.set_ylim(0, 19)
    b.yaxis.set_major_locator(MultipleLocator(4))
    b.set_ylabel("Protected ciphertext\npayload (KiB)")
    b.grid(axis="y", color="#dedede", linewidth=.55, zorder=0)
    b.set_axisbelow(True)
    b.set_title("(b) Profile-bound data-and-tag packing", fontweight="bold", pad=9)
    b.text(.5, .94, "50% smaller protected payload",
           transform=b.transAxes, ha="center", va="top", color=RED,
           fontweight="bold", fontsize=8.3)

    bars(c, summary, "valid_delivery_percent", 59, 10, 3)
    c.set_title("(c) Useful service retained", fontweight="bold", pad=9)
    c.set_ylabel("Valid deliveries /\nsource opportunities (%)")
    gain = summary["advantages"]["delivery_gain_vs_without_intdb2_pp"]["mean"]
    c.text(.5, .94, f"+{gain:.2f} pp versus w/o IntDb2",
           transform=c.transAxes, ha="center", va="top", color=RED,
           fontweight="bold", fontsize=8.3)

    bars(d, summary, "invalid_acceptance_percent", 3.0, .5, 3)
    d.set_title("(d) Sink-side aggregate verification", fontweight="bold", pad=9)
    d.set_ylabel("Invalid accepted /\nadmitted reports (%)")
    d.text(.5, .94, "0% modeled invalid acceptance for DA-AHE",
           transform=d.transAxes, ha="center", va="top", color=RED,
           fontweight="bold", fontsize=8.0)
    fig.savefig(str(output) + ".pdf", metadata={"Title": "DA-AHE ablation and packing",
                                              "CreationDate": None, "ModDate": None})
    fig.savefig(str(output) + ".svg", metadata={"Date": None})
    fig.savefig(str(output) + ".png", dpi=300)
    plt.close(fig)


def caption(summary):
    return (
        "DA-AHE component contributions at 3,000 source nodes. "
        "(a) Modeled CPU cost per valid report, normalized within each seed; "
        "(b) protected ciphertext payload for raw two-polynomial and packed "
        "one-polynomial representations at fixed rank 6; "
        "(c) valid delivery per source opportunity; "
        "(d) modeled invalid acceptance per admitted report. "
        f"Bars in (a), (c) and (d) show equally weighted means over {len(summary['seeds'])} "
        f"paired seeds; error bars are pointwise 95% percentile-bootstrap intervals "
        f"from {summary['bootstrap']['resamples']:,} shared seed resamples. "
        "Panel (b) is exact payload accounting and excludes tickets, MACs, headers "
        "and retransmissions. Fixed nominal is the without-Markov policy; its "
        "admission rate differs from DA-AHE, so panel (a) compares complete policies. "
        "Route-repair and full DA-AHE outcomes coincide in this archive. "
        "All recovery records are right-censored; no recovery-time ranking is shown. "
        "Modeled invalid acceptance does not estimate a cryptographic forgery probability."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="Output prefix for PDF, SVG, PNG, JSON and caption")
    parser.add_argument("--resamples", type=int, default=100000)
    parser.add_argument("--seed", type=int, default=20261017)
    args = parser.parse_args()
    summary = summarize(args.csv, args.config, args.resamples, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    plot(summary, args.output)
    Path(str(args.output) + ".json").write_text(
        json.dumps(summary, indent=2, allow_nan=False) + "\n")
    text = caption(summary)
    Path(str(args.output) + "-caption.txt").write_text(text + "\n")


if __name__ == "__main__":
    main()
