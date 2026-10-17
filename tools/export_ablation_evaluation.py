#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export paired ablation estimates and immutable-source publication figures."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from export_performance_evaluation import load_campaign, read_json  # noqa: E402
from simulation.ablation_analysis import (  # noqa: E402
    DEFAULT_METHODS, DEFAULT_METRICS, METHOD_LABELS, METRIC_SPECS,
    analyze_ablation, manuscript_caption, require,
)
from simulation.io import file_hash  # noqa: E402


def supplemental(path, campaign, methods, *, kind):
    """Bind complete supplemental counts to the exact campaign configuration."""
    value = read_json(path)
    require(value.get("schema_version") == 1 and value.get("kind") == kind,
            "supplemental schema/kind differs")
    require(value.get("config_digest") == campaign["manifest"]["config_digest"],
            "supplemental configuration identity differs")
    records, result = value.get("records"), {}
    require(isinstance(records, list), "supplemental records must be a list")
    for record in records:
        require(isinstance(record, dict) and type(record.get("seed")) is int
                and isinstance(record.get("method"), str), "invalid supplemental identity")
        key = record["seed"], record["method"]
        require(key not in result, "duplicate supplemental record")
        result[key] = record
    expected = {(seed, method) for seed in campaign["seeds"] for method in methods}
    require(set(result) == expected, "supplement must match selected methods and seeds")
    return result


def frame_records(path, campaign, methods):
    records = supplemental(path, campaign, methods, kind="terminal_frame_counts")
    for row in records.values():
        require(row.get("scope") == "source_and_aggregate_transfers_all_run",
                "frame scope must exclude repair/control frames")
    return records


def capability_records(path, campaign, methods):
    records = supplemental(path, campaign, methods, kind="hve_capabilities")
    result = {}
    for (_, method), row in records.items():
        enabled = row.get("enabled")
        require(type(enabled) is bool, "HVE capability must be boolean")
        require(method not in result or result[method] == enabled,
                "method capability differs between paired seeds")
        result[method] = enabled
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
                    encoding="utf-8")


def plot(result, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    methods, metrics = result["methods"], result["selected_metrics"]
    plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 9,
                         "pdf.fonttype": 42, "axes.spines.top": False,
                         "axes.spines.right": False})
    fig, axes = plt.subplots(1, len(metrics), figsize=(5.0 * len(metrics), 4.2),
                             squeeze=False)
    colors = ["#b51836"] + ["#666666"] * (len(methods) - 1)
    hatches = ["", "//", "..", "xx", "\\\\"]
    labels = [METHOD_LABELS[m].replace("Without ", "w/o\n").replace("route repair", "route\nrepair")
              for m in methods]
    for index, metric in enumerate(metrics):
        ax = axes[0, index]
        spec = METRIC_SPECS[metric]
        defined = []
        for position, method in enumerate(methods):
            row = result["statistics"][method][metric]
            mean, ci = row["mean"], row["ci95"]
            if mean is None:
                ax.annotate("Undefined", (position, .02), xycoords=("data", "axes fraction"),
                            rotation=90, ha="center", va="bottom")
                continue
            value = mean * spec.display_scale
            ax.bar(position, value, color=colors[position], edgecolor="#333333",
                   hatch=hatches[position % len(hatches)], width=.65, zorder=2)
            if ci is not None:
                low, high = [v * spec.display_scale for v in ci]
                ax.errorbar(position, value,
                            yerr=np.array([[max(0., value-low)], [max(0., high-value)]]),
                            fmt="none", ecolor="black", capsize=3, zorder=3)
                defined.append(max(value, high))
            else:
                defined.append(value)
            ax.annotate(f"{value:.2f}", (position, value), xytext=(0, 7),
                        textcoords="offset points", ha="center", fontsize=9)
        upper = max(defined, default=0.)
        ax.set_ylim(0, max(1., upper * 1.23))
        ax.set_xticks(range(len(methods)), labels)
        ax.set_ylabel(f"{spec.label} ({spec.unit})")
        ax.set_title(f"({chr(97+index)}) {spec.label}", fontsize=10)
        ax.grid(axis="y", alpha=.25, zorder=0)
        if metric == "recovery_event_fraction":
            ax.text(.5, .94, "Censored / no-excursion counts retained in JSON",
                    ha="center", va="top", transform=ax.transAxes, fontsize=7)
    fig.suptitle(f"Archived {result['node_count']:,}-node ablation records", fontsize=12)
    fig.text(.5, .015, "Paired seed means; pointwise 95% percentile-bootstrap CIs. "
             "HVE coverage denotes configured capability.", ha="center", fontsize=8)
    fig.tight_layout(rect=(0, .07, 1, .94))
    fig.savefig(output, format="pdf", metadata={"Title": "DA-AHE ablation evidence",
                                               "CreationDate": None, "ModDate": None})
    plt.close(fig)


def export(args):
    destination = args.output.resolve()
    require(not destination.exists(), "output directory already exists")
    campaign = load_campaign(args.campaign)
    methods = tuple(args.methods)
    require(set(methods) <= set(campaign["methods"]), "selected method absent from campaign")
    rows = [r for r in campaign["rows"] if r["method"] in methods]
    frames = frame_records(args.fragment_metrics, campaign, methods) if args.fragment_metrics else None
    caps = capability_records(args.hve_capabilities, campaign, methods) if args.hve_capabilities else None
    result = analyze_ablation(rows, campaign["config"], methods=methods, metrics=args.metrics,
        expected_seed_count=args.expected_seeds, resamples=args.bootstrap_resamples,
        bootstrap_seed=args.bootstrap_seed, rmst_horizon_s=args.rmst_horizon,
        frame_metrics=frames, hve_capabilities=caps)
    result["provenance"] = {**campaign["provenance"],
        "selected_method_count": len(methods),
        "excluded_methods": [m for m in campaign["methods"] if m not in methods],
        "selected_row_count": len(rows), "complete_input_row_count": len(campaign["rows"]),
        "supplemental_sha256": {role: file_hash(path) for role, path in (
            ("terminal_frame_counts", args.fragment_metrics),
            ("hve_capabilities", args.hve_capabilities)) if path is not None}}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ablation-", dir=destination.parent) as directory:
        out = Path(directory)
        write_json(out / "ablation-summary.json", result)
        with (out / "ablation-statistics.csv").open("w", newline="", encoding="utf-8") as stream:
            fields = ("method", "metric", "unit", "denominator", "mean", "ci95_lower",
                      "ci95_upper", "n_total", "n_defined", "status",
                      "paired_difference_mean", "paired_difference_ci95_lower",
                      "paired_difference_ci95_upper")
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for method in methods:
                for metric, row in result["statistics"][method].items():
                    ci, delta = row["ci95"], row["paired_difference"]
                    dci = delta["ci95"]
                    writer.writerow({"method": method, "metric": metric,
                        **{key: row[key] for key in ("unit", "denominator", "mean",
                            "n_total", "n_defined", "status")},
                        "ci95_lower": ci[0] if ci else None,
                        "ci95_upper": ci[1] if ci else None,
                        "paired_difference_mean": delta["mean"],
                        "paired_difference_ci95_lower": dci[0] if dci else None,
                        "paired_difference_ci95_upper": dci[1] if dci else None})
        with (out / "ablation-per-seed.csv").open("w", newline="", encoding="utf-8") as stream:
            fields = ("seed", "method", "metric", "value", "value_role", "recovery_status",
                      "recovery_event", "follow_up_s", "configured_hve_enabled")
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for method in methods:
                for metric, row in result["statistics"][method].items():
                    for index, seed in enumerate(result["seeds"]):
                        rec = result["recovery"][method]["per_seed"][index]
                        writer.writerow({"seed": seed, "method": method, "metric": metric,
                            "value": row["per_seed"][index],
                            "value_role": row["per_seed_value_role"],
                            "recovery_status": rec["status"], "recovery_event": rec["event"],
                            "follow_up_s": rec["elapsed_from_onset_s"],
                            "configured_hve_enabled":
                                result["capability_declaration"]["hve_enabled_by_method"][method]})
        caption = manuscript_caption(result)
        (out / "ablation-caption.txt").write_text(caption + "\n", encoding="utf-8")
        escaped = caption.replace("\\", r"\textbackslash{}").replace("%", r"\%")
        (out / "ablation-caption.tex").write_text("\\caption{" + escaped + "}\n", encoding="utf-8")
        if args.figures:
            plot(result, out / "ablation-bars.pdf")
        write_json(out / "export-manifest.json", {
            "schema_version": 1, "analysis_kind": "paired_archived_ablation",
            "provenance": result["provenance"], "bootstrap": result["bootstrap"],
            "selected_metrics": list(args.metrics),
            "source_sha256": {str(p.relative_to(ROOT)): file_hash(p) for p in (
                Path(__file__), ROOT / "simulation/ablation_analysis.py",
                ROOT / "tools/export_performance_evaluation.py")},
            "output_sha256": {p.name: file_hash(p) for p in sorted(out.iterdir())}})
        # Rename the complete directory; existing inputs and figures are never replaced.
        require(not destination.exists(), "output directory appeared during export")
        out.rename(destination)
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("campaign", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--methods", nargs="+", default=list(DEFAULT_METHODS))
    p.add_argument("--metrics", nargs="+", choices=tuple(METRIC_SPECS), default=list(DEFAULT_METRICS))
    p.add_argument("--expected-seeds", type=int, default=20)
    p.add_argument("--bootstrap-resamples", type=int, default=100000)
    p.add_argument("--bootstrap-seed", type=int, default=20261017)
    p.add_argument("--rmst-horizon", type=float)
    p.add_argument("--fragment-metrics", type=Path)
    p.add_argument("--hve-capabilities", type=Path)
    p.add_argument("--figures", action="store_true")
    return p


def main():
    try:
        args = parser().parse_args()
        result = export(args)
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"methods": result["methods"], "seeds": result["seeds"],
                      "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
