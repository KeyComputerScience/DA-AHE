#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Render daahe stats JSON directly, or a legacy {label,mean,low,high} array.

Never reads paper target values. Blocked or undefined paired metrics stop the
plot, rather than silently omitting methods. The unit is supplied explicitly.
"""
import argparse
import html
import json
import math
from pathlib import Path

METRICS = ("latency_ms", "residual_plr", "recovery_s", "hve_coverage")


def extract_plot_rows(payload, *, nodes=None, metric="latency_ms", normalized=False):
    """Adapt an actual statistics result without selecting favorable methods."""
    if isinstance(payload, list):
        if nodes is not None or normalized:
            raise ValueError("node selection and normalization require daahe stats JSON")
        rows = payload
    elif isinstance(payload, dict):
        if payload.get("status") != "computed_from_external_metrics":
            raise ValueError("expected computed daahe stats output")
        groups = payload.get("groups")
        if not isinstance(groups, list) or not groups or metric not in METRICS:
            raise ValueError("statistics groups and a supported metric are required")
        available = {group["nodes"] for group in groups}
        if nodes is None:
            if len(available) != 1:
                raise ValueError("multiple node counts: select --nodes explicitly")
            nodes = next(iter(available))
        if nodes not in available:
            raise ValueError("requested node count is absent")
        reference = payload.get("reference_method")
        if not isinstance(reference, str) or not reference:
            raise ValueError("statistics reference_method is missing")
        source = "normalized_to_" + reference.replace("-", "_") if normalized else "raw"
        rows = []
        for group in groups:
            if group["nodes"] != nodes:
                continue
            value = group.get(source, {}).get(metric, {})
            center = "estimate" if normalized else "mean"
            if "status" in value or not all(key in value for key in (center, "ci_low", "ci_high")):
                raise ValueError(f"cannot plot {group['method']} {metric}: blocked or undefined paired metric")
            rows.append({"label":group["method"], "mean":value[center],
                         "low":value["ci_low"], "high":value["ci_high"]})
    else:
        raise ValueError("plot input must be stats JSON or a legacy array")
    if not rows:
        raise ValueError("no empirical rows")
    labels = set()
    for row in rows:
        if not isinstance(row, dict) or not all(key in row for key in ("label", "mean", "low", "high")):
            raise ValueError("each plot row requires label, mean, low and high")
        if str(row["label"]) in labels:
            raise ValueError("duplicate plot label")
        labels.add(str(row["label"]))
        if any(type(row[key]) not in (int, float) or not math.isfinite(row[key]) for key in ("mean", "low", "high")):
            raise ValueError("nonfinite or nonnumeric result")
        if row["mean"] < 0 or not 0 <= row["low"] <= row["high"]:
            raise ValueError("invalid nonnegative metric or interval")
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--title", required=True)
    p.add_argument("--unit", required=True)
    p.add_argument("--nodes", type=int, help="required when stats includes multiple network sizes")
    p.add_argument("--metric", choices=METRICS, default="latency_ms")
    p.add_argument("--normalized", action="store_true", help="plot method/reference mean ratios and paired CIs")
    a = p.parse_args()
    rows = extract_plot_rows(json.loads(a.input.read_text()), nodes=a.nodes,
                             metric=a.metric, normalized=a.normalized)
    width, height, left, top, bottom = max(600, len(rows)*120+100), 440, 70, 60, 350
    ymax = max(max(r["high"], r["mean"]) for r in rows)*1.12 or 1
    xscale = (width-left-30)/len(rows)
    y = lambda v: bottom-(bottom-top)*v/ymax
    esc = html.escape
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
             '<rect width="100%" height="100%" fill="white"/>',
             '<g font-family="sans-serif" font-size="13" fill="#172533">',
             f'<text x="{left}" y="28" font-size="20">{esc(a.title)}</text>',
             f'<text x="{left}" y="48">{esc(a.unit)}; percentile bootstrap 95% CI</text>']
    for i in range(6):
        v = ymax*i/5
        parts += [f'<path d="M{left},{y(v)}H{width-30}" stroke="#e0e6ec"/>',
                  f'<text x="{left-8}" y="{y(v)+4}" text-anchor="end">{v:.3g}</text>']
    for i,r in enumerate(rows):
        x = left+xscale*(i+.5)
        parts += [f'<rect x="{x-28}" y="{y(r["mean"])}" width="56" height="{bottom-y(r["mean"])}" fill="#267d9f"/>',
                  f'<path d="M{x},{y(r["high"])}V{y(r["low"])} M{x-7},{y(r["high"])}h14 M{x-7},{y(r["low"])}h14" stroke="#172533" fill="none"/>',
                  f'<text x="{x}" y="{bottom+24}" text-anchor="middle">{esc(str(r["label"]))}</text>']
    parts += ['</g></svg>']
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text("\n".join(parts)+"\n")


if __name__ == "__main__":
    main()

