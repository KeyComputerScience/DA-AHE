#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Render summary JSON from daahe stats as a standalone SVG; no external plotting deps.

Input is a simple array of {label,mean,low,high} numeric records, one unit per plot.
Never reads paper target values; requires computed empirical summary data.
"""
import argparse
import html
import json
import math
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--title", required=True)
    p.add_argument("--unit", required=True)
    a = p.parse_args()
    rows = json.loads(a.input.read_text())
    if not rows:
        raise ValueError("no empirical rows")
    for r in rows:
        if not all(math.isfinite(float(r[k])) for k in ("mean", "low", "high")):
            raise ValueError("nonfinite result")
        if not 0 <= r["low"] <= r["mean"] <= r["high"]:
            raise ValueError("invalid interval")
    width, height, left, top, bottom = max(600, len(rows)*120+100), 440, 70, 60, 350
    ymax = max(r["high"] for r in rows)*1.12 or 1
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

