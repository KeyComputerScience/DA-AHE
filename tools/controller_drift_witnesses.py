#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact fallback counterexamples at z=0, using admissible prediction error 0."""
from fractions import Fraction
import argparse
import json
from pathlib import Path


def witnesses(config):
    model, params = config["model"], config["parameters"]
    fallback, rows = config["fallback_id"], []
    for regime, offset in enumerate(model["offsets"]):
        successor = [max(Fraction(x) - Fraction(y), 0)
                     for x, y in zip(offset, model["relief"][fallback])]
        drift = sum(Fraction(p) * x * x for p, x in zip(params["p_diagonal"], successor))
        rows.append({"regime": regime, "state": [0, 0, 0], "prediction_error": [0, 0, 0],
                     "successor_exact": [str(x) for x in successor],
                     "successor_inside_domain": all(0 <= x <= Fraction(u) for x, u in zip(successor, model["zcert_max"])),
                     "drift_exact": str(drift), "drift_decimal": float(drift),
                     "beta_exact": str(Fraction(params["beta"])),
                     "inequality_violated": drift > Fraction(params["beta"])})
    return {"scope": "declared fitted model; not a physical trajectory",
            "calculation": "V(ReLU(offset_j-relief_fallback)) - (1-gamma)*V(0); error=0 lies in each declared residual ball",
            "every_regime_violates_beta": all(r["inequality_violated"] for r in rows), "witnesses": rows}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("controller", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = witnesses(json.loads(args.controller.read_text()))
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"every_regime_violates_beta": result["every_regime_violates_beta"]}))
