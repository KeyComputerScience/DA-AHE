# SPDX-License-Identifier: MIT
"""Paired-seed statistics for externally measured experiments, never synthetic data.

One row is one method/node-count/seed run. PLR and HVE coverage are fractions.
Percentile intervals are pointwise, not simultaneous. The unit of resampling is
an independent seed, retaining the pairing across methods in each resample.
"""
from __future__ import annotations

import csv
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np

METHODS = ("da-ahe", "dpp", "hys", "without_markov", "without_intdb2", "without_route_repair", "without_hve")
HASH = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class MetricRow:
    run_id: str
    method: str
    nodes: int
    seed: int
    latency_ms: float | None
    residual_plr: float
    recovery_s: float | None
    recovery_censored: bool
    hve_coverage: float | None
    warmup_s: float
    duration_s: float
    disturbance_s: float
    measured_window_start_s: float
    measured_window_end_s: float
    trace_sha256: str
    configuration_sha256: str
    calibration_sha256: str
    simulator: str
    measurement_unit: str


def load_metrics_csv(path: str | Path) -> list[MetricRow]:
    """Read the exact metrics schema; reject duplicate headers and silent coercion."""
    with Path(path).open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        expected = set(MetricRow.__dataclass_fields__)
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)) or set(reader.fieldnames) != expected:
            raise ValueError(f"CSV headers must be exactly {sorted(expected)}")
        rows = []
        for line, raw in enumerate(reader, 2):
            try:
                if None in raw or any(value is None for value in raw.values()):
                    raise ValueError("missing or extra CSV values")
                if raw["recovery_censored"] not in {"true", "false"}:
                    raise ValueError("recovery_censored must be true or false")
                rows.append(MetricRow(
                    run_id=raw["run_id"], method=raw["method"], nodes=int(raw["nodes"]), seed=int(raw["seed"]),
                    latency_ms=None if raw["latency_ms"] == "" else float(raw["latency_ms"]), residual_plr=float(raw["residual_plr"]),
                    recovery_s=None if raw["recovery_s"] == "" else float(raw["recovery_s"]),
                    recovery_censored=raw["recovery_censored"] == "true", hve_coverage=None if raw["hve_coverage"] == "" else float(raw["hve_coverage"]),
                    warmup_s=float(raw["warmup_s"]), duration_s=float(raw["duration_s"]),
                    disturbance_s=float(raw["disturbance_s"]),
                    measured_window_start_s=float(raw["measured_window_start_s"]),
                    measured_window_end_s=float(raw["measured_window_end_s"]),
                    trace_sha256=raw["trace_sha256"], configuration_sha256=raw["configuration_sha256"],
                    calibration_sha256=raw["calibration_sha256"], simulator=raw["simulator"],
                    measurement_unit=raw["measurement_unit"],
                ))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid metric row at line {line}: {exc}") from exc
    validate_rows(rows)
    return rows


def validate_rows(rows: Sequence[MetricRow], *, require_paper_protocol: bool = True) -> None:
    if not rows:
        raise ValueError("no measured rows supplied")
    seen: set[tuple[int, str, int]] = set()
    run_ids: set[str] = set()
    for row in rows:
        if (not isinstance(row.run_id, str) or not isinstance(row.method, str)
                or type(row.nodes) is not int or type(row.seed) is not int):
            raise ValueError("run/method IDs must be strings and nodes/seed must be integers")
        key = row.nodes, row.method, row.seed
        if key in seen or row.run_id in run_ids or not row.run_id:
            raise ValueError(f"duplicate/empty run identifier or duplicate seed row: {key}")
        seen.add(key)
        run_ids.add(row.run_id)
        if row.method not in METHODS or row.nodes <= 0 or isinstance(row.seed, bool) or row.seed < 0:
            raise ValueError(f"invalid method/nodes/seed: {key}")
        numeric = (row.residual_plr, row.warmup_s, row.duration_s,
                   row.disturbance_s, row.measured_window_start_s, row.measured_window_end_s)
        numeric += tuple(v for v in (row.latency_ms, row.hve_coverage) if v is not None)
        if any(not isinstance(value, (int, float)) or not math.isfinite(value) for value in numeric):
            raise ValueError(f"nonfinite metric in {key}")
        if ((row.latency_ms is not None and row.latency_ms < 0)
                or not 0 <= row.residual_plr <= 1
                or (row.hve_coverage is not None and not 0 <= row.hve_coverage <= 1)):
            raise ValueError(f"invalid metric range in {key}; PLR/coverage are fractions")
        if (row.latency_ms is None or row.hve_coverage is None) and not (
                row.latency_ms is None and row.hve_coverage is None and row.residual_plr == 1):
            raise ValueError("empty latency and coverage are required together, only for a wholly undelivered run")
        if row.residual_plr == 1 and (row.latency_ms is not None or row.hve_coverage is not None):
            raise ValueError("wholly undelivered runs have undefined latency and coverage")
        if not 0 <= row.warmup_s <= row.measured_window_start_s < row.measured_window_end_s <= row.duration_s:
            raise ValueError(f"measurement window includes warm-up or exceeds duration in {key}")
        if not row.warmup_s <= row.disturbance_s < row.duration_s:
            raise ValueError(f"invalid disturbance time in {key}")
        if not isinstance(row.recovery_censored, bool):
            raise ValueError("recovery_censored must be a boolean")
        if row.recovery_censored:
            if row.recovery_s is not None:
                raise ValueError("censored recovery must have an empty recovery_s, never the run end time")
        elif not isinstance(row.recovery_s, (int, float)) or not math.isfinite(row.recovery_s) or not 0 <= row.recovery_s <= row.duration_s - row.disturbance_s:
            raise ValueError(f"invalid uncensored recovery in {key}")
        for digest in (row.trace_sha256, row.configuration_sha256, row.calibration_sha256):
            if not isinstance(digest, str) or not HASH.fullmatch(digest):
                raise ValueError(f"invalid provenance SHA256 in {key}")
        if row.simulator != "OMNeT++ 6.0 / INET 4.4":
            raise ValueError("paper-comparison rows require the stated external simulator/version")
        if row.measurement_unit not in {"network_packet", "application_report"}:
            raise ValueError("measurement_unit must explicitly identify the loss/latency denominator")
        if require_paper_protocol and (row.warmup_s, row.duration_s, row.disturbance_s,
                                      row.measured_window_start_s, row.measured_window_end_s) != (30, 300, 100, 30, 300):
            raise ValueError("paper protocol requires 30-s warm-up, 300-s duration, disturbance at 100 s, window [30,300]")


def validate_experiment_matrix(rows: Iterable[MetricRow], matrix: dict) -> dict:
    """Require the exact method/size/seed Cartesian product, without running it.

    This checks completeness and seed-disjointness only; it neither authenticates
    traces nor promotes the bundled prospective seed template to original data.
    Pairing/provenance must additionally pass ``summarize``.
    """
    rows = list(rows)
    validate_rows(rows)
    if matrix.get("schema_version") != 1:
        raise ValueError("unsupported experiment matrix schema")
    methods, nodes, seeds = (matrix.get(name) for name in ("methods", "node_counts", "evaluation_seeds"))
    for name, values in (("methods", methods), ("node_counts", nodes), ("evaluation_seeds", seeds)):
        if (not isinstance(values, list) or not values
                or any(type(value) not in (str, int) for value in values)
                or len(set(values)) != len(values)):
            raise ValueError(f"matrix {name} must be a nonempty list without duplicates")
    if any(method not in METHODS for method in methods):
        raise ValueError("matrix contains an unknown method")
    if any(type(value) is not int or value <= 0 for value in nodes):
        raise ValueError("matrix node counts must be positive integers")
    if any(type(value) is not int or value < 0 for value in seeds):
        raise ValueError("matrix evaluation seeds must be nonnegative integers")
    calibration = matrix.get("calibration_seeds", [])
    if not isinstance(calibration, list) or any(type(s) is not int or s < 0 for s in calibration):
        raise ValueError("matrix calibration seeds must be nonnegative integers")
    if set(calibration) & set(seeds):
        raise ValueError("evaluation and calibration seeds overlap")
    expected = {(node, method, seed) for node in nodes for method in methods for seed in seeds}
    if type(matrix.get("expected_runs")) is not int or matrix["expected_runs"] != len(expected):
        raise ValueError("matrix expected_runs differs from its Cartesian product")
    observed = {(row.nodes, row.method, row.seed) for row in rows}
    missing, extra = sorted(expected-observed), sorted(observed-expected)
    if missing or extra:
        raise ValueError(f"experiment matrix incomplete: missing={missing}; unexpected={extra}")
    return {"status": "matrix_complete_requires_provenance_and_review", "expected_runs": len(expected),
            "observed_runs": len(rows), "methods": methods, "node_counts": nodes,
            "evaluation_seeds": seeds, "paper_exact_seeds_available": matrix.get("paper_exact_seeds_available") is True,
            "paper_reproduced": False}


def paired_bootstrap(numerator: Sequence[float], denominator: Sequence[float], *,
                     resamples: int = 100_000, confidence: float = .95,
                     bootstrap_seed: int = 20261014) -> dict[str, float | int]:
    """Percentile CI of ratio of means, not mean of per-seed ratios.

    Indices must already be aligned by seed. This low-level function accepts any
    n>=2 for testing; summarize enforces the manuscript's n=20 by default.
    """
    x, y = np.asarray(numerator, dtype=float), np.asarray(denominator, dtype=float)
    if x.ndim != 1 or x.shape != y.shape or x.size < 2 or not np.isfinite(x).all() or not np.isfinite(y).all():
        raise ValueError("paired finite vectors of equal length >=2 required")
    if (x < 0).any() or (y <= 0).any():
        raise ValueError("nonnegative numerator and strictly positive denominator required")
    if type(resamples) is not int or resamples < 2 or not 0 < confidence < 1 or type(bootstrap_seed) is not int or bootstrap_seed < 0:
        raise ValueError("invalid bootstrap settings")
    rng = np.random.default_rng(bootstrap_seed)
    estimates = np.empty(resamples, dtype=float)
    for start in range(0, resamples, 4096):
        stop = min(start + 4096, resamples)
        indices = rng.integers(0, len(x), size=(stop-start, len(x)))
        estimates[start:stop] = x[indices].mean(axis=1) / y[indices].mean(axis=1)
    tail = (1-confidence)/2
    low, high = np.quantile(estimates, [tail, 1-tail], method="linear")
    return {"estimate": float(x.mean()/y.mean()), "ci_low": float(low), "ci_high": float(high),
            "n": int(x.size), "resamples": resamples, "bootstrap_seed": bootstrap_seed}


def _raw_bootstrap(values: Sequence[float], resamples: int, bootstrap_seed: int) -> dict[str, float]:
    x = np.asarray(values, dtype=float)
    rng = np.random.default_rng(bootstrap_seed)
    estimates = np.empty(resamples)
    for start in range(0, resamples, 4096):
        stop = min(start+4096, resamples)
        indices = rng.integers(0, len(x), size=(stop-start, len(x)))
        estimates[start:stop] = x[indices].mean(axis=1)
    low, high = np.quantile(estimates, [.025, .975], method="linear")
    return {"mean": float(x.mean()), "ci_low": float(low), "ci_high": float(high)}


def summarize(rows: Iterable[MetricRow], *, reference: str = "da-ahe", expected_seeds: int = 20,
              resamples: int = 100_000, bootstrap_seed: int = 20261014,
              required_methods: Sequence[str] | None = None) -> dict:
    """Check pairing/provenance and produce raw and normalized results separately.

    Censored runs are retained in the report; ordinary mean recovery and its
    normalized CI are withheld for the entire node-count stratum if any run is
    censored. No complete-case deletion, artificial timeout, or imputation occurs.
    """
    rows = list(rows)
    validate_rows(rows)
    if type(expected_seeds) is not int or expected_seeds < 2 or type(resamples) is not int or resamples < 2 or type(bootstrap_seed) is not int or bootstrap_seed < 0:
        raise ValueError("at least two seeds and resamples required")
    result = {"status": "computed_from_external_metrics", "confidence": .95, "reference_method": reference,
              "interval": "pointwise paired percentile bootstrap of ratio of means",
              "resamples": resamples, "bootstrap_seed": bootstrap_seed,
              "independence": "user-supplied seeds; independence cannot be proved from CSV", "groups": []}
    for nodes in sorted({r.nodes for r in rows}):
        subset = [r for r in rows if r.nodes == nodes]
        methods = sorted({r.method for r in subset})
        if reference not in methods or (required_methods is not None and set(methods) != set(required_methods)):
            raise ValueError(f"missing reference or requested methods at nodes={nodes}")
        by_method = {method: {r.seed: r for r in subset if r.method == method} for method in methods}
        seed_ids = sorted(by_method[reference])
        if len(seed_ids) != expected_seeds or any(set(group) != set(seed_ids) for group in by_method.values()):
            raise ValueError(f"exactly {expected_seeds} identical paired seeds required for every method at nodes={nodes}")
        for seed in seed_ids:
            paired = [by_method[m][seed] for m in methods]
            for name in ("trace_sha256", "configuration_sha256", "calibration_sha256", "warmup_s", "duration_s",
                         "disturbance_s", "measured_window_start_s", "measured_window_end_s", "simulator", "measurement_unit"):
                if len({getattr(r, name) for r in paired}) != 1:
                    raise ValueError(f"unmatched {name} for paired seed={seed}, nodes={nodes}")
        recovery_blocked = any(r.recovery_censored for r in subset)
        for method in methods:
            ordered = [by_method[method][s] for s in seed_ids]
            base = [by_method[reference][s] for s in seed_ids]
            normalized_key = "normalized_to_" + reference.replace("-", "_")
            report = {"nodes": nodes, "method": method, "paired_seeds": seed_ids, "n": len(seed_ids),
                      "measurement_unit": ordered[0].measurement_unit, "raw": {}, normalized_key: {},
                      "recovery_censored_count": sum(r.recovery_censored for r in ordered)}
            for name in ("latency_ms", "residual_plr", "hve_coverage", "recovery_s"):
                if name == "recovery_s" and recovery_blocked:
                    report["raw"][name] = {"status": "blocked_censored", "observed": [r.recovery_s for r in ordered],
                                             "censored": [r.recovery_censored for r in ordered]}
                    report[normalized_key][name] = {"status": "blocked_censored"}
                    continue
                if any(getattr(row, name) is None for row in subset):
                    report["raw"][name] = {"status": "blocked_undefined_paired_metric",
                        "reason": "a paired run had no delivered units; no complete-case deletion",
                        "observed": [getattr(row, name) for row in ordered]}
                    report[normalized_key][name] = {"status": "blocked_undefined_paired_metric"}
                    continue
                values = [getattr(r, name) for r in ordered]
                denominator = [getattr(r, name) for r in base]
                report["raw"][name] = _raw_bootstrap(values, resamples, bootstrap_seed)
                if any(v <= 0 for v in denominator):
                    report[normalized_key][name] = {"status": "undefined_zero_reference"}
                else:
                    report[normalized_key][name] = paired_bootstrap(
                        values, denominator, resamples=resamples, bootstrap_seed=bootstrap_seed)
            result["groups"].append(report)
    return result


def write_metrics_csv(rows: Iterable[MetricRow], path: str | Path) -> None:
    rows = list(rows)
    validate_rows(rows)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=MetricRow.__dataclass_fields__)
        writer.writeheader()
        for row in rows:
            value = asdict(row)
            value["recovery_censored"] = str(row.recovery_censored).lower()
            writer.writerow(value)
