#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Import an EXTERNAL OMNeT++ instrumented event export; does not simulate a network.

Canonical input contract is in experiments/METRICS_SCHEMA.md. Raw .sca/.vec files
must first be exported by the author module with complete source/sink events.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path

from daahe.evidence import sha256_file
from daahe.statistics import MetricRow, write_metrics_csv


def _finite(raw: str, name: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError(f"nonfinite {name}")
    return value


def _csv(path: Path, fields: set[str]) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)) or set(reader.fieldnames) != fields:
            raise ValueError(f"{path.name}: headers must be exactly {sorted(fields)}")
        rows = list(reader)
        if any(None in row or any(v is None for v in row.values()) for row in rows):
            raise ValueError(f"{path.name}: missing/extra CSV values")
        return rows


def import_external_run(events: Path, telemetry: Path, metadata: Path) -> tuple[MetricRow, dict]:
    meta = json.loads(metadata.read_text(encoding="utf-8"))
    if meta.get("schema_version") != 1 or meta.get("simulator") != "OMNeT++ 6.0 / INET 4.4":
        raise ValueError("external metadata must declare schema 1 and OMNeT++ 6.0 / INET 4.4")
    if meta.get("event_export_complete") is not True:
        raise ValueError("author exporter must attest completeness of source and sink event accounting")
    if type(meta.get("nodes")) is not int or type(meta.get("seed")) is not int:
        raise ValueError("metadata nodes and seed must be JSON integers, without truncation")
    warmup, duration, onset = (float(meta[k]) for k in ("warmup_s", "duration_s", "disturbance_s"))
    if (warmup, duration, onset) != (30, 300, 100):
        raise ValueError("paper protocol requires 30-s warm-up, 300-s duration, disturbance at 100 s")
    # This importer observes a fixed horizon, without silently equating in-flight
    # units with permanent failures or inventing an unrecorded drain interval.
    if (meta.get("loss_observation_boundary") != "window_endpoint_loss"
            or meta.get("delivery_cutoff_s") != duration or meta.get("drain_s") != 0):
        raise ValueError("declare window_endpoint_loss, delivery_cutoff_s=300 and drain_s=0; other boundary protocols need a separate importer")
    if meta.get("telemetry_timestamp_semantics") != "interval_end":
        raise ValueError("recovery telemetry must declare interval_end timestamps")
    q_threshold = _finite(str(meta["normal_queue_threshold"]), "normal queue threshold")
    p_threshold = _finite(str(meta["normal_plr_threshold"]), "normal loss threshold")
    if not 0 < q_threshold <= 1 or not 0 < p_threshold <= 1:
        raise ValueError("calibrated S1 thresholds must be fractions in (0,1]")
    packets = _csv(events, {"packet_id", "created_s", "delivered_s", "aggregate_id", "hve_available"})
    seen, latencies, count, delivered, aggregates = set(), [], 0, 0, {}
    for event in packets:
        identity = event["packet_id"]
        if not identity or identity in seen:
            raise ValueError("duplicate or empty packet_id in complete export")
        seen.add(identity)
        created = _finite(event["created_s"], "created_s")
        if not 0 <= created < duration:
            raise ValueError("packet creation is outside simulation interval")
        arrival = None if event["delivered_s"] == "" else _finite(event["delivered_s"], "delivered_s")
        if arrival is not None and not created <= arrival <= duration:
            raise ValueError("delivery precedes generation or exceeds run end")
        if event["hve_available"] not in {"true", "false", ""}:
            raise ValueError("hve_available must be true/false for delivered aggregates, otherwise empty")
        if arrival is None and (event["aggregate_id"] or event["hve_available"]):
            raise ValueError("undelivered packet cannot attest sink aggregate verification coverage")
        if arrival is not None and (not event["aggregate_id"] or event["hve_available"] not in {"true", "false"}):
            raise ValueError("each delivered unit must identify its sink aggregate and explicit HVE availability")
        if not warmup <= created < duration:
            continue
        count += 1
        if arrival is not None:
            delivered += 1
            latencies.append(1000*(arrival-created))
            if event["aggregate_id"]:
                if event["hve_available"] not in {"true", "false"}:
                    raise ValueError("each delivered aggregate needs an explicit HVE availability indicator")
                available = event["hve_available"] == "true"
                old = aggregates.setdefault(event["aggregate_id"], available)
                if old != available:
                    raise ValueError("inconsistent HVE availability for repeated aggregate ID")
    if count == 0:
        raise ValueError("no generated units in the measurement window")
    observations = _csv(telemetry, {"time_s", "queue_utilization", "residual_plr"})
    recovery, held, last = None, 0, None
    for observation in observations:
        time = _finite(observation["time_s"], "time_s")
        queue = _finite(observation["queue_utilization"], "queue_utilization")
        loss = _finite(observation["residual_plr"], "residual_plr")
        if not 0 <= queue <= 1 or not 0 <= loss <= 1 or not 0 <= time <= duration:
            raise ValueError("telemetry outside time or fraction bounds")
        if last is not None and time <= last:
            raise ValueError("telemetry times must be strictly increasing")
        if last is not None and not math.isclose(time-last, 1.0, abs_tol=1e-9):
            raise ValueError("complete 1-s controller telemetry is required; no interpolation")
        last = time
        # A sample at onset ends the pre-disturbance interval. The first full
        # post-onset control interval ends at onset+1, and five end at onset+5.
        if time <= onset:
            continue
        held = held+1 if queue < q_threshold and loss < p_threshold else 0
        if held == 5 and recovery is None:
            recovery = time-onset
    if (not observations or float(observations[0]["time_s"]) > onset or last != duration
            or not any(float(row["time_s"]) == onset for row in observations)):
        raise ValueError("recovery observation must include onset through simulation end")
    row = MetricRow(
        run_id=meta["run_id"], method=meta["method"], nodes=int(meta["nodes"]), seed=int(meta["seed"]),
        latency_ms=sum(latencies)/len(latencies) if delivered else None, residual_plr=(count-delivered)/count,
        recovery_s=recovery, recovery_censored=recovery is None,
        hve_coverage=sum(aggregates.values())/len(aggregates) if aggregates else None,
        warmup_s=warmup, duration_s=duration, disturbance_s=onset,
        measured_window_start_s=warmup, measured_window_end_s=duration,
        trace_sha256=meta["trace_sha256"], configuration_sha256=meta["configuration_sha256"],
        calibration_sha256=meta["calibration_sha256"], simulator=meta["simulator"], measurement_unit=meta["measurement_unit"],
    )
    provenance = {"schema_version":1, "status":"imported_external_events", "simulator_executed_by_importer":False,
                  "event_sha256":sha256_file(events), "telemetry_sha256":sha256_file(telemetry),
                  "metadata_sha256":sha256_file(metadata), "generated_units":count, "delivered_units":delivered,
                  "delivered_aggregates":len(aggregates), "loss_denominator":meta["measurement_unit"],
                  "loss_observation_boundary":"window_endpoint_loss", "delivery_cutoff_s":duration,
                  "drain_s":0, "in_flight_units_at_cutoff":"not separately identifiable from this export",
                  "undefined_metrics":{} if delivered else {"latency_ms":"no delivered units", "hve_coverage":"no delivered aggregates"},
                  "telemetry_timestamp_semantics":"interval_end", "recovery_criterion_intervals":5,
                  "author_boundary_confirmation_required":True,
                  "note":"Source/sink exporter completeness, packet versus report unit, and queue/loss threshold definitions require author review."}
    return row, provenance


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--telemetry", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.with_suffix(".provenance.json").exists():
        parser.error("output exists; use a new path to preserve evidence")
    row, provenance = import_external_run(args.events, args.telemetry, args.metadata)
    write_metrics_csv([row], args.output)
    args.output.with_suffix(".provenance.json").write_text(json.dumps(provenance, indent=2)+"\n", encoding="utf-8")


if __name__ == "__main__":
    main()
