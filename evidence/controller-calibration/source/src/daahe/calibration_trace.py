# SPDX-License-Identifier: MIT
"""Causal adapters for independently executed service-model calibration.

Operational stage annotations are predeclared simulator conditions, not measured
latent states. Labels never enter the exploration policy or online observations.
Costs are executed model costs; signal probes execute integer arithmetic and are
kept separate from packet transport, physical sensors, and cryptographic noise.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import csv
import hashlib
import math
from pathlib import Path

from .calibration import CSV_COLUMNS, TraceRow
from .control import ControlledHMM
from .profiles import example_profiles
from .safety import violation_state
from .signal import encode_channels, reconstruct_channels

SCENARIOS = ("normal", "congestion", "local_impairment", "global_impairment", "severe_loss")
ANNOTATION_NAMES = ("normal modeled operation", "congestion stress exposure",
                    "local primary-route impairment exposure", "global primary-route impairment exposure",
                    "severe link-error exposure")


class ScheduledExplorationPolicy:
    """Apply complete actions in a fixed, outcome-independent cyclic schedule."""
    def __init__(self, base_policy, phase=0):
        self.data, self.actions = base_policy.data, base_policy.actions
        self.order = tuple(self.actions[name] for name in ("nominal", "repair", "fallback"))
        self.phase, self.epoch = int(phase) % len(self.order), 0
        self.current = self.order[self.phase]

    def choose(self, telemetry, initial=False):
        self.current = self.order[(self.epoch + self.phase) % len(self.order)]
        self.epoch += 1
        params = self.data["params"]
        state = violation_state(telemetry[2], telemetry[1], telemetry[6],
                                delay_threshold=params.delay_threshold,
                                loss_threshold=self.data["loss_threshold"], decoding_margin=1.0)
        return {"telemetry": list(telemetry), "state": list(state), "belief": None,
                "stress": 0.0, "stress_bin": 0,
                "decision": {"action": asdict(self.current), "alarm": False, "certified": False,
                             "reason": "predeclared cyclic system-identification action; no latent labels used",
                             "scores": []},
                "model_status": "independent_open_loop_identification", "certified": False}


def operational_annotation(time_s, config, scenario):
    """Annotate only the condition active at this cutoff, never a future outcome.

The exposure interval is left-closed/right-open. Normal outside the interval
means baseline input conditions, not an assertion of zero queue/loss or recovery.
"""
    if scenario not in SCENARIOS:
        raise ValueError("unknown operational calibration scenario")
    if scenario == "congestion":
        return 1  # Reduced contention-domain counts apply to the complete run.
    d = config["disturbance"]
    return SCENARIOS.index(scenario) if d["start_s"] <= time_s < d["end_s"] else 0


def executed_cpu_energy(events, start, end, power):
    """Integrate reserved CPU execution intervals, clipping queued future work."""
    if end <= start or power < 0:
        raise ValueError("invalid CPU observation window")
    return sum(max(0.0, min(end, float(e["start_s"]) + float(e["duration_s"])) -
                   max(start, float(e["start_s"]))) * power
               for e in events if e.get("event") == "cpu_reservation")


def signal_probe(seed, scenario, epoch, action):
    """Execute a maximum-capacity synthetic integer-signal probe for this action.

This independent utility probe is not a delivered packet or physical telemetry.
True and reconstructed aggregate vectors and all source vectors are retained.
"""
    library = {p.name: p for p in example_profiles()}
    profiles = {240: library["pi0"], 180: library["pi1"], 120: library["pi2"]}
    support = {"nominal": 240, "repair": 180, "fallback": 120}[action.id]
    profile = profiles[support]
    if profile.delta_q != action.delta_q or action.batch_size > profile.nmax:
        raise ValueError("probe profile does not match selected complete action")
    sources = []
    for source in range(action.batch_size):
        channels = []
        for channel in range(2):
            material = f"controller-signal-v1/{seed}/{scenario}/{epoch}/{source}/{channel}".encode()
            digest = hashlib.sha256(material).digest()
            base, amplitude, phase = 50 + digest[0] % 70, 10 + digest[1] % 30, digest[2] % 120
            channels.append([base + amplitude * (60 - abs((t + phase) % 120 - 60)) // 30
                             + (int(t >= 120) * (digest[3] % 12)) for t in range(240)])
        sources.append(channels)
    encoded = [encode_channels(source, profile.support, profile.delta_q, profile.coefficient_bound)
               for source in sources]
    summed = [sum(values) for values in zip(*encoded)]
    if any(abs(v) > 32768 for v in summed):
        raise ValueError("signal probe aggregate wraps plaintext")
    reconstructed = list(sum(reconstruct_channels(summed, profile.support, profile.delta_q), ()))
    truth = [sum(values) for values in zip(*(s[0] + s[1] for s in sources))]
    error = [r - t for r, t in zip(reconstructed, truth)]
    reference_energy = sum(v * v for v in truth)
    if not reference_energy:
        raise ValueError("zero-reference distortion cannot become zero")
    prd_fraction = math.sqrt(sum(v * v for v in error) / reference_energy)
    return {"seed": seed, "scenario": scenario, "epoch": epoch, "action_id": action.id,
            "profile_digest": profile.digest, "batch_size": action.batch_size,
            "scope": "executed synthetic integer-count capacity probe; separate from packet delivery and physical sensors",
            "units": "arbitrary integer counts; distortion is aggregate relative L2 error",
            "sources": sources, "encoded_sources": [list(v) for v in encoded],
            "true_aggregate": truth, "reconstructed_aggregate": reconstructed,
            "squared_error": sum(v * v for v in error), "reference_energy": reference_energy,
            "distortion": prd_fraction}


def extract_transitions(epochs, events, traffic, config, *, seed, scenario, actions,
                        delay_threshold, loss_threshold):
    """Join y_t / a_t to y_(t+1), retaining explicit empty-window diagnostics."""
    rows, probes, diagnostics = [], [], []
    if not epochs or epochs[0]["time_s"] != 0:
        raise ValueError("initial epoch at zero required")
    for index, (current, following) in enumerate(zip(epochs, epochs[1:])):
        start, end = float(current["time_s"]), float(following["time_s"])
        if end <= start or following["observation_start_s"] != start or following["observation_cutoff_s"] != end:
            raise ValueError("noncontiguous causal epoch windows")
        if start >= config["duration_s"]:
            continue
        selection = current["decision"]["action"]
        if selection is None or selection["id"] not in actions:
            raise ValueError("exploration epoch missing a library action")
        action = actions[selection["id"]]
        if asdict(action) != selection:
            raise ValueError("exploration changed a complete action row")
        opportunities = sum(start <= float(r["time_s"]) < end for r in traffic)
        diag = {"seed": seed, "scenario": scenario, "time_s": start,
                "action_id": action.id, "opportunities": opportunities,
                "completed_reports": following["completed_reports"],
                "accepted_reports": following["accepted_reports"],
                "empty_outcome_window": following["completed_reports"] == 0,
                "empty_delay_window": following["accepted_reports"] == 0}
        if not opportunities:
            diagnostics.append({**diag, "included": False, "reason": "undefined per-opportunity energy denominator"})
            continue
        y, next_y = tuple(current["telemetry"]), tuple(following["telemetry"])
        state = violation_state(y[2], y[1], y[6], delay_threshold=delay_threshold,
                                loss_threshold=loss_threshold, decoding_margin=1.0)
        next_state = violation_state(next_y[2], next_y[1], next_y[6], delay_threshold=delay_threshold,
                                     loss_threshold=loss_threshold, decoding_margin=1.0)
        if any(not math.isclose(x, z, rel_tol=1e-9, abs_tol=1e-12)
               for x, z in zip(state, current["state"])):
            raise ValueError("logged current state inconsistent with causal telemetry")
        probe = signal_probe(seed, scenario, index, action)
        probes.append(probe)
        energy = executed_cpu_energy(events, start, end, config["cpu_power_w"]) / opportunities
        rows.append(TraceRow(f"{seed}/{scenario}", start, action.id,
                             operational_annotation(start, config, scenario),
                             operational_annotation(end, config, scenario), state, next_state, y,
                             (energy, next_y[2], probe["distortion"], next_y[6]), next_y[1]))
        diagnostics.append({**diag, "included": True,
                            "empty_window_rule": "retain actual simulator zero-observation defaults; no measured QoS assertion"})
    return rows, probes, diagnostics


def write_trace(path, rows):
    with Path(path).open("x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for r in rows:
            writer.writerow((r.seed, r.time_s, r.action_id, r.regime, r.next_regime, *r.state,
                             *r.next_state, *r.telemetry, *r.metrics[:3], r.next_loss, r.metrics[3]))


def coverage(rows, action_ids):
    current = Counter((r.action_id, r.regime) for r in rows)
    following = Counter((r.action_id, r.next_regime) for r in rows)
    return {"rows": len(rows), "by_action_current_regime": {a: [current[a, j] for j in range(5)] for a in action_ids},
            "by_action_next_regime": {a: [following[a, j] for j in range(5)] for a in action_ids},
            "missing_current_cells": [[a, j] for a in action_ids for j in range(5) if not current[a, j]],
            "missing_next_cells": [[a, j] for a in action_ids for j in range(5) if not following[a, j]]}


def error_summary(errors):
    values = list(errors)
    if not values:
        return {"n": 0, "mae": None, "rmse": None, "bias": None, "max_absolute": None}
    return {"n": len(values), "mae": sum(abs(v) for v in values) / len(values),
            "rmse": math.sqrt(sum(v * v for v in values) / len(values)),
            "bias": sum(values) / len(values), "max_absolute": max(abs(v) for v in values)}


def prediction_report(rows, model, dpp, delay_threshold, loss_threshold):
    """Out-of-fit descriptive errors; next-regime-conditioned errors are diagnostic."""
    metric_names = ("modeled_cpu_j_per_opportunity", "conditional_delay_s", "signal_probe_relative_l2", "noise_proxy")
    pooled_errors, regime_errors, dpp_errors, state_errors = [[] for _ in range(4)], [[] for _ in range(4)], [[] for _ in range(3)], []
    exceeds = 0
    for r in rows:
        pooled = model.pooled_metrics[r.action_id].predict(r.state)
        conditional = model.state_metrics[r.action_id][r.next_regime].predict(r.state)
        for h in range(4):
            pooled_errors[h].append(pooled[h] - r.metrics[h])
            regime_errors[h].append(conditional[h] - r.metrics[h])
        state = tuple(max(model.kappa_z * r.state[h] + model.offsets[r.next_regime][h] - model.relief[r.action_id][h], 0)
                      for h in range(3))
        norm = math.sqrt(sum((p - t) ** 2 for p, t in zip(state, r.next_state)))
        state_errors.append(norm)
        exceeds += norm > model.error_radii[r.action_id][r.next_regime] + 1e-12
        targets = (r.metrics[1] / delay_threshold - 1, r.next_loss / loss_threshold - 1, r.metrics[3] - 1)
        for h in range(3):
            prediction = sum(w * x for w, x in zip(dpp[r.action_id][h], (1.0,) + r.state))
            dpp_errors[h].append(prediction - targets[h])
    return {"pooled_cost_errors": dict(zip(metric_names, map(error_summary, pooled_errors))),
            "next_regime_conditioned_cost_errors": dict(zip(metric_names, map(error_summary, regime_errors))),
            "state_residual_l2": error_summary(state_errors), "state_radius_exceedance_count": exceeds,
            "dpp_signed_target_errors": dict(zip(("delay_excess", "loss_excess", "noise_excess"), map(error_summary, dpp_errors))),
            "scope": "diagnostic next-regime conditioning uses offline outcome labels; not an online oracle or uniform certificate"}


def causal_hmm_predictions(epochs, rows, model):
    """Filter every observed epoch, including empty windows, before scoring.

No regime or next-state label enters update/predict. Outcome labels are used
only after predictions are frozen, for descriptive classification diagnostics.
"""
    hmm = ControlledHMM(model, adapt=False)
    trace_by_time = {r.time_s: r for r in rows}
    previous_action, records, metric_errors, state_errors = None, [], [[] for _ in range(4)], []
    confusion, log_losses, brier = [[0] * 5 for _ in range(5)], [], []
    for index, epoch in enumerate(epochs):
        telemetry = epoch["telemetry"]
        belief = hmm.belief if index == 0 else hmm.update(telemetry, previous_action)
        selection = epoch["decision"]["action"]
        if selection is None:
            raise ValueError("exploration HMM audit cannot skip a missing action")
        action = selection["id"]
        predicted = hmm.predict(action, belief)
        time_s = float(epoch["time_s"])
        row = trace_by_time.get(time_s)
        record = {"time_s": time_s, "action_id": action, "causal_belief": list(belief),
                  "predicted_next_regime": list(predicted), "labels_used_by_filter": False}
        if row is not None:
            metrics = tuple(sum(predicted[j] * model.state_metrics[action][j].predict(row.state)[h]
                                for j in range(5)) for h in range(4))
            state = tuple(sum(predicted[j] * max(model.kappa_z * row.state[h] + model.offsets[j][h] -
                                                  model.relief[action][h], 0.0)
                              for j in range(5)) for h in range(3))
            for h in range(4):
                metric_errors[h].append(metrics[h] - row.metrics[h])
            state_errors.append(math.sqrt(sum((x - y) ** 2 for x, y in zip(state, row.next_state))))
            estimate = max(range(5), key=lambda j: predicted[j])
            confusion[row.next_regime][estimate] += 1
            log_losses.append(-math.log(max(predicted[row.next_regime], 1e-300)))
            brier.append(sum((predicted[j] - int(j == row.next_regime)) ** 2 for j in range(5)))
            record.update(predicted_cost=list(metrics), predicted_state=list(state),
                          scored_next_operational_annotation=row.next_regime)
        records.append(record)
        previous_action = action
    return records, {
        "predicted_cost_errors": dict(zip(("modeled_cpu_j_per_opportunity", "conditional_delay_s",
                                           "signal_probe_relative_l2", "noise_proxy"), map(error_summary, metric_errors))),
        "predicted_state_residual_l2": error_summary(state_errors),
        "next_annotation_confusion_true_by_prediction": confusion,
        "next_annotation_log_loss": sum(log_losses) / len(log_losses) if log_losses else None,
        "next_annotation_brier": sum(brier) / len(brier) if brier else None,
        "scored_rows": len(state_errors), "filtered_epochs": len(epochs),
        "scope": "fixed fitted HMM causal evaluation; offline operational annotations score already frozen predictions only"}
