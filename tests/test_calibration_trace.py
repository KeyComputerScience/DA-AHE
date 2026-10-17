"""Data timing, executed cost, independent labels, and signal-probe checks."""
from dataclasses import asdict
import math

import pytest

from daahe.calibration import read_trace
from daahe.calibration_trace import (executed_cpu_energy, extract_transitions,
                                    operational_annotation, signal_probe, write_trace)
from daahe.safety import Action, violation_state


def test_cpu_execution_clips_past_future_and_boundary_reservations():
    reservations = [
        {"event": "cpu_reservation", "start_s": 4, "duration_s": 3},
        {"event": "cpu_reservation", "start_s": 9, "duration_s": 4},
        {"event": "cpu_reservation", "start_s": 10, "duration_s": 2},
        {"event": "batch_authorized", "time_s": 6},
    ]
    assert executed_cpu_energy(reservations, 5, 10, .03) == pytest.approx(.09)


def test_exposure_annotations_are_declared_current_conditions_with_correct_extent():
    config = {"disturbance": {"start_s": 30, "end_s": 50}}
    assert operational_annotation(29.9, config, "local_impairment") == 0
    assert operational_annotation(30, config, "local_impairment") == 2
    assert operational_annotation(50, config, "local_impairment") == 0
    assert operational_annotation(0, config, "congestion") == 1
    assert operational_annotation(90, config, "congestion") == 1


def test_signal_probe_retains_raw_vectors_and_actual_aggregate_error():
    a = Action("nominal", 1, 8, 16, 64, 0, "p")
    case = signal_probe(20000, "normal", 0, a)
    truth = [sum(x) for x in zip(*(s[0] + s[1] for s in case["sources"]))]
    assert truth == case["true_aggregate"]
    squared = sum((x - y) ** 2 for x, y in zip(truth, case["reconstructed_aggregate"]))
    assert squared == case["squared_error"]
    assert case["distortion"] == math.sqrt(squared / sum(x * x for x in truth))


def epochs(action):
    y0, y1 = [0, 0, 0, 0, 0, 0, .32], [.2, .5, 3, .1, .3, 1, .24]
    result = []
    for time, start, y in ((0, 0, y0), (5, 0, y1)):
        result.append({"time_s": time, "observation_start_s": start, "observation_cutoff_s": time,
                       "telemetry": y, "state": list(violation_state(y[2], y[1], y[6],
                                                                        delay_threshold=.5, loss_threshold=.002, decoding_margin=1)),
                       "decision": {"action": asdict(action)}, "completed_reports": 2, "accepted_reports": 1})
    return result


def test_causal_join_uses_current_action_and_next_outcome_noise_and_roundtrips(tmp_path):
    a = Action("nominal", 1, 8, 16, 64, 0, "p")
    config = {"duration_s": 90, "cpu_power_w": .03, "disturbance": {"start_s": 30, "end_s": 50}}
    rows, probes, diagnostics = extract_transitions(epochs(a), [], [{"time_s": 1}], config,
                                                  seed=20000, scenario="normal", actions={a.id: a},
                                                  delay_threshold=.5, loss_threshold=.002)
    assert rows[0].telemetry[-1] == .32
    assert rows[0].metrics[-1] == .24
    assert rows[0].next_state == (5, 249, 0)
    assert rows[0].next_loss == .5
    assert probes and diagnostics[0]["included"]
    path = tmp_path / "trace.csv"
    write_trace(path, rows)
    assert read_trace(path) == rows


def test_adapter_rejects_changed_action_and_noncontiguous_window():
    a = Action("nominal", 1, 8, 16, 64, 0, "p")
    e = epochs(a)
    e[0]["decision"]["action"]["rho"] = .5
    config = {"duration_s": 90, "cpu_power_w": .03, "disturbance": {"start_s": 30, "end_s": 50}}
    kwargs = dict(seed=20000, scenario="normal", actions={a.id: a}, delay_threshold=.5, loss_threshold=.002)
    with pytest.raises(ValueError, match="complete action"):
        extract_transitions(e, [], [{"time_s": 1}], config, **kwargs)
    e = epochs(a)
    e[1]["observation_start_s"] = 1
    with pytest.raises(ValueError, match="noncontiguous"):
        extract_transitions(e, [], [{"time_s": 1}], config, **kwargs)
