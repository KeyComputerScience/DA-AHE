# SPDX-License-Identifier: MIT
"""Causal controller decision replay over externally recorded telemetry.

This is neither a network simulator nor an estimate of counterfactual outcomes:
changing a decision does not change the input trace. Never use replayed traces
to claim that one controller caused lower loss, energy, or recovery time.
"""

from __future__ import annotations

from dataclasses import asdict
import csv
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from .control import (ControlModel, ControlledHMM, ControllerParams, DPPController,
                      HysteresisController, RobustController, StressTracker)
from .safety import Action, Certificate, RuntimeContext, violation_state

TELEMETRY_COLUMNS = ("time_s", "queue", "loss", "delay", "ber", "anomaly", "tamper",
                     "noise_utilization")


def load_control_config(path: str | Path, *, allow_synthetic: bool = False) -> dict[str, Any]:
    config_path = Path(path)
    data = json.loads(config_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("unsupported control configuration schema")
    actions = tuple(Action.from_dict(value) for value in data["actions"])
    initial_actions = data.get("initial_action")
    action_ids = {action.id for action in actions}
    if (not isinstance(initial_actions, dict) or set(initial_actions) != {"da-ahe", "dpp", "hys"}
            or any(not isinstance(value, str) or value not in action_ids
                   for value in initial_actions.values())):
        raise ValueError("initial_action must explicitly map da-ahe, dpp and hys to library action IDs")
    if "initialization_policy" in data:
        if data["initialization_policy"] != "common_nominal_synthetic":
            raise ValueError("unsupported initialization_policy")
        if (not allow_synthetic or set(initial_actions.values()) != {"nominal"}
                or data["hysteresis"]["mode_actions"]["N"] != "nominal"):
            raise ValueError("common_nominal_synthetic requires allow_synthetic and nominal initialization for all three methods and HYS N mode")
    elif initial_actions["dpp"] != data["fallback_id"]:
        raise ValueError("Algorithm 4 requires the fallback as DPP's initial action")
    if initial_actions["hys"] != data["hysteresis"]["mode_actions"]["N"]:
        raise ValueError("Algorithm 5 requires the N-mode action as HYS's initial action")
    certificates = {key: Certificate.from_dict(value) for key, value in data["certificates"].items()}
    model = ControlModel.from_dict(data["model"])
    params = ControllerParams(**data.get("parameters", {}))
    runtime_data = dict(data["runtime"])
    # Strict is the CLI default even if a fixture tries to request otherwise.
    runtime_data["strict"] = not allow_synthetic
    if runtime_data.get("evidence_root"):
        runtime_data["evidence_root"] = str((config_path.parent / runtime_data["evidence_root"]).resolve())
    runtime = RuntimeContext(**runtime_data)
    if model.metadata.get("action_digests"):
        expected = model.metadata["action_digests"]
        if expected != {action.id: action.digest() for action in actions}:
            raise ValueError("calibrated model does not bind the configured complete action library")
    data.update(actions=actions, certificates=certificates, model=model,
                params=params, runtime=runtime)
    return data


def replay_csv(config_path: str | Path, telemetry_path: str | Path, *,
               method: str = "da-ahe", allow_synthetic: bool = False) -> dict[str, Any]:
    """Return decision audit JSON. Fail-closed rows have action=None and stop replay.

    CSV requires TELEMETRY_COLUMNS. Telemetry y_t updates the belief/virtual
    queues using a_{t-1}; then a_t is selected. No next-state columns, hidden
    regime labels, or data after the current row are read by a decision rule.
    DPP's signed g-hat regressions are explicit offline coefficients; actual
    virtual queue increments use the realized normalized current excesses.
    """
    data = load_control_config(config_path, allow_synthetic=allow_synthetic)
    model, actions, certs = data["model"], data["actions"], data["certificates"]
    runtime, params = data["runtime"], data["params"]
    controller_args = (model, actions, certs, data["fallback_id"], params)
    if method == "da-ahe":
        hmm = ControlledHMM(model, adapt=bool(data.get("online_adaptation", False)))
        controller = RobustController(*controller_args, hmm=hmm)
    elif method == "dpp":
        hmm = None
        controller = DPPController(*controller_args, v_dpp=float(data.get("v_dpp", 1.0)))
    elif method == "hys":
        hmm = None
        controller = HysteresisController(*controller_args, **data["hysteresis"])
    else:
        raise ValueError("method must be da-ahe, dpp, or hys")
    loss_threshold = float(data["loss_threshold"])
    tracker = StressTracker(data["stress_thresholds"],
                            smoothing=float(data.get("stress_smoothing", 0.80)),
                            boundaries=data.get("stress_boundaries", (0.2, 0.4, 0.6, 0.8)))
    action_lookup = {action.id: action for action in actions}
    previous_action = action_lookup[data["initial_action"][method]]
    previous_time = None
    # P(a,b_{t-1}) generated the prior for y_t; do not replace it with b_t.
    previous_bin = 0
    decisions = []
    with Path(telemetry_path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = set(TELEMETRY_COLUMNS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError("telemetry CSV missing columns: " + ", ".join(sorted(missing)))
        forbidden = {"regime", "next_regime", "next_z_delay", "next_z_loss", "next_z_noise",
                     "next_delay", "next_loss", "next_noise_utilization"}
        if forbidden & set(reader.fieldnames or ()):
            raise ValueError("online telemetry must exclude offline labels and future-state columns")
        for line, row in enumerate(reader, 2):
            try:
                time = float(row["time_s"])
                telemetry = tuple(float(row[key]) for key in TELEMETRY_COLUMNS[1:])
                if not math.isfinite(time) or time < 0 or any(
                        not math.isfinite(v) or v < 0 for v in telemetry):
                    raise ValueError("time and telemetry must be finite and nonnegative")
                if previous_time is not None and time <= previous_time:
                    raise ValueError("telemetry timestamps must strictly increase")
                if any(telemetry[h] > 1 for h in (0, 1, 3)) or telemetry[5] not in (0, 1):
                    raise ValueError("queue/loss/BER are fractions and tamper is binary")
                state = violation_state(telemetry[2], telemetry[1], telemetry[6],
                                        delay_threshold=params.delay_threshold,
                                        loss_threshold=loss_threshold, decoding_margin=1.0)
                stress, stress_bin = tracker.update(telemetry)
                if hmm is not None:
                    # Algorithm 6 fixes mu_0 and filters only from t>0. The
                    # configured a_-1 still determines the t=0 switching cost.
                    belief = (hmm.belief if previous_time is None else
                              hmm.update(telemetry, previous_action.id, stress_bin=previous_bin))
                    decision = controller.select(state, belief, previous_action, runtime, stress_bin=stress_bin)
                elif method == "dpp":
                    belief = None
                    if previous_time is not None:
                        controller.observe((telemetry[2] / params.delay_threshold - 1,
                                            telemetry[1] / loss_threshold - 1, telemetry[6] - 1))
                    features = (1.0,) + state
                    estimates = {}
                    for action in actions:
                        weights = data["dpp_violation_models"][action.id]
                        if len(weights) != 3 or any(len(row_weights) != 4 for row_weights in weights):
                            raise ValueError("DPP violation model must have three four-coefficient rows")
                        estimates[action.id] = tuple(sum(float(w) * x for w, x in zip(row_weights, features))
                                                     for row_weights in weights)
                    decision = controller.select(state, None, previous_action, runtime,
                                                 violation_estimates=estimates)
                else:
                    belief = None
                    decision = controller.select(state, None, previous_action, runtime, stress=stress)
                decisions.append({"time_s": time, "telemetry": telemetry, "state": state,
                                  "belief": belief, "stress": stress, "stress_bin": stress_bin,
                                  "decision": asdict(decision)})
                previous_time = time
                if decision.action is None:
                    break
                previous_action, previous_bin = decision.action, stress_bin
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"{telemetry_path}:{line}: {exc}") from exc
    if not decisions:
        raise ValueError("telemetry CSV contains no observations")
    return {
        "status": "decision_replay_only_no_counterfactual_performance_claim",
        "method": method, "strict": runtime.strict,
        "synthetic_allowed": allow_synthetic,
        "model_digest": model.digest(),
        "initial_action_id": data["initial_action"][method],
        "config_sha256": hashlib.sha256(Path(config_path).read_bytes()).hexdigest(),
        "telemetry_sha256": hashlib.sha256(Path(telemetry_path).read_bytes()).hexdigest(),
        "decisions": decisions,
        "completed_without_fail_closed": all(row["decision"]["action"] is not None for row in decisions),
        "all_decisions_certified": all(row["decision"]["certified"] for row in decisions),
        "limitations": [
            "Fixed telemetry replay cannot establish closed-loop performance or reproduce packet-level results.",
            "Empirical uncertainty radii are not uniform bounds or a domain-invariance certificate.",
            "External evidence hashes establish provenance; the reviewer must assess their substantive claims.",
        ],
    }
