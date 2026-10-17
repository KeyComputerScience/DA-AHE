"""Existing controller equations, explicitly synthetic model and certificates.

No new heuristic is mislabeled as an exact paper controller. The controller
implementation is reused with the selected reference or calibrated empirical
configuration. Network performance and model-relative checks have separate scopes.
"""
from __future__ import annotations

from dataclasses import asdict

from daahe.control import (ControlledHMM, DPPController, HysteresisController,
                           RobustController, StressTracker)
from daahe.replay import load_control_config
from daahe.safety import violation_state


class Policy:
    def __init__(self, config_path, method):
        self.data = d = load_control_config(config_path, allow_synthetic=True)
        self.method = method
        self.base = method if method in {"dpp", "hys"} else "da-ahe"
        self.actions = {a.id: a for a in d["actions"]}
        self.current = self.actions[d["initial_action"][self.base]]
        args = (d["model"], d["actions"], d["certificates"], d["fallback_id"], d["params"])
        self.hmm = ControlledHMM(d["model"], adapt=False) if self.base == "da-ahe" else None
        self.controller = (RobustController(*args, hmm=self.hmm) if self.base == "da-ahe" else
                           DPPController(*args, v_dpp=d["v_dpp"]) if self.base == "dpp" else
                           HysteresisController(*args, **d["hysteresis"]))
        self.tracker = StressTracker(d["stress_thresholds"], smoothing=d["stress_smoothing"],
                                     boundaries=d["stress_boundaries"])
        self.previous_bin = 0
        self.previous_applied = self.current
        self.observations = 0

    def choose(self, telemetry, initial=False):
        d, params = self.data, self.data["params"]
        state = violation_state(telemetry[2], telemetry[1], telemetry[6],
                                delay_threshold=params.delay_threshold,
                                loss_threshold=d["loss_threshold"], decoding_margin=1.0)
        stress, stress_bin = self.tracker.update(telemetry)
        belief = None
        if initial or self.method == "without_markov":
            decision = {"action": asdict(self.current) if self.current else None,
                        "alarm": False, "certified": False,
                        "reason": "configured initial action" if initial else
                                  "fixed nominal ablation; no filtering or Markov selection", "scores": []}
        else:
            if self.hmm is not None:
                belief = self.hmm.update(telemetry, self.previous_applied.id,
                                         stress_bin=self.previous_bin)
                selected = self.controller.select(state, belief, self.previous_applied,
                                                  d["runtime"], stress_bin=stress_bin)
            elif self.base == "dpp":
                self.controller.observe((telemetry[2] / params.delay_threshold - 1,
                                         telemetry[1] / d["loss_threshold"] - 1, telemetry[6] - 1))
                features = (1.0,) + state
                estimates = {a.id: tuple(sum(w * x for w, x in zip(row, features)) for row in
                                         d["dpp_violation_models"][a.id]) for a in d["actions"]}
                selected = self.controller.select(state, None, self.previous_applied,
                                                  d["runtime"], violation_estimates=estimates)
            else:
                selected = self.controller.select(state, None, self.previous_applied,
                                                  d["runtime"], stress=stress)
            self.current = selected.action
            decision = asdict(selected)
        if self.current is not None:
            self.previous_applied = self.current
        self.previous_bin = stress_bin
        self.observations += 1
        return {"telemetry": list(telemetry), "state": list(state), "belief": belief,
                "stress": stress, "stress_bin": stress_bin, "decision": decision,
                "model_status": "synthetic_unvalidated", "certified": False}
