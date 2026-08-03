from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import math

import numpy as np

from .certification import certify_profile, cryptographic_utilization, envelope_bytes
from .params import LatticeParams, Profile


class State(IntEnum):
    NORMAL = 0
    CONGESTED = 1
    ROUTE_REPAIR = 2
    GLOBAL_DODAG_REPAIR = 3
    SEVERE_LOSS = 4


ADJACENCY: dict[State, tuple[State, ...]] = {
    State.NORMAL: (State.NORMAL, State.CONGESTED, State.ROUTE_REPAIR),
    State.CONGESTED: (State.NORMAL, State.CONGESTED, State.SEVERE_LOSS),
    State.ROUTE_REPAIR: (State.NORMAL, State.ROUTE_REPAIR, State.GLOBAL_DODAG_REPAIR),
    State.GLOBAL_DODAG_REPAIR: (
        State.NORMAL,
        State.ROUTE_REPAIR,
        State.GLOBAL_DODAG_REPAIR,
    ),
    State.SEVERE_LOSS: (State.NORMAL, State.CONGESTED, State.SEVERE_LOSS),
}


@dataclass(frozen=True)
class Action:
    profile: Profile
    batch_size: int
    mac_backoff: int
    route_intensity: int

    def normalized(self) -> np.ndarray:
        return np.array(
            [
                self.profile.retention,
                self.batch_size / self.profile.n_policy,
                self.profile.block_size / 1_024.0,
                self.mac_backoff / 4.0,
                self.route_intensity / 4.0,
                self.profile.sigma_enc / 3.6,
            ],
            dtype=np.float64,
        )


@dataclass
class BoundedSoftmaxModel:
    epsilon0: float = 0.01

    def __post_init__(self) -> None:
        max_degree = max(len(edges) for edges in ADJACENCY.values())
        if not (0.0 < self.epsilon0 < 1.0 / max_degree):
            raise ValueError("epsilon0 violates the active-edge probability bound")

    def matrix(self, action: Action, feedback: np.ndarray) -> np.ndarray:
        feedback = np.asarray(feedback, dtype=np.float64)
        if feedback.shape != (3,):
            raise ValueError("feedback must be [queue, loss, previous utilization]")
        queue, loss, previous_eta = feedback
        normalized = action.normalized()
        retention, batch_load, _, backoff, route, noise = normalized
        matrix = np.zeros((5, 5), dtype=np.float64)

        for source, targets in ADJACENCY.items():
            logits: list[float] = []
            for target in targets:
                score = 0.4 if target == source else 0.0
                if target == State.NORMAL:
                    score += 1.2 * route + 0.4 * backoff - queue - 1.4 * loss
                elif target == State.CONGESTED:
                    score += 1.8 * queue + 0.6 * batch_load - 0.5 * backoff
                elif target == State.ROUTE_REPAIR:
                    score += 1.0 * loss + 0.9 * route + 0.3 * previous_eta
                elif target == State.GLOBAL_DODAG_REPAIR:
                    score += 1.6 * loss + 0.5 * route
                elif target == State.SEVERE_LOSS:
                    score += 2.5 * loss + 0.5 * batch_load - 0.6 * route
                score += 0.05 * noise - 0.05 * retention
                logits.append(score)
            logits_array = np.asarray(logits, dtype=np.float64)
            logits_array -= np.max(logits_array)
            softmax = np.exp(logits_array)
            softmax /= np.sum(softmax)
            degree = len(targets)
            probabilities = self.epsilon0 + (1.0 - degree * self.epsilon0) * softmax
            for target, probability in zip(targets, probabilities, strict=True):
                matrix[int(source), int(target)] = probability
        return matrix


def candidate_actions(
    profiles: tuple[Profile, ...], params: LatticeParams
) -> list[Action]:
    actions: list[Action] = []
    for profile in profiles:
        report = certify_profile(profile, params)
        if not report.accepted:
            continue
        for batch_size in sorted({1, report.n_effective}):
            for backoff in (0, 2, 4):
                for route in (0, 2, 4):
                    actions.append(Action(profile, batch_size, backoff, route))
    return actions


@dataclass
class Controller:
    params: LatticeParams
    model: BoundedSoftmaxModel
    weight_energy: float = 0.15
    weight_latency: float = 0.35
    weight_distortion: float = 0.20
    weight_safety: float = 0.20
    weight_congestion: float = 0.50

    def objective(
        self,
        distribution: np.ndarray,
        feedback: np.ndarray,
        action: Action,
    ) -> float:
        profile = action.profile
        bytes_per_node = envelope_bytes(profile, self.params)
        energy = action.batch_size * bytes_per_node / 100_000.0
        latency = (
            8.0 * action.batch_size * bytes_per_node / profile.r_min_bps
            + 0.01 * action.mac_backoff
            + 0.02 * action.route_intensity
        )
        distortion = (1.0 - profile.retention) + profile.quant_step / 256.0
        safety = cryptographic_utilization(
            action.batch_size, profile.sigma_enc, self.params
        )
        transition = self.model.matrix(action, feedback)
        next_distribution = np.asarray(distribution, dtype=np.float64) @ transition
        congestion_penalty = np.array([0.0, 1.0, 0.6, 0.9, 2.0])
        expected_congestion = float(next_distribution @ congestion_penalty)
        return (
            self.weight_energy * energy
            + self.weight_latency * latency
            + self.weight_distortion * distortion
            + self.weight_safety * safety
            + self.weight_congestion * expected_congestion
        )

    def choose(
        self,
        distribution: np.ndarray,
        feedback: np.ndarray,
        actions: list[Action],
    ) -> tuple[Action, float, np.ndarray]:
        if not actions:
            raise ValueError("no certified actions")
        scored = [
            (self.objective(distribution, feedback, action), action)
            for action in actions
        ]
        score, selected = min(scored, key=lambda pair: pair[0])
        transition = self.model.matrix(selected, feedback)
        next_distribution = np.asarray(distribution, dtype=np.float64) @ transition
        return selected, score, next_distribution


def scrambling_horizon() -> int:
    adjacency = np.zeros((5, 5), dtype=bool)
    for source, targets in ADJACENCY.items():
        for target in targets:
            adjacency[int(source), int(target)] = True
    power = adjacency.copy()
    for horizon in range(1, 51):
        if np.all(power):
            return horizon
        power = (power.astype(np.int64) @ adjacency.astype(np.int64)) > 0
    raise RuntimeError("the fixed transition graph is not primitive")


def weak_ergodicity_constants(epsilon0: float) -> dict[str, float | int]:
    horizon = scrambling_horizon()
    epsilon_min = epsilon0**horizon
    gamma = 1.0 - 5.0 * epsilon_min
    if not (0.0 < gamma < 1.0):
        raise ValueError("invalid Dobrushin contraction constant")
    rho = gamma ** (1.0 / horizon)
    return {
        "h_mix": horizon,
        "epsilon_min": epsilon_min,
        "gamma": gamma,
        "rho": rho,
        "C": 1.0 / gamma,
    }

