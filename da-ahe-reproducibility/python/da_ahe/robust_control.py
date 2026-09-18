"""Robust five-regime controller matching Eqs. (2), (3), and (19).

All cryptographic profiles are certified offline.  The online objective uses
decryption-noise utilization; it never treats the fixed 128.1-bit estimator
result as a tunable action reward.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .certification import certify_profile, cryptographic_utilization
from .params import LatticeParams, Profile


REGIME_NAMES = (
    "normal",
    "congestion",
    "local-route-repair",
    "global-dodag-repair",
    "severe-loss",
)


def safety_state(
    delay: float,
    delay_threshold: float,
    packet_loss: float,
    loss_threshold: float,
    certified_noise: float,
    tau_dec: float,
    zeta: float,
) -> np.ndarray:
    if min(delay_threshold, loss_threshold, tau_dec - zeta) <= 0:
        raise ValueError("invalid safety-state denominator")
    return np.maximum(
        np.array(
            [
                (delay - delay_threshold) / delay_threshold,
                (packet_loss - loss_threshold) / loss_threshold,
                (certified_noise - tau_dec + zeta) / (tau_dec - zeta),
            ],
            dtype=float,
        ),
        0.0,
    )


def gaussian_emission(observation: np.ndarray, mean: np.ndarray, std: np.ndarray) -> float:
    residual = (np.asarray(observation, dtype=float) - mean) / std
    return float(np.exp(-0.5 * residual @ residual) / np.prod(std))


def belief_update(
    belief: np.ndarray,
    transition: np.ndarray,
    observation: np.ndarray,
    emission_means: np.ndarray,
    emission_std: np.ndarray,
) -> np.ndarray:
    prediction = np.asarray(belief, dtype=float) @ np.asarray(transition, dtype=float)
    likelihood = np.array(
        [gaussian_emission(observation, mean, emission_std) for mean in emission_means]
    )
    posterior = prediction * likelihood
    normalizer = float(np.sum(posterior))
    if normalizer <= 0 or not np.isfinite(normalizer):
        raise FloatingPointError("belief update has zero likelihood")
    return posterior / normalizer


def worst_case_l1_expectation(
    nominal: np.ndarray, values: np.ndarray, epsilon: float
) -> tuple[float, np.ndarray]:
    """Solve max pi^T values, ||pi-nominal||_1<=epsilon, pi in simplex."""

    probability = np.asarray(nominal, dtype=float).copy()
    probability = np.maximum(probability, 0.0)
    probability /= probability.sum()
    values = np.asarray(values, dtype=float)
    budget = min(max(float(epsilon), 0.0), 2.0) / 2.0
    low = list(np.argsort(values))
    high = list(np.argsort(-values))
    i = j = 0
    while budget > 1e-15 and i < len(low) and j < len(high):
        donor, receiver = low[i], high[j]
        if values[receiver] <= values[donor] + 1e-15:
            break
        if donor == receiver:
            j += 1
            continue
        moved = min(probability[donor], 1.0 - probability[receiver], budget)
        if moved <= 1e-15:
            i += probability[donor] <= 1e-15
            j += 1.0 - probability[receiver] <= 1e-15
            continue
        probability[donor] -= moved
        probability[receiver] += moved
        budget -= moved
        if probability[donor] <= 1e-15:
            i += 1
        if 1.0 - probability[receiver] <= 1e-15:
            j += 1
    return float(probability @ values), probability


@dataclass(frozen=True)
class RobustAction:
    name: str
    profile: Profile
    batch_size: int
    sampling_ratio: float
    route_repair: float
    transition: np.ndarray
    mitigation: np.ndarray
    prediction_error: np.ndarray
    regime_cost: np.ndarray

    def __post_init__(self) -> None:
        if self.transition.shape != (5, 5):
            raise ValueError("transition must be 5x5")
        if not np.allclose(self.transition.sum(axis=1), 1.0):
            raise ValueError("transition rows must sum to one")
        if self.mitigation.shape != (3,) or self.prediction_error.shape != (5,):
            raise ValueError("invalid robust-action calibration shape")
        if self.regime_cost.shape != (5,):
            raise ValueError("regime cost must have five entries")

    def vector(self) -> np.ndarray:
        return np.array(
            [
                self.sampling_ratio,
                self.profile.quant_step / 16.0,
                self.batch_size / 16.0,
                self.profile.block_size / 64.0,
                self.route_repair,
                self.profile.profile_id / 2.0,
            ]
        )


@dataclass
class RobustMarkovController:
    params: LatticeParams
    p_v: np.ndarray
    gamma: float
    beta: float
    epsilon_transition: float
    kappa_z: float
    disturbances: np.ndarray
    fallback_name: str
    weight_noise: float = 0.20
    weight_switch: float = 0.05

    def __post_init__(self) -> None:
        if self.p_v.shape != (3, 3) or np.min(np.linalg.eigvalsh(self.p_v)) <= 0:
            raise ValueError("P_V must be positive definite")
        if self.disturbances.shape != (5, 3):
            raise ValueError("disturbances must have shape (5,3)")
        if not (0 < self.gamma < 1) or self.beta < 0:
            raise ValueError("invalid drift parameters")

    def robust_bound(
        self, z: np.ndarray, belief: np.ndarray, action: RobustAction
    ) -> tuple[float, np.ndarray]:
        predictions = np.maximum(
            self.kappa_z * np.asarray(z)[None, :]
            + self.disturbances
            - action.mitigation[None, :],
            0.0,
        )
        lambda_max = float(np.max(np.linalg.eigvalsh(self.p_v)))
        psi = np.empty(5)
        for regime in range(5):
            z_hat = predictions[regime]
            e_bar = action.prediction_error[regime]
            psi[regime] = (
                z_hat @ self.p_v @ z_hat
                + 2.0 * lambda_max * np.linalg.norm(z_hat) * e_bar
                + lambda_max * e_bar**2
            )
        nominal = np.asarray(belief) @ action.transition
        return worst_case_l1_expectation(nominal, psi, self.epsilon_transition)

    def drift_feasible(self, z: np.ndarray, belief: np.ndarray, action: RobustAction) -> bool:
        report = certify_profile(action.profile, self.params)
        if not report.accepted or action.batch_size > report.n_effective:
            return False
        robust_value, _ = self.robust_bound(z, belief, action)
        current = float(np.asarray(z) @ self.p_v @ np.asarray(z))
        return robust_value <= (1.0 - self.gamma) * current + self.beta

    def objective(
        self,
        belief: np.ndarray,
        action: RobustAction,
        previous: RobustAction,
    ) -> float:
        predicted = np.asarray(belief) @ action.transition
        operational = float(predicted @ action.regime_cost)
        eta = cryptographic_utilization(
            action.batch_size, action.profile.sigma_enc, self.params
        )
        switch = float(np.sum((action.vector() - previous.vector()) ** 2))
        return operational + self.weight_noise * eta + self.weight_switch * switch

    def select(
        self,
        z: np.ndarray,
        belief: np.ndarray,
        actions: Sequence[RobustAction],
        previous: RobustAction,
    ) -> RobustAction:
        feasible = [a for a in actions if self.drift_feasible(z, belief, a)]
        if feasible:
            return min(feasible, key=lambda a: self.objective(belief, a, previous))
        for action in actions:
            if action.name == self.fallback_name:
                return action
        raise ValueError("offline-certified fallback action is missing")
