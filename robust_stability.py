#!/usr/bin/env python3
"""DA-AHE robust closed-loop stability verifier.

This script is a runnable reference implementation of the revised stability
argument for DA-AHE.  It implements:

1. Five-state HMM belief filtering with action-conditioned Markov kernels.
2. State-conditioned one-step safety-state prediction.
3. An exact worst-case expectation over an L1 transition ambiguity set.
4. Robust Lyapunov screening with bounded prediction residuals.
5. Offline certification of the fallback action on a continuous box using a
   grid certificate plus a conservative Lipschitz covering margin.
6. Monte Carlo validation against the exponential mean-square bound.

The numerical plant below is an executable validation model, not a substitute
for the OMNeT++ data used in the paper.  Replace REGIME_INPUTS, transition
kernels, residual radii, and action cost models with values calibrated from the
paper's disjoint calibration traces before reporting experimental results.

Usage:
    python da_ahe_robust_stability.py
    python da_ahe_robust_stability.py --steps 120 --runs 300 --seed 2026
    python da_ahe_robust_stability.py --no-plots --output-dir results

Dependencies:
    numpy
    matplotlib  (only required when plots are enabled)
"""

from __future__ import annotations

import argparse
import csv
import heapq
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np


REGIME_NAMES: Tuple[str, ...] = (
    "Normal",
    "Congested",
    "Local repair",
    "Global repair",
    "Severe loss",
)

# State-conditioned additive inputs in the normalized safety-state model.
# Components correspond to delay, residual packet loss, and decryption noise.
REGIME_INPUTS = np.array(
    [
        [0.00, 0.00, 0.00],
        [0.16, 0.10, 0.08],
        [0.12, 0.08, 0.05],
        [0.25, 0.18, 0.12],
        [0.38, 0.30, 0.20],
    ],
    dtype=float,
)

# Seven normalized observation features:
# queue, packet loss, delay, BER, entropy anomaly, tampering, noise use.
OBSERVATION_MEANS = np.array(
    [
        [0.15, 0.01, 0.20, 0.02, 0.10, 0.00, 0.30],
        [0.75, 0.08, 0.75, 0.05, 0.40, 0.05, 0.55],
        [0.55, 0.05, 0.60, 0.04, 0.35, 0.05, 0.45],
        [0.80, 0.10, 0.85, 0.08, 0.60, 0.10, 0.65],
        [0.95, 0.16, 0.95, 0.12, 0.80, 0.15, 0.85],
    ],
    dtype=float,
)
OBSERVATION_STD = np.array([0.09, 0.018, 0.09, 0.015, 0.10, 0.025, 0.08])


@dataclass(frozen=True)
class Action:
    """One offline-certified DA-AHE control profile."""

    name: str
    rho: float
    delta_q: int
    batch_size: int
    block_size: int
    repair_intensity: float
    profile: int
    energy_scale: float
    delay_scale: float
    distortion: float
    relief: Tuple[float, float, float]
    base_model_error: float


@dataclass(frozen=True)
class ControllerParameters:
    alpha: float
    beta: float
    epsilon_transition: float
    contraction: float
    p_v: Tuple[Tuple[float, float, float], ...]
    z_max: float
    weights: Tuple[float, float, float, float, float]

    @property
    def p_matrix(self) -> np.ndarray:
        return np.asarray(self.p_v, dtype=float)


@dataclass
class ActionDiagnostic:
    index: int
    robust_v: float
    nominal_v: float
    drift_limit: float
    cost: float
    feasible: bool
    worst_distribution: np.ndarray


@dataclass
class SimulationResult:
    z: np.ndarray
    regimes: np.ndarray
    actions: np.ndarray
    beliefs: np.ndarray
    robust_v: np.ndarray
    nominal_v: np.ndarray
    drift_limit: np.ndarray
    empty_set_count: int


def build_actions() -> List[Action]:
    """Return the finite action set used by the reference experiment."""

    return [
        Action(
            "Nominal", 1.00, 16, 16, 64, 0.00, 0,
            0.80, 1.00, 0.02, (0.04, 0.03, 0.04), 0.030,
        ),
        Action(
            "Conservative", 0.75, 16, 14, 64, 0.45, 1,
            1.00, 0.82, 0.09, (0.10, 0.10, 0.14), 0.026,
        ),
        Action(
            "Recovery", 0.50, 16, 12, 32, 1.00, 2,
            1.25, 0.65, 0.20, (0.18, 0.20, 0.22), 0.022,
        ),
        Action(
            "Fallback", 0.50, 16, 1, 64, 0.00, 0,
            1.50, 0.58, 0.35, (0.26, 0.25, 0.30), 0.018,
        ),
    ]


def _row_stochastic(matrix: Sequence[Sequence[float]]) -> np.ndarray:
    p = np.asarray(matrix, dtype=float)
    if p.shape != (5, 5):
        raise ValueError(f"Expected a 5x5 transition matrix, got {p.shape}")
    if np.any(p < 0.0):
        raise ValueError("Transition probabilities must be nonnegative")
    row_sums = p.sum(axis=1)
    if not np.allclose(row_sums, 1.0, atol=1e-12):
        raise ValueError(f"Transition rows do not sum to one: {row_sums}")
    return p


def build_transition_kernels(actions: Sequence[Action]) -> Dict[str, np.ndarray]:
    """Construct action-conditioned five-state transition kernels."""

    matrices = {
        "Nominal": [
            [0.900, 0.080, 0.010, 0.005, 0.005],
            [0.180, 0.500, 0.180, 0.090, 0.050],
            [0.300, 0.150, 0.400, 0.100, 0.050],
            [0.150, 0.150, 0.150, 0.400, 0.150],
            [0.080, 0.120, 0.100, 0.250, 0.450],
        ],
        "Conservative": [
            [0.930, 0.060, 0.008, 0.002, 0.000],
            [0.280, 0.450, 0.180, 0.070, 0.020],
            [0.450, 0.140, 0.320, 0.070, 0.020],
            [0.260, 0.160, 0.180, 0.330, 0.070],
            [0.150, 0.180, 0.130, 0.260, 0.280],
        ],
        "Recovery": [
            [0.950, 0.040, 0.010, 0.000, 0.000],
            [0.350, 0.380, 0.180, 0.070, 0.020],
            [0.550, 0.120, 0.250, 0.070, 0.010],
            [0.350, 0.150, 0.200, 0.250, 0.050],
            [0.200, 0.200, 0.150, 0.250, 0.200],
        ],
        "Fallback": [
            [0.960, 0.035, 0.005, 0.000, 0.000],
            [0.450, 0.380, 0.120, 0.040, 0.010],
            [0.650, 0.100, 0.200, 0.040, 0.010],
            [0.450, 0.150, 0.150, 0.220, 0.030],
            [0.280, 0.220, 0.150, 0.200, 0.150],
        ],
    }
    action_names = {action.name for action in actions}
    if action_names != set(matrices):
        raise ValueError("Transition kernels and action names are inconsistent")
    return {name: _row_stochastic(matrix) for name, matrix in matrices.items()}


def lyapunov(z: np.ndarray, p_v: np.ndarray) -> float:
    return float(z @ p_v @ z)


def model_error_radius(action: Action, regime: int) -> float:
    """Certified state-prediction residual radius for one state-action pair."""

    return action.base_model_error * (1.0 + 0.20 * regime)


def predict_next_z(
    z: np.ndarray,
    action: Action,
    regime: int,
    contraction: float,
) -> np.ndarray:
    relief = np.asarray(action.relief, dtype=float)
    return np.maximum(0.0, contraction * z + REGIME_INPUTS[regime] - relief)


def regime_lyapunov_upper_values(
    z: np.ndarray,
    action: Action,
    p_v: np.ndarray,
    contraction: float,
) -> Tuple[np.ndarray, np.ndarray]:
    """Return Psi_j and predicted z_j for all five next regimes."""

    lambda_max = float(np.linalg.eigvalsh(p_v).max())
    predicted = np.vstack(
        [predict_next_z(z, action, j, contraction) for j in range(5)]
    )
    psi = np.empty(5, dtype=float)
    for j in range(5):
        e_bar = model_error_radius(action, j)
        z_hat = predicted[j]
        psi[j] = (
            lyapunov(z_hat, p_v)
            + 2.0 * lambda_max * np.linalg.norm(z_hat) * e_bar
            + lambda_max * e_bar * e_bar
        )
    return psi, predicted


def worst_case_l1_expectation(
    nominal: np.ndarray,
    values: np.ndarray,
    epsilon: float,
) -> Tuple[float, np.ndarray]:
    """Maximize q^T values over the simplex with ||q-nominal||_1 <= epsilon.

    Moving probability mass m changes the L1 distance by 2m.  The exact
    optimizer therefore transfers at most epsilon/2 mass from the lowest-value
    states to the highest-value states.
    """

    p = np.asarray(nominal, dtype=float).copy()
    v = np.asarray(values, dtype=float)
    if p.ndim != 1 or v.shape != p.shape:
        raise ValueError("nominal and values must be one-dimensional and aligned")
    if np.any(p < -1e-12):
        raise ValueError("nominal distribution contains a negative entry")
    total = float(p.sum())
    if total <= 0.0:
        raise ValueError("nominal distribution has zero mass")
    p = np.clip(p / total, 0.0, 1.0)
    p /= p.sum()

    remaining = min(max(float(epsilon), 0.0), 2.0) / 2.0
    donors = list(np.argsort(v))
    receivers = list(np.argsort(-v))
    donor_pos = 0
    receiver_pos = 0

    while remaining > 1e-15 and donor_pos < len(p) and receiver_pos < len(p):
        donor = donors[donor_pos]
        receiver = receivers[receiver_pos]

        if v[receiver] <= v[donor] + 1e-15:
            break
        if donor == receiver:
            if p[donor] <= 1e-15:
                donor_pos += 1
            else:
                receiver_pos += 1
            continue

        transferable = min(p[donor], 1.0 - p[receiver], remaining)
        if transferable <= 1e-15:
            if p[donor] <= 1e-15:
                donor_pos += 1
            if 1.0 - p[receiver] <= 1e-15:
                receiver_pos += 1
            continue

        p[donor] -= transferable
        p[receiver] += transferable
        remaining -= transferable

        if p[donor] <= 1e-15:
            donor_pos += 1
        if 1.0 - p[receiver] <= 1e-15:
            receiver_pos += 1

    p = np.clip(p, 0.0, 1.0)
    p /= p.sum()
    return float(p @ v), p


def robust_lyapunov_bound(
    z: np.ndarray,
    belief: np.ndarray,
    action: Action,
    transition: np.ndarray,
    parameters: ControllerParameters,
) -> Tuple[float, float, np.ndarray, np.ndarray]:
    """Compute nominal and ambiguity-aware one-step Lyapunov predictions."""

    nominal_distribution = np.asarray(belief, dtype=float) @ transition
    psi, predicted = regime_lyapunov_upper_values(
        z, action, parameters.p_matrix, parameters.contraction
    )
    nominal_value = float(nominal_distribution @ psi)
    robust_value, worst_distribution = worst_case_l1_expectation(
        nominal_distribution, psi, parameters.epsilon_transition
    )
    return robust_value, nominal_value, worst_distribution, predicted


def action_distance(a: Action, b: Action) -> float:
    """Normalized squared switching distance used in J_t."""

    va = np.array(
        [a.rho, a.delta_q / 16.0, a.batch_size / 16.0,
         a.block_size / 64.0, a.repair_intensity, a.profile / 2.0]
    )
    vb = np.array(
        [b.rho, b.delta_q / 16.0, b.batch_size / 16.0,
         b.block_size / 64.0, b.repair_intensity, b.profile / 2.0]
    )
    weights = np.array([1.0, 0.2, 1.0, 0.3, 1.2, 0.6])
    # Normalize by total weight so w_switch retains the interpretation of a
    # bounded objective weight instead of permanently locking a costly action.
    return float(np.sum(weights * (va - vb) ** 2) / (2.0 * weights.sum()))


def resource_feasible(action: Action) -> bool:
    profile_capacity = {0: 16, 1: 14, 2: 12}
    return (
        action.batch_size <= profile_capacity[action.profile]
        and action.block_size in (32, 64)
        and 0.0 < action.rho <= 1.0
    )


def operational_cost(
    action: Action,
    previous_action: Action,
    predicted_distribution: np.ndarray,
    weights: Tuple[float, float, float, float, float],
) -> float:
    """Reference implementation of the normalized objective J_t."""

    w_energy, w_latency, w_distortion, w_security, w_switch = weights
    regime_energy = np.array([1.00, 1.15, 1.20, 1.35, 1.55])
    regime_delay = np.array([0.75, 1.20, 1.10, 1.45, 1.90])

    expected_energy = float(predicted_distribution @ regime_energy) * action.energy_scale
    expected_delay = float(predicted_distribution @ regime_delay) * action.delay_scale

    lambda_est = 128.1
    epsilon_batch = {0: 2.0 ** -140, 1: 2.0 ** -136, 2: 2.0 ** -132}
    risk_reference = 2.0 ** -128
    security_proxy = (
        2.0 ** (-lambda_est) + epsilon_batch[action.profile]
    ) / risk_reference

    return (
        w_energy * expected_energy
        + w_latency * expected_delay
        + w_distortion * action.distortion
        + w_security * security_proxy
        + w_switch * action_distance(action, previous_action)
    )


def select_action(
    z: np.ndarray,
    belief: np.ndarray,
    previous_index: int,
    actions: Sequence[Action],
    kernels: Dict[str, np.ndarray],
    parameters: ControllerParameters,
) -> Tuple[int, List[ActionDiagnostic]]:
    """Enumerate A_stab and minimize J_t over the robustly feasible actions."""

    drift_limit = (1.0 - parameters.alpha) * lyapunov(z, parameters.p_matrix) + parameters.beta
    diagnostics: List[ActionDiagnostic] = []
    feasible_indices: List[int] = []

    for index, action in enumerate(actions):
        transition = kernels[action.name]
        robust_v, nominal_v, worst_distribution, _ = robust_lyapunov_bound(
            z, belief, action, transition, parameters
        )
        predicted_distribution = belief @ transition
        cost = operational_cost(
            action, actions[previous_index], predicted_distribution, parameters.weights
        )
        feasible = resource_feasible(action) and robust_v <= drift_limit + 1e-12
        diagnostics.append(
            ActionDiagnostic(
                index=index,
                robust_v=robust_v,
                nominal_v=nominal_v,
                drift_limit=drift_limit,
                cost=cost,
                feasible=feasible,
                worst_distribution=worst_distribution,
            )
        )
        if feasible:
            feasible_indices.append(index)

    if not feasible_indices:
        return len(actions) - 1, diagnostics

    chosen = min(feasible_indices, key=lambda idx: diagnostics[idx].cost)
    return chosen, diagnostics


def fallback_certificate(
    fallback: Action,
    p_v: np.ndarray,
    alpha: float,
    contraction: float,
    z_max: float,
    grid_points: int,
    tolerance: float = 5.0e-3,
    max_boxes: int = 20_000,
) -> Dict[str, float | List[float]]:
    """Certify the fallback over [0,z_max]^3.

    A coarse grid first supplies a feasible lower bound.  A Lipschitz
    branch-and-bound calculation then encloses the continuous-box maximum to
    the requested tolerance.  The fallback uses max_j Psi_j, which
    upper-bounds every regime belief and every transition ambiguity set.
    """

    if grid_points < 2:
        raise ValueError("grid_points must be at least two")
    if tolerance <= 0.0:
        raise ValueError("tolerance must be positive")
    if max_boxes < 2:
        raise ValueError("max_boxes must be at least two")

    lambda_max = float(np.linalg.eigvalsh(p_v).max())
    relief = np.asarray(fallback.relief)

    def gap_at(z: np.ndarray) -> float:
        psi, _ = regime_lyapunov_upper_values(z, fallback, p_v, contraction)
        return float(psi.max() - (1.0 - alpha) * lyapunov(z, p_v))

    def box_bounds(low: np.ndarray, high: np.ndarray) -> Tuple[float, float, np.ndarray]:
        """Return sampled lower bound, Lipschitz upper bound, and maximizer."""

        center = 0.5 * (low + high)
        sample_points = [center]
        for mask in range(8):
            sample_points.append(
                np.array(
                    [high[d] if mask & (1 << d) else low[d] for d in range(3)],
                    dtype=float,
                )
            )
        sample_values = [gap_at(point) for point in sample_points]
        best_position = int(np.argmax(sample_values))
        lower_bound = float(sample_values[best_position])
        maximizer_local = sample_points[best_position]

        # Local Lipschitz bound over this box.  ReLU is nonexpansive and the
        # predicted safety state is coordinatewise monotone in z.
        l_psi = 0.0
        for regime in range(5):
            z_hat_high = np.maximum(
                0.0,
                contraction * high + REGIME_INPUTS[regime] - relief,
            )
            error_radius = model_error_radius(fallback, regime)
            l_regime = (
                2.0
                * contraction
                * lambda_max
                * (np.linalg.norm(z_hat_high) + error_radius)
            )
            l_psi = max(l_psi, l_regime)
        l_current = (
            2.0
            * (1.0 - alpha)
            * lambda_max
            * np.linalg.norm(high)
        )
        covering_radius = 0.5 * np.linalg.norm(high - low)
        upper_bound = gap_at(center) + (l_psi + l_current) * covering_radius
        upper_bound = max(upper_bound, lower_bound)
        return lower_bound, float(upper_bound), maximizer_local

    grid = np.linspace(0.0, z_max, grid_points)
    max_grid_gap = -math.inf
    maximizer = np.zeros(3)

    for z0 in grid:
        for z1 in grid:
            for z2 in grid:
                z = np.array([z0, z1, z2])
                gap = gap_at(z)
                if gap > max_grid_gap:
                    max_grid_gap = gap
                    maximizer = z.copy()

    root_low = np.zeros(3)
    root_high = np.full(3, z_max)
    root_lower, root_upper, root_argmax = box_bounds(root_low, root_high)
    if root_lower > max_grid_gap:
        max_grid_gap = root_lower
        maximizer = root_argmax.copy()

    queue: List[Tuple[float, int, np.ndarray, np.ndarray]] = []
    sequence = 0
    heapq.heappush(queue, (-root_upper, sequence, root_low, root_high))
    boxes_evaluated = 1

    while queue and boxes_evaluated < max_boxes:
        current_upper = -queue[0][0]
        if current_upper - max_grid_gap <= tolerance:
            break

        _, _, low, high = heapq.heappop(queue)
        split_dimension = int(np.argmax(high - low))
        midpoint = 0.5 * (low[split_dimension] + high[split_dimension])

        for left_half in (True, False):
            child_low = low.copy()
            child_high = high.copy()
            if left_half:
                child_high[split_dimension] = midpoint
            else:
                child_low[split_dimension] = midpoint

            child_lower, child_upper, child_argmax = box_bounds(
                child_low, child_high
            )
            boxes_evaluated += 1
            if child_lower > max_grid_gap:
                max_grid_gap = child_lower
                maximizer = child_argmax.copy()
            if child_upper > max_grid_gap:
                sequence += 1
                heapq.heappush(
                    queue,
                    (-child_upper, sequence, child_low, child_high),
                )

    certified_upper = max_grid_gap
    if queue:
        certified_upper = max(certified_upper, -queue[0][0])
    certification_gap = max(0.0, certified_upper - max_grid_gap)
    beta_required = max(0.0, certified_upper)

    return {
        "beta_required": beta_required,
        "max_grid_gap": max_grid_gap,
        "certified_upper_gap": certified_upper,
        "certification_gap": certification_gap,
        "requested_tolerance": tolerance,
        "max_boxes": max_boxes,
        "boxes_evaluated": boxes_evaluated,
        "terminated_by_box_limit": boxes_evaluated >= max_boxes,
        "grid_maximizer": maximizer.tolist(),
        "grid_points_per_dimension": grid_points,
    }


def gaussian_likelihood(observation: np.ndarray) -> np.ndarray:
    residual = (observation[None, :] - OBSERVATION_MEANS) / OBSERVATION_STD
    log_likelihood = -0.5 * np.sum(residual * residual, axis=1)
    log_likelihood -= log_likelihood.max()
    likelihood = np.exp(log_likelihood)
    return np.maximum(likelihood, 1e-300)


def belief_update(
    belief: np.ndarray,
    transition: np.ndarray,
    observation: np.ndarray,
) -> np.ndarray:
    predicted = belief @ transition
    posterior = predicted * gaussian_likelihood(observation)
    total = float(posterior.sum())
    if total <= 0.0 or not np.isfinite(total):
        return predicted / predicted.sum()
    return posterior / total


def sample_bounded_error(
    rng: np.random.Generator,
    radius: float,
    dimension: int = 3,
) -> np.ndarray:
    direction = rng.normal(size=dimension)
    norm = float(np.linalg.norm(direction))
    if norm <= 1e-15:
        direction = np.ones(dimension) / math.sqrt(dimension)
    else:
        direction /= norm
    # Uniform-in-radius is sufficient here; the hard bound is what matters.
    magnitude = radius * rng.uniform(0.0, 0.95)
    return magnitude * direction


def simulate_one_run(
    steps: int,
    seed: int,
    actions: Sequence[Action],
    kernels: Dict[str, np.ndarray],
    parameters: ControllerParameters,
    disturbance_schedule: Dict[int, int],
) -> SimulationResult:
    rng = np.random.default_rng(seed)
    z = np.zeros((steps + 1, 3), dtype=float)
    regimes = np.zeros(steps + 1, dtype=int)
    actions_taken = np.zeros(steps, dtype=int)
    beliefs = np.zeros((steps + 1, 5), dtype=float)
    beliefs[0, 0] = 1.0
    robust_v = np.zeros(steps)
    nominal_v = np.zeros(steps)
    drift_limit = np.zeros(steps)
    previous_index = 0
    empty_set_count = 0

    for t in range(steps):
        chosen_index, diagnostics = select_action(
            z[t], beliefs[t], previous_index, actions, kernels, parameters
        )
        chosen = actions[chosen_index]
        chosen_diag = diagnostics[chosen_index]

        if not chosen_diag.feasible:
            empty_set_count += 1
        actions_taken[t] = chosen_index
        robust_v[t] = chosen_diag.robust_v
        nominal_v[t] = chosen_diag.nominal_v
        drift_limit[t] = chosen_diag.drift_limit

        if t in disturbance_schedule:
            next_regime = disturbance_schedule[t]
        else:
            next_regime = int(
                rng.choice(5, p=kernels[chosen.name][regimes[t]])
            )

        z_hat = predict_next_z(
            z[t], chosen, next_regime, parameters.contraction
        )
        error = sample_bounded_error(
            rng, model_error_radius(chosen, next_regime)
        )
        z[t + 1] = np.maximum(0.0, z_hat + error)
        regimes[t + 1] = next_regime

        observation = np.clip(
            OBSERVATION_MEANS[next_regime]
            + rng.normal(scale=OBSERVATION_STD),
            0.0,
            1.0,
        )
        beliefs[t + 1] = belief_update(
            beliefs[t], kernels[chosen.name], observation
        )
        previous_index = chosen_index

    return SimulationResult(
        z=z,
        regimes=regimes,
        actions=actions_taken,
        beliefs=beliefs,
        robust_v=robust_v,
        nominal_v=nominal_v,
        drift_limit=drift_limit,
        empty_set_count=empty_set_count,
    )


def run_self_checks(
    actions: Sequence[Action],
    kernels: Dict[str, np.ndarray],
    parameters: ControllerParameters,
    certificate: Dict[str, float | List[float]],
    seed: int,
) -> None:
    """Exercise the optimizer, robust bound, and fallback certificate."""

    rng = np.random.default_rng(seed + 91_337)

    for _ in range(1_000):
        nominal = rng.dirichlet(np.ones(5))
        values = rng.uniform(0.0, 3.0, size=5)
        epsilon = rng.uniform(0.0, 2.0)
        worst, distribution = worst_case_l1_expectation(nominal, values, epsilon)
        if worst + 1e-12 < float(nominal @ values):
            raise AssertionError("Worst-case expectation is below nominal")
        if worst > float(values.max()) + 1e-12:
            raise AssertionError("Worst-case expectation exceeds max state value")
        if np.linalg.norm(distribution - nominal, ord=1) > epsilon + 1e-10:
            raise AssertionError("L1 ambiguity constraint was violated")

    for _ in range(500):
        z = rng.uniform(0.0, parameters.z_max, size=3)
        belief = rng.dirichlet(np.ones(5))
        action = actions[int(rng.integers(len(actions)))]
        psi, predicted = regime_lyapunov_upper_values(
            z, action, parameters.p_matrix, parameters.contraction
        )
        nominal_distribution = belief @ kernels[action.name]
        robust, _ = worst_case_l1_expectation(
            nominal_distribution, psi, parameters.epsilon_transition
        )
        if robust + 1e-12 < float(nominal_distribution @ psi):
            raise AssertionError("Robust value does not upper-bound nominal value")

        for regime in range(5):
            error = sample_bounded_error(
                rng, model_error_radius(action, regime)
            )
            actual = np.maximum(0.0, predicted[regime] + error)
            if lyapunov(actual, parameters.p_matrix) > psi[regime] + 1e-10:
                raise AssertionError("Regime-wise Lyapunov upper bound failed")

    fallback = actions[-1]
    beta = float(certificate["beta_required"])
    for _ in range(10_000):
        z = rng.uniform(0.0, parameters.z_max, size=3)
        psi, _ = regime_lyapunov_upper_values(
            z, fallback, parameters.p_matrix, parameters.contraction
        )
        rhs = (1.0 - parameters.alpha) * lyapunov(z, parameters.p_matrix) + beta
        if float(psi.max()) > rhs + 1e-10:
            raise AssertionError("Random fallback certificate check failed")


def simulate_ensemble(
    steps: int,
    runs: int,
    seed: int,
    actions: Sequence[Action],
    kernels: Dict[str, np.ndarray],
    parameters: ControllerParameters,
) -> Tuple[SimulationResult, np.ndarray, np.ndarray, np.ndarray]:
    disturbance_schedule = {
        max(5, int(0.30 * steps)): 1,
        max(10, int(0.62 * steps)): 4,
    }
    results = [
        simulate_one_run(
            steps,
            seed + 10_007 * run,
            actions,
            kernels,
            parameters,
            disturbance_schedule,
        )
        for run in range(runs)
    ]
    norm_squared = np.vstack(
        [np.sum(result.z * result.z, axis=1) for result in results]
    )
    mean_norm_squared = norm_squared.mean(axis=0)
    if runs > 1:
        standard_error = norm_squared.std(axis=0, ddof=1) / math.sqrt(runs)
    else:
        standard_error = np.zeros(steps + 1)
    ci95 = 1.96 * standard_error
    return results[0], mean_norm_squared, ci95, norm_squared


def theoretical_bounds(
    steps: int,
    initial_z: np.ndarray,
    parameters: ControllerParameters,
) -> Tuple[np.ndarray, np.ndarray]:
    p_v = parameters.p_matrix
    eigenvalues = np.linalg.eigvalsh(p_v)
    lambda_min = float(eigenvalues.min())
    lambda_max = float(eigenvalues.max())
    kappa = lambda_max / lambda_min
    time = np.arange(steps + 1)
    decay = (1.0 - parameters.alpha) ** time
    initial_norm_squared = float(initial_z @ initial_z)
    finite_time = (
        kappa * decay * initial_norm_squared
        + parameters.beta * (1.0 - decay) / (parameters.alpha * lambda_min)
    )
    ultimate = np.full(
        steps + 1,
        parameters.beta / (parameters.alpha * lambda_min),
    )
    return finite_time, ultimate


def write_csv(
    path: Path,
    representative: SimulationResult,
    mean_norm_squared: np.ndarray,
    ci95: np.ndarray,
    finite_bound: np.ndarray,
    ultimate_bound: np.ndarray,
) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "t",
                "mean_norm_squared",
                "ci95_low",
                "ci95_high",
                "finite_time_bound",
                "ultimate_bound",
                "rep_z_delay",
                "rep_z_loss",
                "rep_z_noise",
                "rep_regime",
                "rep_action",
                "selected_robust_v",
                "selected_nominal_v",
                "drift_limit",
            ]
        )
        for t in range(len(mean_norm_squared)):
            action = int(representative.actions[t]) if t < len(representative.actions) else ""
            robust = representative.robust_v[t] if t < len(representative.robust_v) else ""
            nominal = representative.nominal_v[t] if t < len(representative.nominal_v) else ""
            drift = representative.drift_limit[t] if t < len(representative.drift_limit) else ""
            writer.writerow(
                [
                    t,
                    mean_norm_squared[t],
                    max(0.0, mean_norm_squared[t] - ci95[t]),
                    mean_norm_squared[t] + ci95[t],
                    finite_bound[t],
                    ultimate_bound[t],
                    *representative.z[t].tolist(),
                    int(representative.regimes[t]),
                    action,
                    robust,
                    nominal,
                    drift,
                ]
            )


def create_plot(
    path: Path,
    representative: SimulationResult,
    mean_norm_squared: np.ndarray,
    ci95: np.ndarray,
    finite_bound: np.ndarray,
    ultimate_bound: np.ndarray,
    actions: Sequence[Action],
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    time = np.arange(len(mean_norm_squared))
    control_time = np.arange(len(representative.actions))
    fig, axes = plt.subplots(2, 2, figsize=(12.0, 8.0), constrained_layout=True)

    ax = axes[0, 0]
    ax.plot(time, mean_norm_squared, color="#C8102E", lw=2.0, label="Monte Carlo mean")
    ax.fill_between(
        time,
        np.maximum(0.0, mean_norm_squared - ci95),
        mean_norm_squared + ci95,
        color="#C8102E",
        alpha=0.18,
        label="95% CI",
    )
    ax.plot(time, finite_bound, "--", color="#1F4E79", lw=1.8, label="Finite-time bound")
    ax.plot(time, ultimate_bound, ":", color="#444444", lw=1.5, label="Ultimate bound")
    ax.set_title("Mean-square safety state")
    ax.set_xlabel("Control epoch")
    ax.set_ylabel(r"$\mathbb{E}[\|z_t\|_2^2]$")
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8)

    ax = axes[0, 1]
    labels = ("Delay violation", "Loss violation", "Noise violation")
    colors = ("#1F77B4", "#D62728", "#2CA02C")
    for component, (label, color) in enumerate(zip(labels, colors)):
        ax.plot(time, representative.z[:, component], label=label, color=color, lw=1.7)
    ax.set_title("Representative safety trajectory")
    ax.set_xlabel("Control epoch")
    ax.set_ylabel("Normalized violation")
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8)

    ax = axes[1, 0]
    ax.step(time, representative.regimes, where="post", color="#444444", lw=1.5, label="Regime")
    ax.step(
        control_time,
        representative.actions + 0.05,
        where="post",
        color="#C8102E",
        lw=1.5,
        label="Action",
    )
    ax.set_yticks(range(5), REGIME_NAMES)
    ax.set_title("Regime and selected action index")
    ax.set_xlabel("Control epoch")
    ax.grid(alpha=0.25)
    action_text = ", ".join(f"{i}: {a.name}" for i, a in enumerate(actions))
    ax.text(0.01, -0.28, action_text, transform=ax.transAxes, fontsize=7)
    ax.legend(fontsize=8)

    ax = axes[1, 1]
    ax.plot(control_time, representative.robust_v, color="#C8102E", lw=1.8, label="Robust prediction")
    ax.plot(control_time, representative.nominal_v, color="#1F77B4", lw=1.4, label="Nominal prediction")
    ax.plot(control_time, representative.drift_limit, "--", color="#222222", lw=1.5, label="Drift limit")
    ax.set_title("Online robust drift screening")
    ax.set_xlabel("Control epoch")
    ax.set_ylabel("One-step Lyapunov value")
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8)

    fig.suptitle("DA-AHE Robust Markov/Lyapunov Validation", fontsize=14)
    fig.savefig(path, dpi=220)
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate robust Markov/Lyapunov screening for DA-AHE."
    )
    parser.add_argument("--steps", type=int, default=100, help="Control epochs per run")
    parser.add_argument("--runs", type=int, default=200, help="Monte Carlo runs")
    parser.add_argument("--seed", type=int, default=20260918, help="Random seed")
    parser.add_argument("--alpha", type=float, default=0.10, help="Drift contraction parameter")
    parser.add_argument(
        "--transition-radius",
        type=float,
        default=0.12,
        help="L1 radius of the transition ambiguity set",
    )
    parser.add_argument(
        "--z-max",
        type=float,
        default=1.50,
        help="Upper edge of each certified safety-state coordinate",
    )
    parser.add_argument(
        "--certificate-grid",
        type=int,
        default=11,
        help="Coarse grid points per dimension used to seed certification",
    )
    parser.add_argument(
        "--certificate-tolerance",
        type=float,
        default=5.0e-3,
        help="Maximum branch-and-bound gap for continuous-box certification",
    )
    parser.add_argument(
        "--certificate-max-boxes",
        type=int,
        default=20_000,
        help="Maximum boxes evaluated by fallback branch-and-bound",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("da_ahe_stability_results"),
        help="Directory for CSV, JSON, and PNG outputs",
    )
    parser.add_argument("--no-plots", action="store_true", help="Skip PNG generation")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.steps <= 0 or args.runs <= 0:
        raise ValueError("steps and runs must be positive")
    if not 0.0 < args.alpha < 1.0:
        raise ValueError("alpha must lie in (0,1)")
    if not 0.0 <= args.transition_radius <= 2.0:
        raise ValueError("transition-radius must lie in [0,2]")

    actions = build_actions()
    kernels = build_transition_kernels(actions)
    p_v = np.diag([1.0, 1.2, 1.5])
    contraction = 0.58

    certificate = fallback_certificate(
        fallback=actions[-1],
        p_v=p_v,
        alpha=args.alpha,
        contraction=contraction,
        z_max=args.z_max,
        grid_points=args.certificate_grid,
        tolerance=args.certificate_tolerance,
        max_boxes=args.certificate_max_boxes,
    )
    beta = float(certificate["beta_required"]) + 1e-9
    parameters = ControllerParameters(
        alpha=args.alpha,
        beta=beta,
        epsilon_transition=args.transition_radius,
        contraction=contraction,
        p_v=tuple(tuple(float(value) for value in row) for row in p_v),
        z_max=args.z_max,
        weights=(0.22, 0.28, 0.15, 0.25, 0.10),
    )

    run_self_checks(actions, kernels, parameters, certificate, args.seed)
    representative, mean_norm_squared, ci95, _ = simulate_ensemble(
        steps=args.steps,
        runs=args.runs,
        seed=args.seed,
        actions=actions,
        kernels=kernels,
        parameters=parameters,
    )
    finite_bound, ultimate_bound = theoretical_bounds(
        args.steps, representative.z[0], parameters
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_dir / "stability_timeseries.csv"
    json_path = args.output_dir / "certificate_summary.json"
    plot_path = args.output_dir / "stability_validation.png"

    write_csv(
        csv_path,
        representative,
        mean_norm_squared,
        ci95,
        finite_bound,
        ultimate_bound,
    )
    summary = {
        "parameters": asdict(parameters),
        "certificate": certificate,
        "actions": [asdict(action) for action in actions],
        "simulation": {
            "steps": args.steps,
            "runs": args.runs,
            "seed": args.seed,
            "representative_empty_set_count": representative.empty_set_count,
            "maximum_empirical_mean_norm_squared": float(mean_norm_squared.max()),
            "ultimate_mean_square_bound": float(ultimate_bound[0]),
            "empirical_bound_satisfied": bool(
                np.all(mean_norm_squared <= finite_bound + ci95 + 1e-10)
            ),
        },
    }
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if not args.no_plots:
        create_plot(
            plot_path,
            representative,
            mean_norm_squared,
            ci95,
            finite_bound,
            ultimate_bound,
            actions,
        )

    action_counts = np.bincount(representative.actions, minlength=len(actions))
    print("DA-AHE robust stability validation completed")
    print(f"  beta_required       : {certificate['beta_required']:.8f}")
    print(f"  ultimate MS bound   : {ultimate_bound[0]:.8f}")
    print(f"  max empirical E||z||^2: {mean_norm_squared.max():.8f}")
    print(f"  empty feasible sets : {representative.empty_set_count}")
    print("  representative actions:")
    for action, count in zip(actions, action_counts):
        print(f"    {action.name:12s}: {count}")
    print(f"  CSV                 : {csv_path.resolve()}")
    print(f"  JSON                : {json_path.resolve()}")
    if not args.no_plots:
        print(f"  PNG                 : {plot_path.resolve()}")


if __name__ == "__main__":
    main()
