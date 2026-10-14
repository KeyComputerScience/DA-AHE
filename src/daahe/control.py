# SPDX-License-Identifier: MIT
"""Causal five-regime filtering, Eq. (15), and Algorithms 4--6.

The routines implement the *conditional* controller in the manuscript. An
empirical calibration is useful for experiments but is not a uniform uncertainty
bound or an invariant-domain proof. Strict mode requires external bound evidence
and a valid analytic fallback bound; all controllers fail closed outside Z_cert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, ROUND_CEILING, localcontext
from fractions import Fraction
import math
from typing import Any, Mapping, Sequence

from .safety import (Action, Certificate, EvidenceArtifact, RuntimeContext,
                     SafetyFilter, _freeze, _plain, canonical_digest)

N_REGIMES = 5
CONTINUOUS_INDICES = (0, 1, 2, 3, 4, 6)


def _vector(values: Sequence[float], length: int, name: str,
            nonnegative: bool = False) -> tuple[float, ...]:
    result = tuple(float(v) for v in values)
    if len(result) != length or any(not math.isfinite(v) for v in result):
        raise ValueError(f"{name} must contain {length} finite values")
    if nonnegative and any(v < 0 for v in result):
        raise ValueError(f"{name} cannot contain negative values")
    return result


def _probability(values: Sequence[float]) -> tuple[float, ...]:
    result = _vector(values, len(values), "probability", nonnegative=True)
    total = sum(result)
    if not result or abs(total - 1.0) > 1e-10:
        raise ValueError("probability vector must sum to one")
    return tuple(v / total for v in result)


@dataclass(frozen=True)
class AmbiguityResult:
    value: float
    distribution: tuple[float, ...]
    moved_mass: float


def l1_worst_case(probabilities: Sequence[float], values: Sequence[float],
                  radius: float) -> AmbiguityResult:
    """Exactly maximize p·values subject to simplex and ||p-p0||_1 <= radius.

    Move at most radius/2 probability mass from the lowest-valued occupied
    coordinate to the highest-valued nonsaturated coordinate. Donor/receiver
    pointers stop at equal values. Therefore ties never cause a harmful reverse
    transfer. Each transfer is an exchange-optimal improvement of a linear
    objective; exhaustion of gain, mass, capacity, or budget proves optimality.
    Deterministic index tie-breaking makes audit output reproducible.
    """
    p0 = _probability(probabilities)
    c = _vector(values, len(p0), "objective")
    if not math.isfinite(radius) or not 0 <= radius <= 2:
        raise ValueError("L1 radius must lie in [0, 2]")
    p = list(p0)
    donors = sorted(range(len(p)), key=lambda i: (c[i], i))
    receivers = sorted(range(len(p)), key=lambda i: (-c[i], i))
    low = high = 0
    budget = radius / 2.0
    while budget > 0 and low < len(p) and high < len(p):
        i, j = donors[low], receivers[high]
        if c[j] <= c[i]:
            break
        if p[i] <= 0:
            low += 1
            continue
        if p[j] >= 1:
            high += 1
            continue
        amount = min(budget, p[i], 1.0 - p[j])
        if amount <= 0:
            break
        p[i] -= amount
        p[j] += amount
        budget -= amount
        if p[i] <= 0:
            low += 1
        if p[j] >= 1:
            high += 1
    return AmbiguityResult(sum(v * x for v, x in zip(p, c)), tuple(p),
                           sum(abs(x - y) for x, y in zip(p, p0)) / 2.0)


@dataclass(frozen=True)
class EmissionModel:
    """Diagonal Gaussian for y[0:5],y[6], Bernoulli for binary y[5]."""

    means: tuple[tuple[float, ...], ...]
    variances: tuple[tuple[float, ...], ...]
    tamper_probabilities: tuple[float, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "means", tuple(tuple(v) for v in self.means))
        object.__setattr__(self, "variances", tuple(tuple(v) for v in self.variances))
        object.__setattr__(self, "tamper_probabilities", tuple(self.tamper_probabilities))
        if len(self.means) != 5 or len(self.variances) != 5:
            raise ValueError("emissions require five regimes")
        for mean, variance in zip(self.means, self.variances):
            _vector(mean, 6, "emission means")
            if any(v <= 0 for v in _vector(variance, 6, "emission variances")):
                raise ValueError("Gaussian variances must be positive")
        if any(not 0 < p < 1 for p in _vector(self.tamper_probabilities, 5, "tamper probabilities")):
            raise ValueError("Bernoulli parameters must be strictly between zero and one")

    def log_likelihoods(self, telemetry: Sequence[float]) -> tuple[float, ...]:
        y = _vector(telemetry, 7, "telemetry")
        if y[5] not in (0.0, 1.0):
            raise ValueError("authenticated tamper indicator y[5] must be binary")
        result = []
        for j in range(5):
            total = 0.0
            for h, index in enumerate(CONTINUOUS_INDICES):
                var = self.variances[j][h]
                standardized = (y[index] - self.means[j][h]) / math.sqrt(var)
                total -= 0.5 * (math.log(2 * math.pi * var) +
                                standardized * standardized)
            probability = self.tamper_probabilities[j]
            total += math.log(probability if y[5] else 1.0 - probability)
            if not math.isfinite(total):
                raise ValueError("telemetry lies outside the numerical range of the emission model")
            result.append(total)
        return tuple(result)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EmissionModel":
        return cls(tuple(tuple(v) for v in value["means"]),
                   tuple(tuple(v) for v in value["variances"]),
                   tuple(value["tamper_probabilities"]))


@dataclass(frozen=True)
class MetricModel:
    """Ridge coefficients for [1,z_delay,z_loss,z_noise] in SI units.

    energy is joules/report, delay is seconds, distortion is a declared scalar
    reconstruction metric; noise_utilization is B/(tau-zeta). Fits are estimates,
    never hard constraints. Clipping negative linear predictions is explicit.
    """

    energy: tuple[float, ...]
    delay: tuple[float, ...]
    distortion: tuple[float, ...]
    noise_utilization: tuple[float, ...]

    def __post_init__(self) -> None:
        for name in ("energy", "delay", "distortion", "noise_utilization"):
            object.__setattr__(self, name, _vector(getattr(self, name), 4, "metric regression"))

    def predict(self, state: Sequence[float]) -> tuple[float, ...]:
        features = (1.0,) + _vector(state, 3, "state", nonnegative=True)
        return tuple(max(0.0, sum(w * x for w, x in zip(weights, features)))
                     for weights in (self.energy, self.delay, self.distortion,
                                     self.noise_utilization))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MetricModel":
        return cls(**{key: tuple(value[key]) for key in
                     ("energy", "delay", "distortion", "noise_utilization")})


@dataclass(frozen=True)
class ControlModel:
    """Frozen offline model, with optional explicitly enabled causal adaptation.

    transitions[action_id] is 5x5; zero entries are inadmissible transitions.
    Optional transitions_by_bin[action_id][bin] overrides that nominal matrix.
    offsets[j] = u_j, relief[action] = r(a), error_radii[action][j] = e_j,a.
    Empirical maxima do not certify population or uniform state-space bounds.
    External bound artifacts must bind digest(), region and all assumptions.
    """

    transitions: Mapping[str, tuple[tuple[float, ...], ...]]
    offsets: tuple[tuple[float, ...], ...]
    relief: Mapping[str, tuple[float, ...]]
    error_radii: Mapping[str, tuple[float, ...]]
    transition_radii: Mapping[str, float]
    pooled_metrics: Mapping[str, MetricModel]
    state_metrics: Mapping[str, tuple[MetricModel, ...]] = field(default_factory=dict)
    emissions: EmissionModel | None = None
    kappa_z: float = 0.8
    zcert_max: tuple[float, float, float] = (1.0, 1.0, 1.0)
    transitions_by_bin: Mapping[str, tuple[tuple[tuple[float, ...], ...], ...]] = field(default_factory=dict)
    bound_kind: str = "empirical"
    bound_evidence: Mapping[str, EvidenceArtifact] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not math.isfinite(self.kappa_z) or self.kappa_z < 0:
            raise ValueError("kappa_z must be finite and nonnegative")
        _vector(self.zcert_max, 3, "model certified cube", nonnegative=True)
        if len(self.offsets) != 5:
            raise ValueError("five regime offsets are required")
        for row in self.offsets:
            _vector(row, 3, "regime offset")
        action_ids = set(self.transitions)
        if not action_ids or any(set(mapping) != action_ids for mapping in
                                 (self.relief, self.error_radii,
                                  self.transition_radii, self.pooled_metrics)):
            raise ValueError("all required model maps must cover exactly the same actions")
        for action_id, matrix in self.transitions.items():
            self._check_matrix(matrix)
            _vector(self.relief[action_id], 3, "action relief")
            _vector(self.error_radii[action_id], 5, "error radii", nonnegative=True)
            radius = self.transition_radii[action_id]
            if not math.isfinite(radius) or not 0 <= radius <= 2:
                raise ValueError("transition radius must be in [0,2]")
            if action_id in self.state_metrics and len(self.state_metrics[action_id]) != 5:
                raise ValueError("state metrics must have five rows")
        for action_id, bins in self.transitions_by_bin.items():
            if action_id not in action_ids or not bins:
                raise ValueError("stress-bin transition map references an unknown action")
            for matrix in bins:
                self._check_matrix(matrix)
        for name in ("transitions", "offsets", "relief", "error_radii", "transition_radii",
                     "pooled_metrics", "state_metrics", "zcert_max", "transitions_by_bin",
                     "bound_evidence", "metadata"):
            object.__setattr__(self, name, _freeze(getattr(self, name)))

    @staticmethod
    def _check_matrix(matrix: Sequence[Sequence[float]]) -> None:
        if len(matrix) != 5:
            raise ValueError("transition matrix must be 5x5")
        for row in matrix:
            if len(row) != 5:
                raise ValueError("transition matrix must be 5x5")
            _probability(row)

    def matrix(self, action_id: str, stress_bin: int = 0) -> tuple[tuple[float, ...], ...]:
        bins = self.transitions_by_bin.get(action_id)
        if bins is not None:
            if not 0 <= stress_bin < len(bins):
                raise ValueError("stress bin outside calibrated transition range")
            return bins[stress_bin]
        return self.transitions[action_id]

    def to_dict(self) -> dict[str, Any]:
        return _plain(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ControlModel":
        data = dict(value)
        data["transitions"] = {k: tuple(tuple(row) for row in v)
                               for k, v in data["transitions"].items()}
        data["offsets"] = tuple(tuple(row) for row in data["offsets"])
        data["relief"] = {k: tuple(v) for k, v in data["relief"].items()}
        data["error_radii"] = {k: tuple(v) for k, v in data["error_radii"].items()}
        data["pooled_metrics"] = {k: MetricModel.from_dict(v)
                                  for k, v in data["pooled_metrics"].items()}
        data["state_metrics"] = {k: tuple(MetricModel.from_dict(row) for row in v)
                                 for k, v in data.get("state_metrics", {}).items()}
        data["emissions"] = (EmissionModel.from_dict(data["emissions"])
                             if data.get("emissions") else None)
        data["bound_evidence"] = {k: EvidenceArtifact.from_dict(v)
                                  for k, v in data.get("bound_evidence", {}).items()}
        data["zcert_max"] = tuple(data.get("zcert_max", (1.0, 1.0, 1.0)))
        data["transitions_by_bin"] = {
            k: tuple(tuple(tuple(row) for row in matrix) for matrix in bins)
            for k, bins in data.get("transitions_by_bin", {}).items()
        }
        return cls(**data)

    def digest(self) -> str:
        value = self.to_dict()
        # External reports refer to this digest; adding their references must not
        # change the model being certified or introduce a circular hash.
        value.pop("bound_evidence", None)
        value.pop("bound_kind", None)
        return canonical_digest(value)


class ControlledHMM:
    """Bayesian filtering with optional discounted *expected* transition counts.

    update(y_t, a_{t-1}) uses no latent labels or future observations. Frozen
    transition tables remain immutable. Adaptation, if enabled, is per action
    and stress bin and uses omega=.98, prior strength=5, reference mixing=.02.
    Call predict() on this instance to make the policy use its adapted kernels.
    """

    def __init__(self, model: ControlModel, initial: Sequence[float] = (1, 0, 0, 0, 0),
                 *, adapt: bool = False, discount: float = 0.98,
                 prior_strength: float = 5.0, reference_mix: float = 0.02):
        if model.emissions is None:
            raise ValueError("the calibrated model has no emission model")
        if not 0 < discount <= 1 or prior_strength <= 0 or not 0 <= reference_mix <= 1:
            raise ValueError("invalid HMM adaptation hyperparameters")
        self.model = model
        self.belief = _probability(initial)
        if len(self.belief) != 5:
            raise ValueError("HMM initial belief must have five entries")
        self.adapt = adapt
        self.discount = discount
        self.prior_strength = prior_strength
        self.reference_mix = reference_mix
        self.counts: dict[tuple[str, int], list[list[float]]] = {}

    def kernel(self, action_id: str, stress_bin: int = 0) -> tuple[tuple[float, ...], ...]:
        nominal = self.model.matrix(action_id, stress_bin)
        counts = self.counts.get((action_id, stress_bin)) if self.adapt else None
        if counts is None:
            return nominal
        rows = []
        for i, row in enumerate(nominal):
            total = sum(counts[i]) + self.prior_strength
            fitted = [(counts[i][j] + self.prior_strength * row[j]) / total
                      if row[j] > 0 else 0.0 for j in range(5)]
            rows.append(tuple((1 - self.reference_mix) * fitted[j] +
                              self.reference_mix * row[j] for j in range(5)))
        return tuple(rows)

    def predict(self, action_id: str, belief: Sequence[float] | None = None,
                stress_bin: int = 0) -> tuple[float, ...]:
        prior = self.belief if belief is None else _probability(belief)
        if len(prior) != 5:
            raise ValueError("belief must have five entries")
        matrix = self.kernel(action_id, stress_bin)
        return tuple(sum(prior[i] * matrix[i][j] for i in range(5)) for j in range(5))

    def update(self, telemetry: Sequence[float], previous_action: str | None = None,
               *, stress_bin: int = 0) -> tuple[float, ...]:
        logs = self.model.emissions.log_likelihoods(telemetry)  # type: ignore[union-attr]
        before = self.belief
        if previous_action is None:
            predicted = before
        else:
            predicted = self.predict(previous_action, before, stress_bin)
        # Scale by the largest reachable log weight, preventing underflow when
        # an impossible state happens to have the highest raw likelihood.
        weights_log = [math.log(predicted[j]) + logs[j]
                       if predicted[j] > 0 else -math.inf for j in range(5)]
        maximum = max(weights_log)
        weights = [math.exp(value - maximum) for value in weights_log]
        total = sum(weights)
        posterior = tuple(value / total for value in weights)
        if self.adapt and previous_action is not None:
            kernel = self.kernel(previous_action, stress_bin)
            # Discount once per observed transition, including kernels that
            # were not selected this epoch (time-based, not visit-based decay).
            for old_counts in self.counts.values():
                for old_row in old_counts:
                    for j in range(5):
                        old_row[j] *= self.discount
            counts = self.counts.setdefault((previous_action, stress_bin),
                                           [[0.0] * 5 for _ in range(5)])
            for i in range(5):
                for j in range(5):
                    # xi_ij = Pr(s_{t-1}=i,s_t=j | all y through t).
                    expected = (posterior[j] * before[i] * kernel[i][j] / predicted[j]
                                if predicted[j] > 0 else 0.0)
                    counts[i][j] += expected
        self.belief = posterior
        return posterior


@dataclass(frozen=True)
class ControllerParams:
    p_diagonal: tuple[float, float, float] = (1.0, 1.0, 1.0)
    gamma: float = 0.10
    beta: float = 0.02
    weights: tuple[float, float, float, float, float] = (0.22, 0.28, 0.15, 0.25, 0.10)
    energy_reference: float = 1.0
    delay_threshold: float = 1.0
    distortion_maximum: float = 1.0
    switching_diagonal: tuple[float, ...] = (1.0, 1 / 256, 1 / 256, 1 / 4096, 1.0, 1.0)

    def __post_init__(self) -> None:
        if any(v <= 0 for v in _vector(self.p_diagonal, 3, "P diagonal")):
            raise ValueError("Lyapunov matrix must be positive definite")
        if not math.isfinite(self.gamma) or not 0 < self.gamma < 1:
            raise ValueError("gamma must be in (0,1)")
        if not math.isfinite(self.beta) or self.beta < 0:
            raise ValueError("beta must be nonnegative")
        _vector(self.weights, 5, "objective weights", nonnegative=True)
        _vector(self.switching_diagonal, 6, "switching matrix", nonnegative=True)
        if any(not math.isfinite(v) or v <= 0 for v in
               (self.energy_reference, self.delay_threshold, self.distortion_maximum)):
            raise ValueError("objective normalizers must be positive and finite")
        for name in ("p_diagonal", "weights", "switching_diagonal"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    def lyapunov(self, state: Sequence[float]) -> float:
        z = _vector(state, 3, "state", nonnegative=True)
        return sum(p * v * v for p, v in zip(self.p_diagonal, z))


def regime_predictions(model: ControlModel, action_id: str,
                       state: Sequence[float], params: ControllerParams
                       ) -> tuple[tuple[tuple[float, ...], ...], tuple[float, ...]]:
    """Eq. (15), with lambda_max(P) for diagonal positive P."""
    z = _vector(state, 3, "state", nonnegative=True)
    predictions, psi = [], []
    maximum = max(params.p_diagonal)
    for j in range(5):
        prediction = tuple(max(model.kappa_z * z[h] + model.offsets[j][h] -
                               model.relief[action_id][h], 0.0) for h in range(3))
        radius = model.error_radii[action_id][j]
        norm = math.sqrt(sum(v * v for v in prediction))
        predictions.append(prediction)
        psi.append(params.lyapunov(prediction) + 2 * maximum * norm * radius +
                   maximum * radius * radius)
    return tuple(predictions), tuple(psi)


def fallback_bound(model: ControlModel, fallback_id: str,
                   params: ControllerParams) -> float:
    """Analytic conservative supremum of max_j Psi_j-(1-gamma)V on the cube.

    For each coordinate, max(kappa*z+b,0)^2-(1-gamma)z^2 is piecewise
    quadratic. Its maximum is attained at an endpoint, the ReLU kink, or an
    interior stationary point of a concave quadratic. We enumerate precisely
    these candidates with exact rational arithmetic for binary input numbers.
    The radius cross term uses an outward-rounded decimal square root of the coordinatewise maximum
    norm on the cube. Summing coordinate maxima and this norm upper bound is
    conservative; this is an interval/analytic proof, never a sampled grid.
    """
    if fallback_id not in model.relief:
        raise ValueError("fallback is absent from the calibrated model")
    kappa = Fraction(model.kappa_z)
    contraction = 1 - Fraction(params.gamma)
    maximum_eigenvalue = Fraction(max(params.p_diagonal))
    bounds = []
    for j in range(5):
        separable = Fraction(0)
        norm_squared = Fraction(0)
        for h, upper_float in enumerate(model.zcert_max):
            upper = Fraction(upper_float)
            offset = Fraction(model.offsets[j][h]) - Fraction(model.relief[fallback_id][h])
            candidates = [Fraction(0), upper]
            if kappa > 0:
                kink = -offset / kappa
                if 0 < kink < upper:
                    candidates.append(kink)
            quadratic = kappa * kappa - contraction
            if quadratic < 0:
                stationary = -kappa * offset / quadratic
                if 0 < stationary < upper and kappa * stationary + offset >= 0:
                    candidates.append(stationary)
            separable += Fraction(params.p_diagonal[h]) * max(
                max(kappa * v + offset, 0) ** 2 - contraction * v * v
                for v in candidates)
            norm_squared += max(kappa * upper + offset, 0) ** 2
        if norm_squared:
            # Division rounds upward; sqrt rounds to nearest, then next_plus
            # moves beyond that rounding error. Both quantities are positive.
            with localcontext() as context:
                context.prec = 80
                context.rounding = ROUND_CEILING
                squared_upper = Decimal(norm_squared.numerator) / Decimal(norm_squared.denominator)
                norm_upper = Fraction(squared_upper.sqrt().next_plus())
        else:
            norm_upper = Fraction(0)
        error = Fraction(model.error_radii[fallback_id][j])
        bounds.append(separable + 2 * maximum_eigenvalue * norm_upper * error +
                      maximum_eigenvalue * error * error)
    exact_upper = max(bounds)
    try:
        result = float(exact_upper)
    except OverflowError:
        return math.inf
    if not math.isfinite(result):
        return math.inf
    return math.nextafter(result, math.inf) if Fraction(result) < exact_upper else result


@dataclass(frozen=True)
class CandidateScore:
    action_id: str
    objective: float | None
    robust_bound: float | None
    admitted: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    """Admission result; DA-AHE certification includes its robust model gates.

    DPP/HYS certification covers Eq. (3) resource/security admission only and
    does not establish the DA-AHE Lyapunov theorem for either baseline.
    """
    action: Action | None
    certified: bool
    alarm: bool
    reason: str
    scores: tuple[CandidateScore, ...] = ()


def _switch_cost(action: Action, last_action: Action | None,
                 params: ControllerParams) -> float:
    if last_action is None:
        return 0.0
    differences = [float(a) - float(b) for a, b in
                   zip(action.vector()[:5], last_action.vector()[:5])]
    differences.append(float(action.profile_id != last_action.profile_id))
    return sum(w * d * d for w, d in zip(params.switching_diagonal, differences))


def _cost(metrics: Sequence[float], params: ControllerParams) -> float:
    energy, delay, distortion, noise = metrics
    w_energy, w_delay, w_distortion, w_noise, _ = params.weights
    return (w_energy * energy / params.energy_reference +
            w_delay * delay / params.delay_threshold +
            w_distortion * distortion / params.distortion_maximum + w_noise * noise)


class _ControllerBase:
    def __init__(self, model: ControlModel, actions: Sequence[Action],
                 certificates: Mapping[str, Certificate], fallback_id: str,
                 params: ControllerParams | None = None):
        self.model = model
        self.actions = {a.id: a for a in actions}
        if len(self.actions) != len(actions) or set(self.actions) != set(model.transitions):
            raise ValueError("unique action library must exactly match model actions")
        if fallback_id not in self.actions:
            raise ValueError("fallback must be in the same action library")
        self.fallback_id = fallback_id
        self.params = params or ControllerParams()
        self.safety = SafetyFilter(certificates)

    def _region_failure(self, state: Sequence[float], runtime: RuntimeContext) -> str | None:
        try:
            z = _vector(state, 3, "state", nonnegative=True)
        except ValueError as exc:
            return str(exc)
        domain = tuple(min(a, b) for a, b in zip(self.model.zcert_max, runtime.zcert_max))
        if any(value > maximum for value, maximum in zip(z, domain)):
            return "state outside certified region; fail closed and recertify"
        return None

    def _fallback(self, state: Sequence[float], runtime: RuntimeContext,
                  scores: Sequence[CandidateScore], cause: str) -> Decision:
        action = self.actions[self.fallback_id]
        safe = self.safety.check(action, runtime, state)
        region = self._region_failure(state, runtime)
        if safe.allowed and region is None:
            return Decision(action, safe.certified, True,
                            cause + "; resource-safe fallback selected; recertification required",
                            tuple(scores))
        return Decision(None, False, True, cause + "; no safe fallback: " +
                        "; ".join(safe.reasons + ((region,) if region else ())), tuple(scores))


class RobustController(_ControllerBase):
    """Algorithm 6; strict certification additionally requires model evidence.

    ``hmm`` is optional. When adaptation is enabled in an HMM, attach that same
    instance here so predictions use its causal adapted kernels. Its calibrated
    L1 radii must cover adaptation; external evidence must explicitly say so.
    """

    def __init__(self, *args: Any, hmm: ControlledHMM | None = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        if hmm is not None and hmm.model.digest() != self.model.digest():
            raise ValueError("HMM and controller must use the same frozen model")
        self.hmm = hmm

    def _model_evidence_failure(self, runtime: RuntimeContext) -> str | None:
        if not runtime.strict:
            return None
        if self.model.bound_kind != "external":
            return "empirical calibration is not a uniform uncertainty certificate"
        if self.model.metadata.get("action_digests") != {
                action_id: action.digest() for action_id, action in self.actions.items()}:
            return "model evidence does not bind the complete immutable action library"
        names = ["state_error", "transition", "domain"]
        if self.hmm is not None and self.hmm.adapt:
            names.append("adaptation")
        for name in names:
            evidence = self.model.bound_evidence.get(name)
            if evidence is None:
                return f"missing external model {name} evidence"
            valid, reason = evidence.check(runtime.evidence_root)
            if not valid:
                return f"model {name} evidence: {reason}"
        if fallback_bound(self.model, self.fallback_id, self.params) > self.params.beta:
            return "analytic fallback bound exceeds beta; recertification required"
        return None

    def select(self, state: Sequence[float], belief: Sequence[float],
               last_action: Action | None, runtime: RuntimeContext,
               *, stress_bin: int = 0) -> Decision:
        failure = self._region_failure(state, runtime) or self._model_evidence_failure(runtime)
        if failure:
            return Decision(None, False, True, failure)
        mu = _probability(belief)
        if len(mu) != 5:
            raise ValueError("belief must have five entries")
        threshold = (1.0 - self.params.gamma) * self.params.lyapunov(state) + self.params.beta
        scores: list[CandidateScore] = []
        admitted: list[tuple[float, str, bool]] = []
        for action_id in sorted(self.actions):
            action = self.actions[action_id]
            safe = self.safety.check(action, runtime, state)
            if not safe.allowed:
                scores.append(CandidateScore(action_id, None, None, False, safe.reasons))
                continue
            if self.hmm is None:
                matrix = self.model.matrix(action_id, stress_bin)
                predicted = tuple(sum(mu[i] * matrix[i][j] for i in range(5)) for j in range(5))
            else:
                predicted = self.hmm.predict(action_id, mu, stress_bin)
            _, psi = regime_predictions(self.model, action_id, state, self.params)
            robust = l1_worst_case(predicted, psi, self.model.transition_radii[action_id])
            if robust.value > threshold:
                scores.append(CandidateScore(action_id, None, robust.value, False,
                                              ("robust Lyapunov condition failed",)))
                continue
            rows = self.model.state_metrics.get(action_id)
            if rows:
                metrics = tuple(sum(predicted[j] * rows[j].predict(state)[h] for j in range(5))
                                for h in range(4))
            else:
                metrics = self.model.pooled_metrics[action_id].predict(state)
            objective = _cost(metrics, self.params) + self.params.weights[4] * _switch_cost(
                action, last_action, self.params)
            certified = safe.certified and self.model.bound_kind == "external" and runtime.strict
            admitted.append((objective, action_id, certified))
            scores.append(CandidateScore(action_id, objective, robust.value, True))
        if admitted:
            _, action_id, certified = min(admitted)
            return Decision(self.actions[action_id], certified, False,
                            "robustly admitted" if certified else "unvalidated empirical demonstration",
                            tuple(scores))
        # Algorithm 6's alarm does NOT make an uncertified/out-of-domain fallback
        # safe. Require the same pointwise Lyapunov gate for an applied fallback.
        return Decision(None, False, True,
                        "no action satisfies all hard and robust gates; fail closed and recertify",
                        tuple(scores))


class DPPController(_ControllerBase):
    """Algorithm 4: causal pooled costs and virtual queues, no latent-state model.

    observe(g_t) is called AFTER applying the selected action. Callers supply
    signed, causal g-hat estimates via ``violation_estimates``. They must be
    fitted independently of online latent-state labels and future outcomes.
    """

    def __init__(self, *args: Any, v_dpp: float = 1.0, **kwargs: Any):
        super().__init__(*args, **kwargs)
        if not math.isfinite(v_dpp) or v_dpp < 0:
            raise ValueError("V_DPP must be finite and nonnegative")
        self.v_dpp = v_dpp
        self.queues = (0.0, 0.0, 0.0)

    def observe(self, realized_violations: Sequence[float]) -> tuple[float, ...]:
        g = _vector(realized_violations, 3, "realized queue increments")
        self.queues = tuple(max(q + value, 0.0) for q, value in zip(self.queues, g))
        return self.queues

    def select(self, state: Sequence[float], belief: Sequence[float] | None,
               last_action: Action | None, runtime: RuntimeContext, *,
               violation_estimates: Mapping[str, Sequence[float]] | None = None) -> Decision:
        failure = self._region_failure(state, runtime)
        if failure:
            return Decision(None, False, True, failure)
        scores, admissible = [], []
        for action_id in sorted(self.actions):
            action = self.actions[action_id]
            safe = self.safety.check(action, runtime, state)
            if not safe.allowed:
                scores.append(CandidateScore(action_id, None, None, False, safe.reasons))
                continue
            metrics = self.model.pooled_metrics[action_id].predict(state)
            if violation_estimates is None or action_id not in violation_estimates:
                raise ValueError("DPP requires causal action-conditioned g-hat for every safe action")
            g_hat = _vector(violation_estimates[action_id], 3, "causal violation estimate")
            objective = (sum(q * value for q, value in zip(self.queues, g_hat)) +
                         self.v_dpp * _cost(metrics, self.params) + self.params.weights[4] *
                         _switch_cost(action, last_action, self.params))
            admissible.append((objective, action_id, safe.certified))
            scores.append(CandidateScore(action_id, objective, None, True))
        if not admissible:
            return self._fallback(state, runtime, scores, "empty runtime-feasible set")
        _, action_id, certified = min(admissible)
        return Decision(self.actions[action_id], certified, False,
                        "DPP runtime-safe action" if certified else "unvalidated empirical demonstration",
                        tuple(scores))


class HysteresisController(_ControllerBase):
    """Algorithm 5: held N/M/S modes and separate entry/exit thresholds."""

    def __init__(self, *args: Any, mode_actions: Mapping[str, str],
                 theta_low: float = 0.35, theta_high: float = 0.60,
                 theta_severe: float = 0.85, hold_intervals: int = 3, **kwargs: Any):
        super().__init__(*args, **kwargs)
        if set(mode_actions) != {"N", "M", "S"} or any(
                action_id not in self.actions for action_id in mode_actions.values()):
            raise ValueError("HYS requires N/M/S actions in the same certified library")
        if not 0 <= theta_low < theta_high < theta_severe or not all(
                math.isfinite(v) for v in (theta_low, theta_high, theta_severe)):
            raise ValueError("HYS thresholds must satisfy 0 <= low < high < severe")
        if type(hold_intervals) is not int or hold_intervals < 0:
            raise ValueError("hold interval count must be a nonnegative integer")
        self.mode_actions = dict(mode_actions)
        self.theta_low, self.theta_high, self.theta_severe = theta_low, theta_high, theta_severe
        self.hold_intervals = hold_intervals
        self.mode = "N"
        self.held = hold_intervals

    def select(self, state: Sequence[float], belief: Sequence[float] | None,
               last_action: Action | None, runtime: RuntimeContext, *,
               stress: float | None = None) -> Decision:
        failure = self._region_failure(state, runtime)
        if failure:
            return Decision(None, False, True, failure)
        value = max(state) if stress is None else float(stress)
        if not math.isfinite(value) or value < 0:
            raise ValueError("HYS stress must be finite and nonnegative")
        target = self.mode
        if self.held >= self.hold_intervals:
            if (self.mode == "N" and value >= self.theta_high) or (
                    self.mode == "S" and value <= self.theta_high):
                target = "M"
            elif self.mode == "M" and value >= self.theta_severe:
                target = "S"
            elif self.mode == "M" and value <= self.theta_low:
                target = "N"
        action = self.actions[self.mode_actions[target]]
        safe = self.safety.check(action, runtime, state)
        self.held = 0 if target != self.mode else min(self.held + 1, self.hold_intervals)
        self.mode = target
        if not safe.allowed:
            return self._fallback(state, runtime, [], "HYS mode action failed runtime safety")
        return Decision(action, safe.certified, False,
                        "HYS runtime-safe action" if safe.certified else "unvalidated empirical demonstration")


class StressTracker:
    """EMA of maximum normalized telemetry; bins must be declared offline."""

    def __init__(self, thresholds: Sequence[float], *, smoothing: float = 0.80,
                 boundaries: Sequence[float] = (0.2, 0.4, 0.6, 0.8)):
        self.thresholds = _vector(thresholds, 7, "telemetry normalization")
        if any(v <= 0 for v in self.thresholds) or not 0 <= smoothing < 1:
            raise ValueError("stress normalizers must be positive; smoothing in [0,1)")
        self.boundaries = _vector(boundaries, 4, "stress boundaries", nonnegative=True)
        if tuple(sorted(set(self.boundaries))) != self.boundaries:
            raise ValueError("four stress boundaries must be strictly increasing")
        self.smoothing = smoothing
        self.value: float | None = None

    def update(self, telemetry: Sequence[float]) -> tuple[float, int]:
        y = _vector(telemetry, 7, "telemetry", nonnegative=True)
        current = max(v / threshold for v, threshold in zip(y, self.thresholds))
        self.value = current if self.value is None else (
            self.smoothing * self.value + (1 - self.smoothing) * current)
        return self.value, sum(self.value >= boundary for boundary in self.boundaries)
