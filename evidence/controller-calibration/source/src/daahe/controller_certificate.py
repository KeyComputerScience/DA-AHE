# SPDX-License-Identifier: MIT
"""Recomputable certificates for a declared controller model, not a deployment.

The verified successor set is R_+^3 intersected with a Euclidean ball of
radius e[a,j] around ReLU(kappa*z + offset[j] - relief[a]).  The current
domain, action library, gamma, beta and P are inputs; this module never fits or
changes them to make a check pass. Empirical residual radii can define this
mathematical set, but do not establish uniform coverage of a real process.

Arithmetic interprets finite binary model inputs exactly as rationals. The
fallback inequality uses exact piecewise-quadratic extrema and Young's
inequality, with a separate dyadic upper square-root bound as another valid
candidate. No sampled grid is used as a proof. Reports intentionally have a
different artifact type from external model-bound deployment evidence.
"""

from __future__ import annotations

from dataclasses import asdict
from decimal import Decimal, localcontext
from fractions import Fraction
from math import isfinite, isqrt
from typing import Any, Mapping, Sequence

from .control import ControlModel, ControllerParams
from .safety import Action, canonical_digest

SCOPE = "declared_model_only"
ARTIFACT_TYPE = "daahe-declared-controller-certificate"
SQRT_BITS = 256
# These multipliers tighten a proof bound, never the supplied controller.
YOUNG_MULTIPLIERS = tuple(Fraction(2) ** exponent for exponent in range(-16, 17))


def _rational(value: Any, label: str = "value") -> Fraction:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Fraction)):
        raise ValueError(f"{label} must be a finite real number")
    if isinstance(value, float) and not isfinite(value):
        raise ValueError(f"{label} must be finite")
    try:
        return Fraction(value)
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError(f"{label} must be a finite rational value") from error


def _record(value: Fraction) -> dict[str, str]:
    with localcontext() as context:
        context.prec = 24
        approximate = str(Decimal(value.numerator) / Decimal(value.denominator))
    return {"exact": str(value), "decimal_approx": approximate}


def sqrt_upper(value: Fraction, *, bits: int = SQRT_BITS) -> Fraction:
    """Return a dyadic bound with a directly checkable integer-square witness."""
    if value < 0 or type(bits) is not int or not 1 <= bits <= 4096:
        raise ValueError("sqrt needs a nonnegative rational and precision in 1..4096")
    numerator = value.numerator << (2 * bits)
    root = isqrt(numerator // value.denominator)
    if root * root * value.denominator < numerator:
        root += 1
    return Fraction(root, 1 << bits)


def coordinate_supremum(kappa: Fraction, offset: Fraction, upper: Fraction,
                        prediction_weight: Fraction, state_weight: Fraction
                        ) -> tuple[Fraction, Fraction]:
    """Exactly maximize a*ReLU(k*z+b)^2-c*z^2 on 0<=z<=upper.

    The inactive piece is decreasing because c>0. The active piece is a
    quadratic; endpoints, its kink and any interior stationary point suffice.
    The returned witness belongs to the declared interval.
    """
    if kappa < 0 or upper < 0 or prediction_weight <= 0 or state_weight <= 0:
        raise ValueError("coordinate supremum needs nonnegative k/domain and positive weights")
    candidates = {Fraction(0), upper}
    if kappa:
        kink = -offset / kappa
        if 0 <= kink <= upper:
            candidates.add(kink)
    quadratic = prediction_weight * kappa * kappa - state_weight
    if quadratic < 0:
        stationary = -prediction_weight * kappa * offset / quadratic
        if 0 <= stationary <= upper and kappa * stationary + offset >= 0:
            candidates.add(stationary)
    values = [(prediction_weight * max(kappa * z + offset, 0) ** 2
               - state_weight * z * z, z) for z in candidates]
    return max(values, key=lambda item: (item[0], -item[1]))


def fallback_drift_bounds(model: ControlModel, fallback_id: str,
                          params: ControllerParams) -> list[dict[str, Any]]:
    """Upper-bound Eq. (28) separately for every regime, without a grid.

    For each positive tau, 2*lambda_max*||hat z||*e is at most
    tau*||hat z||^2 + lambda_max^2*e^2/tau. Separable exact extrema then
    bound the entire cube. Taking the minimum of valid upper bounds is valid.
    The original norm-on-cube bound is also retained and can be tighter.
    """
    if fallback_id not in model.relief:
        raise ValueError("fallback is outside the declared action library")
    kappa = _rational(model.kappa_z)
    contraction = 1 - _rational(params.gamma)
    weights = tuple(_rational(v) for v in params.p_diagonal)
    maximum = max(weights)
    domain = tuple(_rational(v) for v in model.zcert_max)
    results = []
    for regime in range(5):
        offsets = tuple(_rational(model.offsets[regime][h])
                        - _rational(model.relief[fallback_id][h]) for h in range(3))
        radius = _rational(model.error_radii[fallback_id][regime])
        direct_terms = [coordinate_supremum(kappa, offsets[h], domain[h], weights[h],
                                            contraction * weights[h])[0]
                        for h in range(3)]
        norm_squared = sum(max(kappa * upper + b, 0) ** 2
                           for upper, b in zip(domain, offsets))
        norm_upper = sqrt_upper(norm_squared)
        direct = (sum(direct_terms) + 2 * maximum * radius * norm_upper
                  + maximum * radius * radius)
        candidates = [(direct, "coordinate_extrema_plus_dyadic_norm", None, direct_terms)]
        if radius:
            for tau in YOUNG_MULTIPLIERS:
                terms = [coordinate_supremum(kappa, offsets[h], domain[h], weights[h] + tau,
                                             contraction * weights[h])[0]
                         for h in range(3)]
                bound = (sum(terms) + maximum * radius * radius
                         + maximum * maximum * radius * radius / tau)
                candidates.append((bound, "young_coordinate_extrema", tau, terms))
        best, method, tau, terms = min(candidates, key=lambda item: item[0])
        results.append({
            "regime": regime,
            "upper_bound": _record(best),
            "beta": _record(_rational(params.beta)),
            "passes": best <= _rational(params.beta),
            "method": method,
            "young_multiplier": None if tau is None else _record(tau),
            "coordinate_suprema": [_record(term) for term in terms],
            "direct_bound": _record(direct),
            "norm_squared": _record(norm_squared),
            "norm_upper": _record(norm_upper),
            "sqrt_precision_bits": SQRT_BITS,
            "candidate_upper_bounds_checked": len(candidates),
        })
    return results


def _domain_check(model: ControlModel) -> dict[str, Any]:
    kappa = _rational(model.kappa_z)
    domain = tuple(_rational(v) for v in model.zcert_max)
    details = []
    for action in sorted(model.relief):
        for regime in range(5):
            radius = _rational(model.error_radii[action][regime])
            for h, upper in enumerate(domain):
                nominal_upper = max(kappa * upper + _rational(model.offsets[regime][h])
                                    - _rational(model.relief[action][h]), 0)
                successor_upper = nominal_upper + radius
                details.append({"action_id": action, "regime": regime, "coordinate": h,
                                "successor_upper": _record(successor_upper),
                                "domain_upper": _record(upper),
                                "passes": successor_upper <= upper})
    return {"status": "passed" if all(row["passes"] for row in details) else "failed",
            "method": "monotone ReLU box extrema plus coordinate projection of Euclidean ball",
            "covers": "every declared action and regime, including the initialization action",
            "details": details}


def _transition_check(model: ControlModel, assumptions: Mapping[str, Any]
                      ) -> dict[str, Any]:
    required = {"posterior_l1_bound", "kernel_row_l1_bounds"}
    if not required <= assumptions.keys():
        return {"status": "unchecked", "details": [],
                "reason": "Explicit posterior and per-row kernel uncertainty bounds are required"}
    posterior = _rational(assumptions["posterior_l1_bound"], "posterior_l1_bound")
    row_bounds = assumptions["kernel_row_l1_bounds"]
    if not 0 <= posterior <= 2 or not isinstance(row_bounds, Mapping):
        raise ValueError("posterior and kernel bounds must describe L1 simplex uncertainty")
    if set(row_bounds) != set(model.transitions):
        raise ValueError("kernel_row_l1_bounds must cover exactly the action library")
    details = []
    for action in sorted(model.transitions):
        rows = row_bounds[action]
        if (not isinstance(rows, (tuple, list)) or len(rows) != 5):
            raise ValueError("each action needs exactly five kernel row L1 bounds")
        radii = tuple(_rational(v, "kernel row L1 bound") for v in rows)
        if any(not 0 <= value <= 2 for value in radii):
            raise ValueError("kernel row L1 bounds must lie in [0,2]")
        required_radius = min(Fraction(2), posterior + max(radii))
        online_radius = _rational(model.transition_radii[action])
        details.append({"action_id": action, "posterior_l1_bound": _record(posterior),
                        "kernel_row_l1_bounds": [_record(v) for v in radii],
                        "required_prediction_radius": _record(required_radius),
                        "online_ambiguity_radius": _record(online_radius),
                        "passes": required_radius <= online_radius})
    return {"status": "passed" if all(row["passes"] for row in details) else "failed",
            "method": "Markov-kernel L1 contraction and triangle inequality, capped at simplex diameter",
            "assumption": "Declared true posterior and kernel belong to these sets at every permitted history",
            "coverage_of_actual_process_proven": False,
            "details": details}


def verify_declared_model(model: ControlModel, actions: Sequence[Action],
                          params: ControllerParams, fallback_id: str, *,
                          assumptions: Mapping[str, Any] | None = None,
                          runtime_domain: Sequence[float] | None = None,
                          online_adaptation: bool = False) -> dict[str, Any]:
    """Recompute geometric/drift checks; never issue external deployment evidence."""
    declarations = dict(assumptions or {})
    if declarations and declarations.get("scope") != SCOPE:
        raise ValueError("certificate assumptions must explicitly use declared_model_only scope")
    ids = [action.id for action in actions]
    if len(set(ids)) != len(ids) or set(ids) != set(model.transitions):
        raise ValueError("unique complete action library must match the model")
    if fallback_id not in ids:
        raise ValueError("fallback must belong to the unchanged action library")
    action_digests = {action.id: action.digest() for action in actions}
    if (model.metadata.get("action_digests") is not None
            and dict(model.metadata["action_digests"]) != action_digests):
        raise ValueError("model metadata does not bind the complete supplied actions")
    if runtime_domain is not None and tuple(runtime_domain) != tuple(model.zcert_max):
        raise ValueError("runtime and model domains must match; certificate cannot resize the domain")
    drift_details = fallback_drift_bounds(model, fallback_id, params)
    checks = {
        "domain_invariance": _domain_check(model),
        "fallback_drift": {
            "status": "passed" if all(row["passes"] for row in drift_details) else "failed",
            "fallback_action_id": fallback_id,
            "method": "uniform all-regime rational upper bounds on Eq. (28)",
            "details": drift_details,
        },
        "transition_set_containment": _transition_check(model, declarations),
        "online_adaptation": {
            "status": "failed" if online_adaptation else "passed",
            "reason": "Adaptive kernels require separate evolving-set proofs" if online_adaptation
            else "Frozen declared kernels; no online transition adaptation",
        },
    }
    subject = {"model_digest": model.digest(), "action_digests": action_digests,
               "controller_parameters": asdict(params), "fallback_action_id": fallback_id,
               "domain": list(model.zcert_max), "assumptions": declarations,
               "online_adaptation": online_adaptation}
    return {
        "schema_version": 1,
        "artifact_type": ARTIFACT_TYPE,
        "scope": SCOPE,
        "status": "verified_declared_model" if all(check["status"] == "passed"
                                                    for check in checks.values()) else "failed",
        "subject": subject,
        "subject_digest": canonical_digest(subject),
        "model_bound_kind": model.bound_kind,
        "arithmetic": "finite binary inputs interpreted exactly as rationals; 256-bit dyadic upper sqrt",
        "checks": checks,
        "deployment_certified": False,
        "full_system_certified": False,
        "empirical_uniform_coverage_proven": False,
        "online_gate_roundoff_certified": False,
        "resource_security_certificates_verified": False,
        "limitations": [
            "The stated successor and probability sets are assumptions, not inferred population bounds.",
            "Calibration holdout maxima do not prove uniform real-process or per-history coverage.",
            "Domain and drift certificates cover the declared model only; resources and cryptography remain separate.",
            "Ordinary floating-point runtime gates and external deployment evidence are not certified by this report.",
        ],
    }


def verify_controller_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Accept the complete controller.json emitted by the calibration runner."""
    model = ControlModel.from_dict(config["model"])
    actions = tuple(Action.from_dict(value) for value in config["actions"])
    params = ControllerParams(**config.get("parameters", {}))
    report = verify_declared_model(model, actions, params, config["fallback_id"],
                                   assumptions=config.get("certificate_assumptions"),
                                   runtime_domain=config.get("runtime", {}).get("zcert_max"),
                                   online_adaptation=bool(config.get("online_adaptation", False)))
    report["controller_config_digest"] = canonical_digest(config)
    return report


def verify_saved_report(config: Mapping[str, Any], report: Mapping[str, Any]) -> dict[str, Any]:
    """Detect stale, hand-edited or unrelated reports by independent recomputation."""
    recomputed = verify_controller_config(config)
    matches = canonical_digest(report) == canonical_digest(recomputed)
    return {"status": "matched" if matches else "failed", "scope": SCOPE,
            "matches_recomputation": matches,
            "recomputed_certificate_status": recomputed["status"],
            "deployment_certified": False, "full_system_certified": False}
