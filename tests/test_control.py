# SPDX-License-Identifier: MIT
"""Analytic and independently enumerated optimizer checks, execution receipts are recorded separately."""
from dataclasses import replace

import pytest

from daahe.calibration import validate_seed_split
from daahe.control import ControlModel, ControllerParams, MetricModel, RobustController, fallback_bound, l1_worst_case
from daahe.safety import Action, Certificate, RuntimeContext, SafetyFilter


def compositions(total, length):
    if length == 1:
        yield (total,)
    else:
        for first in range(total+1):
            for rest in compositions(total-first, length-1):
                yield (first,)+rest


def test_exact_l1_solver_matches_independent_rational_simplex_enumeration():
    # Rational feasible-polytope vertices lie on this tenth-grid in this case.
    p, c, radius = (.1,.2,.3,.2,.2), (-2.,.5,4.,1.,-1.), .6
    result = l1_worst_case(p,c,radius)
    candidates = [tuple(v/10 for v in integers) for integers in compositions(10,5)]
    optimum = max(sum(x*y for x,y in zip(candidate,c)) for candidate in candidates
                  if sum(abs(x-y) for x,y in zip(candidate,p)) <= radius+1e-12)
    assert result.value == pytest.approx(optimum)
    assert sum(result.distribution) == pytest.approx(1.0)
    assert min(result.distribution) >= 0
    assert sum(abs(x-y) for x,y in zip(result.distribution,p)) <= radius+1e-12
    assert result.moved_mass == pytest.approx(radius/2)


def test_l1_solver_zero_full_radius_and_ties():
    assert l1_worst_case([.5,.5], [2,6], 0).value == 4
    assert l1_worst_case([.5,.5], [2,6], 2).value == 6
    tied = l1_worst_case([.2,.8], [4,4], 2)
    assert tied.value == 4 and tied.moved_mass == 0


@pytest.mark.parametrize("p,c,radius", [([.3,.3],[1,2],.2), ([.5,.5],[1,float("nan")],.2), ([.5,.5],[1,2],2.1), ([-.1,1.1],[1,2],.1)])
def test_l1_solver_rejects_invalid_ambiguity_sets(p,c,radius):
    with pytest.raises(ValueError):
        l1_worst_case(p,c,radius)


def model(offset=.0):
    identity = tuple(tuple(float(i==j) for j in range(5)) for i in range(5))
    metric = MetricModel((1.,0.,0.,0.), (1.,0.,0.,0.), (0.,0.,0.,0.), (.1,0.,0.,0.))
    return ControlModel(transitions={"fb":identity}, offsets=((offset,)*3,)*5,
                        relief={"fb":(0.,0.,0.)}, error_radii={"fb":(0.,)*5},
                        transition_radii={"fb":.1}, pooled_metrics={"fb":metric})


def test_fallback_supremum_includes_interior_stationary_point():
    # (.8*z+.2)^2-.9*z^2=-.26*z^2+.32*z+.04, maximized at z=.32/.52.
    assert fallback_bound(model(.2), "fb", ControllerParams()) == pytest.approx(3*(.04+.32**2/(4*.26)))
    assert fallback_bound(model(0), "fb", ControllerParams()) == pytest.approx(0)


def cert(action):
    return Certificate(action.digest(),"a"*64,"b"*64,128.1,-128.,1.,10.,1.,100,65537,1000,.1,1)


def test_synthetic_bounds_never_become_strict_certificates():
    action = Action("fb",.5,16,1,64,0.,"p")
    runtime = RuntimeContext(profile_digests={"p":"a"*64},context_digest="b"*64)
    assert not SafetyFilter({"fb":cert(action)}).check(action,runtime,(0,0,0)).allowed
    permissive = replace(runtime,strict=False)
    result = SafetyFilter({"fb":cert(action)}).check(action,permissive,(0,0,0))
    assert result.allowed and not result.certified
    changed = replace(action,block_bytes=32)
    assert not SafetyFilter({"fb":cert(action)}).check(changed,permissive,(0,0,0)).allowed


def test_security_and_no_wrap_are_hard_gates_even_in_demo():
    action = Action("fb",.5,16,1,64,0.,"p")
    runtime = RuntimeContext(strict=False,profile_digests={"p":"a"*64},context_digest="b"*64)
    for invalid in (replace(cert(action),lambda_est_bits=127.9), replace(cert(action),single_node_plain_bound=32769),
                    replace(cert(action),workspace_bytes=10241), replace(cert(action),log2_epsilon_dec=-127.9)):
        assert not SafetyFilter({"fb":invalid}).check(action,runtime,(0,0,0)).allowed


def test_missing_certificate_and_out_of_region_cannot_apply_fallback():
    action = Action("fb",.5,16,1,64,0.,"p")
    controller = RobustController(model(),[action],{},"fb")
    decision = controller.select((0,0,0),(1,0,0,0,0),None,RuntimeContext(strict=False))
    assert decision.action is None and decision.alarm and not decision.certified
    decision = controller.select((1.1,0,0),(1,0,0,0,0),None,RuntimeContext(strict=False))
    assert decision.action is None and "outside" in decision.reason


def test_calibration_evaluation_seeds_must_be_disjoint():
    with pytest.raises(ValueError, match="overlap"):
        validate_seed_split([1,2],[3,4],[2,5])
    assert validate_seed_split([1],[2],[3])["evaluation"] == ["3"]
