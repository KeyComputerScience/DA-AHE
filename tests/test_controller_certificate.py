# SPDX-License-Identifier: MIT
"""Independent extrema, boundary, provenance and scope checks for certificates."""
from copy import deepcopy
from dataclasses import asdict, replace
from fractions import Fraction
import json
from pathlib import Path
import subprocess
import sys

import pytest

from daahe.control import ControlModel, ControllerParams, MetricModel, RobustController
from daahe.controller_certificate import (coordinate_supremum, fallback_drift_bounds,
                                           sqrt_upper, verify_controller_config,
                                           verify_declared_model, verify_saved_report)
from daahe.safety import Action, Certificate, EvidenceArtifact, RuntimeContext


def declared_model(*, kappa=.3, offsets=(.05, .05, .05), radius=.01, ambiguity=.1):
    action = Action("fallback", .5, 16, 1, 64, 0., "profile")
    identity = tuple(tuple(float(i == j) for j in range(5)) for i in range(5))
    metric = MetricModel((1., 0., 0., 0.), (1., 0., 0., 0.),
                         (0., 0., 0., 0.), (.1, 0., 0., 0.))
    model = ControlModel({action.id: identity}, (offsets,) * 5,
                         {action.id: (0., 0., 0.)}, {action.id: (radius,) * 5},
                         {action.id: ambiguity}, {action.id: metric}, kappa_z=kappa,
                         zcert_max=(1., 1., 1.), bound_kind="empirical",
                         metadata={"action_digests": {action.id: action.digest()}})
    return model, action


def assumptions(*, posterior=.05, kernel=.05):
    return {"scope": "declared_model_only", "posterior_l1_bound": posterior,
            "kernel_row_l1_bounds": {"fallback": [kernel] * 5},
            "state_error_interpretation": "declared Euclidean balls, empirical coverage separate"}


def configuration():
    model, action = declared_model()
    return {"model": model.to_dict(), "actions": [action.to_dict()],
            "parameters": asdict(ControllerParams()), "fallback_id": action.id,
            "runtime": {"zcert_max": [1., 1., 1.]},
            "certificate_assumptions": assumptions(), "online_adaptation": False}


def test_square_root_has_exact_integer_witness_and_one_dyadic_ulp_accuracy():
    for value in (Fraction(0), Fraction(2), Fraction(7, 13), Fraction(10**100, 3)):
        bound = sqrt_upper(value, bits=64)
        assert bound * bound >= value
        if bound:
            assert (bound - Fraction(1, 2**64)) ** 2 < value
    with pytest.raises(ValueError):
        sqrt_upper(Fraction(-1))


def test_coordinate_extremum_finds_interior_maximum_and_relu_kink():
    # 2*(.8*z+.2)^2-1.8*z^2 has its maximum at z=8/13.
    bound, witness = coordinate_supremum(Fraction(4, 5), Fraction(1, 5), Fraction(1),
                                        Fraction(2), Fraction(9, 5))
    assert witness == Fraction(8, 13)
    exhaustive = [Fraction(i, 130) for i in range(131)]
    values = [2 * (Fraction(4, 5) * z + Fraction(1, 5)) ** 2
              - Fraction(9, 5) * z * z for z in exhaustive]
    assert bound == max(values)
    assert coordinate_supremum(Fraction(1), Fraction(-1, 2), Fraction(1),
                               Fraction(1), Fraction(9, 10))[0] == 0


def test_young_fallback_bound_dominates_independently_evaluated_states():
    model, action = declared_model()
    params = ControllerParams()
    bounds = fallback_drift_bounds(model, action.id, params)
    # Independently evaluate the original (17), not the verifier's Young bound.
    for x in (0., .04, .2, .8, 1.):
        for y in (0., .1, .5, 1.):
            for z in (0., .3, .7, 1.):
                prediction = [max(.3 * value + .05, 0) for value in (x, y, z)]
                exact_terms = [Fraction(value) ** 2 for value in prediction]
                norm = sqrt_upper(sum(exact_terms))
                evaluated = (sum(exact_terms) + 2 * Fraction(.01) * norm + Fraction(.01) ** 2
                             - (1 - Fraction(.1)) * sum(Fraction(v) ** 2 for v in (x, y, z)))
                # Prediction above uses floats; allow their tiny rounding discrepancy.
                assert evaluated <= Fraction(bounds[0]["upper_bound"]["exact"]) + Fraction(1, 10**14)
    assert all(row["passes"] for row in bounds)
    assert bounds[0]["method"] == "young_coordinate_extrema"
    assert Fraction(bounds[0]["upper_bound"]["exact"]) < Fraction(bounds[0]["direct_bound"]["exact"])


def test_declared_model_pass_does_not_promote_empirical_inputs_or_deployment():
    config = configuration()
    report = verify_controller_config(config)
    assert report["status"] == "verified_declared_model"
    assert report["scope"] == "declared_model_only"
    assert report["model_bound_kind"] == "empirical"
    for flag in ("deployment_certified", "full_system_certified", "empirical_uniform_coverage_proven",
                 "online_gate_roundoff_certified", "resource_security_certificates_verified"):
        assert report[flag] is False
    assert config == configuration()  # Verifying never repairs beta, domain or model.


def test_domain_escape_and_noncontracting_fallback_are_retained_as_failures():
    model, action = declared_model(kappa=1., offsets=(.1, 0., 0.), radius=0.)
    report = verify_declared_model(model, [action], ControllerParams(), action.id,
                                   assumptions=assumptions())
    assert report["checks"]["domain_invariance"]["status"] == "failed"
    assert report["checks"]["fallback_drift"]["status"] == "failed"
    assert report["status"] == "failed"
    assert report["subject"]["controller_parameters"]["beta"] == .02
    assert report["subject"]["domain"] == [1., 1., 1.]


def test_tight_binary_boundary_is_not_rounded_into_a_pass():
    model, action = declared_model(kappa=0., offsets=(.1, 0., 0.), radius=0.)
    params = replace(ControllerParams(), beta=.01)
    # float .1 squared is larger than the exact binary float .01.
    assert Fraction(.1) ** 2 > Fraction(.01)
    report = verify_declared_model(model, [action], params, action.id,
                                   assumptions=assumptions())
    assert report["checks"]["fallback_drift"]["status"] == "failed"


def test_missing_transition_set_and_uncovered_posterior_do_not_pass():
    model, action = declared_model()
    absent = verify_declared_model(model, [action], ControllerParams(), action.id)
    assert absent["checks"]["transition_set_containment"]["status"] == "unchecked"
    assert absent["status"] == "failed"
    uncovered = verify_declared_model(model, [action], ControllerParams(), action.id,
                                      assumptions=assumptions(posterior=.1, kernel=.1))
    assert uncovered["checks"]["transition_set_containment"]["status"] == "failed"
    covered = verify_declared_model(replace(model, transition_radii={action.id: 2.}), [action],
                                    ControllerParams(), action.id,
                                    assumptions=assumptions(posterior=2., kernel=2.))
    assert covered["checks"]["transition_set_containment"]["status"] == "passed"


def test_changed_parameters_actions_domains_and_tampered_reports_are_detected():
    config = configuration()
    report = verify_controller_config(config)
    assert verify_saved_report(config, report)["matches_recomputation"]
    changed = deepcopy(config)
    changed["parameters"]["beta"] = .021
    assert not verify_saved_report(changed, report)["matches_recomputation"]
    tampered = deepcopy(report)
    tampered["checks"]["fallback_drift"]["details"][0]["upper_bound"]["exact"] = "0"
    assert not verify_saved_report(config, tampered)["matches_recomputation"]
    changed = deepcopy(config)
    changed["actions"][0]["block_bytes"] = 32
    with pytest.raises(ValueError, match="complete supplied actions"):
        verify_controller_config(changed)
    changed = deepcopy(config)
    changed["runtime"]["zcert_max"][0] = 2.
    with pytest.raises(ValueError, match="cannot resize"):
        verify_controller_config(changed)


def test_declared_certificate_cannot_satisfy_strict_external_evidence(tmp_path):
    config = configuration()
    model = ControlModel.from_dict(config["model"])
    action = Action.from_dict(config["actions"][0])
    report = verify_controller_config(config)
    raw = json.dumps(report).encode()
    import hashlib
    path = tmp_path / "declared.json"
    path.write_bytes(raw)
    artifact = EvidenceArtifact("declared.json", hashlib.sha256(raw).hexdigest(),
                                "declared-model arithmetic only")
    ok, reason = artifact.check_model_binding(tmp_path, report["subject"], "domain")
    assert not ok and "schema or claim" in reason
    certificate = Certificate(action.digest(), "a" * 64, "b" * 64, 128.1, -128., 1.,
                              10., 1., 100, 65537, 1000, .1, 1)
    runtime = RuntimeContext(evidence_root=str(tmp_path), profile_digests={"profile": "a" * 64},
                             context_digest="b" * 64)
    controller = RobustController(model, [action], {action.id: certificate}, action.id)
    decision = controller.select((0., 0., 0.), (1., 0., 0., 0., 0.), None, runtime)
    assert decision.action is None and not decision.certified


def test_adaptation_requires_a_separate_proof():
    config = configuration()
    config["online_adaptation"] = True
    report = verify_controller_config(config)
    assert report["checks"]["online_adaptation"]["status"] == "failed"


def test_cli_preserves_failed_report_and_refuses_overwrite(tmp_path):
    root = Path(__file__).resolve().parents[1]
    config = configuration()
    config.pop("certificate_assumptions")
    source, output = tmp_path / "controller.json", tmp_path / "certificate.json"
    source.write_text(json.dumps(config))
    command = [sys.executable, str(root / "tools/verify_controller_certificate.py"),
               "--controller", str(source), "--output", str(output)]
    first = subprocess.run(command, capture_output=True, text=True, check=False)
    assert first.returncode == 2
    saved = output.read_bytes()
    assert json.loads(saved)["status"] == "failed"
    second = subprocess.run(command, capture_output=True, text=True, check=False)
    assert second.returncode == 1 and output.read_bytes() == saved
    audit = subprocess.run([sys.executable, str(root / "tools/verify_controller_certificate.py"),
                            "--controller", str(source), "--verify-report", str(output)],
                           capture_output=True, text=True, check=False)
    assert audit.returncode == 0
    result = json.loads(audit.stdout)
    assert result["status"] == "matched" and result["recomputed_certificate_status"] == "failed"
