# SPDX-License-Identifier: MIT
"""Independent causal/binding regressions; execution receipts are recorded separately."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from daahe.calibration import TraceRow, calibrate_bundle, read_trace
from daahe.control import (ControlModel, ControlledHMM, ControllerParams,
                           EmissionModel, MetricModel, RobustController)
from daahe.replay import replay_csv
from daahe.safety import (Action, Certificate, EvidenceArtifact, REQUIRED_EVIDENCE,
                          RuntimeContext, SafetyFilter)


def identity():
    return tuple(tuple(float(i == j) for j in range(5)) for i in range(5))


def write_artifact(root, name, payload):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    (root / name).write_bytes(raw)
    return EvidenceArtifact(name, hashlib.sha256(raw).hexdigest(), "test-only reviewed-bound fixture")


def bound_controller(tmp_path, *, adapt=False):
    action = Action("fb", .5, 16, 1, 64, 0., "p")
    metric = MetricModel((1., 0., 0., 0.), (1., 0., 0., 0.),
                         (0., 0., 0., 0.), (.1, 0., 0., 0.))
    emissions = EmissionModel(((0.,) * 6,) * 5, ((1.,) * 6,) * 5, (.1,) * 5)
    model = ControlModel({"fb": identity()}, ((0.,) * 3,) * 5,
                         {"fb": (0.,) * 3}, {"fb": (0.,) * 5}, {"fb": .1},
                         {"fb": metric}, emissions=emissions, bound_kind="external",
                         metadata={"action_digests": {"fb": action.digest()}})
    runtime = RuntimeContext(evidence_root=str(tmp_path), profile_digests={"p": "a" * 64},
                             context_digest="b" * 64)
    cert = Certificate(action.digest(), "a" * 64, "b" * 64, 128.1, -128.,
                       1., 10., 1., 100, 65537, 1000, .1, 1,
                       kind="external")
    resource_evidence = {}
    for claim in REQUIRED_EVIDENCE:
        resource_evidence[claim] = write_artifact(tmp_path, claim + ".json", {
            "schema_version": 1, "artifact_type": "daahe-action-bound", "claim": claim,
            "subject": cert.evidence_subject(),
            "proof_review": "Test identity fixture, not a real security or resource proof.",
        })
    cert = replace(cert, evidence=resource_evidence)
    controller = RobustController(model, [action], {"fb": cert}, "fb",
                                  hmm=ControlledHMM(model, adapt=adapt))
    subject = controller.evidence_subject(runtime)
    evidence = {}
    for claim in ("state_error", "transition", "domain") + (("adaptation",) if adapt else ()):
        evidence[claim] = write_artifact(tmp_path, claim + ".json", {
            "schema_version": 1, "artifact_type": "daahe-model-bound",
            "claim": claim, "subject": subject,
            "proof_review": "A test identity fixture never establishes network bounds.",
        })
    model = replace(model, bound_evidence=evidence)
    return (RobustController(model, [action], {"fb": cert}, "fb",
                             hmm=ControlledHMM(model, adapt=adapt)), runtime)


def select_zero(controller, runtime):
    return controller.select((0., 0., 0.), (1., 0., 0., 0., 0.), None, runtime)


def test_matching_model_identity_passes_and_evidence_does_not_change_model_digest(tmp_path):
    controller, runtime = bound_controller(tmp_path)
    assert controller.model.digest() == replace(controller.model, bound_evidence={}).digest()
    assert select_zero(controller, runtime).certified


def test_action_reports_bind_all_bounds_without_evidence_hash_cycle(tmp_path):
    controller, runtime = bound_controller(tmp_path)
    action = controller.actions["fb"]
    cert = controller.safety.certificates["fb"]
    assert cert.evidence_subject() == replace(cert, evidence={}).evidence_subject()
    # This new value still passes the numerical gate; its old proof identity must fail.
    changed = replace(cert, noise_bound=2.)
    result = SafetyFilter({"fb": changed}).check(action, runtime, (0., 0., 0.))
    assert not result.allowed and not result.certified
    assert any("subject does not match" in reason for reason in result.reasons)


def test_hash_correct_unrelated_action_report_is_rejected(tmp_path):
    controller, runtime = bound_controller(tmp_path)
    cert = controller.safety.certificates["fb"]
    evidence = dict(cert.evidence)
    evidence["security"] = write_artifact(tmp_path, "unrelated-security.json", {"note": "unrelated"})
    result = SafetyFilter({"fb": replace(cert, evidence=evidence)}).check(
        controller.actions["fb"], runtime, (0., 0., 0.))
    assert not result.allowed and not result.certified
    assert any("invalid action-bound report" in reason for reason in result.reasons)


def test_tightened_runtime_budget_preserves_identity_but_enforces_numeric_gate(tmp_path):
    controller, runtime = bound_controller(tmp_path)
    assert select_zero(controller, replace(runtime, max_workspace_bytes=1000)).certified
    result = controller.safety.check(controller.actions["fb"],
                                     replace(runtime, max_workspace_bytes=999), (0., 0., 0.))
    assert not result.allowed
    assert "streaming workspace exceeds available budget" in result.reasons
    assert not any("subject does not match" in reason for reason in result.reasons)


@pytest.mark.parametrize("change", ["radius", "matrix"])
def test_stale_evidence_is_rejected_after_valid_transition_model_change(tmp_path, change):
    controller, runtime = bound_controller(tmp_path)
    if change == "radius":
        changed = replace(controller.model, transition_radii={"fb": .2})
    else:
        changed = replace(controller.model, transitions={"fb": ((.2,) * 5,) * 5})
    assert changed.digest() != controller.model.digest()
    stale = RobustController(changed, list(controller.actions.values()),
                             controller.safety.certificates, "fb")
    result = select_zero(stale, runtime)
    assert result.action is None and not result.certified
    assert "subject does not match" in result.reason


@pytest.mark.parametrize("field", ["context", "region", "gamma"])
def test_model_report_binds_context_region_and_lyapunov_parameters(tmp_path, field):
    controller, runtime = bound_controller(tmp_path)
    if field == "context":
        runtime = replace(runtime, context_digest="c" * 64)
    elif field == "region":
        runtime = replace(runtime, zcert_max=(.5, .5, .5))
    else:
        controller.params = replace(controller.params, gamma=.2)
    result = select_zero(controller, runtime)
    assert result.action is None and "subject does not match" in result.reason


def test_hash_correct_unrelated_report_cannot_certify_model(tmp_path):
    controller, runtime = bound_controller(tmp_path)
    evidence = dict(controller.model.bound_evidence)
    evidence["state_error"] = write_artifact(tmp_path, "unrelated.json", {"unrelated": True})
    changed = replace(controller.model, bound_evidence=evidence)
    controller = RobustController(changed, list(controller.actions.values()),
                                  controller.safety.certificates, "fb")
    assert "invalid model-bound report" in select_zero(controller, runtime).reason


def test_adaptation_report_binds_actual_update_hyperparameters(tmp_path):
    controller, runtime = bound_controller(tmp_path, adapt=True)
    assert select_zero(controller, runtime).certified
    stale_hmm = ControlledHMM(controller.model, adapt=True, discount=.5)
    stale = RobustController(controller.model, list(controller.actions.values()),
                             controller.safety.certificates, "fb", hmm=stale_hmm)
    assert "subject does not match" in select_zero(stale, runtime).reason


def test_hmm_uses_supplied_previous_bin_and_preserves_transition_mask(tmp_path):
    controller, _ = bound_controller(tmp_path)
    swap = tuple(tuple(float(j == (1 - i if i < 2 else i)) for j in range(5))
                 for i in range(5))
    model = replace(controller.model, transitions_by_bin={"fb": (identity(), swap)})
    hmm = ControlledHMM(model, initial=(.75, .25, 0., 0., 0.), adapt=True)
    # Identical emissions leave the Bayesian posterior equal to the causal prior.
    posterior = hmm.update((0.,) * 7, "fb", stress_bin=1)
    assert posterior == pytest.approx((.25, .75, 0., 0., 0.))
    assert sum(sum(row) for row in hmm.counts[("fb", 1)]) == pytest.approx(1.)
    for nominal, adapted in zip(swap, hmm.kernel("fb", 1)):
        assert sum(adapted) == pytest.approx(1.)
        assert all(value == 0. for expected, value in zip(nominal, adapted) if expected == 0.)


def test_replay_dpp_has_fallback_switching_cost_but_no_first_row_outcome_update(tmp_path):
    source = Path(__file__).resolve().parents[1] / "simulation" / "controller_reference.json"
    data = json.loads(source.read_text())
    data["v_dpp"] = 0.
    config = tmp_path / "control.json"
    config.write_text(json.dumps(data))
    telemetry = tmp_path / "current.csv"
    telemetry.write_text("time_s,queue,loss,delay,ber,anomaly,tamper,noise_utilization\n"
                         "0,0.5,0.0024,0.6,0.001,0.2,0,0.4\n")
    result = replay_csv(config, telemetry, method="dpp", allow_synthetic=True)
    assert result["initial_action_id"] == "fallback"
    scores = {item["action_id"]: item for item in result["decisions"][0]["decision"]["scores"]}
    assert scores["fallback"]["objective"] == 0.
    assert scores["nominal"]["objective"] > 0.
    da_result = replay_csv(config, telemetry, method="da-ahe", allow_synthetic=True)
    assert da_result["initial_action_id"] == "nominal"
    assert da_result["decisions"][0]["belief"] == (1., 0., 0., 0., 0.)


def test_calibration_bundle_preserves_negative_dpp_excess_and_noise_timing():
    action = Action("fb", .5, 16, 1, 64, 0., "p")
    def rows(seed, next_noise=.2):
        return [TraceRow(seed, float(i), "fb", i, i, (0.,) * 3, (0.,) * 3,
                         (.1, .001, .25, .001, .1, 0., .4),
                         (1., .25, 0., next_noise), next_loss=.001) for i in range(5)]
    bundle = calibrate_bundle(rows("train"), rows("holdout", .7), [action],
                              delay_threshold=.5, loss_threshold=.002,
                              evaluation_seeds=["evaluation"],
                              nominal_transitions={"fb": ((.2,) * 5,) * 5})
    # All causal states are zero. The regularized intercept has a closed form.
    coefficients = bundle["dpp_violation_models"]["fb"]
    assert [weights[0] for weights in coefficients] == pytest.approx(
        [5 * target / 5.001 for target in (-.5, -.5, -.8)])
    assert all(weights[1:] == [0., 0., 0.] for weights in coefficients)
    assert bundle["model"]["emissions"]["means"][0][-1] == .4
    assert bundle["model"]["pooled_metrics"]["fb"]["noise_utilization"][0] == pytest.approx(1. / 5.001)
    assert bundle["calibration_metadata"]["dpp_fit_partition"] == "training_only"
    bad_training = rows("train")
    bad_training[0] = replace(bad_training[0], state=(.1, 0., 0.))
    with pytest.raises(ValueError, match="current state disagrees"):
        calibrate_bundle(bad_training, rows("holdout"), [action],
                         delay_threshold=.5, loss_threshold=.002,
                         evaluation_seeds=["evaluation"],
                         nominal_transitions={"fb": ((.2,) * 5,) * 5})


def test_ambiguous_legacy_calibration_noise_column_is_rejected(tmp_path):
    path = tmp_path / "legacy.csv"
    path.write_text("seed,time_s,noise_utilization\nx,0,0.4\n")
    with pytest.raises(ValueError, match="legacy calibration"):
        read_trace(path)
