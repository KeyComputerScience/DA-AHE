"""Frame denominators and model diagnostics stay separate from report outcomes."""
from simulation.audit import (
    recovery_observation, repair_activity_counts, unique_frame_counts,
    verification_report_counts,
)
import pytest


def test_unique_frames_conserve_delivery_loss_and_unresolved():
    result = unique_frame_counts(12, {"received": 6, "queue_overflow": 1,
        "deadline": 1, "retry_exhausted:channel_error": 2, "administratively_censored": 1})
    assert result == {"offered": 12, "delivered": 6, "lost": 4, "unresolved": 2}
    with pytest.raises(ValueError, match="exceed"):
        unique_frame_counts(2, {"received": 3})
    with pytest.raises(ValueError, match="unknown"):
        unique_frame_counts(2, {"other": 1})


def test_zero_frame_denominator_has_no_manufactured_loss():
    assert unique_frame_counts(0, {}) == {
        "offered": 0, "delivered": 0, "lost": 0, "unresolved": 0}


def test_recovery_observations_keep_no_excursion_separate():
    base = {"status": "right_censored", "observation_end_s": 125.,
            "disturbance_onset_s": 30., "elapsed_from_onset_s": 95.}
    result = recovery_observation(base)
    assert result["censor_duration_s"] == 95. and result["observed_duration_s"] is None
    base.update(status="no_observed_excursion", elapsed_from_onset_s=0.)
    result = recovery_observation(base)
    assert result["analysis_eligible"] is False
    assert result["time_to_event_or_censor_s"] is None
    base.update(status="observed_recovery", elapsed_from_onset_s=15.)
    result = recovery_observation(base)
    assert result["event_observed"] and result["observed_duration_s"] == 15.


def test_verification_coverage_counts_invalid_accepts_in_denominator():
    reports = {"delivered_valid": 8, "delivered_invalid": 2, "integrity_rejected": 3}
    off = verification_report_counts(reports, False)
    assert off["accepted_reports"] == 10
    assert off["verification_enabled_accepted_reports"] == 0
    on = verification_report_counts(reports, True)
    assert on["verification_enabled_accepted_reports"] == 10
    assert "not cryptographic detection" in on["semantics"]


def test_selected_repair_epochs_are_distinct_from_actual_actuations():
    epochs = [{"decision": {"action": {"repair": 1.}}},
              {"decision": {"action": {"repair": 0.}}},
              {"decision": {"action": None}}]
    result = repair_activity_counts(epochs, "da-ahe", 3, 1, 1)
    assert result["selected_control_epochs"] == 1
    assert result["actuations_unresolved"] == 1
    assert repair_activity_counts(epochs, "without_route_repair", 0, 0, 0)["enabled_control_epochs"] == 0
    with pytest.raises(ValueError):
        repair_activity_counts(epochs, "da-ahe", 1, 2, 0)
