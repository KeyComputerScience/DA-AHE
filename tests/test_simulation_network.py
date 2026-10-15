"""Network conservation, common budgets, causal feedback and deterministic replay."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from simulation.audit import recompute_run, recovery_from_epochs
from simulation import METHODS
from simulation.engine import fragment_block, run_one
from simulation.exogenous import generate_exogenous, load_config, validate_bound_artifacts, validate_config
from simulation.io import read_jsonl

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "simulation/controller_fixture.json"


def small_config():
    c = load_config(ROOT / "simulation/config.json")
    c.update(nodes=8, gateways=2, local_contention_domains=2, backhaul_contention_domains=2,
             evaluation_seeds=[23], protected_fraction=.25)
    return c


def execute(tmp_path, c, method="da-ahe", name="run", seed=23):
    exo = tmp_path / (name + "-exo")
    generate_exogenous(c, seed, exo)
    out = tmp_path / name
    result = run_one(c, seed, method, exo, out, CONTROLLER)
    return result, out


def test_fragment_wire_sizes_include_all_headers_and_fragmentation():
    c = small_config()
    assert fragment_block(32, c) == [(75, 111)]
    assert fragment_block(64, c) == [(93, 133), (14, 54)]
    assert sum(wire for _, wire in fragment_block(64, c)) == 187
    assert all(wire <= c["max_psdu_bytes"] + c["phy_bytes"] for _, wire in fragment_block(64, c))


def test_security_label_cannot_keep_old_ciphertext_wire_budget():
    c = small_config()
    assert c["cryptographic_parameters"]["module_rank"] == 6
    assert c["protected_ciphertext_bytes"] == 7168
    validate_bound_artifacts(c, ROOT)
    c["protected_ciphertext_bytes"] = 4096
    with pytest.raises(ValueError, match="ciphertext bytes do not match"):
        validate_config(c)


def test_old_tuple_cannot_reuse_new_security_report_label():
    c = small_config()
    c["cryptographic_parameters"].update(module_rank=3, n=768, m=768)
    c["protected_ciphertext_bytes"] = 4096
    validate_config(c)  # Internally coherent wire arithmetic alone is insufficient.
    with pytest.raises(ValueError, match="tuple differs from the bound security profile"):
        validate_bound_artifacts(c, ROOT)


def test_identical_seed_replays_bit_identical_raw_and_exogenous(tmp_path):
    c = small_config()
    one, out = execute(tmp_path, c, name="one")
    two, second = execute(tmp_path, c, name="two")
    assert one == two
    first_manifest = json.loads((out / "manifest.json").read_text())
    second_manifest = json.loads((second / "manifest.json").read_text())
    assert first_manifest["raw_files"] == second_manifest["raw_files"]
    assert first_manifest["exogenous_digest"] == second_manifest["exogenous_digest"]
    assert recompute_run(out, c) == one


def test_every_source_and_aggregate_transmits_configured_ticket(tmp_path):
    c = small_config()
    _, out = execute(tmp_path, c)
    transfers = [r for r in read_jsonl(out / "events.jsonl.gz") if r["event"] == "transfer_created"]
    assert {r["kind"] for r in transfers} >= {"source", "aggregate"}
    for row in transfers:
        if row["kind"] == "repair":
            continue
        assert row["ticket_signature_bytes"] == 2420
        assert row["ticket_bytes"] == 2420 + 128 + 20 * len(row["ticket_roster"])
        assert row["payload_bytes"] > row["ticket_bytes"]


def test_closed_loop_actions_change_actual_generated_packets_not_fixed_telemetry(tmp_path):
    c = small_config()
    adaptive, a = execute(tmp_path, c, "da-ahe", name="adaptive")
    fixed, b = execute(tmp_path, c, "without_markov", name="fixed")
    assert adaptive["exogenous_digest"] == fixed["exogenous_digest"]
    assert adaptive["raw_counts"]["reports"]["opportunities"] == fixed["raw_counts"]["reports"]["opportunities"] == 8
    assert adaptive["raw_counts"]["wire_bytes"] != fixed["raw_counts"]["wire_bytes"]
    first, second = list(read_jsonl(a / "epochs.jsonl.gz")), list(read_jsonl(b / "epochs.jsonl.gz"))
    assert any(x["telemetry"] != y["telemetry"] for x, y in zip(first, second))
    assert not adaptive["all_decisions_certified"]


def test_future_disturbance_cannot_change_prior_decisions_or_measurements(tmp_path):
    c = small_config()
    _, a = execute(tmp_path, c, name="early")
    later = deepcopy(c)
    later["disturbance"].update(start_s=60.0, end_s=80.0)
    _, b = execute(tmp_path, later, name="late")
    first = [row for row in read_jsonl(a / "epochs.jsonl.gz") if row["time_s"] < 30]
    second = [row for row in read_jsonl(b / "epochs.jsonl.gz") if row["time_s"] < 30]
    assert first == second


def test_forced_bad_radio_obeys_retry_budget_and_conserves_losses(tmp_path):
    c = small_config()
    c["disturbance"].update(baseline_ber=1.0, disturbed_ber=1.0)
    summary, out = execute(tmp_path, c, "without_markov")
    reports = summary["raw_counts"]["reports"]
    assert reports["opportunities"] == reports["admitted"] == reports["deadline_expired"] == 8
    frames = list(read_jsonl(out / "packets.jsonl.gz"))
    assert all(row["attempts"] == c["max_retries"] + 1 for row in frames)
    assert summary["metrics"]["observed_residual_loss_fraction"] == 1.0


def test_without_hve_hidden_forgery_is_not_oracle_feedback(tmp_path):
    c = small_config()
    c["disturbance"].update(baseline_ber=0.0, disturbed_ber=0.0,
        baseline_external_tamper_probability=0.0, disturbed_external_tamper_probability=0.0,
        gateway_forgery_probability=1.0, affected_gateway_fraction=0.0)
    c["contention_collision_per_extra_sender"] = 0.0
    summary, out = execute(tmp_path, c, "without_hve")
    assert summary["raw_counts"]["reports"]["delivered_invalid"] > 0
    observations = list(read_jsonl(out / "epochs.jsonl.gz"))
    assert all(row["telemetry"][5] == 0.0 for row in observations)
    assert all(row["telemetry"][1] == 0.0 for row in observations)


def test_recovery_requires_populated_consecutive_windows_and_right_censors():
    c = small_config()
    rows = [{"time_s": 30.0, "completed_reports": 4, "telemetry": [0, .5, 1, 0, 0, 0, 0]},
            {"time_s": 35.0, "completed_reports": 0, "telemetry": [0, 0, 0, 0, 0, 0, 0]},
            {"time_s": 40.0, "completed_reports": 4, "telemetry": [0, 0, 1, 0, 0, 0, 0]}]
    result = recovery_from_epochs(rows, c)
    assert result["right_censored"] and result["recovery_completion_s"] is None
    rows.append({"time_s": 45.0, "completed_reports": 4, "telemetry": [0, 0, 1, 0, 0, 0, 0]})
    result = recovery_from_epochs(rows, c)
    assert not result["right_censored"] and result["elapsed_from_onset_s"] == 15.0


def test_corrupted_raw_file_fails_hash_verification(tmp_path):
    c = small_config()
    _, out = execute(tmp_path, c)
    with (out / "reports.jsonl.gz").open("ab") as stream:
        stream.write(b"corrupted")
    with pytest.raises(ValueError, match="checksum"):
        recompute_run(out, c)


@pytest.mark.parametrize("method", METHODS)
def test_all_seven_methods_execute_with_conserved_opportunities(tmp_path, method):
    c = small_config()
    summary, out = execute(tmp_path, c, method)
    reports = summary["raw_counts"]["reports"]
    assert reports["opportunities"] == c["nodes"]
    assert reports["opportunities"] == (reports.get("admitted", 0) +
        reports.get("sampling_skipped", 0) + reports.get("controller_stopped", 0))
    assert summary["status"] == "independent_experimental_uncertified"
    assert recompute_run(out, c) == summary
