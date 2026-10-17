"""Preauthorization and exact-roster regression tests, including missing members."""
import json
from pathlib import Path

import pytest

import simulation.engine as engine
from simulation.audit import recompute_run
from simulation.exogenous import generate_exogenous, load_config
from simulation.io import JsonlWriter, digest, file_hash, read_jsonl, write_json

ROOT = Path(__file__).resolve().parents[1]


def fixed_three_member_experiment(tmp_path, *, hold=0.0):
    c = load_config(ROOT / "simulation/config.json")
    c.update(nodes=3, gateways=1, local_contention_domains=1, backhaul_contention_domains=1,
             evaluation_seeds=[9], protected_fraction=1.0, batch_ready_hold_s=hold,
             drain_s=max(35.0, 30.0 + hold), contention_collision_per_extra_sender=0.0)
    c["disturbance"].update(affected_gateway_fraction=0.0, baseline_ber=1e-10,
        disturbed_ber=1e-10, baseline_external_tamper_probability=0.0,
        disturbed_external_tamper_probability=0.0, gateway_forgery_probability=0.0)
    exo = tmp_path / "exogenous"
    manifest = generate_exogenous(c, 9, exo)
    # A public source schedule, fixed BEFORE authorization or any packet event.
    with JsonlWriter(exo / "traffic.jsonl.gz") as stream:
        for node in range(3):
            stream.write({"id": f"n{node}:s0", "node": node, "sample": 0,
                          "time_s": 1.0 + .2 * node, "sampling_uniform": .1})
    manifest["files"]["traffic.jsonl.gz"] = file_hash(exo / "traffic.jsonl.gz")
    manifest["exogenous_digest"] = digest(manifest["files"])
    write_json(exo / "manifest.json", manifest)
    return c, exo


def test_all_sources_reuse_same_full_roster_ticket_authorized_before_arrivals(tmp_path):
    c, exo = fixed_three_member_experiment(tmp_path)
    out = tmp_path / "run"
    result = engine.run_one(c, 9, "without_markov", exo, out, ROOT / "simulation/controller_reference.json")
    events = list(read_jsonl(out / "events.jsonl.gz"))
    authorized = [r for r in events if r["event"] == "batch_authorized"]
    assert len(authorized) == 1 and authorized[0]["time_s"] == 0.0
    roster = ["n0:s0", "n1:s0", "n2:s0"]
    assert authorized[0]["roster"] == roster
    transfers = [r for r in events if r["event"] == "transfer_created"]
    assert len(transfers) == 4  # Three source envelopes plus one whole-roster aggregate.
    assert all(r["ticket_roster"] == roster and r["ticket_bytes"] == 2420 + 128 + 60 for r in transfers)
    assert all(r["time_s"] > authorized[0]["time_s"] for r in transfers)
    aggregate = next(r for r in transfers if r["kind"] == "aggregate")
    assert aggregate["reports"] == roster and aggregate["expiry_s"] == 31.0
    reports = list(read_jsonl(out / "reports.jsonl.gz"))
    assert {r["status"] for r in reports} == {"delivered_valid"}
    assert len({r["outcome_s"] for r in reports}) == 1
    assert result["raw_counts"]["whole_batch_outcomes"] == {"delivered_valid": 1}


def test_missing_member_rejects_entire_original_batch_without_partial_aggregation(tmp_path, monkeypatch):
    c, exo = fixed_three_member_experiment(tmp_path)
    original = engine.uniform
    def one_source_always_corrupted(seed, stream, *key):
        if stream == "frame_error" and str(key[0]).startswith("source/n1:s0/"):
            return 0.0
        return original(seed, stream, *key)
    monkeypatch.setattr(engine, "uniform", one_source_always_corrupted)
    out = tmp_path / "run"
    result = engine.run_one(c, 9, "without_markov", exo, out, ROOT / "simulation/controller_reference.json")
    events = list(read_jsonl(out / "events.jsonl.gz"))
    arrivals = {r["report"] for r in events if r["event"] == "authorized_member_received"}
    assert arrivals == {"n0:s0", "n2:s0"}
    assert not any(r["event"] == "transfer_created" and r["kind"] == "aggregate" for r in events)
    expired = next(r for r in events if r["event"] == "authorized_batch_expired")
    assert expired["roster"] == ["n0:s0", "n1:s0", "n2:s0"]
    assert expired["missing_members"] == ["n1:s0"]
    reports = list(read_jsonl(out / "reports.jsonl.gz"))
    assert {r["status"] for r in reports} == {"deadline_expired"}
    assert {r["outcome_s"] for r in reports} == {31.0}
    assert result["raw_counts"]["reports"]["deadline_expired"] == 3
    assert recompute_run(out, c) == result


def test_expiration_during_post_ready_hold_cannot_remove_expired_members(tmp_path):
    c, exo = fixed_three_member_experiment(tmp_path, hold=35.0)
    out = tmp_path / "run"
    result = engine.run_one(c, 9, "without_markov", exo, out, ROOT / "simulation/controller_reference.json")
    events = list(read_jsonl(out / "events.jsonl.gz"))
    assert len([r for r in events if r["event"] == "authorized_member_received"]) == 3
    assert not any(r["event"] == "transfer_created" and r["kind"] == "aggregate" for r in events)
    assert result["raw_counts"]["reports"]["deadline_expired"] == 3
    assert result["raw_counts"]["whole_batch_outcomes"] == {"deadline_expired": 1}


def test_independent_audit_rejects_aggregate_roster_shrinking_even_without_hash_check(tmp_path):
    c, exo = fixed_three_member_experiment(tmp_path)
    out = tmp_path / "run"
    engine.run_one(c, 9, "without_markov", exo, out, ROOT / "simulation/controller_reference.json")
    events = list(read_jsonl(out / "events.jsonl.gz"))
    aggregate = next(r for r in events if r["event"] == "transfer_created" and r["kind"] == "aggregate")
    aggregate["reports"].pop()
    with JsonlWriter(out / "events.jsonl.gz") as stream:
        for row in events:
            stream.write(row)
    with pytest.raises(ValueError, match="aggregate roster was modified"):
        recompute_run(out, c, verify_hashes=False)
