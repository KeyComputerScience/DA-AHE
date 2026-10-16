# SPDX-License-Identifier: MIT
"""Analytic paired fixtures for schema, provenance, censoring, and publication exports."""
import csv
import json

import pytest

from simulation import STATUS
from simulation.audit import paired_campaign_summary
from simulation.io import digest, file_hash, write_json
from tools.export_performance_evaluation import (
    BOUND_ROLES, FIELDS, FIGURES, METRICS, export_campaign, load_campaign, paired_statistics,
    recovery_summary, validate_epochs, write_rows,
)


def analytic_rows(seeds=(61, 62), methods=("da-ahe", "dpp", "without_hve")):
    rows = []
    for i, seed in enumerate(seeds):
        for method in methods:
            valid = .5 + .2 * i
            admission = .5 + .1 * i
            invalid = .05 if method == "without_hve" else 0.
            delay = (1., 7.)[i] if method == "da-ahe" else (4., 12.)[i]
            metrics = {
                "accepted_delivery_fraction_per_admitted": valid + invalid,
                "invalid_acceptance_fraction_per_admitted": invalid,
                "modeled_cpu_energy_j_all_run": 1. + i,
                "modeled_radio_tx_energy_j_all_run": 2. + i,
                "observed_residual_loss_fraction": 1. - valid - invalid,
                "source_admission_fraction": admission,
                "valid_delay_mean_s": delay,
                "valid_delay_p95_s": delay + 1.,
                "valid_delivery_fraction_per_admitted": valid,
                "valid_delivery_fraction_per_opportunity": valid * admission,
                "wire_bytes_per_source_opportunity_all_run": 1000. + i,
            }
            rows.append({"seed": seed, "method": method, "metrics": metrics,
                         "recovery_right_censored": True, "recovery_completion_s": None,
                         "all_decisions_certified": False})
    return rows


def campaign_fixture(tmp_path, *, rows=None, complete=False):
    root = tmp_path / "campaign"
    root.mkdir()
    rows = analytic_rows() if rows is None else rows
    seeds = sorted({r["seed"] for r in rows})
    methods = list(dict.fromkeys(r["method"] for r in rows))
    config = {"schema_version": 1, "protocol_model_version": 2, "nodes": 17,
              "evaluation_seeds": seeds, "methods": methods, "calibration_seeds": [],
              "duration_s": 20., "drain_s": 5., "disturbance": {"start_s": 5.},
              "control_interval_s": 5., "bound_evidence_artifacts": {}}
    bindings = {}
    if complete:
        for role in sorted(BOUND_ROLES):
            relative = "bound_artifacts/" + role + ".json"
            write_json(root / relative, {"description": "Analytic test identity", "role": role})
            identity = {"path": "test-bound/" + role + ".json",
                        "sha256": file_hash(root / relative)}
            bindings[role] = {"file": relative, **identity}
            config["bound_evidence_artifacts"][role] = identity
    controller = {"description": "Analytic unit-test fixture"}
    audit_rows = [{**r, "recovery": {
        "right_censored": r["recovery_right_censored"],
        "status": "right_censored" if r["recovery_right_censored"] else (
            "observed_recovery" if r["recovery_completion_s"] is not None
            else "no_observed_excursion")}} for r in rows]
    summary = paired_campaign_summary(audit_rows, methods)
    for name, value in (("config", config), ("controller", controller), ("summary", summary)):
        write_json(root / (name + ".json"), value)
    source = {"simulation/unit_fixture.py": "a" * 64}
    if complete:
        path = root / "source/simulation/unit_fixture.py"
        path.parent.mkdir(parents=True)
        path.write_text("# Analytic source identity fixture.\n")
        source["simulation/unit_fixture.py"] = file_hash(path)
    manifest = {"schema_version": 1, "status": STATUS, "completed": True,
                "config_digest": digest(config), "effective_config_sha256": file_hash(root / "config.json"),
                "controller_sha256": file_hash(root / "controller.json"),
                "summary_sha256": file_hash(root / "summary.json"),
                "source_hashes": source, "source_digest": digest(source),
                "evaluation_seeds": seeds, "methods": methods, "calibration_seeds": [],
                "paired_design": "Analytic paired seed fixtures", "bound_artifacts": bindings, "runs": []}
    for row in rows:
        relative = f"runs/seed-{row['seed']}/{row['method']}"
        run = {"seed": row["seed"], "method": row["method"], "directory": relative,
               "manifest_sha256": "b" * 64, "summary_sha256": "c" * 64}
        if complete:
            directory = root / relative
            directory.mkdir(parents=True)
            rm = {"seed": row["seed"], "method": row["method"],
                  "source_digest": manifest["source_digest"],
                  "controller_sha256": manifest["controller_sha256"],
                  "config_digest": manifest["config_digest"],
                  "exogenous_digest": f"{row['seed']:064x}", "raw_files": {}}
            rs = {**row, "config_digest": manifest["config_digest"],
                  "exogenous_digest": rm["exogenous_digest"], "recovery": {
                      "right_censored": row["recovery_right_censored"],
                      "recovery_completion_s": row["recovery_completion_s"]}}
            write_json(directory / "manifest.json", rm)
            write_json(directory / "summary.json", rs)
            run.update(manifest_sha256=file_hash(directory / "manifest.json"),
                       summary_sha256=file_hash(directory / "summary.json"))
        manifest["runs"].append(run)
    write_json(root / "manifest.json", manifest)
    write_rows(root / "per-seed.csv", rows)
    return root


def rewrite_csv(path, mutate):
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        fields, rows = reader.fieldnames, list(reader)
    fields, rows = mutate(fields, rows)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_declared_matrix_accepts_two_seeds_and_arbitrary_positive_node_count(tmp_path):
    data = load_campaign(campaign_fixture(tmp_path))
    assert data["seeds"] == [61, 62]
    assert data["config"]["nodes"] == 17
    assert len(data["rows"]) == 6
    assert data["provenance"]["input_kind"] == "campaign_report_bundle"
    assert data["provenance"]["source_snapshot_count"] == 0
    assert data["provenance"]["source_declared_count"] == 1


@pytest.mark.parametrize("mutation", [
    lambda fields, rows: (fields, rows + [rows[0]]),
    lambda fields, rows: (fields, rows[:-1]),
    lambda fields, rows: (fields[:-1], [{k: v for k, v in r.items() if k != fields[-1]} for r in rows]),
    lambda fields, rows: (fields + ["extra"], [{**r, "extra": "1"} for r in rows]),
    lambda fields, rows: (fields, [{**rows[0], "valid_delay_mean_s": "nan"}, *rows[1:]]),
    lambda fields, rows: (fields, [{**rows[0], "modeled_cpu_energy_j_all_run": ""}, *rows[1:]]),
    lambda fields, rows: (fields, [{**rows[0], "source_admission_fraction": "1.1"}, *rows[1:]]),
    lambda fields, rows: (fields, [{**rows[0], "recovery_completion_s": "20"}, *rows[1:]]),
])
def test_csv_rejects_missing_duplicate_nonfinite_and_wrong_schema(tmp_path, mutation):
    root = campaign_fixture(tmp_path)
    rewrite_csv(root / "per-seed.csv", mutation)
    with pytest.raises(ValueError):
        load_campaign(root)


def test_consistent_csv_changes_still_require_agreement_with_bound_summary(tmp_path):
    root = campaign_fixture(tmp_path)
    rewrite_csv(root / "per-seed.csv", lambda f, r: (
        f, [{**r[0], "modeled_cpu_energy_j_all_run": "20"}, *r[1:]]))
    with pytest.raises(ValueError, match="summary statistics differ"):
        load_campaign(root)


def test_mismatched_configuration_hash_is_rejected(tmp_path):
    root = campaign_fixture(tmp_path)
    config = json.loads((root / "config.json").read_text())
    config["nodes"] = 99
    write_json(root / "config.json", config)
    with pytest.raises(ValueError, match="hash mismatch"):
        load_campaign(root)


def test_missing_manifest_pair_is_rejected(tmp_path):
    root = campaign_fixture(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["runs"].pop()
    write_json(root / "manifest.json", manifest)
    with pytest.raises(ValueError, match="declared seed/method product"):
        load_campaign(root)


def test_partial_run_directory_provenance_is_rejected(tmp_path):
    root = campaign_fixture(tmp_path)
    directory = root / "runs/seed-61/da-ahe"
    directory.mkdir(parents=True)
    (directory / "manifest.json").write_text("{}")
    with pytest.raises(ValueError, match="partial run provenance"):
        load_campaign(root)


def test_complete_run_snapshots_can_supply_per_seed_csv(tmp_path):
    root = campaign_fixture(tmp_path, complete=True)
    (root / "per-seed.csv").unlink()
    data = load_campaign(root)
    assert data["provenance"]["input_kind"] == "campaign_run_snapshots"
    assert data["provenance"]["per_seed_origin"] == "bound_run_summaries"
    assert data["provenance"]["source_snapshot_count"] == 1
    assert set(data["provenance"]["verified_bound_artifacts"]) == BOUND_ROLES
    assert not (root / "per-seed.csv").exists()


def test_full_campaign_requires_three_bound_roles_even_when_metadata_is_rebound(tmp_path):
    root = campaign_fixture(tmp_path, complete=True)
    manifest = json.loads((root / "manifest.json").read_text())
    config = json.loads((root / "config.json").read_text())
    del manifest["bound_artifacts"]["decoding_report"]
    del config["bound_evidence_artifacts"]["decoding_report"]
    write_json(root / "config.json", config)
    manifest.update(config_digest=digest(config),
                    effective_config_sha256=file_hash(root / "config.json"))
    write_json(root / "manifest.json", manifest)
    with pytest.raises(ValueError, match="all three bound evidence roles"):
        load_campaign(root)


def test_full_campaign_requires_actual_bound_snapshot_bytes(tmp_path):
    root = campaign_fixture(tmp_path, complete=True)
    (root / "bound_artifacts/decoding_report.json").unlink()
    with pytest.raises(ValueError, match="missing campaign bound artifact snapshot"):
        load_campaign(root)


def test_epoch_shape_matches_engine_window_telemetry_and_policy_decision():
    def epoch(time, start, accepted):
        return {"time_s": time, "observation_start_s": start, "observation_cutoff_s": time,
                "accepted_reports": accepted, "telemetry": [0., .1, .2, 0., 0., 0., .32],
                "state": [0., 0., 0.], "belief": [1., 0., 0., 0., 0.], "certified": False,
                "decision": {"action": {"batch_size": 16}, "certified": False}}
    rows = [epoch(0., 0., 0), epoch(5., 0., 2)]
    validate_epochs(rows)
    rows[1]["telemetry"] = [0.] * 6
    with pytest.raises(ValueError, match="invalid epoch telemetry"):
        validate_epochs(rows)


def test_shared_bootstrap_is_ratio_of_means_and_self_normalizes_exactly():
    rows = analytic_rows(methods=("da-ahe", "dpp"))
    stats, record = paired_statistics(rows, [61, 62], ["da-ahe", "dpp"], resamples=128)
    ratio = stats["dpp"]["valid_delay_mean_s"]["paired_to_da_ahe"]
    assert ratio["ratio_of_means"] == 2.
    assert ratio["ratio_of_means"] != pytest.approx((4 / 1 + 12 / 7) / 2)
    own = stats["da-ahe"]["valid_delay_mean_s"]["paired_to_da_ahe"]
    assert own["ratio_percentile_ci_95"] == [1., 1.]
    assert own["difference_percentile_ci_95"] == [0., 0.]
    assert record["resamples"] == 128 and record["seed_count"] == 2


def test_undefined_delay_retains_seed_and_withholds_paired_estimate(tmp_path):
    rows = analytic_rows()
    row = next(r for r in rows if r["seed"] == 61 and r["method"] == "dpp")
    row["metrics"].update(valid_delay_mean_s=None, valid_delay_p95_s=None,
                          valid_delivery_fraction_per_admitted=0.,
                          valid_delivery_fraction_per_opportunity=0.,
                          accepted_delivery_fraction_per_admitted=0., observed_residual_loss_fraction=1.)
    data = load_campaign(campaign_fixture(tmp_path, rows=rows))
    stats, _ = paired_statistics(data["rows"], data["seeds"], data["methods"], resamples=16)
    item = stats["dpp"]["valid_delay_mean_s"]
    assert item["n_total"] == 2 and item["n_defined"] == 1
    assert item["mean"] is None and item["percentile_ci_95"] is None
    assert item["paired_to_da_ahe"]["status"] == "withheld_undefined_paired_metric"
    assert item["per_seed"] == [None, 12.]


def test_zero_reference_retains_difference_without_infinite_ratio():
    stats, _ = paired_statistics(analytic_rows(), [61, 62],
                                ["da-ahe", "dpp", "without_hve"], resamples=16)
    pair = stats["without_hve"]["invalid_acceptance_fraction_per_admitted"]["paired_to_da_ahe"]
    assert pair["mean_difference"] == .05
    assert pair["ratio_of_means"] is None
    assert pair["ratio_status"] == "undefined_zero_reference"


def test_censoring_and_no_excursion_are_not_recovery_times(tmp_path):
    rows = analytic_rows()
    rows[0]["recovery_right_censored"] = False
    data = load_campaign(campaign_fixture(tmp_path, rows=rows))
    result = recovery_summary(data, resamples=16)
    assert result["statistics"] is None
    assert result["methods"]["da-ahe"]["no_observed_excursion"] == 1
    assert result["methods"]["da-ahe"]["right_censored"] == 1
    assert all(r["elapsed_from_onset_s"] is None for r in result["methods"]["da-ahe"]["per_seed"])


def test_observed_recovery_uses_elapsed_from_onset_and_shared_seed_bootstrap(tmp_path):
    rows = analytic_rows()
    for row in rows:
        row.update(recovery_right_censored=False, recovery_completion_s=10. if row["seed"] == 61 else 15.)
    data = load_campaign(campaign_fixture(tmp_path, rows=rows))
    result = recovery_summary(data, resamples=16)
    assert result["status"] == "all_observed"
    assert result["statistics"]["da-ahe"]["mean"] == 7.5


def test_export_preserves_inputs_and_refuses_existing_or_input_directories(tmp_path):
    root = campaign_fixture(tmp_path)
    before = {p.name: file_hash(p) for p in root.iterdir()}
    output = tmp_path / "publication"
    result = export_campaign(root, output, resamples=16, figures=False)
    assert result["bootstrap"]["seed_count"] == 2
    assert {p.name: file_hash(p) for p in root.iterdir()} == before
    assert {"summary.json", "tables.md", "table.tex", "per-seed.csv", "export-manifest.json"} <= {
        p.name for p in output.iterdir()}
    assert "2 paired seeds" in (output / "tables.md").read_text()
    with pytest.raises(ValueError, match="new directory"):
        export_campaign(root, output, resamples=16, figures=False)
    with pytest.raises(ValueError, match="separate from input"):
        export_campaign(root, root / "derived", resamples=16, figures=False)


def test_five_panels_use_declared_seed_count_and_evidence_coverage(tmp_path):
    root = campaign_fixture(tmp_path)
    result = export_campaign(root, tmp_path / "panels", resamples=16)
    assert result["feedback_panel"]["kind"] == "evidence_coverage"
    assert len(result["figure_captions"]) == 5
    for name in FIGURES:
        assert (tmp_path / "panels" / (name + ".pdf")).read_bytes().startswith(b"%PDF")


def test_required_csv_columns_are_stable():
    assert len(FIELDS) == len(set(FIELDS))
    assert set(METRICS) < set(FIELDS)
