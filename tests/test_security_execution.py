# SPDX-License-Identifier: MIT
"""Executed host invariants for security evidence; no mocked cost is published."""
import importlib.util
import math
from pathlib import Path

import pytest


def adapter():
    path = Path(__file__).resolve().parents[1] / "tools" / "estimator_result_adapter.py"
    spec = importlib.util.spec_from_file_location("security_adapter_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def records():
    # Analytic test fixtures only; these are not estimator results or evidence.
    return [{"algorithm": name, "status": "success", "log2_rop": 101.0 + index}
            for index, name in enumerate(adapter().REQUIRED_ATTACKS)]


def test_full_minimum_comes_from_actual_records_without_default_threshold():
    summary = adapter().summarize_attacks(records())
    assert summary["lambda_est_bits"] == 101.0
    assert summary["minimum_successful_attack"] == "primal_usvp"
    assert summary["threshold_bits"] is None
    assert summary["threshold_passed"] is None
    assert summary["status"] == "estimate_complete"


def test_review_threshold_does_not_replace_a_below_threshold_result():
    summary = adapter().summarize_attacks(records(), 110.0)
    assert summary["lambda_est_bits"] == 101.0
    assert summary["threshold_passed"] is False
    assert summary["status"] == "failed_below_threshold"


def test_explicit_threshold_can_pass_only_after_complete_computation():
    assert adapter().summarize_attacks(records(), 100.0)["threshold_passed"] is True


@pytest.mark.parametrize("status", ["failed", "timeout"])
def test_failure_or_timeout_retains_partial_minimum_but_cannot_certify(status):
    partial = records()
    partial[-1] = {"algorithm": "coded_bkw", "status": status}
    summary = adapter().summarize_attacks(partial, 100.0)
    assert summary["minimum_successful_attack_bits"] == 101.0
    assert summary["lambda_est_bits"] is None
    assert summary["threshold_passed"] is False
    assert summary["failed_attacks"] == ["coded_bkw"]


def test_diagnostic_subset_never_counts_as_the_complete_attack_set():
    summary = adapter().summarize_attacks(records()[:1])
    assert summary["complete_attack_set"] is False
    assert summary["lambda_est_bits"] is None
    assert len(summary["failed_attacks"]) == 6


@pytest.mark.parametrize("bits", [math.nan, math.inf, -math.inf, None])
def test_nonfinite_successful_result_is_rejected(bits):
    invalid = records()
    invalid[0]["log2_rop"] = bits
    with pytest.raises(ValueError, match="finite log2"):
        adapter().summarize_attacks(invalid)


def test_duplicate_or_unknown_attack_is_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        adapter().summarize_attacks(records() + records()[:1])
    with pytest.raises(ValueError, match="unrecognized"):
        adapter().summarize_attacks([{"algorithm": "invented", "status": "failed"}])


@pytest.mark.parametrize("threshold", [0, -1, math.nan, math.inf])
def test_invalid_review_threshold_is_rejected(threshold):
    with pytest.raises(ValueError, match="threshold"):
        adapter().summarize_attacks(records(), threshold)


def test_source_digest_is_order_independent_and_detects_a_changed_byte(tmp_path):
    (tmp_path / "a.py").write_text("first\n")
    (tmp_path / "b.py").write_text("second\n")
    original = adapter().source_manifest(tmp_path, ["a.py", "b.py"])
    assert original == adapter().source_manifest(tmp_path, ["b.py", "a.py"])
    (tmp_path / "a.py").write_text("First\n")
    changed = adapter().source_manifest(tmp_path, ["a.py", "b.py"])
    assert original["manifest_sha256"] != changed["manifest_sha256"]


def test_source_manifest_rejects_a_symlink(tmp_path):
    (tmp_path / "source").write_text("x")
    (tmp_path / "link").symlink_to(tmp_path / "source")
    with pytest.raises(ValueError, match="regular in-tree"):
        adapter().source_manifest(tmp_path, ["link"])


def runner(monkeypatch):
    import importlib.machinery
    tools = Path(__file__).resolve().parents[1] / "tools"
    monkeypatch.syspath_prepend(str(tools))
    loader = importlib.machinery.SourceFileLoader("security_runner_test", str(tools / "estimate_security.sage"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_dirty_source_at_end_revokes_a_previously_complete_passing_result(monkeypatch):
    module = runner(monkeypatch)
    report = adapter().summarize_attacks(records(), 100.0)
    def dirty(_repo):
        raise ValueError("estimator checkout must be clean")
    monkeypatch.setattr(module, "verified_source", dirty)
    assert module.finalize_source_status(report, Path("unused"), "a" * 64) == 2
    assert report["status"] == "failed_source_changed"
    assert report["lambda_est_bits"] is None
    assert report["threshold_passed"] is False
    assert report["source_unchanged_after_run"] is False
    assert report["finished_at"]
    assert report["execution_returncode"] == 2


def test_byte_digest_mismatch_revokes_result_even_if_git_check_succeeds(monkeypatch):
    module = runner(monkeypatch)
    report = adapter().summarize_attacks(records())
    monkeypatch.setattr(module, "verified_source", lambda _: {"manifest_sha256": "b" * 64})
    assert module.finalize_source_status(report, Path("unused"), "a" * 64) == 2
    assert report["status"] == "failed_source_changed"


def test_unchanged_source_preserves_complete_computation(monkeypatch):
    module = runner(monkeypatch)
    report = adapter().summarize_attacks(records())
    monkeypatch.setattr(module, "verified_source", lambda _: {"manifest_sha256": "a" * 64})
    assert module.finalize_source_status(report, Path("unused"), "a" * 64) == 0
    assert report["status"] == "estimate_complete"
    assert report["source_unchanged_after_run"] is True


def parameter_runner(monkeypatch):
    tools = Path(__file__).resolve().parents[1] / "tools"
    monkeypatch.syspath_prepend(str(tools))
    spec = importlib.util.spec_from_file_location("security_parameter_runner_test", tools / "estimate_security_parameters.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parameter_args(**changes):
    from daahe.mlwe import DEFAULT_PARAMETERS
    from types import SimpleNamespace
    values = {"module_rank": DEFAULT_PARAMETERS.k, "ring_degree": DEFAULT_PARAMETERS.d,
              "n": None, "q": DEFAULT_PARAMETERS.q, "sigma_key": DEFAULT_PARAMETERS.sigma_key}
    values.update(changes)
    return SimpleNamespace(**values)


def test_explicit_legacy_parameter_tuple_retains_original_wire_size(monkeypatch):
    inputs = parameter_runner(monkeypatch).security_parameters(parameter_args(module_rank=3))
    assert (inputs["module_rank"], inputs["ring_degree"], inputs["n"], inputs["m"], inputs["q"], inputs["sigma_key"]) == (3, 256, 768, 768, 2**32, 3.2)
    assert inputs["ciphertext_bytes"] == 4096


@pytest.mark.parametrize("arguments,rank,dimension,wire_bytes", [
    ([], 6, 1536, 7168), (["--module-rank", "3"], 3, 768, 4096),
])
def test_parameter_cli_defaults_to_active_tuple_and_legacy_requires_explicit_rank(
        monkeypatch, tmp_path, arguments, rank, dimension, wire_bytes):
    module = parameter_runner(monkeypatch)
    captured = {}

    def capture_worker(_repo, _name, _output, inputs):
        # Check CLI input routing only; no fabricated attack cost or evidence.
        captured.update(inputs)
        return 0

    monkeypatch.setattr(module, "run_worker", capture_worker)
    assert module.main(["--estimator", str(tmp_path), "--attack-worker", "primal_usvp",
                        "--worker-output", str(tmp_path / "unused.json"), *arguments]) == 0
    assert captured["module_rank"] == rank
    assert captured["n"] == captured["m"] == dimension
    assert captured["ciphertext_bytes"] == wire_bytes
    assert not (tmp_path / "unused.json").exists()


def test_parameter_change_updates_dimension_samples_and_ciphertext_bytes(monkeypatch):
    inputs = parameter_runner(monkeypatch).security_parameters(parameter_args(module_rank=7))
    assert inputs["n"] == inputs["m"] == 1792
    assert inputs["ciphertext_bytes"] == 8192
    assert inputs["sigma_key"] == inputs["sigma_secret"] == 3.2


@pytest.mark.parametrize("changes", [{"module_rank": 0}, {"ring_degree": 255},
    {"n": 777}, {"q": 65537}, {"sigma_key": math.nan}, {"sigma_key": 0}])
def test_parameter_runner_rejects_inconsistent_or_undefined_instances(monkeypatch, changes):
    with pytest.raises(ValueError):
        parameter_runner(monkeypatch).security_parameters(parameter_args(**changes))
