# SPDX-License-Identifier: MIT
"""Reject parameter regression and retrospective rewriting of published evidence."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("alignment_checker_test", ROOT / "tools/check_manuscript_alignment.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


@pytest.fixture
def checkout(tmp_path):
    names = ["configs/manuscript_alignment.json", "configs/security_profile.json",
             "evidence/independent/claim-coverage.json"]
    contract = json.loads((ROOT / names[0]).read_text())
    profile = json.loads((ROOT / names[1]).read_text())
    names += [profile["security_report"]]
    names += [r["path"] for r in contract["preserved_legacy_records"]]
    names += [r["path"] for r in contract.get("archived_original_experiment_contracts", [])]
    for name in names:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    return tmp_path


def mutate(root, name, change):
    path = root / name
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data, indent=2) + "\n")


def test_current_records_pass_without_claiming_original_pdf_or_system_certification(checkout):
    result = checker.verify(checkout)
    assert result["ciphertext_bytes"] == 7168
    assert result["manuscript_aligned"] is False
    assert result["full_system_certified"] is False


@pytest.mark.parametrize("key,value", [("module_rank", 3), ("n", 768), ("ciphertext_bytes", 4096)])
def test_old_parameter_or_wire_size_cannot_return_as_current(checkout, key, value):
    mutate(checkout, "configs/security_profile.json", lambda d: d.update({key: value}))
    with pytest.raises(ValueError, match="differs from code"):
        checker.verify(checkout)


def test_old_airtime_cannot_be_reused_for_larger_ciphertext(checkout):
    mutate(checkout, "configs/manuscript_alignment.json",
           lambda d: d["payload_arithmetic"].update(single_payload_airtime_ms="131.072"))
    with pytest.raises(ValueError, match="arithmetic drift"):
        checker.verify(checkout)


def test_historical_attack_log_cannot_be_rewritten_to_requested_threshold(checkout):
    name = json.loads((checkout / "configs/manuscript_alignment.json").read_text())["preserved_legacy_records"][0]["path"]
    mutate(checkout, name, lambda d: d["attacks"][0].update(log2_rop=128.1))
    with pytest.raises(ValueError, match="historical evidence changed"):
        checker.verify(checkout)


def test_rehashed_incomplete_selected_attack_set_still_fails(checkout):
    profile_path = checkout / "configs/security_profile.json"
    profile = json.loads(profile_path.read_text())
    name = profile["security_report"]
    mutate(checkout, name, lambda d: d["attacks"][-1].update(status="failed"))
    profile["security_report_sha256"] = hashlib.sha256((checkout / name).read_bytes()).hexdigest()
    profile_path.write_text(json.dumps(profile) + "\n")
    with pytest.raises(ValueError, match="incomplete or below"):
        checker.verify(checkout)


def test_repository_metadata_cannot_claim_the_unedited_manuscript_is_corrected(checkout):
    mutate(checkout, "configs/manuscript_alignment.json",
           lambda d: d["claim_status"].update(original_pdf_modified=True))
    with pytest.raises(ValueError, match="unsupported manuscript claim"):
        checker.verify(checkout)


def test_correct_legacy_payload_is_not_the_new_parameter_set(checkout):
    original = json.loads((checkout / "configs/manuscript_alignment.json").read_text())
    changed = deepcopy(original)
    changed["current_parameters"]["k"] = 3
    (checkout / "configs/manuscript_alignment.json").write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="canonical parameter drift"):
        checker.verify(checkout)


@pytest.mark.parametrize("name", ["security/run-01/security.json", "reference-bounds.json",
                                 "experiments/paper_targets.json", "experiments/matrix.json"])
def test_retired_duplicate_results_cannot_return_to_current_paths(checkout, name):
    path = checkout / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n")
    with pytest.raises(ValueError, match="retired legacy artifact returned"):
        checker.verify(checkout)


def test_original_experiment_archive_cannot_be_rewritten_to_new_results(checkout):
    contract = json.loads((checkout / "configs/manuscript_alignment.json").read_text())
    name = contract["archived_original_experiment_contracts"][0]["path"]
    (checkout / name).write_text('{"latency_ms": 1}\n')
    with pytest.raises(ValueError, match="original experiment archive changed"):
        checker.verify(checkout)
