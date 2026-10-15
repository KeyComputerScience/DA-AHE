# SPDX-License-Identifier: MIT
"""Saved-record verification must detect altered sampler or weakened bounds."""
import importlib.util
import json
from pathlib import Path
import shutil

import pytest


ROOT = Path(__file__).resolve().parents[1]


def verifier():
    spec = importlib.util.spec_from_file_location("decoding_record", ROOT / "tools/verify_decoding_record.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copied_record(tmp_path):
    directory = tmp_path / "decoding"
    shutil.copytree(ROOT / "evidence/independent/decoding/k6-cdt-03", directory)
    return directory


def rehash_record(directory, tool, filename):
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"][filename] = tool.digest(directory / filename)
    (directory / "manifest.json").write_text(json.dumps(manifest))


def test_preserved_decoding_record_is_bound_to_sampler_and_exact_probability_target():
    report = verifier().verify(ROOT / "evidence/independent/decoding/k6-cdt-03")
    assert report["fixed_profile_checks"] == 6
    assert report["finite_adaptive_union_count"] == 42
    assert report["original_paper_evidence"] is False


def test_changed_sampler_probabilities_fail_even_after_file_hashes_are_updated(tmp_path):
    tool, directory = verifier(), copied_record(tmp_path)
    cdt = json.loads((directory / "sampler-cdts.json").read_text())
    cdt["3.2"]["counts"][0][1] += 1
    (directory / "sampler-cdts.json").write_text(json.dumps(cdt))
    report = json.loads((directory / "decoding-bound.json").read_text())
    report["sampler_cdt_file_sha256"] = tool.digest(directory / "sampler-cdts.json")
    (directory / "decoding-bound.json").write_text(json.dumps(report))
    for name in ("sampler-cdts.json", "decoding-bound.json"):
        rehash_record(directory, tool, name)
    with pytest.raises(ValueError, match="integer probabilities"):
        tool.verify(directory)


def test_weakened_probability_bound_fails_even_when_pass_flag_and_hash_are_updated(tmp_path):
    tool, directory = verifier(), copied_record(tmp_path)
    report = json.loads((directory / "decoding-bound.json").read_text())
    report["profiles"][0]["checks"][0]["union_bound_log2"]["upper_exact_rational"] = "-127"
    (directory / "decoding-bound.json").write_text(json.dumps(report))
    rehash_record(directory, tool, "decoding-bound.json")
    with pytest.raises(ValueError, match="upper bound exceeds target"):
        tool.verify(directory)
