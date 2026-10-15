# SPDX-License-Identifier: MIT
"""Exercise the CI gate against GitHub's terminal job outcomes."""
import importlib.util
import json
from pathlib import Path

import pytest


def coverage_tool():
    path = Path(__file__).resolve().parents[1] / "tools/check_ci_coverage.py"
    spec = importlib.util.spec_from_file_location("ci_coverage", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_complete_software_checks_do_not_certify_the_paper_or_physical_board():
    tool = coverage_tool()
    result = tool.assess({name: {"result": "success"} for name in tool.REQUIRED_JOBS})
    assert result["status"] == "passed_all_independent_ci_checks"
    assert result["paper_reproduced"] is False
    assert result["physical_board_measurements_verified"] is False
    assert result["full_system_certified"] is False


@pytest.mark.parametrize("outcome", ["skipped", "failure", "cancelled", None])
def test_security_job_cannot_be_skipped_or_fail_under_a_green_aggregate(outcome):
    tool = coverage_tool()
    results = {name: {"result": "success"} for name in tool.REQUIRED_JOBS}
    results["security"] = {"result": outcome}
    result = tool.assess(results)
    assert result["status"] == "failed_incomplete_ci_coverage"
    assert result["errors"] == [{"job": "security", "result": outcome}]


def test_absent_historical_archive_job_is_not_accepted():
    tool = coverage_tool()
    results = {name: {"result": "success"} for name in tool.REQUIRED_JOBS if name != "history"}
    result = tool.assess(results)
    assert result["status"] == "failed_incomplete_ci_coverage"
    assert result["errors"] == [{"job": "history", "result": "missing"}]


def test_an_unlisted_new_job_requires_coverage_contract_update():
    tool = coverage_tool()
    results = {name: {"result": "success"} for name in tool.REQUIRED_JOBS}
    results["new_check"] = {"result": "success"}
    assert tool.assess(results)["errors"] == [{"unexpected_jobs": ["new_check"]}]


def test_current_claim_contract_does_not_overstate_ci_or_board_scope():
    tool = coverage_tool()
    assert len(tool.validate_claim_scope(tool.ROOT / "evidence/independent/claim-coverage.json")) == 64


@pytest.mark.parametrize("field", ["paper_reproduced", "all_manuscript_metrics_verified",
                                  "full_system_certified", "original_author_artifacts_restored"])
def test_green_checks_cannot_silently_relabel_missing_original_evidence(field, tmp_path):
    tool = coverage_tool()
    claims = json.loads((tool.ROOT / "evidence/independent/claim-coverage.json").read_text())
    claims[field] = True
    path = tmp_path / "claims.json"
    path.write_text(json.dumps(claims))
    with pytest.raises(ValueError, match="unsupported"):
        tool.validate_claim_scope(path)
