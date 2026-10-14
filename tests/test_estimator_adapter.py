# SPDX-License-Identifier: MIT
"""Pinned upstream sample-accounting contract; analytic mocks, unexecuted."""
import importlib.util
import math
from pathlib import Path
from types import SimpleNamespace

import pytest


def adapter():
    path = Path(__file__).resolve().parents[1]/"tools"/"estimator_result_adapter.py"
    spec = importlib.util.spec_from_file_location("daahe_estimator_adapter_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.sample_accounting


def problem(m, sigma):
    return SimpleNamespace(n=768, q=2**32, m=m, Xe=SimpleNamespace(mean=0, stddev=sigma))


def test_unreported_primal_samples_remain_unknown_instead_of_fabricating_768():
    result = adapter()("primal_usvp", {})
    assert result["original_independent_samples"] == 768
    assert result["reported_attack_samples"] is None
    assert result["status"] == "sample_count_not_reported_by_upstream"


def test_finite_sample_attacks_still_enforce_original_budget():
    assert adapter()("dual", {"m":700})["status"] == "within_original_sample_budget"
    with pytest.raises(ValueError, match="original independent sample budget"):
        adapter()("dual", {"m":769})


def test_coded_bkw_preserves_original_budget_and_records_audited_derived_samples():
    # k=1 produces 1535 signed combinations; 2000 requires k=2.
    result = adapter()("coded_bkw", {"m":2000, "problem":problem(2000, math.sqrt(2)*3.2)})
    assert result["sample_amplification"] is True
    assert result["original_independent_samples"] == 768
    assert result["reported_attack_samples"] == "2000"
    assert result["amplification_terms"] == 2
    assert result["effective_problem_samples"] == "2000"


def test_coded_bkw_rejects_missing_provenance_unchanged_noise_and_wrong_dimensions():
    with pytest.raises(ValueError, match="effective upstream problem"):
        adapter()("coded_bkw", {"m":2000})
    with pytest.raises(ValueError, match="noise does not match"):
        adapter()("coded_bkw", {"m":2000, "problem":problem(2000, 3.2)})
    changed = problem(2000, math.sqrt(2)*3.2)
    changed.q = 65537
    with pytest.raises(ValueError, match="dimension or modulus"):
        adapter()("coded_bkw", {"m":2000, "problem":changed})
