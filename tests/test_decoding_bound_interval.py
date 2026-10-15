# SPDX-License-Identifier: MIT
"""Sage interval checks against explicit tiny-PMF enumeration (not evidence)."""
import importlib.util
from pathlib import Path

import pytest

sage = pytest.importorskip("sage.all")


def tool():
    path = Path(__file__).resolve().parents[1] / "tools" / "certify_decoding_bound.py"
    spec = importlib.util.spec_from_file_location("decoding_interval_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reused_key_product_mgf_matches_explicit_two_noise_enumeration():
    field, rational = sage.RealIntervalField(256), sage.QQ
    space = 2**256
    counts = ((-1, space//8), (0, space//4), (1, 5*space//8))
    row = tool().certify_profile(counts, counts, rank=1, degree=2, sigma_key=1,
        sigma_enc=1, batch_size=2, q=256, p=17, poly_counts=[1, 2],
        precision=256, target_bits=1, t_factor="1/5")
    t = rational(row["t_exact_rational"])
    pmf = [(value, rational(count)/space) for value, count in counts]
    expected = sum((field(pa*px*py)*(field(t*a*(x+y))).exp()
                    for a, pa in pmf for x, px in pmf for y, py in pmf), field(0))
    recorded = row["g_plus"]
    actual = field(rational(recorded["lower_exact_rational"]),
                   rational(recorded["upper_exact_rational"]))
    assert 0 in actual-expected
    # The incorrect placement of ^N assumes a newly sampled key per report.
    one_product = sum((field(pa*px)*field(t*a*x).exp()
                       for a, pa in pmf for x, px in pmf), field(0))
    assert 0 not in actual-one_product**2


def test_adaptive_union_refuses_to_assume_mgf_monotonicity():
    result = tool().adaptive_union([{"smaller_batch_dominance": {"verified": False}}],
                                  poly_count=2, precision=256, target_bits=128)
    assert result == {"passed": False, "status": "failed_mgf_dominance_check"}
