# SPDX-License-Identifier: MIT
"""Independent discrete arithmetic checks for the CDT-decoding tail proof."""
import importlib.util
import itertools
from pathlib import Path
from types import SimpleNamespace

import pytest


def tool():
    path = Path(__file__).resolve().parents[1] / "tools" / "certify_decoding_bound.py"
    spec = importlib.util.spec_from_file_location("decoding_bound_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cdt_integer_counts_equal_actual_bisect_right_frequencies():
    from bisect import bisect_right
    radius, cdf = 1, (1, 6, 8)
    counts = dict(tool().cdt_counts(radius, cdf, bits=3))
    actual = {value: sum(bisect_right(cdf, draw)-radius == value for draw in range(8))
              for value in range(-radius, radius+1)}
    assert counts == actual == {-1: 1, 0: 5, 1: 2}


@pytest.mark.parametrize("radius,cdf", [(1, (1, 8)), (1, (3, 2, 8)),
    (1, (1, 6, 7)), (1, (1, 6, 9)), (1, (1, 6.0, 8))])
def test_invalid_cdf_cannot_be_used_as_a_probability_distribution(radius, cdf):
    with pytest.raises(ValueError):
        tool().cdt_counts(radius, cdf, bits=3)


def test_real_cdt_probabilities_sum_to_exact_256_bit_sample_space():
    from daahe.mlwe import _gaussian_cdt
    for sigma in (3.2, 3.4, 3.6):
        radius, cdf = _gaussian_cdt(sigma)
        counts = tool().cdt_counts(radius, cdf)
        assert sum(count for _, count in counts) == 2**256
        assert all(count >= 0 for _, count in counts)


def center(value, modulus):
    value %= modulus
    return value-modulus if value >= (modulus+1)//2 else value


@pytest.mark.parametrize("batch_size", [1, 2, 3, 4])
def test_scaling_carry_margin_proves_exact_decoder_on_all_toy_plaintexts(batch_size):
    # Small independent exhaustive analogue of q=p*Delta+1 with odd Delta.
    p, delta, q = 7, 15, 106
    margin = tool().decoding_threshold(q, p, batch_size)
    threshold = margin["noise_tail_threshold"]
    for messages in itertools.product(range(-(p//2), p//2+1), repeat=batch_size):
        total = sum(messages)
        target = center(total, p)
        carry = (total-target)//p
        assert abs(carry) <= margin["carry_abs_upper"]
        for noise in range(-threshold+1, threshold):
            noisy = center(delta*total+noise, q)
            decoded = ((noisy+delta//2)//delta) % p
            assert decoded == total % p


@pytest.mark.parametrize("q,p,n", [(2**32-1, 65537, 16), (256, 16, 2),
    (2**32, 65537, 0), (100, 7, 2)])
def test_unsupported_scaling_or_batch_cannot_claim_the_carry_certificate(q, p, n):
    with pytest.raises(ValueError):
        tool().decoding_threshold(q, p, n)


def test_selected_tuple_margin_is_conservative_and_exact():
    margin = tool().decoding_threshold(2**32, 65537, 16)
    assert margin == {"delta": 65535, "scaling_remainder": 1,
                      "carry_abs_upper": 8, "noise_tail_threshold": 32758}


def test_security_record_binding_rejects_the_original_rank_three_tuple():
    inputs = {"module_rank": 3, "ring_degree": 256, "q": 2**32,
              "n": 768, "m": 768, "sigma_key": 3.2}
    with pytest.raises(ValueError, match="module_rank"):
        tool().tuple_binding({"inputs": inputs}, rank=6, degree=256,
                             q=2**32, p=65537, sigma_key=3.2)
