# SPDX-License-Identifier: MIT
"""Full-window regressions for the two-level reference transform; not paper data.

Execution receipts are recorded separately. Synthetic coverage checks do
not establish Table III PRD or fidelity for any deployed sensor population.
"""
import math

import pytest

from daahe.profiles import Profile, example_profiles
from daahe.signal import (TRANSFORM_ID, encode_channels, forward_channel,
                          inverse_channel, reconstruct_channels, support_for_length)


def compressed_profiles():
    return [p for p in example_profiles() if p.name in {"pi0", "pi1", "pi2"}]


@pytest.mark.parametrize("position", range(240))
def test_two_level_full_transform_exactly_inverts_impulse_at_every_time(position):
    samples = tuple(64 if index == position else 0 for index in range(240))
    assert inverse_channel(forward_channel(samples)) == samples


@pytest.mark.parametrize("length", [120, 180, 240])
def test_all_reference_supports_retain_every_coarse_position_in_both_channels(length):
    support = support_for_length(length)
    assert len(support) == len(set(support)) == length
    assert set(range(60)).issubset(support)
    assert set(range(240, 300)).issubset(support)


@pytest.mark.parametrize("length", [120, 180, 240])
@pytest.mark.parametrize("channel", [0, 1])
def test_selected_coarse_support_detects_impulses_throughout_both_windows(length, channel):
    support = support_for_length(length)
    for position in range(240):
        channels = [[0] * 240 for _ in range(2)]
        channels[channel][position] = 64
        encoded = encode_channels(channels, support, step=1, coefficient_bound=32768)
        reconstructed = reconstruct_channels(encoded, support, step=1)
        assert any(reconstructed[channel]), (length, channel, position)
        assert not any(reconstructed[1-channel])


@pytest.mark.parametrize("profile", compressed_profiles(), ids=lambda p: p.name)
def test_constant_signal_is_retained_across_the_complete_window(profile):
    channels = ((1000,) * 240, (1000,) * 240)
    encoded = encode_channels(channels, profile.support, profile.delta_q,
                              profile.coefficient_bound)
    reconstructed = reconstruct_channels(encoded, profile.support, profile.delta_q)
    for channel in reconstructed:
        assert all(value != 0 for value in channel)
        assert max(abs(value-1000) for value in channel) <= 16


@pytest.mark.parametrize("profile", compressed_profiles(), ids=lambda p: p.name)
def test_synthetic_trend_keeps_tail_and_has_bounded_reference_error(profile):
    channels = (tuple(1000+t for t in range(240)),
                tuple(1500-2*t for t in range(240)))
    encoded = encode_channels(channels, profile.support, profile.delta_q,
                              profile.coefficient_bound)
    reconstructed = reconstruct_channels(encoded, profile.support, profile.delta_q)
    error_energy = sum((actual-expected)**2 for original, recovered in
                       zip(channels, reconstructed) for expected, actual in zip(original, recovered))
    signal_energy = sum(value*value for channel in channels for value in channel)
    assert all(any(channel[start:start+60]) for channel in reconstructed
               for start in (0, 60, 120, 180))
    # A coarse synthetic regression threshold, not the published PRD target.
    assert math.sqrt(error_energy / signal_energy) < 0.10


def test_rounded_lifting_remains_nonadditive_and_requires_aggregate_fidelity_analysis():
    single = forward_channel((1,) * 240)
    combined = inverse_channel(tuple(2*value for value in single))
    assert combined != (2,) * 240


def test_transform_version_is_bound_to_profile_digest_and_old_version_is_rejected():
    profile = Profile("versioned", 120, 16, 3.2, 1, support_for_length(120), 2048)
    assert profile.transform_id == TRANSFORM_ID
    assert "two-level" in profile.transform_id
    with pytest.raises(ValueError, match="transform version"):
        Profile("old", 120, 16, 3.2, 1, support_for_length(120), 2048,
                transform_id="reference-intdb2-one-level-periodic-unnormalized-q30-v1")
