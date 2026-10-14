# SPDX-License-Identifier: MIT
"""Explicit reference completion of the paper's unspecified IntDb2 transform.

API: ``forward_channel(samples240)`` / ``inverse_channel(coefficients240)``;
``support_for_length(L)``; ``encode_channels(channels, support, step,
coefficient_bound)``; ``reconstruct_channels(centered_quantized, support, step)``.
The paper supplies no lifting constants, normalization, levels or boundary rule.
Here one unnormalized Db2 lifting level uses periodic boundaries, fixed dyadic
approximations to sqrt(3), sqrt(3)/4 and (sqrt(3)-2)/4, and nearest rounding with
ties away from zero. Three reversible integer shears give exact inversion before
selection/quantization. This choice is deterministic and inspectable, but is not
the authors' original transform, an orthonormal Db2 implementation, or a verified
reproduction of their distortion measurements.

Each 240-coefficient channel is [120 approximation, 120 detail]. Two channels
concatenate to 480 coefficients. At most 240 fixed positions are retained; the
support policy alternates channels within approximation coefficients, then detail
coefficients. Quantization q=round(z/step) guarantees |z-step*q| <= step/2 at each
retained position. Magnitudes exceeding coefficient_bound are rejected, never
silently clipped. The protocol separately enforces N*coefficient_bound <= 32768.
Rounded integer lifting is nonlinear: inverse(sum(transformed_channels)) can
differ from sum(channels), even with full support. The resulting aggregation
rounding error needs application-specific analysis and must not be advertised
as exact raw-sample homomorphism or as a certified reconstruction bound.
"""

from __future__ import annotations

from collections.abc import Sequence

CHANNEL_SAMPLES = 240
CHANNEL_COUNT = 2
TOTAL_COEFFICIENTS = CHANNEL_SAMPLES * CHANNEL_COUNT
P = 65537
_HALF = CHANNEL_SAMPLES // 2
_FIXED_DENOMINATOR = 1 << 30
_SQRT3 = 1859775393
_SQRT3_OVER4 = 464943848
_SQRT3_MINUS2_OVER4 = -71927064
TRANSFORM_ID = "reference-intdb2-one-level-periodic-unnormalized-q30-v1"


def round_div(numerator: int, denominator: int) -> int:
    """Round an exact rational to the nearest integer, ties away from zero."""
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise ValueError("round_div requires an integer numerator and positive denominator")
    magnitude = (2 * abs(numerator) + denominator) // (2 * denominator)
    return -magnitude if numerator < 0 else magnitude


def _channel(values: Sequence[int]) -> tuple[int, ...]:
    if len(values) != CHANNEL_SAMPLES or any(type(value) is not int for value in values):
        raise ValueError("a channel must contain exactly 240 integer values")
    return tuple(values)


def forward_channel(samples: Sequence[int]) -> tuple[int, ...]:
    """One reversible integer Db2 lifting level; approximation then detail."""
    values = _channel(samples)
    even = values[0::2]
    odd = values[1::2]
    updated = tuple(
        left + round_div(_SQRT3 * right, _FIXED_DENOMINATOR)
        for left, right in zip(even, odd)
    )
    detail = tuple(
        odd[index] - round_div(
            _SQRT3_OVER4 * updated[index]
            + _SQRT3_MINUS2_OVER4 * updated[(index - 1) % _HALF],
            _FIXED_DENOMINATOR,
        )
        for index in range(_HALF)
    )
    approximation = tuple(updated[index] - detail[(index + 1) % _HALF] for index in range(_HALF))
    return approximation + detail


def inverse_channel(coefficients: Sequence[int]) -> tuple[int, ...]:
    """Reverse exactly the integer shears, including their rounding operations."""
    values = _channel(coefficients)
    approximation, detail = values[:_HALF], values[_HALF:]
    updated = tuple(approximation[index] + detail[(index + 1) % _HALF] for index in range(_HALF))
    odd = tuple(
        detail[index] + round_div(
            _SQRT3_OVER4 * updated[index]
            + _SQRT3_MINUS2_OVER4 * updated[(index - 1) % _HALF],
            _FIXED_DENOMINATOR,
        )
        for index in range(_HALF)
    )
    even = tuple(
        updated[index] - round_div(_SQRT3 * odd[index], _FIXED_DENOMINATOR)
        for index in range(_HALF)
    )
    return tuple(value for pair in zip(even, odd) for value in pair)


def support_for_length(L: int) -> tuple[int, ...]:
    """Deterministic balanced approximation-first support, encoded in profile ID."""
    if type(L) is not int or not 1 <= L <= 240:
        raise ValueError("retained support length must be in [1, 240]")
    approximation = tuple(index for local in range(_HALF) for index in (local, CHANNEL_SAMPLES + local))
    detail = tuple(index for local in range(_HALF, CHANNEL_SAMPLES) for index in (local, CHANNEL_SAMPLES + local))
    return (approximation + detail)[:L]


def _support(support: Sequence[int]) -> tuple[int, ...]:
    positions = tuple(support)
    if not 1 <= len(positions) <= 240:
        raise ValueError("support must contain 1 to 240 positions")
    if any(type(position) is not int or not 0 <= position < TOTAL_COEFFICIENTS for position in positions):
        raise ValueError("support contains an invalid coefficient position")
    if len(set(positions)) != len(positions):
        raise ValueError("support contains duplicate positions")
    return positions


def _step(step: int) -> None:
    if type(step) is not int or step <= 0:
        raise ValueError("quantization step must be a positive integer")


def encode_channels(
    channels: Sequence[Sequence[int]],
    support: Sequence[int],
    step: int,
    coefficient_bound: int,
) -> tuple[int, ...]:
    """Transform/select/quantize to centered integers, rejecting bound violations."""
    positions = _support(support)
    _step(step)
    if type(coefficient_bound) is not int or not 0 <= coefficient_bound <= (P - 1) // 2:
        raise ValueError("coefficient bound must be an integer in [0, 32768]")
    if len(channels) != CHANNEL_COUNT:
        raise ValueError("exactly two synchronized channels are required")
    coefficients = forward_channel(channels[0]) + forward_channel(channels[1])
    quantized = tuple(round_div(coefficients[position], step) for position in positions)
    if any(abs(value) > coefficient_bound for value in quantized):
        raise ValueError("quantized coefficient exceeds the profile bound")
    return quantized


def reconstruct_channels(
    centered_quantized: Sequence[int], support: Sequence[int], step: int
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Scatter dequantized values into the 480 positions; omitted positions are 0."""
    positions = _support(support)
    _step(step)
    if len(centered_quantized) != len(positions) or any(
        type(value) is not int or not -(P // 2) <= value <= P // 2
        for value in centered_quantized
    ):
        raise ValueError("quantized vector must contain centered F_65537 coefficients")
    coefficients = [0] * TOTAL_COEFFICIENTS
    for position, value in zip(positions, centered_quantized):
        coefficients[position] = value * step
    return inverse_channel(coefficients[:CHANNEL_SAMPLES]), inverse_channel(coefficients[CHANNEL_SAMPLES:])
