from __future__ import annotations

import numpy as np


def mod_q(poly: np.ndarray, q: int) -> np.ndarray:
    """Return coefficients in [0, q)."""

    if q == 1 << 32:
        return np.bitwise_and(np.asarray(poly, dtype=np.int64), q - 1)
    return np.mod(np.asarray(poly, dtype=np.int64), q)


def centered(values: np.ndarray, modulus: int) -> np.ndarray:
    values = np.mod(np.asarray(values, dtype=np.int64), modulus)
    half = modulus // 2
    return np.where(values > half, values - modulus, values).astype(np.int64)


def negacyclic_mul(a: np.ndarray, b: np.ndarray, q: int) -> np.ndarray:
    """Multiply in Z_q[X]/(X^d + 1).

    DA-AHE multiplications always contain at least one small Gaussian operand,
    so signed 64-bit convolution is sufficient for the fixed d=256 profile.
    """

    a64 = np.asarray(a, dtype=np.int64)
    b64 = np.asarray(b, dtype=np.int64)
    if a64.shape != b64.shape or a64.ndim != 1:
        raise ValueError("polynomials must be equal-length one-dimensional arrays")
    d = a64.size
    bound = int(np.max(np.abs(a64))) * int(np.max(np.abs(b64))) * d
    if bound >= (1 << 62):
        raise OverflowError("unsafe int64 convolution; one operand must be small")
    conv = np.convolve(a64, b64)
    result = conv[:d].copy()
    result[: d - 1] -= conv[d:]
    return mod_q(result, q)


def ring_inner_product(
    left: np.ndarray, right: np.ndarray, q: int
) -> np.ndarray:
    if left.shape != right.shape or left.ndim != 2:
        raise ValueError("ring vectors must have shape (k, d)")
    acc = np.zeros(left.shape[1], dtype=np.int64)
    for a, b in zip(left, right, strict=True):
        acc = mod_q(acc + negacyclic_mul(a, b, q), q)
    return acc

