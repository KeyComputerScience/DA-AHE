# SPDX-License-Identifier: MIT
"""Exact, deliberately slow polynomial arithmetic in Z_q[X]/(X^d + 1).

API: ``centered(value, modulus)``, ``add(a, b, q)``, ``sub(a, b, q)``,
``negacyclic_mul(a, b, q)`` and ``dot(a_vector, b_vector, q)``.
All products and sums use Python integers. There is no machine-word overflow,
floating-point convolution, NTT assumption, or constant-time guarantee.
"""

from __future__ import annotations

from collections.abc import Sequence

Poly = tuple[int, ...]


def _modulus(modulus: int) -> None:
    if type(modulus) is not int or modulus < 2:
        raise ValueError("modulus must be an integer greater than one")


def _coefficients(values: Sequence[int]) -> None:
    if not values or any(type(value) is not int for value in values):
        raise ValueError("a polynomial must contain integer coefficients")


def centered(value: int, modulus: int) -> int:
    """Return the unique representative in [-floor(modulus/2), ceil(modulus/2))."""
    _modulus(modulus)
    if type(value) is not int:
        raise TypeError("coefficient must be an integer")
    residue = value % modulus
    return residue - modulus if residue >= (modulus + 1) // 2 else residue


def normalize(values: Sequence[int], modulus: int) -> Poly:
    _modulus(modulus)
    _coefficients(values)
    return tuple(value % modulus for value in values)


def _pair(a: Sequence[int], b: Sequence[int], q: int) -> None:
    _modulus(q)
    _coefficients(a)
    _coefficients(b)
    if len(a) != len(b):
        raise ValueError("polynomials have different degrees")


def add(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    _pair(a, b, q)
    return tuple((left + right) % q for left, right in zip(a, b))


def sub(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    _pair(a, b, q)
    return tuple((left - right) % q for left, right in zip(a, b))


def negacyclic_mul(a: Sequence[int], b: Sequence[int], q: int) -> Poly:
    """Schoolbook multiplication, reducing X^d to -1 and coefficients mod q."""
    _pair(a, b, q)
    degree = len(a)
    result = [0] * degree
    for i, left in enumerate(a):
        for j, right in enumerate(b):
            position = i + j
            if position < degree:
                result[position] += left * right
            else:
                result[position - degree] -= left * right
    return tuple(value % q for value in result)


def dot(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]], q: int) -> Poly:
    """Ring-valued dot product of equally sized nonempty polynomial vectors."""
    if not a or len(a) != len(b):
        raise ValueError("polynomial vector dimensions do not match")
    degree = len(a[0])
    accumulator: Poly = (0,) * degree
    for left, right in zip(a, b):
        if len(left) != degree or len(right) != degree:
            raise ValueError("polynomial vector contains inconsistent degrees")
        accumulator = add(accumulator, negacyclic_mul(left, right, q), q)
    return accumulator


mul = negacyclic_mul
