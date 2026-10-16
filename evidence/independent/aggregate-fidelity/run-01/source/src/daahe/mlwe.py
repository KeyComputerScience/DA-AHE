# SPDX-License-Identifier: MIT
"""Auditable M-LWE additive-encryption reference with explicit module rank.

API: ``keygen(rng=None) -> KeyPair``, ``encrypt(pk, message, sigma=3.2,
rng=None) -> Ciphertext``, ``decrypt(sk, ciphertext) -> tuple[int, ...]`` and
``iter_ciphertext_blocks(ciphertext, block_size)``. KeyPair exposes ``public`` /
``secret`` and aliases ``pk`` / ``sk``. Ciphertext supports ``+``, ``to_bytes``
and ``from_bytes``. Plaintexts contain at most 256 residues of F_65537.

This is an educational CPA-style additive primitive, not an ML-KEM instance or
a hardened deployment cryptosystem. Python arithmetic, the sampler and memory
handling are not constant-time. A default CSPRNG supplies randomness; injecting
``random.Random`` is supported solely for reproducible tests. The finite CDT
sampler has support +/-ceil(16*sigma), decimal precision 120 and 256-bit CDF
quantization. It is explicitly a reference approximation to a discrete Gaussian.
No lattice-estimator security claim or decryption-failure certificate is implied.
The seeded matrix encoding and CDT below are completion choices absent from the
article, not a claim to reproduce the authors' unpublished implementation.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from bisect import bisect_right
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_FLOOR, localcontext
from functools import lru_cache
from typing import Any

from .ring import Poly, add, centered, dot, sub


@dataclass(frozen=True)
class MLWEParameters:
    q: int = 2**32
    p: int = 65537
    d: int = 256
    k: int = 6
    lambda_tag: int = 16
    sigma_key: float = 3.2

    def __post_init__(self) -> None:
        if (self.q, self.p, self.d, self.lambda_tag) != (
            2**32, 65537, 256, 16
        ) or self.sigma_key != 3.2 or type(self.k) is not int or not 3 <= self.k <= 16:
            raise ValueError("supported tuples require d=256, q=2^32, p=65537, sigma_key=3.2 and integer module rank 3..16; security must be estimated separately")

    @property
    def delta(self) -> int:
        return self.q // self.p

    @property
    def n(self) -> int:
        return self.k * self.d

    @property
    def ciphertext_bytes(self) -> int:
        return (self.k + 1) * self.d * 4


DEFAULT_PARAMETERS = MLWEParameters()
LEGACY_PARAMETERS = MLWEParameters(k=3)
CIPHERTEXT_BYTES = DEFAULT_PARAMETERS.ciphertext_bytes


def _randbelow(rng: Any | None, upper: int) -> int:
    if rng is None:
        return secrets.randbelow(upper)
    if hasattr(rng, "randbelow"):
        value = rng.randbelow(upper)
    elif hasattr(rng, "randrange"):
        value = rng.randrange(upper)
    else:
        raise TypeError("rng must provide randbelow or randrange")
    if type(value) is not int or not 0 <= value < upper:
        raise ValueError("rng returned an out-of-range integer")
    return value


def _random_bytes(rng: Any | None, size: int) -> bytes:
    if rng is None:
        return secrets.token_bytes(size)
    if hasattr(rng, "randbytes"):
        result = rng.randbytes(size)
    elif hasattr(rng, "token_bytes"):
        result = rng.token_bytes(size)
    else:
        result = bytes(_randbelow(rng, 256) for _ in range(size))
    if not isinstance(result, bytes) or len(result) != size:
        raise ValueError("rng returned an invalid byte string")
    return result


@lru_cache(maxsize=8)
def _gaussian_cdt(sigma: float) -> tuple[int, tuple[int, ...]]:
    if not math.isfinite(sigma) or not 0.0 < sigma <= 16.0:
        raise ValueError("sigma must be finite and in (0, 16]")
    radius = math.ceil(16 * sigma)
    total_space = 1 << 256
    with localcontext() as context:
        context.prec = 120
        sigma_decimal = Decimal(str(sigma))
        variance_factor = 2 * sigma_decimal * sigma_decimal
        weights = [
            (-Decimal(value * value) / variance_factor).exp()
            for value in range(-radius, radius + 1)
        ]
        total_weight = sum(weights)
        cumulative = Decimal(0)
        cdf = []
        for weight in weights:
            cumulative += weight
            boundary = (cumulative * total_space / total_weight).to_integral_value(
                rounding=ROUND_FLOOR
            )
            cdf.append(int(boundary))
    cdf[-1] = total_space
    return radius, tuple(cdf)


def sample_discrete_gaussian(sigma: float = 3.2, rng: Any | None = None) -> int:
    """Draw the documented symmetric, truncated, 256-bit-CDT reference noise."""
    radius, cdf = _gaussian_cdt(float(sigma))
    return bisect_right(cdf, _randbelow(rng, 1 << 256)) - radius


def _noise_poly(params: MLWEParameters, sigma: float, rng: Any | None) -> Poly:
    return tuple(sample_discrete_gaussian(sigma, rng) for _ in range(params.d))


def expand_matrix(
    seed: bytes, params: MLWEParameters = DEFAULT_PARAMETERS
) -> tuple[tuple[Poly, ...], ...]:
    """SHAKE256 row-major uniform 32-bit words; the 256-bit public seed fixes A."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("public matrix seed must contain 32 bytes")
    domain = b"DA-AHE/reference/v1/A\x00" + seed
    raw = hashlib.shake_256(domain).digest(params.k * params.k * params.d * 4)
    cursor = 0
    rows = []
    for _ in range(params.k):
        row = []
        for _ in range(params.k):
            polynomial = []
            for _ in range(params.d):
                polynomial.append(int.from_bytes(raw[cursor : cursor + 4], "little"))
                cursor += 4
            row.append(tuple(polynomial))
        rows.append(tuple(row))
    return tuple(rows)


def _vector(value: Sequence[Sequence[int]], params: MLWEParameters) -> tuple[Poly, ...]:
    if len(value) != params.k:
        raise ValueError("polynomial vector has the wrong rank")
    result = tuple(tuple(poly) for poly in value)
    if any(
        len(poly) != params.d or any(type(word) is not int for word in poly)
        for poly in result
    ):
        raise ValueError("polynomial vector has invalid coefficients or degree")
    return result


@dataclass(frozen=True)
class PublicKey:
    a_seed: bytes
    b: tuple[Poly, ...]
    params: MLWEParameters = DEFAULT_PARAMETERS

    def __post_init__(self) -> None:
        if not isinstance(self.a_seed, bytes) or len(self.a_seed) != 32:
            raise ValueError("public matrix seed must contain 32 bytes")
        canonical = _vector(self.b, self.params)
        if any(not 0 <= word < self.params.q for poly in canonical for word in poly):
            raise ValueError("public-key coefficients must be canonical residues")
        object.__setattr__(self, "b", canonical)


@dataclass(frozen=True)
class SecretKey:
    s: tuple[Poly, ...] = field(repr=False)
    params: MLWEParameters = DEFAULT_PARAMETERS

    def __post_init__(self) -> None:
        object.__setattr__(self, "s", _vector(self.s, self.params))


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    secret: SecretKey = field(repr=False)

    @property
    def pk(self) -> PublicKey:
        return self.public

    @property
    def sk(self) -> SecretKey:
        return self.secret


@dataclass(frozen=True)
class Ciphertext:
    """Immutable (u[0],...,u[k-1],v), each holding 256 canonical uint32 words."""

    u: tuple[Poly, ...]
    v: Poly
    params: MLWEParameters = DEFAULT_PARAMETERS

    def __post_init__(self) -> None:
        u = _vector(self.u, self.params)
        v = tuple(self.v)
        if len(v) != self.params.d or any(type(word) is not int for word in v):
            raise ValueError("ciphertext v has invalid coefficients or degree")
        if any(not 0 <= word < self.params.q for poly in (*u, v) for word in poly):
            raise ValueError("ciphertext coefficients must be canonical residues")
        object.__setattr__(self, "u", u)
        object.__setattr__(self, "v", v)

    def __add__(self, other: Ciphertext) -> Ciphertext:
        if not isinstance(other, Ciphertext):
            return NotImplemented
        if self.params != other.params:
            raise ValueError("ciphertext parameters differ")
        return Ciphertext(
            tuple(add(left, right, self.params.q) for left, right in zip(self.u, other.u)),
            add(self.v, other.v, self.params.q),
            self.params,
        )

    def to_bytes(self) -> bytes:
        """Materialize parameter-derived bytes; streaming avoids a second buffer."""
        return b"".join(iter_ciphertext_blocks(self, 64))

    @classmethod
    def from_bytes(
        cls, encoded: bytes, params: MLWEParameters = DEFAULT_PARAMETERS
    ) -> Ciphertext:
        if not isinstance(encoded, bytes) or len(encoded) != params.ciphertext_bytes:
            raise ValueError(f"ciphertext must contain exactly {params.ciphertext_bytes} bytes for module rank {params.k}")
        words = tuple(
            int.from_bytes(encoded[index : index + 4], "little")
            for index in range(0, len(encoded), 4)
        )
        u = tuple(words[index * params.d : (index + 1) * params.d] for index in range(params.k))
        return cls(u, words[params.k * params.d :], params)


def keygen(
    rng: Any | None = None, params: MLWEParameters = DEFAULT_PARAMETERS
) -> KeyPair:
    """Sample s,e at sigma_key=3.2, publishing b=A*s+e modulo q."""
    seed = _random_bytes(rng, 32)
    matrix = expand_matrix(seed, params)
    secret = tuple(_noise_poly(params, params.sigma_key, rng) for _ in range(params.k))
    error = tuple(_noise_poly(params, params.sigma_key, rng) for _ in range(params.k))
    b = tuple(add(dot(row, secret, params.q), e, params.q) for row, e in zip(matrix, error))
    return KeyPair(PublicKey(seed, b, params), SecretKey(secret, params))


def encrypt(
    pk: PublicKey,
    message: Sequence[int],
    sigma: float = 3.2,
    rng: Any | None = None,
) -> Ciphertext:
    """Encrypt canonical F_p residues, padding the message with trailing zeros."""
    params = pk.params
    if len(message) > params.d or any(
        type(word) is not int or not 0 <= word < params.p for word in message
    ):
        raise ValueError("plaintext must hold at most 256 canonical F_p residues")
    if float(sigma) not in (3.2, 3.4, 3.6):
        raise ValueError("encryption sigma must be one of 3.2, 3.4, 3.6")
    plaintext = tuple(message) + (0,) * (params.d - len(message))
    matrix = expand_matrix(pk.a_seed, params)
    r = tuple(_noise_poly(params, sigma, rng) for _ in range(params.k))
    e1 = tuple(_noise_poly(params, sigma, rng) for _ in range(params.k))
    e2 = _noise_poly(params, sigma, rng)
    transpose = tuple(tuple(matrix[row][column] for row in range(params.k)) for column in range(params.k))
    u = tuple(add(dot(column, r, params.q), error, params.q) for column, error in zip(transpose, e1))
    lifted = tuple(params.delta * centered(word, params.p) for word in plaintext)
    v = add(add(dot(pk.b, r, params.q), e2, params.q), lifted, params.q)
    return Ciphertext(u, v, params)


def decrypt(sk: SecretKey, ciphertext: Ciphertext) -> Poly:
    """Decode round(center_q(v-s^T*u)/Delta) modulo p using exact integers.

    A decoding result alone does not authenticate a message. Protocol callers
    must verify the ticket, exact roster and hidden aggregate tag before release.
    The decoder cannot detect noise exceeding its margin without authentication.
    """
    if sk.params != ciphertext.params:
        raise ValueError("key and ciphertext parameters differ")
    params = sk.params
    noisy = sub(ciphertext.v, dot(sk.s, ciphertext.u, params.q), params.q)
    return tuple(
        ((centered(word, params.q) + params.delta // 2) // params.delta) % params.p
        for word in noisy
    )


def iter_ciphertext_blocks(ciphertext: Ciphertext, block_size: int = 64) -> Iterator[bytes]:
    """Yield canonical little-endian words using one 32/64-byte block buffer.

    The ciphertext object and Python temporaries still consume host memory; this
    iterator does not establish the article's embedded 10-KiB workspace result.
    """
    if type(block_size) is not int or block_size not in (32, 64):
        raise ValueError("block_size must be 32 or 64 bytes")
    block = bytearray()
    for polynomial in (*ciphertext.u, ciphertext.v):
        for word in polynomial:
            block.extend(word.to_bytes(4, "little"))
            if len(block) == block_size:
                yield bytes(block)
                block.clear()
    if block:
        yield bytes(block)


def deserialize_ciphertext(encoded: bytes, params: MLWEParameters = DEFAULT_PARAMETERS) -> Ciphertext:
    return Ciphertext.from_bytes(encoded, params)


def add_ciphertexts(ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
    if not ciphertexts:
        raise ValueError("cannot aggregate an empty ciphertext sequence")
    aggregate = ciphertexts[0]
    for ciphertext in ciphertexts[1:]:
        aggregate = aggregate + ciphertext
    return aggregate
