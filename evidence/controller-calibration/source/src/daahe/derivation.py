# SPDX-License-Identifier: MIT
"""Domain-separated hidden linear authenticators over F_65537.

API: ``derive_matrix(epoch_secret32, ticket_digest32, L)`` returns 16 x L
residues; ``derive_offset(secret, digest, source_id, nonce)`` returns 16 residues;
``linear_tag(matrix, x, offset)`` computes K*x+offset mod 65537.
``expand_fp(seed, count)`` rejects 32-bit values outside the largest multiple of
p below 2**32, avoiding modulo bias. This precise framing/KDF is a reference
completion of the article's domain-separated SHAKE256 derivation description.
It does not turn a generic linear authenticator into a proved multi-query MAC.
The protocol must enforce signed, single-use roster entries and reject replay.
The two-polynomial raw-data baseline permits L=480; protected compression still
limits L to 240 in its signed profile.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence

P = 65537
TAG_DIMENSION = 16
_PREFIX = b"DA-AHE/reference/v1/"


def _frame(*parts: bytes) -> bytes:
    if any(not isinstance(part, bytes) for part in parts):
        raise TypeError("domain-separated fields must be byte strings")
    return b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def _context(secret: bytes, digest: bytes) -> None:
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise ValueError("epoch secret must contain exactly 32 bytes")
    if not isinstance(digest, bytes) or len(digest) != 32:
        raise ValueError("ticket digest must contain exactly 32 bytes")


def _source_identifier(source_id: str | bytes | int) -> bytes:
    if isinstance(source_id, str):
        return b"str\x00" + source_id.encode("utf-8")
    if isinstance(source_id, bytes):
        return b"bytes\x00" + source_id
    if type(source_id) is int and source_id >= 0:
        return b"int\x00" + str(source_id).encode("ascii")
    raise ValueError("source_id must be text, bytes or a nonnegative integer")


def expand_fp(seed: bytes, count: int, p: int = P) -> tuple[int, ...]:
    """Expand a byte seed to unbiased F_p words by SHAKE256 rejection sampling."""
    if not isinstance(seed, bytes):
        raise TypeError("expansion seed must be bytes")
    if type(count) is not int or not 0 <= count <= TAG_DIMENSION * 480:
        raise ValueError("count is outside the reference allocation limit")
    if p != P:
        raise ValueError("only F_65537 is implemented")
    limit = (1 << 32) - ((1 << 32) % p)
    # Counter-framed SHAKE blocks avoid quadratic prefix re-expansion when a
    # rejection occurs. A fresh domain and 64-bit counter fix the exact stream.
    values: list[int] = []
    counter = 0
    while len(values) < count:
        stream = hashlib.shake_256(
            _PREFIX + b"expand-fp\x00" + _frame(seed, counter.to_bytes(8, "big"))
        ).digest(1024)
        counter += 1
        for index in range(0, len(stream), 4):
            candidate = int.from_bytes(stream[index : index + 4], "little")
            if candidate < limit:
                values.append(candidate % p)
                if len(values) == count:
                    break
    return tuple(values)


def _derive_key(secret: bytes, label: bytes) -> bytes:
    return hmac.digest(secret, _PREFIX + b"epoch-key\x00" + _frame(label), "sha3_256")


def derive_matrix(epoch_secret: bytes, ticket_digest: bytes, L: int) -> tuple[tuple[int, ...], ...]:
    _context(epoch_secret, ticket_digest)
    if type(L) is not int or not 1 <= L <= 480:
        raise ValueError("data length must be in [1, 480]")
    key = _derive_key(epoch_secret, b"matrix")
    seed = hmac.digest(
        key,
        _PREFIX + b"batch-matrix\x00" + _frame(ticket_digest, L.to_bytes(2, "big")),
        "sha3_256",
    )
    words = expand_fp(seed, TAG_DIMENSION * L)
    return tuple(words[row * L : (row + 1) * L] for row in range(TAG_DIMENSION))


def derive_offset(
    epoch_secret: bytes,
    ticket_digest: bytes,
    source_id: str | bytes | int,
    nonce: bytes,
) -> tuple[int, ...]:
    _context(epoch_secret, ticket_digest)
    if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 64:
        raise ValueError("node nonce must contain 16 to 64 bytes")
    key = _derive_key(epoch_secret, b"offset")
    seed = hmac.digest(
        key,
        _PREFIX + b"source-offset\x00" + _frame(ticket_digest, _source_identifier(source_id), nonce),
        "sha3_256",
    )
    return expand_fp(seed, TAG_DIMENSION)


def linear_tag(
    matrix: Sequence[Sequence[int]], x: Sequence[int], offset: Sequence[int]
) -> tuple[int, ...]:
    """Evaluate a 16-vector authenticator; signed x values are reduced mod p."""
    if len(matrix) != TAG_DIMENSION or len(offset) != TAG_DIMENSION:
        raise ValueError("authenticator must have 16 rows and offsets")
    if not 1 <= len(x) <= 480 or any(type(value) is not int for value in x):
        raise ValueError("data vector has invalid length or coefficients")
    if any(type(value) is not int or not 0 <= value < P for value in offset):
        raise ValueError("offset coefficients must be canonical F_p residues")
    result = []
    for row, shift in zip(matrix, offset):
        if len(row) != len(x) or any(type(value) is not int or not 0 <= value < P for value in row):
            raise ValueError("matrix shape or coefficients are invalid")
        result.append((sum(coefficient * value for coefficient, value in zip(row, x)) + shift) % P)
    return tuple(result)
