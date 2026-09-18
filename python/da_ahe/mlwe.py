from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os

import numpy as np

from .params import LatticeParams
from .ring import centered, mod_q, negacyclic_mul, ring_inner_product
from .sampling import ResearchSampler


@dataclass(frozen=True)
class PublicKey:
    matrix_seed: bytes
    b: np.ndarray


@dataclass(frozen=True)
class SecretKey:
    s: np.ndarray


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    secret: SecretKey
    key_error: np.ndarray


@dataclass(frozen=True)
class Ciphertext:
    u: np.ndarray
    v: np.ndarray

    def to_words(self, params: LatticeParams) -> np.ndarray:
        words = np.concatenate((self.u.reshape(-1), self.v))
        if words.size != params.ciphertext_words:
            raise ValueError("invalid ciphertext shape")
        return np.asarray(words, dtype=np.uint32)

    def to_bytes(self, params: LatticeParams) -> bytes:
        return self.to_words(params).astype("<u4", copy=False).tobytes()

    @classmethod
    def from_bytes(cls, raw: bytes, params: LatticeParams) -> "Ciphertext":
        if len(raw) != params.ciphertext_bytes:
            raise ValueError("incorrect ciphertext length")
        words = np.frombuffer(raw, dtype="<u4").astype(np.int64)
        u_words = params.k * params.d
        return cls(words[:u_words].reshape(params.k, params.d), words[u_words:])


def expand_a(seed: bytes, params: LatticeParams) -> np.ndarray:
    matrix = np.empty((params.k, params.k, params.d), dtype=np.int64)
    for row in range(params.k):
        for column in range(params.k):
            raw = hashlib.shake_256(
                b"DA-AHE/A/" + seed + bytes((row, column))
            ).digest(params.d * 4)
            matrix[row, column] = np.frombuffer(raw, dtype="<u4").astype(np.int64)
    return matrix


def keygen(
    params: LatticeParams,
    sampler: ResearchSampler,
    matrix_seed: bytes | None = None,
) -> KeyPair:
    params.validate()
    matrix_seed = matrix_seed or os.urandom(32)
    a = expand_a(matrix_seed, params)
    s = sampler.gaussian((params.k, params.d), params.sigma_key)
    e = sampler.gaussian((params.k, params.d), params.sigma_key)
    b = np.zeros((params.k, params.d), dtype=np.int64)
    for row in range(params.k):
        acc = np.zeros(params.d, dtype=np.int64)
        for col in range(params.k):
            acc = mod_q(acc + negacyclic_mul(a[row, col], s[col], params.q), params.q)
        b[row] = mod_q(acc + e[row], params.q)
    return KeyPair(PublicKey(matrix_seed, b), SecretKey(s), e)


def encrypt(
    public_key: PublicKey,
    message: np.ndarray,
    sigma_enc: float,
    params: LatticeParams,
    sampler: ResearchSampler,
) -> Ciphertext:
    message = np.asarray(message, dtype=np.int64)
    if message.shape != (params.d,):
        raise ValueError(f"message must contain {params.d} coefficients")
    a = expand_a(public_key.matrix_seed, params)
    r = sampler.gaussian((params.k, params.d), sigma_enc)
    e1 = sampler.gaussian((params.k, params.d), sigma_enc)
    e2 = sampler.gaussian(params.d, sigma_enc)

    u = np.zeros((params.k, params.d), dtype=np.int64)
    for col in range(params.k):
        acc = np.zeros(params.d, dtype=np.int64)
        for row in range(params.k):
            acc = mod_q(acc + negacyclic_mul(a[row, col], r[row], params.q), params.q)
        u[col] = mod_q(acc + e1[col], params.q)

    v = ring_inner_product(public_key.b, r, params.q)
    lifted = centered(message, params.p)
    v = mod_q(v + e2 + params.delta * lifted, params.q)
    return Ciphertext(u, v)


def add_ciphertexts(ciphertexts: list[Ciphertext], params: LatticeParams) -> Ciphertext:
    if not ciphertexts:
        raise ValueError("cannot aggregate an empty ciphertext list")
    u = np.zeros((params.k, params.d), dtype=np.int64)
    v = np.zeros(params.d, dtype=np.int64)
    for ciphertext in ciphertexts:
        u = mod_q(u + ciphertext.u, params.q)
        v = mod_q(v + ciphertext.v, params.q)
    return Ciphertext(u, v)


def _round_divide_signed(values: np.ndarray, divisor: int) -> np.ndarray:
    values = np.asarray(values, dtype=np.int64)
    absolute = np.abs(values)
    quotient = (absolute + divisor // 2) // divisor
    return np.where(values < 0, -quotient, quotient)


def decrypt(
    secret_key: SecretKey, ciphertext: Ciphertext, params: LatticeParams
) -> np.ndarray:
    phase = mod_q(
        ciphertext.v - ring_inner_product(secret_key.s, ciphertext.u, params.q),
        params.q,
    )
    decoded = _round_divide_signed(centered(phase, params.q), params.delta)
    return np.mod(decoded, params.p).astype(np.int64)
