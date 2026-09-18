#!/usr/bin/env python3
"""Executable DA-AHE Markov-to-post-quantum closed-loop reference model.

This program extends ``da_ahe_robust_stability.py`` with an executable data
path that mirrors the paper's implementation chain:

    telemetry -> HMM belief -> robust action screening -> ProfileID/ticket
    -> fixed-point db2 -> quantization -> linear tag -> one-polynomial pack
    -> Module-LWE encryption -> authenticated block streaming
    -> exact-roster homomorphic aggregation -> sink verification/decryption
    -> certified noise feedback.

Security boundary
-----------------
This is a deterministic research/validation model.  Its NumPy Module-LWE
arithmetic is not constant-time, its samplers are not production samplers,
and it has not been audited.  It MUST NOT protect real data.

The code uses an ML-DSA-44 ticket backend when the optional ``pqcrypto``
package is installed.  Otherwise it uses a clearly labelled HMAC-SHA3-256
demo backend so that the complete pipeline remains runnable.  The symmetric
fallback models quantum-resistant shared-key authentication, but it is not a
public-key signature and therefore does not satisfy the paper's public
post-quantum ticket-signature claim.  Use ``--require-pq-signature`` to fail
closed when ML-DSA is unavailable.

Run:
    python da_ahe_pq_closed_loop.py
    python da_ahe_pq_closed_loop.py --steps 8 --nodes 6
    python da_ahe_pq_closed_loop.py --require-pq-signature

Required:
    numpy
    da_ahe_robust_stability.py  (in the same directory)

Optional:
    pqcrypto  (for ML-DSA-44 batch-ticket signatures)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Protocol, Sequence, Tuple

import numpy as np

try:
    from da_ahe_robust_stability import (
        OBSERVATION_MEANS,
        OBSERVATION_STD,
        Action,
        ControllerParameters,
        belief_update,
        build_actions,
        build_transition_kernels,
        model_error_radius,
        predict_next_z,
        sample_bounded_error,
        select_action,
    )
except ImportError as exc:  # pragma: no cover - exercised only on bad install
    raise SystemExit(
        "Place da_ahe_robust_stability.py beside this file before running it."
    ) from exc


# Paper-level Module-LWE parameters.  Python integers/NumPy int64 are used for
# readable reference arithmetic; the firmware uses fixed-width streaming code.
Q = 1 << 32
P = 65_537
RING_D = 256
MODULE_K = 3
TAG_DIM = 16
DELTA = Q // P
TAU_DEC = DELTA // 2
NOISE_GUARD = 1_024
MAX_SUPPORT = RING_D - TAG_DIM
MAX_RAM_BYTES = 10 * 1_024
MAX_AIRTIME_MS = 220.0
RADIO_BITRATE = 250_000.0

DOMAIN_TICKET = b"DA-AHE/ticket/v1"
DOMAIN_BATCH_MATRIX = b"DA-AHE/batch-matrix/v1"
DOMAIN_SOURCE_OFFSET = b"DA-AHE/source-offset/v1"
DOMAIN_BLOCK_KEY = b"DA-AHE/block-key/v1"
DOMAIN_BLOCK = b"DA-AHE/block/v1"
DOMAIN_AGGREGATE_KEY = b"DA-AHE/aggregate-key/v1"
DOMAIN_AGGREGATE = b"DA-AHE/aggregate/v1"


class ChainError(RuntimeError):
    """Raised when a profile, envelope, roster, or verification check fails."""


@dataclass(frozen=True)
class RuntimeProfile:
    """One action bound to an offline-certified cryptographic profile."""

    name: str
    ell: int
    rho: float
    quant_step: int
    batch_size: int
    block_size: int
    repair_intensity: float
    sigma_enc: float
    max_batch: int
    support_length: int
    tag_dimension: int
    estimated_quantum_bits: float
    certified_failure_log2: float
    certified_noise_bound: int
    message_abs_bound: int
    ram_bytes: int
    airtime_ms: float
    profile_id: str


@dataclass(frozen=True)
class RosterEntry:
    node_id: str
    nonce: str


@dataclass(frozen=True)
class BatchTicket:
    epoch: int
    batch_id: str
    context_id: str
    profile_id: str
    roster: Tuple[RosterEntry, ...]
    batch_nonce: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "batch_id": self.batch_id,
            "batch_nonce": self.batch_nonce,
            "context_id": self.context_id,
            "epoch": self.epoch,
            "profile_id": self.profile_id,
            "roster": [asdict(entry) for entry in self.roster],
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def digest(self) -> bytes:
        return hashlib.sha3_256(self.canonical_bytes()).digest()


@dataclass(frozen=True)
class SignedTicket:
    ticket: BatchTicket
    signature: bytes
    scheme: str


@dataclass
class MLWESecretKey:
    coefficients: np.ndarray  # shape (MODULE_K, RING_D)


@dataclass
class MLWEPublicKey:
    matrix_a: np.ndarray  # shape (MODULE_K, MODULE_K, RING_D)
    vector_b: np.ndarray  # shape (MODULE_K, RING_D)


@dataclass
class MLWECiphertext:
    vector_u: np.ndarray  # shape (MODULE_K, RING_D)
    poly_v: np.ndarray  # shape (RING_D,)


@dataclass(frozen=True)
class AuthenticatedBlock:
    index: int
    total: int
    payload: bytes
    tag: bytes


@dataclass(frozen=True)
class NodeEnvelope:
    node_id: str
    nonce: str
    profile_id: str
    ticket_digest: str
    blocks: Tuple[AuthenticatedBlock, ...]


@dataclass(frozen=True)
class AggregateEnvelope:
    profile_id: str
    ticket_digest: str
    roster: Tuple[RosterEntry, ...]
    ciphertext_bytes: bytes
    transport_tag: bytes


@dataclass
class NodePayload:
    node_id: str
    quantized: np.ndarray
    support: np.ndarray
    offset: np.ndarray
    source_window: np.ndarray


@dataclass
class VerifiedAggregate:
    quantized_sum: np.ndarray
    tag_sum: np.ndarray
    reconstructed_window: np.ndarray
    actual_noise_inf: int
    certified_noise_bound: int


@dataclass
class EpochRecord:
    epoch: int
    regime: int
    action: str
    profile_id: str
    roster_size: int
    robust_v: float
    drift_limit: float
    actual_noise_inf: int
    certified_noise_bound: int
    tag_verified: bool
    decryption_correct: bool
    mean_square_state: float


class TicketAuthenticator(Protocol):
    scheme: str
    is_public_pq_signature: bool

    def sign(self, message: bytes) -> bytes:
        ...

    def verify(self, message: bytes, signature: bytes) -> bool:
        ...


class SymmetricTicketAuthenticator:
    """Runnable shared-key fallback; intentionally not called a signature."""

    scheme = "HMAC-SHA3-256-DEMO-NOT-A-PUBLIC-SIGNATURE"
    is_public_pq_signature = False

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("The demo ticket key must contain at least 256 bits")
        self._key = key

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._key, message, hashlib.sha3_256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)


class MLDSA44TicketAuthenticator:
    """Thin adapter for pqcrypto.sign.ml_dsa_44 when installed."""

    scheme = "ML-DSA-44"
    is_public_pq_signature = True

    def __init__(self) -> None:
        from pqcrypto.sign import ml_dsa_44  # type: ignore[import-not-found]

        self._backend = ml_dsa_44
        self._public_key, self._secret_key = ml_dsa_44.generate_keypair()

    def sign(self, message: bytes) -> bytes:
        return self._backend.sign(self._secret_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            result = self._backend.verify(self._public_key, message, signature)
            return result is None or result is True
        except Exception:
            return False


def build_ticket_authenticator(
    master_seed: bytes,
    require_pq_signature: bool,
) -> TicketAuthenticator:
    try:
        return MLDSA44TicketAuthenticator()
    except (ImportError, ModuleNotFoundError):
        if require_pq_signature:
            raise ChainError(
                "ML-DSA backend unavailable. Install pqcrypto or omit "
                "--require-pq-signature for the labelled symmetric demo."
            )
        demo_key = hashlib.shake_256(
            b"DA-AHE/demo-ticket-key" + master_seed
        ).digest(32)
        return SymmetricTicketAuthenticator(demo_key)


def _canonical_profile_payload(action: Action, support_length: int) -> bytes:
    payload = {
        "batch_size": action.batch_size,
        "block_size": action.block_size,
        "ell": action.profile,
        "k": MODULE_K,
        "n": MODULE_K * RING_D,
        "p": P,
        "q": Q,
        "quant_step": action.delta_q,
        "rho": action.rho,
        "support_length": support_length,
        "tag_dimension": TAG_DIM,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def bind_runtime_profile(action: Action) -> RuntimeProfile:
    max_batches = {0: 16, 1: 14, 2: 12}
    sigma = {0: 3.2, 1: 3.4, 2: 3.6}
    certified_noise = {0: 5_200, 1: 6_100, 2: 7_100}

    support_length = int(round(MAX_SUPPORT * action.rho))
    support_length = max(2, min(MAX_SUPPORT, support_length))
    if support_length % 2:
        support_length -= 1

    block_count = math.ceil(4_096 / action.block_size)
    transported_bytes = 4_096 + 16 * block_count
    airtime_ms = transported_bytes * 8.0 / RADIO_BITRATE * 1_000.0
    profile_payload = _canonical_profile_payload(action, support_length)
    profile_id = hashlib.sha3_256(profile_payload).hexdigest()[:24]

    return RuntimeProfile(
        name=action.name,
        ell=action.profile,
        rho=action.rho,
        quant_step=action.delta_q,
        batch_size=action.batch_size,
        block_size=action.block_size,
        repair_intensity=action.repair_intensity,
        sigma_enc=sigma[action.profile],
        max_batch=max_batches[action.profile],
        support_length=support_length,
        tag_dimension=TAG_DIM,
        estimated_quantum_bits=128.1,
        certified_failure_log2=-128.0,
        certified_noise_bound=certified_noise[action.profile],
        message_abs_bound=1_500,
        ram_bytes=8_140,
        airtime_ms=airtime_ms,
        profile_id=profile_id,
    )


def assert_profile_safe(profile: RuntimeProfile, roster_size: int) -> None:
    checks = {
        "positive roster": 0 < roster_size,
        "action batch": roster_size <= profile.batch_size,
        "profile batch": roster_size <= profile.max_batch,
        "single polynomial": profile.support_length + TAG_DIM <= RING_D,
        "plaintext no-wrap": (
            roster_size * profile.message_abs_bound <= (P - 1) // 2
        ),
        "noise margin": profile.certified_noise_bound <= TAU_DEC - NOISE_GUARD,
        "failure target": profile.certified_failure_log2 <= -128.0,
        "quantum estimate": profile.estimated_quantum_bits >= 128.1,
        "SRAM": profile.ram_bytes <= MAX_RAM_BYTES,
        "airtime": profile.airtime_ms <= MAX_AIRTIME_MS,
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ChainError(f"Profile {profile.name} failed: {', '.join(failed)}")


def _kdf(key: bytes, domain: bytes, context: bytes, length: int) -> bytes:
    return hashlib.shake_256(
        len(domain).to_bytes(2, "big") + domain + key + context
    ).digest(length)


def _expand_field(seed: bytes, count: int) -> np.ndarray:
    raw = hashlib.shake_256(seed).digest(4 * count)
    values = [int.from_bytes(raw[4 * i : 4 * i + 4], "little") % P for i in range(count)]
    return np.asarray(values, dtype=np.int64)


def derive_batch_matrix(
    epoch_secret: bytes,
    ticket: BatchTicket,
    support_length: int,
) -> np.ndarray:
    seed = _kdf(
        epoch_secret,
        DOMAIN_BATCH_MATRIX,
        ticket.digest(),
        32,
    )
    return _expand_field(seed, TAG_DIM * support_length).reshape(
        TAG_DIM, support_length
    )


def derive_source_offset(
    epoch_secret: bytes,
    ticket: BatchTicket,
    entry: RosterEntry,
) -> np.ndarray:
    context = (
        ticket.digest()
        + entry.node_id.encode("utf-8")
        + entry.nonce.encode("ascii")
    )
    seed = _kdf(epoch_secret, DOMAIN_SOURCE_OFFSET, context, 32)
    return _expand_field(seed, TAG_DIM)


def derive_block_key(
    epoch_secret: bytes,
    ticket: BatchTicket,
    entry: RosterEntry,
) -> bytes:
    context = ticket.digest() + entry.node_id.encode() + entry.nonce.encode()
    return _kdf(epoch_secret, DOMAIN_BLOCK_KEY, context, 32)


def derive_gateway_key(epoch_secret: bytes, ticket: BatchTicket) -> bytes:
    return _kdf(epoch_secret, DOMAIN_AGGREGATE_KEY, ticket.digest(), 32)


# Fixed-point orthonormal db2 analysis filters.  This is a readable reference
# transform, not the firmware's cycle-optimized bit-exact implementation.
DB2_SCALE = 1 << 15
_DB2_LOW_FLOAT = np.asarray(
    [-0.1294095226, 0.2241438680, 0.8365163037, 0.4829629131]
)
_DB2_HIGH_FLOAT = np.asarray(
    [_DB2_LOW_FLOAT[3], -_DB2_LOW_FLOAT[2], _DB2_LOW_FLOAT[1], -_DB2_LOW_FLOAT[0]]
)
DB2_LOW = np.rint(_DB2_LOW_FLOAT * DB2_SCALE).astype(np.int64)
DB2_HIGH = np.rint(_DB2_HIGH_FLOAT * DB2_SCALE).astype(np.int64)


def fixed_db2_forward(signal: np.ndarray) -> np.ndarray:
    signal = np.asarray(signal, dtype=np.int64)
    if signal.ndim != 1 or signal.size % 2:
        raise ValueError("db2 input must be a one-dimensional even-length array")
    half = signal.size // 2
    approximation = np.empty(half, dtype=np.int64)
    detail = np.empty(half, dtype=np.int64)
    for index in range(half):
        positions = [(2 * index + tap) % signal.size for tap in range(4)]
        window = signal[positions]
        approximation[index] = int(np.rint(float(DB2_LOW @ window) / DB2_SCALE))
        detail[index] = int(np.rint(float(DB2_HIGH @ window) / DB2_SCALE))
    return np.concatenate((approximation, detail))


def fixed_db2_inverse(coefficients: np.ndarray) -> np.ndarray:
    coefficients = np.asarray(coefficients, dtype=np.int64)
    if coefficients.ndim != 1 or coefficients.size % 2:
        raise ValueError("db2 coefficient array must have even length")
    half = coefficients.size // 2
    accumulator = np.zeros(coefficients.size, dtype=np.int64)
    for index in range(half):
        for tap in range(4):
            position = (2 * index + tap) % coefficients.size
            accumulator[position] += (
                DB2_LOW[tap] * coefficients[index]
                + DB2_HIGH[tap] * coefficients[half + index]
            )
    return np.rint(accumulator.astype(float) / DB2_SCALE).astype(np.int64)


def transform_window(window: np.ndarray) -> np.ndarray:
    window = np.asarray(window, dtype=np.int64)
    if window.shape != (2, 240):
        raise ValueError(f"Expected two 240-sample channels, got {window.shape}")
    return np.concatenate(
        (fixed_db2_forward(window[0]), fixed_db2_forward(window[1]))
    )


def fixed_support(profile: RuntimeProfile) -> np.ndarray:
    per_channel = profile.support_length // 2
    # Low-frequency coefficients occupy [0,120) and [240,360).
    support = np.concatenate(
        (
            np.arange(per_channel, dtype=np.int64),
            np.arange(240, 240 + per_channel, dtype=np.int64),
        )
    )
    if support.size != profile.support_length:
        raise AssertionError("Profile support construction is inconsistent")
    return support


def quantize_window(
    window: np.ndarray,
    profile: RuntimeProfile,
) -> Tuple[np.ndarray, np.ndarray]:
    coefficients = transform_window(window)
    support = fixed_support(profile)
    selected = coefficients[support]
    quantized_signed = np.rint(selected / profile.quant_step).astype(np.int64)
    if np.max(np.abs(quantized_signed), initial=0) > profile.message_abs_bound:
        raise ChainError("A source coefficient exceeded the certified no-wrap bound")
    return np.mod(quantized_signed, P), support


def reconstruct_window(
    aggregate_quantized: np.ndarray,
    support: np.ndarray,
    profile: RuntimeProfile,
) -> np.ndarray:
    signed = centered_mod(aggregate_quantized, P)
    coefficients = np.zeros(480, dtype=np.int64)
    coefficients[support] = signed * profile.quant_step
    return np.vstack(
        (
            fixed_db2_inverse(coefficients[:240]),
            fixed_db2_inverse(coefficients[240:]),
        )
    )


def centered_mod(values: np.ndarray, modulus: int) -> np.ndarray:
    reduced = np.mod(np.asarray(values, dtype=np.int64), modulus)
    half = modulus // 2
    return np.where(reduced > half, reduced - modulus, reduced)


def _sample_small(
    rng: np.random.Generator,
    shape: Tuple[int, ...],
    sigma: float,
) -> np.ndarray:
    samples = np.rint(rng.normal(0.0, sigma, size=shape)).astype(np.int64)
    limit = max(12, int(math.ceil(6.0 * sigma)))
    return np.clip(samples, -limit, limit)


def negacyclic_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    a64 = np.asarray(a, dtype=np.int64)
    b64 = np.asarray(b, dtype=np.int64)
    if a64.shape != (RING_D,) or b64.shape != (RING_D,):
        raise ValueError("Ring operands must contain exactly RING_D coefficients")
    convolution = np.convolve(a64, b64)
    result = convolution[:RING_D].copy()
    result[: RING_D - 1] -= convolution[RING_D:]
    return np.mod(result, Q).astype(np.int64)


def mlwe_keygen(
    rng: np.random.Generator,
    sigma_key: float = 3.2,
) -> Tuple[MLWEPublicKey, MLWESecretKey]:
    matrix_a = rng.integers(
        0, Q, size=(MODULE_K, MODULE_K, RING_D), dtype=np.uint64
    ).astype(np.int64)
    secret = _sample_small(rng, (MODULE_K, RING_D), sigma_key)
    error = _sample_small(rng, (MODULE_K, RING_D), sigma_key)
    vector_b = np.empty((MODULE_K, RING_D), dtype=np.int64)
    for row in range(MODULE_K):
        value = error[row].copy()
        for column in range(MODULE_K):
            value = np.mod(
                value + negacyclic_mul(matrix_a[row, column], secret[column]),
                Q,
            )
        vector_b[row] = value
    return MLWEPublicKey(matrix_a, vector_b), MLWESecretKey(secret)


def pack_plaintext(data: np.ndarray, tag: np.ndarray) -> np.ndarray:
    data = np.mod(np.asarray(data, dtype=np.int64), P)
    tag = np.mod(np.asarray(tag, dtype=np.int64), P)
    if data.ndim != 1 or tag.shape != (TAG_DIM,):
        raise ValueError("Invalid data or tag dimensions")
    if data.size + TAG_DIM > RING_D:
        raise ChainError("Data and tag do not fit one plaintext polynomial")
    polynomial = np.zeros(RING_D, dtype=np.int64)
    polynomial[: data.size] = data
    polynomial[data.size : data.size + TAG_DIM] = tag
    return polynomial


def unpack_plaintext(
    polynomial: np.ndarray,
    data_length: int,
) -> Tuple[np.ndarray, np.ndarray]:
    polynomial = np.mod(np.asarray(polynomial, dtype=np.int64), P)
    return (
        polynomial[:data_length].copy(),
        polynomial[data_length : data_length + TAG_DIM].copy(),
    )


def mlwe_encrypt(
    public_key: MLWEPublicKey,
    message: np.ndarray,
    sigma_enc: float,
    rng: np.random.Generator,
) -> MLWECiphertext:
    message = np.mod(np.asarray(message, dtype=np.int64), P)
    random_r = _sample_small(rng, (MODULE_K, RING_D), sigma_enc)
    error_1 = _sample_small(rng, (MODULE_K, RING_D), sigma_enc)
    error_2 = _sample_small(rng, (RING_D,), sigma_enc)

    vector_u = np.empty((MODULE_K, RING_D), dtype=np.int64)
    for column in range(MODULE_K):
        value = error_1[column].copy()
        for row in range(MODULE_K):
            value = np.mod(
                value
                + negacyclic_mul(public_key.matrix_a[row, column], random_r[row]),
                Q,
            )
        vector_u[column] = value

    poly_v = error_2.copy()
    for row in range(MODULE_K):
        poly_v = np.mod(
            poly_v + negacyclic_mul(public_key.vector_b[row], random_r[row]),
            Q,
        )
    poly_v = np.mod(poly_v + DELTA * message, Q).astype(np.int64)
    return MLWECiphertext(vector_u, poly_v)


def add_ciphertexts(ciphertexts: Iterable[MLWECiphertext]) -> MLWECiphertext:
    items = list(ciphertexts)
    if not items:
        raise ChainError("Cannot aggregate an empty ciphertext list")
    vector_u = np.zeros((MODULE_K, RING_D), dtype=np.int64)
    poly_v = np.zeros(RING_D, dtype=np.int64)
    for ciphertext in items:
        vector_u = np.mod(vector_u + ciphertext.vector_u, Q)
        poly_v = np.mod(poly_v + ciphertext.poly_v, Q)
    return MLWECiphertext(vector_u, poly_v)


def mlwe_decrypt(
    secret_key: MLWESecretKey,
    ciphertext: MLWECiphertext,
) -> Tuple[np.ndarray, int]:
    phase = ciphertext.poly_v.copy()
    for index in range(MODULE_K):
        phase = np.mod(
            phase
            - negacyclic_mul(secret_key.coefficients[index], ciphertext.vector_u[index]),
            Q,
        )
    decoded = np.mod((phase + DELTA // 2) // DELTA, P).astype(np.int64)
    expected = np.mod(DELTA * decoded, Q)
    residual = centered_mod(phase - expected, Q)
    return decoded, int(np.max(np.abs(residual), initial=0))


def serialize_ciphertext(ciphertext: MLWECiphertext) -> bytes:
    coefficients = np.concatenate(
        (ciphertext.vector_u.reshape(-1), ciphertext.poly_v)
    )
    return np.asarray(coefficients, dtype="<u4").tobytes()


def deserialize_ciphertext(payload: bytes) -> MLWECiphertext:
    expected = (MODULE_K + 1) * RING_D * 4
    if len(payload) != expected:
        raise ChainError(f"Expected {expected} ciphertext bytes, got {len(payload)}")
    coefficients = np.frombuffer(payload, dtype="<u4").astype(np.int64)
    vector_u = coefficients[: MODULE_K * RING_D].reshape(MODULE_K, RING_D)
    poly_v = coefficients[MODULE_K * RING_D :]
    return MLWECiphertext(vector_u.copy(), poly_v.copy())


def sign_ticket(
    ticket: BatchTicket,
    authenticator: TicketAuthenticator,
) -> SignedTicket:
    message = DOMAIN_TICKET + ticket.digest()
    return SignedTicket(ticket, authenticator.sign(message), authenticator.scheme)


def verify_ticket(
    signed_ticket: SignedTicket,
    authenticator: TicketAuthenticator,
) -> bool:
    if signed_ticket.scheme != authenticator.scheme:
        return False
    message = DOMAIN_TICKET + signed_ticket.ticket.digest()
    return authenticator.verify(message, signed_ticket.signature)


def _block_mac_message(
    ticket: BatchTicket,
    entry: RosterEntry,
    profile_id: str,
    index: int,
    total: int,
    payload: bytes,
) -> bytes:
    return b"|".join(
        (
            DOMAIN_BLOCK,
            ticket.digest(),
            profile_id.encode("ascii"),
            entry.node_id.encode("utf-8"),
            entry.nonce.encode("ascii"),
            index.to_bytes(4, "big"),
            total.to_bytes(4, "big"),
            payload,
        )
    )


def make_node_envelope(
    ciphertext: MLWECiphertext,
    signed_ticket: SignedTicket,
    profile: RuntimeProfile,
    entry: RosterEntry,
    epoch_secret: bytes,
) -> NodeEnvelope:
    serialized = serialize_ciphertext(ciphertext)
    total = math.ceil(len(serialized) / profile.block_size)
    key = derive_block_key(epoch_secret, signed_ticket.ticket, entry)
    blocks: List[AuthenticatedBlock] = []
    for index in range(total):
        start = index * profile.block_size
        payload = serialized[start : start + profile.block_size]
        message = _block_mac_message(
            signed_ticket.ticket,
            entry,
            profile.profile_id,
            index,
            total,
            payload,
        )
        tag = hmac.new(key, message, hashlib.sha3_256).digest()[:16]
        blocks.append(AuthenticatedBlock(index, total, payload, tag))
    return NodeEnvelope(
        node_id=entry.node_id,
        nonce=entry.nonce,
        profile_id=profile.profile_id,
        ticket_digest=signed_ticket.ticket.digest().hex(),
        blocks=tuple(blocks),
    )


def verify_and_decode_node_envelope(
    envelope: NodeEnvelope,
    ticket: BatchTicket,
    profile: RuntimeProfile,
    entry: RosterEntry,
    epoch_secret: bytes,
) -> MLWECiphertext:
    if envelope.node_id != entry.node_id or envelope.nonce != entry.nonce:
        raise ChainError("Envelope identity or nonce mismatch")
    if envelope.profile_id != profile.profile_id:
        raise ChainError("Mixed-profile envelope rejected")
    if envelope.ticket_digest != ticket.digest().hex():
        raise ChainError("Envelope is bound to a different ticket")
    if not envelope.blocks:
        raise ChainError("Envelope contains no ciphertext blocks")

    total = envelope.blocks[0].total
    if len(envelope.blocks) != total:
        raise ChainError("Incomplete ciphertext block sequence")
    if [block.index for block in envelope.blocks] != list(range(total)):
        raise ChainError("Reordered or duplicate ciphertext blocks")

    key = derive_block_key(epoch_secret, ticket, entry)
    assembled = bytearray()
    for block in envelope.blocks:
        if block.total != total:
            raise ChainError("Inconsistent block count")
        message = _block_mac_message(
            ticket,
            entry,
            profile.profile_id,
            block.index,
            block.total,
            block.payload,
        )
        expected = hmac.new(key, message, hashlib.sha3_256).digest()[:16]
        if not hmac.compare_digest(expected, block.tag):
            raise ChainError("Block authenticator verification failed")
        assembled.extend(block.payload)
    return deserialize_ciphertext(bytes(assembled))


def _aggregate_mac_message(
    ticket: BatchTicket,
    profile_id: str,
    roster: Sequence[RosterEntry],
    ciphertext_bytes: bytes,
) -> bytes:
    roster_bytes = json.dumps(
        [asdict(entry) for entry in roster],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return b"|".join(
        (
            DOMAIN_AGGREGATE,
            ticket.digest(),
            profile_id.encode("ascii"),
            hashlib.sha3_256(roster_bytes).digest(),
            hashlib.sha3_256(ciphertext_bytes).digest(),
        )
    )


def gateway_aggregate(
    signed_ticket: SignedTicket,
    authenticator: TicketAuthenticator,
    profile: RuntimeProfile,
    envelopes: Sequence[NodeEnvelope],
    epoch_secret: bytes,
) -> AggregateEnvelope:
    if not verify_ticket(signed_ticket, authenticator):
        raise ChainError("Gateway rejected the batch ticket")
    ticket = signed_ticket.ticket
    if ticket.profile_id != profile.profile_id:
        raise ChainError("Ticket ProfileID does not match the selected action")
    assert_profile_safe(profile, len(ticket.roster))

    by_identity = {(env.node_id, env.nonce): env for env in envelopes}
    expected_identities = {(entry.node_id, entry.nonce) for entry in ticket.roster}
    if set(by_identity) != expected_identities:
        raise ChainError("Received roster differs from the signed exact roster")

    ciphertexts = []
    for entry in ticket.roster:
        ciphertexts.append(
            verify_and_decode_node_envelope(
                by_identity[(entry.node_id, entry.nonce)],
                ticket,
                profile,
                entry,
                epoch_secret,
            )
        )
    aggregate = add_ciphertexts(ciphertexts)
    serialized = serialize_ciphertext(aggregate)
    gateway_key = derive_gateway_key(epoch_secret, ticket)
    message = _aggregate_mac_message(
        ticket, profile.profile_id, ticket.roster, serialized
    )
    transport_tag = hmac.new(
        gateway_key, message, hashlib.sha3_256
    ).digest()
    return AggregateEnvelope(
        profile_id=profile.profile_id,
        ticket_digest=ticket.digest().hex(),
        roster=ticket.roster,
        ciphertext_bytes=serialized,
        transport_tag=transport_tag,
    )


def sink_verify_decrypt(
    aggregate: AggregateEnvelope,
    signed_ticket: SignedTicket,
    authenticator: TicketAuthenticator,
    profile: RuntimeProfile,
    epoch_secret: bytes,
    secret_key: MLWESecretKey,
) -> VerifiedAggregate:
    if not verify_ticket(signed_ticket, authenticator):
        raise ChainError("Sink rejected the batch ticket")
    ticket = signed_ticket.ticket
    if aggregate.profile_id != ticket.profile_id or ticket.profile_id != profile.profile_id:
        raise ChainError("Aggregate, ticket, and selected profile differ")
    if aggregate.ticket_digest != ticket.digest().hex():
        raise ChainError("Aggregate is bound to another ticket")
    if aggregate.roster != ticket.roster:
        raise ChainError("Aggregate roster differs from the signed roster")
    assert_profile_safe(profile, len(ticket.roster))

    gateway_key = derive_gateway_key(epoch_secret, ticket)
    message = _aggregate_mac_message(
        ticket,
        profile.profile_id,
        aggregate.roster,
        aggregate.ciphertext_bytes,
    )
    expected_transport_tag = hmac.new(
        gateway_key, message, hashlib.sha3_256
    ).digest()
    if not hmac.compare_digest(expected_transport_tag, aggregate.transport_tag):
        raise ChainError("Gateway-to-sink transport authenticator failed")

    ciphertext = deserialize_ciphertext(aggregate.ciphertext_bytes)
    polynomial, actual_noise_inf = mlwe_decrypt(secret_key, ciphertext)
    quantized_sum, tag_sum = unpack_plaintext(
        polynomial, profile.support_length
    )

    batch_matrix = derive_batch_matrix(
        epoch_secret, ticket, profile.support_length
    )
    offset_sum = np.zeros(TAG_DIM, dtype=np.int64)
    for entry in ticket.roster:
        offset_sum = np.mod(
            offset_sum + derive_source_offset(epoch_secret, ticket, entry), P
        )
    expected_tag = np.mod(batch_matrix @ quantized_sum + offset_sum, P)
    if not np.array_equal(tag_sum, expected_tag):
        raise ChainError("Hidden linear aggregate tag verification failed")

    signed_sum = centered_mod(quantized_sum, P)
    if np.max(np.abs(signed_sum), initial=0) > (P - 1) // 2:
        raise ChainError("Plaintext no-wrap check failed")
    if actual_noise_inf > TAU_DEC:
        raise ChainError("Observed decryption noise exceeded the decoding threshold")

    support = fixed_support(profile)
    reconstructed = reconstruct_window(quantized_sum, support, profile)
    return VerifiedAggregate(
        quantized_sum=quantized_sum,
        tag_sum=tag_sum,
        reconstructed_window=reconstructed,
        actual_noise_inf=actual_noise_inf,
        certified_noise_bound=profile.certified_noise_bound,
    )


def issue_ticket(
    epoch: int,
    profile: RuntimeProfile,
    nodes: int,
    authenticator: TicketAuthenticator,
    rng: np.random.Generator,
) -> SignedTicket:
    roster = tuple(
        RosterEntry(
            node_id=f"node-{index:04d}",
            nonce=rng.bytes(12).hex(),
        )
        for index in range(nodes)
    )
    ticket = BatchTicket(
        epoch=epoch,
        batch_id=f"batch-{epoch:06d}",
        context_id="DA-AHE-reference",
        profile_id=profile.profile_id,
        roster=roster,
        batch_nonce=rng.bytes(16).hex(),
    )
    return sign_ticket(ticket, authenticator)


def generate_sensor_window(
    node_index: int,
    epoch: int,
    regime: int,
    rng: np.random.Generator,
) -> np.ndarray:
    sample = np.arange(240, dtype=float)
    phase = 0.13 * node_index + 0.07 * epoch
    severity = 1.0 + 0.12 * regime
    channel_1 = (
        45.0 * severity * np.sin(2.0 * np.pi * sample / 48.0 + phase)
        + 8.0 * np.cos(2.0 * np.pi * sample / 17.0)
    )
    channel_2 = (
        35.0 * severity * np.cos(2.0 * np.pi * sample / 60.0 + phase)
        + 6.0 * np.sin(2.0 * np.pi * sample / 23.0)
    )
    noise = rng.normal(0.0, 1.5 + 0.2 * regime, size=(2, 240))
    return np.rint(np.vstack((channel_1, channel_2)) + noise).astype(np.int64)


def encapsulate_batch(
    signed_ticket: SignedTicket,
    authenticator: TicketAuthenticator,
    profile: RuntimeProfile,
    epoch_secret: bytes,
    public_key: MLWEPublicKey,
    epoch: int,
    regime: int,
    rng: np.random.Generator,
) -> Tuple[List[NodeEnvelope], List[NodePayload]]:
    if not verify_ticket(signed_ticket, authenticator):
        raise ChainError("Source rejected the ticket")
    ticket = signed_ticket.ticket
    if ticket.profile_id != profile.profile_id:
        raise ChainError("Source rejected an unauthorized profile substitution")

    batch_matrix = derive_batch_matrix(
        epoch_secret, ticket, profile.support_length
    )
    envelopes: List[NodeEnvelope] = []
    payloads: List[NodePayload] = []
    for node_index, entry in enumerate(ticket.roster):
        source_window = generate_sensor_window(
            node_index, epoch, regime, rng
        )
        quantized, support = quantize_window(source_window, profile)
        offset = derive_source_offset(epoch_secret, ticket, entry)
        tag = np.mod(batch_matrix @ quantized + offset, P)
        message = pack_plaintext(quantized, tag)
        ciphertext = mlwe_encrypt(
            public_key, message, profile.sigma_enc, rng
        )
        envelope = make_node_envelope(
            ciphertext,
            signed_ticket,
            profile,
            entry,
            epoch_secret,
        )
        envelopes.append(envelope)
        payloads.append(
            NodePayload(
                node_id=entry.node_id,
                quantized=quantized,
                support=support,
                offset=offset,
                source_window=source_window,
            )
        )
    return envelopes, payloads


def expected_quantized_sum(payloads: Sequence[NodePayload]) -> np.ndarray:
    if not payloads:
        raise ChainError("No source payloads were generated")
    total = np.zeros_like(payloads[0].quantized)
    for payload in payloads:
        total = np.mod(total + payload.quantized, P)
    return total


def build_controller() -> Tuple[
    List[Action], Dict[str, np.ndarray], ControllerParameters
]:
    actions = build_actions()
    kernels = build_transition_kernels(actions)
    p_v = np.diag([1.0, 1.2, 1.5])
    parameters = ControllerParameters(
        alpha=0.10,
        beta=0.05590904434629476,
        epsilon_transition=0.12,
        contraction=0.58,
        p_v=tuple(tuple(float(value) for value in row) for row in p_v),
        z_max=1.50,
        weights=(0.22, 0.28, 0.15, 0.25, 0.10),
    )
    return actions, kernels, parameters


def run_self_tests(seed: int) -> Dict[str, bool]:
    rng = np.random.default_rng(seed + 99_991)
    seed_material = hashlib.sha3_256(str(seed).encode()).digest()
    auth = SymmetricTicketAuthenticator(seed_material)
    actions, _, _ = build_controller()
    profile = bind_runtime_profile(actions[0])
    ticket = issue_ticket(0, profile, 3, auth, rng)

    if not verify_ticket(ticket, auth):
        raise AssertionError("Valid ticket failed verification")
    tampered = bytearray(ticket.signature)
    tampered[0] ^= 0x01
    if auth.verify(DOMAIN_TICKET + ticket.ticket.digest(), bytes(tampered)):
        raise AssertionError("Tampered ticket was accepted")

    public_key, secret_key = mlwe_keygen(rng)
    message = rng.integers(0, P, size=RING_D, dtype=np.int64)
    ciphertext = mlwe_encrypt(public_key, message, profile.sigma_enc, rng)
    recovered, _ = mlwe_decrypt(secret_key, ciphertext)
    if not np.array_equal(message, recovered):
        raise AssertionError("Single-ciphertext M-LWE round trip failed")

    messages = [
        rng.integers(0, 200, size=RING_D, dtype=np.int64)
        for _ in range(3)
    ]
    ciphertexts = [
        mlwe_encrypt(public_key, item, profile.sigma_enc, rng)
        for item in messages
    ]
    aggregate, _ = mlwe_decrypt(secret_key, add_ciphertexts(ciphertexts))
    expected = np.mod(np.sum(messages, axis=0), P)
    if not np.array_equal(aggregate, expected):
        raise AssertionError("Homomorphic M-LWE addition failed")

    epoch_secret = hashlib.shake_256(b"self-test" + seed_material).digest(32)
    envelopes, _ = encapsulate_batch(
        ticket,
        auth,
        profile,
        epoch_secret,
        public_key,
        0,
        0,
        rng,
    )
    first = envelopes[0]
    blocks = list(first.blocks)
    altered_payload = bytearray(blocks[0].payload)
    altered_payload[0] ^= 0x01
    blocks[0] = AuthenticatedBlock(
        blocks[0].index,
        blocks[0].total,
        bytes(altered_payload),
        blocks[0].tag,
    )
    altered_envelope = NodeEnvelope(
        first.node_id,
        first.nonce,
        first.profile_id,
        first.ticket_digest,
        tuple(blocks),
    )
    try:
        verify_and_decode_node_envelope(
            altered_envelope,
            ticket.ticket,
            profile,
            ticket.ticket.roster[0],
            epoch_secret,
        )
    except ChainError:
        pass
    else:
        raise AssertionError("Tampered ciphertext block was accepted")

    return {
        "ticket_tamper_rejected": True,
        "mlwe_round_trip": True,
        "homomorphic_addition": True,
        "block_tamper_rejected": True,
    }


def simulate_closed_loop(
    steps: int,
    requested_nodes: int,
    seed: int,
    require_pq_signature: bool,
) -> Tuple[List[EpochRecord], Dict[str, object]]:
    rng = np.random.default_rng(seed)
    actions, kernels, parameters = build_controller()
    authenticator = build_ticket_authenticator(
        hashlib.sha3_256(str(seed).encode()).digest(),
        require_pq_signature,
    )
    public_key, secret_key = mlwe_keygen(rng)
    epoch_root = hashlib.shake_256(
        b"DA-AHE/reference-epoch-root" + str(seed).encode()
    ).digest(32)

    belief = np.zeros(5, dtype=float)
    belief[0] = 1.0
    z = np.zeros(3, dtype=float)
    regime = 0
    previous_index = 0
    records: List[EpochRecord] = []
    action_counts = np.zeros(len(actions), dtype=int)

    forced_regimes = {
        max(1, int(0.30 * steps)): 1,
        max(2, int(0.62 * steps)): 4,
    }

    for epoch in range(steps):
        chosen_index, diagnostics = select_action(
            z,
            belief,
            previous_index,
            actions,
            kernels,
            parameters,
        )
        action = actions[chosen_index]
        diagnostic = diagnostics[chosen_index]
        profile = bind_runtime_profile(action)
        roster_size = min(requested_nodes, action.batch_size, profile.max_batch)
        assert_profile_safe(profile, roster_size)

        epoch_secret = _kdf(
            epoch_root,
            b"DA-AHE/epoch/v1",
            epoch.to_bytes(8, "big"),
            32,
        )
        ticket = issue_ticket(
            epoch, profile, roster_size, authenticator, rng
        )
        envelopes, payloads = encapsulate_batch(
            ticket,
            authenticator,
            profile,
            epoch_secret,
            public_key,
            epoch,
            regime,
            rng,
        )
        aggregate_envelope = gateway_aggregate(
            ticket,
            authenticator,
            profile,
            envelopes,
            epoch_secret,
        )
        verified = sink_verify_decrypt(
            aggregate_envelope,
            ticket,
            authenticator,
            profile,
            epoch_secret,
            secret_key,
        )
        expected_sum = expected_quantized_sum(payloads)
        decryption_correct = bool(
            np.array_equal(verified.quantized_sum, expected_sum)
        )
        if not decryption_correct:
            raise ChainError("Accepted aggregate differs from the source sum")

        records.append(
            EpochRecord(
                epoch=epoch,
                regime=regime,
                action=action.name,
                profile_id=profile.profile_id,
                roster_size=roster_size,
                robust_v=diagnostic.robust_v,
                drift_limit=diagnostic.drift_limit,
                actual_noise_inf=verified.actual_noise_inf,
                certified_noise_bound=verified.certified_noise_bound,
                tag_verified=True,
                decryption_correct=decryption_correct,
                mean_square_state=float(z @ z),
            )
        )
        action_counts[chosen_index] += 1

        if epoch in forced_regimes:
            next_regime = forced_regimes[epoch]
        else:
            next_regime = int(
                rng.choice(5, p=kernels[action.name][regime])
            )
        z_hat = predict_next_z(
            z, action, next_regime, parameters.contraction
        )
        error = sample_bounded_error(
            rng, model_error_radius(action, next_regime)
        )
        z_next = np.maximum(0.0, z_hat + error)
        noise_violation = max(
            0.0,
            (
                verified.certified_noise_bound
                - TAU_DEC
                + NOISE_GUARD
            )
            / (TAU_DEC - NOISE_GUARD),
        )
        z_next[2] = max(z_next[2], noise_violation)

        observation = np.clip(
            OBSERVATION_MEANS[next_regime]
            + rng.normal(scale=OBSERVATION_STD),
            0.0,
            1.0,
        )
        belief = belief_update(
            belief, kernels[action.name], observation
        )
        z = z_next
        regime = next_regime
        previous_index = chosen_index

    summary: Dict[str, object] = {
        "reference_model_only": True,
        "production_ready": False,
        "ticket_authentication": authenticator.scheme,
        "public_post_quantum_ticket_signature": (
            authenticator.is_public_pq_signature
        ),
        "full_public_signature_chain_claim_supported": (
            authenticator.is_public_pq_signature
        ),
        "mlwe_parameters": {
            "q": Q,
            "p": P,
            "d": RING_D,
            "k": MODULE_K,
            "n": MODULE_K * RING_D,
            "tag_dimension": TAG_DIM,
            "delta": DELTA,
            "tau_dec": TAU_DEC,
        },
        "simulation": {
            "steps": steps,
            "requested_nodes": requested_nodes,
            "seed": seed,
            "all_tags_verified": all(record.tag_verified for record in records),
            "all_decryptions_correct": all(
                record.decryption_correct for record in records
            ),
            "max_actual_noise_inf": max(
                record.actual_noise_inf for record in records
            ),
            "max_certified_noise_bound": max(
                record.certified_noise_bound for record in records
            ),
            "action_counts": {
                action.name: int(count)
                for action, count in zip(actions, action_counts)
            },
        },
    }
    return records, summary


def write_outputs(
    output_dir: Path,
    records: Sequence[EpochRecord],
    summary: Dict[str, object],
    self_tests: Dict[str, bool],
) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "pq_closed_loop_epochs.csv"
    json_path = output_dir / "pq_closed_loop_summary.json"

    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        fieldnames = list(asdict(records[0]).keys())
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(asdict(record))

    payload = dict(summary)
    payload["self_tests"] = self_tests
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return csv_path, json_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the DA-AHE robust Markov/PQ actuation reference model."
    )
    parser.add_argument("--steps", type=int, default=6)
    parser.add_argument("--nodes", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20260918)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("da_ahe_pq_closed_loop_results"),
    )
    parser.add_argument(
        "--require-pq-signature",
        action="store_true",
        help="Fail unless the optional pqcrypto ML-DSA backend is available.",
    )
    parser.add_argument(
        "--skip-self-tests",
        action="store_true",
        help="Skip algebra and tamper-detection self-tests.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.steps <= 0 or args.nodes <= 0:
        raise ValueError("--steps and --nodes must be positive")

    self_tests = (
        {}
        if args.skip_self_tests
        else run_self_tests(args.seed)
    )
    try:
        records, summary = simulate_closed_loop(
            steps=args.steps,
            requested_nodes=args.nodes,
            seed=args.seed,
            require_pq_signature=args.require_pq_signature,
        )
    except ChainError as exc:
        raise SystemExit(f"DA-AHE validation failed: {exc}") from None
    csv_path, json_path = write_outputs(
        args.output_dir, records, summary, self_tests
    )

    simulation = summary["simulation"]
    assert isinstance(simulation, dict)
    print("DA-AHE post-quantum closed-loop reference run completed")
    print(f"  ticket authentication : {summary['ticket_authentication']}")
    print(
        "  public PQ signature   : "
        f"{summary['public_post_quantum_ticket_signature']}"
    )
    print(f"  tags verified         : {simulation['all_tags_verified']}")
    print(f"  decryptions correct   : {simulation['all_decryptions_correct']}")
    print(f"  max actual noise      : {simulation['max_actual_noise_inf']}")
    print(f"  max certified noise   : {simulation['max_certified_noise_bound']}")
    print(f"  action counts         : {simulation['action_counts']}")
    print(f"  CSV                   : {csv_path.resolve()}")
    print(f"  JSON                  : {json_path.resolve()}")
    if not summary["public_post_quantum_ticket_signature"]:
        print(
            "  WARNING: symmetric demo ticket authentication is active; "
            "do not claim a public PQ signature implementation.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
