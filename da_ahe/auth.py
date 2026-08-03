from __future__ import annotations

import hashlib
import struct

import numpy as np

from .params import LatticeParams


def _uniform_field_elements(
    seed: bytes, domain: bytes, count: int, modulus: int
) -> np.ndarray:
    """Derive rejection-sampled field elements from SHAKE-256."""

    if modulus <= 1 or modulus >= 1 << 32:
        raise ValueError("unsupported field modulus")
    limit = (1 << 32) - ((1 << 32) % modulus)
    output: list[int] = []
    counter = 0
    while len(output) < count:
        material = domain + struct.pack("<I", counter) + seed
        raw = hashlib.shake_256(material).digest(4_096)
        words = np.frombuffer(raw, dtype="<u4")
        for word in words:
            value = int(word)
            if value < limit:
                output.append(value % modulus)
                if len(output) == count:
                    break
        counter += 1
    return np.asarray(output, dtype=np.int64)


def derive_auth_matrix(
    auth_secret: bytes, ticket_context: bytes, params: LatticeParams
) -> np.ndarray:
    seed = hashlib.sha256(auth_secret + b"/matrix/" + ticket_context).digest()
    values = _uniform_field_elements(
        seed,
        b"DA-AHE/K/",
        params.tag_count * params.data_slots,
        params.p,
    )
    return values.reshape(params.tag_count, params.data_slots)


def derive_label_mask(
    mask_secret: bytes, label: bytes, params: LatticeParams
) -> np.ndarray:
    seed = hashlib.sha256(mask_secret + b"/mask/" + label).digest()
    return _uniform_field_elements(seed, b"DA-AHE/XI/", params.tag_count, params.p)


def linear_tags(
    auth_matrix: np.ndarray,
    data_coefficients: np.ndarray,
    label_mask: np.ndarray,
    params: LatticeParams,
) -> np.ndarray:
    data = np.mod(np.asarray(data_coefficients, dtype=np.int64), params.p)
    tags = auth_matrix @ data + label_mask
    return np.mod(tags, params.p).astype(np.int64)


def pack_codeword(
    data_coefficients: np.ndarray,
    tags: np.ndarray,
    params: LatticeParams,
) -> np.ndarray:
    data = np.asarray(data_coefficients, dtype=np.int64)
    tags = np.asarray(tags, dtype=np.int64)
    if data.shape != (params.data_slots,):
        raise ValueError("invalid data coefficient shape")
    if tags.shape != (params.tag_count,):
        raise ValueError("invalid authentication tag shape")
    codeword = np.zeros(params.d, dtype=np.int64)
    codeword[: params.data_slots] = np.mod(data, params.p)
    start = params.data_slots
    codeword[start : start + params.tag_count] = np.mod(tags, params.p)
    return codeword


def unpack_codeword(
    codeword: np.ndarray, params: LatticeParams
) -> tuple[np.ndarray, np.ndarray]:
    codeword = np.mod(np.asarray(codeword, dtype=np.int64), params.p)
    if codeword.shape != (params.d,):
        raise ValueError("invalid codeword shape")
    start = params.data_slots
    return (
        codeword[:start].copy(),
        codeword[start : start + params.tag_count].copy(),
    )


def verify_aggregate_tags(
    aggregate_data: np.ndarray,
    aggregate_tags: np.ndarray,
    aggregate_mask: np.ndarray,
    auth_matrix: np.ndarray,
    params: LatticeParams,
) -> bool:
    expected = linear_tags(auth_matrix, aggregate_data, aggregate_mask, params)
    return bool(np.array_equal(np.mod(aggregate_tags, params.p), expected))

