from __future__ import annotations

from dataclasses import dataclass
import math

import numpy as np

from .params import LatticeParams, Profile
from .ring import centered


def _db2_matrix(length: int) -> np.ndarray:
    """One-level periodized orthonormal Db2 analysis matrix."""

    if length % 2:
        raise ValueError("Db2 signal length must be even")
    root3 = math.sqrt(3.0)
    scale = 4.0 * math.sqrt(2.0)
    low = np.array(
        [
            (1.0 + root3) / scale,
            (3.0 + root3) / scale,
            (3.0 - root3) / scale,
            (1.0 - root3) / scale,
        ],
        dtype=np.float64,
    )
    high = np.array([low[3], -low[2], low[1], -low[0]], dtype=np.float64)
    matrix = np.zeros((length, length), dtype=np.float64)
    half = length // 2
    for row in range(half):
        for tap in range(4):
            column = (2 * row + tap) % length
            matrix[row, column] = low[tap]
            matrix[half + row, column] = high[tap]
    return matrix


@dataclass
class Db2Codec:
    params: LatticeParams

    def __post_init__(self) -> None:
        self._analysis = _db2_matrix(self.params.d)
        error = np.max(np.abs(self._analysis @ self._analysis.T - np.eye(self.params.d)))
        if error > 1e-12:
            raise RuntimeError("Db2 analysis matrix is not orthonormal")

    def compress(self, signal: np.ndarray, profile: Profile) -> np.ndarray:
        signal = np.asarray(signal, dtype=np.float64)
        if signal.shape != (self.params.d,):
            raise ValueError(f"signal must have length {self.params.d}")
        transformed = self._analysis @ signal
        retained = int(round(profile.retention * self.params.d))
        retained = min(retained, self.params.data_slots)
        quantized = np.zeros(self.params.data_slots, dtype=np.int64)
        values = np.rint(transformed[:retained] / profile.quant_step).astype(np.int64)
        values = np.clip(values, -profile.coefficient_bound, profile.coefficient_bound)
        quantized[:retained] = values
        return quantized

    def reconstruct(self, aggregate_coefficients: np.ndarray, profile: Profile) -> np.ndarray:
        aggregate_coefficients = np.asarray(aggregate_coefficients, dtype=np.int64)
        if aggregate_coefficients.shape != (self.params.data_slots,):
            raise ValueError("invalid aggregate coefficient vector")
        coefficients = np.zeros(self.params.d, dtype=np.float64)
        coefficients[: self.params.data_slots] = aggregate_coefficients * profile.quant_step
        return self._analysis.T @ coefficients

    def field_to_centered(self, values: np.ndarray) -> np.ndarray:
        return centered(values, self.params.p)

