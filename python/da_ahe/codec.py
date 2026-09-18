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
        n = self.params.samples_per_channel
        self._analysis = _db2_matrix(n)
        error = np.max(np.abs(self._analysis @ self._analysis.T - np.eye(n)))
        if error > 1e-12:
            raise RuntimeError("Db2 analysis matrix is not orthonormal")

    def compress(self, signal: np.ndarray, profile: Profile) -> np.ndarray:
        signal = np.asarray(signal, dtype=np.float64)
        expected = (self.params.channels, self.params.samples_per_channel)
        if signal.shape == (self.params.raw_samples,):
            signal = signal.reshape(expected)
        if signal.shape != expected:
            raise ValueError(f"signal must have shape {expected}")
        low_pass = np.vstack(
            [(self._analysis @ channel)[: self.params.samples_per_channel // 2]
             for channel in signal]
        )
        # Interleaving keeps the two synchronized channels balanced when L<240.
        transformed = low_pass.T.reshape(-1)
        retained = int(round(profile.retention * self.params.data_slots))
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
        retained = int(round(profile.retention * self.params.data_slots))
        packed = np.zeros(self.params.data_slots, dtype=np.float64)
        packed[:retained] = aggregate_coefficients[:retained] * profile.quant_step
        low_pass = packed.reshape(-1, self.params.channels).T
        reconstructed = []
        for channel in range(self.params.channels):
            coefficients = np.zeros(self.params.samples_per_channel, dtype=np.float64)
            coefficients[: self.params.samples_per_channel // 2] = low_pass[channel]
            reconstructed.append(self._analysis.T @ coefficients)
        return np.vstack(reconstructed)

    def field_to_centered(self, values: np.ndarray) -> np.ndarray:
        return centered(values, self.params.p)
