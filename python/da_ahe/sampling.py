from __future__ import annotations

import numpy as np


class ResearchSampler:
    """Deterministic truncated discrete-Gaussian research sampler.

    The probability of integer x is proportional to exp(-x^2/(2*sigma^2)).
    The support is truncated at 12 sigma.  This is reproducible reference code,
    not a constant-time deployment sampler.
    """

    def __init__(self, seed: int | bytes):
        if isinstance(seed, bytes):
            seed = int.from_bytes(seed[:16].ljust(16, b"\0"), "little")
        self._rng = np.random.default_rng(seed)

    def gaussian(self, shape: tuple[int, ...] | int, sigma: float) -> np.ndarray:
        tail = int(np.ceil(12.0 * sigma))
        support = np.arange(-tail, tail + 1, dtype=np.int64)
        weights = np.exp(-(support.astype(np.float64) ** 2) / (2.0 * sigma**2))
        probabilities = weights / np.sum(weights)
        return self._rng.choice(support, size=shape, p=probabilities).astype(np.int64)
