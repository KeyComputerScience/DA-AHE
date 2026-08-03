from __future__ import annotations

import numpy as np


class ResearchSampler:
    """Deterministic simulation sampler; not suitable for production keys."""

    def __init__(self, seed: int | bytes):
        if isinstance(seed, bytes):
            seed = int.from_bytes(seed[:16].ljust(16, b"\0"), "little")
        self._rng = np.random.default_rng(seed)

    def gaussian(self, shape: tuple[int, ...] | int, sigma: float) -> np.ndarray:
        return np.rint(self._rng.normal(0.0, sigma, size=shape)).astype(np.int64)

