from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LatticeParams:
    """Fixed cryptographic parameters from the revised construction."""

    d: int = 256
    k: int = 3
    q: int = 1 << 32
    p: int = 65_537
    sigma_key: float = 3.2
    estimator_bits: float = 128.1
    tag_count: int = 16
    data_slots: int = 240
    channels: int = 2
    samples_per_channel: int = 240
    tag_bytes: int = 16

    @property
    def delta(self) -> int:
        return self.q // self.p

    @property
    def scale_residual(self) -> int:
        return self.q - self.p * self.delta

    @property
    def ciphertext_words(self) -> int:
        return (self.k + 1) * self.d

    @property
    def ciphertext_bytes(self) -> int:
        return self.ciphertext_words * 4

    @property
    def raw_samples(self) -> int:
        return self.channels * self.samples_per_channel

    def validate(self) -> None:
        if self.data_slots + self.tag_count > self.d:
            raise ValueError("data and authentication slots exceed ring degree")
        if self.q != 1 << 32:
            raise ValueError("the reference serializer requires q = 2^32")
        if self.p != 65_537:
            raise ValueError("the authenticated field is fixed to p = 65537")
        if self.channels != 2 or self.samples_per_channel != 240:
            raise ValueError("the paper instance uses two 240-sample channels")
        if self.data_slots != 240 or self.tag_count != 16:
            raise ValueError("the paper packing is 240 data + 16 tag coefficients")
        if self.delta != 65_535 or self.scale_residual != 1:
            raise ValueError("unexpected plaintext scaling parameters")


@dataclass(frozen=True)
class Profile:
    """Offline profile inputs used by certification and the controller.

    Goodput and stack RAM are illustrative defaults. Replace them with the
    lower-confidence goodput and measured memory watermark of the target.
    """

    profile_id: int
    retention: float
    quant_step: float
    block_size: int
    sigma_enc: float
    n_policy: int
    coefficient_bound: int
    batch_deadline_s: float = 32.0
    r_min_bps: float = 25_000.0
    stack_ram_bytes: int = 4_000
    auth_workspace_bytes: int = 512
    per_block_metadata_bytes: int = 24
    envelope_metadata_bytes: int = 256

    def validate(self, params: LatticeParams) -> None:
        if not (0.0 < self.retention <= 1.0):
            raise ValueError("retention must be in (0, 1]")
        if self.block_size <= 0 or self.block_size % 4:
            raise ValueError("block size must be a positive multiple of 4")
        if params.ciphertext_bytes % self.block_size:
            raise ValueError("block size must divide the ciphertext length")
        if self.n_policy < 1:
            raise ValueError("policy batch size must be positive")
        if self.coefficient_bound < 1:
            raise ValueError("coefficient bound must be positive")


def default_profiles() -> tuple[Profile, ...]:
    return (
        Profile(0, 240 / 240, 8.0, 64, 3.2, 16, 2_048),
        Profile(1, 180 / 240, 12.0, 64, 3.4, 14, 2_340),
        Profile(2, 120 / 240, 16.0, 32, 3.6, 12, 2_730),
    )
