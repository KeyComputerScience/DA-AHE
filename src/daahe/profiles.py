# SPDX-License-Identifier: MIT
"""Immutable, digest-bound profiles. Bundled profiles are hypotheses, not certificates."""
from dataclasses import asdict, dataclass
import hashlib
import json

P = 65537


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class Profile:
    name: str
    L: int
    delta_q: int
    sigma_enc: float
    nmax: int
    support: tuple[int, ...]
    coefficient_bound: int
    representation: str = "intdb2"
    verify_integrity: bool = True
    status: str = "reconstructed_uncertified"

    def __post_init__(self):
        object.__setattr__(self, "support", tuple(self.support))
        if any(type(v) is not int for v in (self.L,self.delta_q,self.nmax,self.coefficient_bound)):
            raise ValueError("profile dimensions, quantization and bounds must be integers")
        if type(self.verify_integrity) is not bool or not isinstance(self.name,str) or not self.name:
            raise ValueError("invalid profile name/integrity flag")
        if self.representation not in {"intdb2", "raw"}:
            raise ValueError("unknown representation")
        if not 1 <= self.L <= (480 if self.representation == "raw" else 240):
            raise ValueError("invalid support capacity")
        if len(self.support) != self.L or len(set(self.support)) != self.L:
            raise ValueError("support must contain L distinct positions")
        if any(type(i) is not int or not 0 <= i < 480 for i in self.support):
            raise ValueError("support outside two-channel window")
        if self.representation == "raw" and (self.L != 480 or self.support != tuple(range(480))):
            raise ValueError("raw baseline must preserve all 480 scalar readings")
        if self.delta_q < 1 or not 1 <= self.nmax <= 16 or self.sigma_enc not in (3.2,3.4,3.6):
            raise ValueError("invalid profile parameters")
        if self.coefficient_bound < 1 or self.nmax * self.coefficient_bound > (P-1)//2:
            raise ValueError("plaintext data no-wrap condition violated")

    @property
    def digest(self) -> str:
        return hashlib.sha3_256(canonical_json(asdict(self))).hexdigest()

    @property
    def profile_id(self) -> str:
        return self.digest[:24]

    @property
    def tag_count(self) -> int:
        return 16 if self.verify_integrity else 0

    @property
    def polynomial_count(self) -> int:
        return (self.L + self.tag_count + 255)//256

    @classmethod
    def from_dict(cls, value):
        value = dict(value)
        value["support"] = tuple(value["support"])
        return cls(**value)


class ProfileLibrary:
    def __init__(self, profiles):
        self._profiles = {}
        for profile in profiles:
            if profile.profile_id in self._profiles:
                raise ValueError("duplicate/colliding profile index")
            self._profiles[profile.profile_id] = profile

    def lookup(self, profile_id: str) -> Profile:
        return self._profiles[profile_id]

    def __iter__(self):
        return iter(self._profiles.values())


def example_profiles() -> ProfileLibrary:
    """Table III settings; support and Bx were NOT supplied by manuscript authors."""
    from .signal import support_for_length
    return ProfileLibrary([
        Profile("pi0", 240, 8, 3.2, 16, support_for_length(240), 2048),
        Profile("pi1", 180, 12, 3.4, 14, support_for_length(180), 2048),
        Profile("pi2", 120, 16, 3.6, 12, support_for_length(120), 2048),
        Profile("static_eq22", 240, 16, 3.2, 16, support_for_length(240), 2048),
        Profile("fallback", 120, 16, 3.2, 1, support_for_length(120), 2048),
        Profile("without_intdb2", 480, 16, 3.2, 16, tuple(range(480)), 2048, "raw"),
        Profile("without_hve", 240, 8, 3.2, 16, support_for_length(240), 2048,
                verify_integrity=False),
    ])

