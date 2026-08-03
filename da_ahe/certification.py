from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from .params import LatticeParams, Profile


EPSILON_KEY_LOG2 = -130.0
TARGET_BATCH_LOG2 = -128.0


def good_key_threshold(params: LatticeParams, epsilon_key_log2: float = -130.0) -> float:
    m_key = 2 * params.k * params.d
    x_key = -epsilon_key_log2 * math.log(2.0)
    return params.sigma_key**2 * (
        m_key + 2.0 * math.sqrt(m_key * x_key) + 2.0 * x_key
    )


def epsilon_dec_star() -> float:
    return 2.0**TARGET_BATCH_LOG2 - 2.0**EPSILON_KEY_LOG2


def scale_error_bound(batch_size: int, params: LatticeParams) -> int:
    return math.ceil(batch_size / 2) * params.scale_residual


def safe_margin(batch_size: int, params: LatticeParams) -> int:
    return params.delta // 2 - 1 - scale_error_bound(batch_size, params)


def analytical_lwe_bound(
    batch_size: int,
    sigma_enc: float,
    params: LatticeParams,
) -> float:
    k0 = good_key_threshold(params)
    return sigma_enc * math.sqrt(
        2.0
        * batch_size
        * (k0 + 1.0)
        * math.log((2.0 * params.d) / epsilon_dec_star())
    )


def cryptographic_utilization(
    batch_size: int,
    sigma_enc: float,
    params: LatticeParams,
) -> float:
    margin = safe_margin(batch_size, params)
    if margin <= 0:
        return math.inf
    return analytical_lwe_bound(batch_size, sigma_enc, params) / margin


def conditional_failure_log2(
    batch_size: int,
    sigma_enc: float,
    params: LatticeParams,
) -> float:
    margin = safe_margin(batch_size, params)
    if margin <= 0:
        return 0.0
    k0 = good_key_threshold(params)
    exponent = margin**2 / (
        2.0 * batch_size * sigma_enc**2 * (k0 + 1.0)
    )
    return math.log2(2.0 * params.d) - exponent / math.log(2.0)


def _log2_add(left: float, right: float) -> float:
    larger = max(left, right)
    return larger + math.log2(2.0 ** (left - larger) + 2.0 ** (right - larger))


def batch_failure_log2(
    batch_size: int,
    sigma_enc: float,
    params: LatticeParams,
) -> float:
    return _log2_add(
        EPSILON_KEY_LOG2,
        conditional_failure_log2(batch_size, sigma_enc, params),
    )


def ciphertext_blocks(profile: Profile, params: LatticeParams) -> int:
    return params.ciphertext_bytes // profile.block_size


def envelope_bytes(profile: Profile, params: LatticeParams) -> int:
    return (
        params.ciphertext_bytes
        + ciphertext_blocks(profile, params) * profile.per_block_metadata_bytes
        + profile.envelope_metadata_bytes
    )


def network_limit(profile: Profile, params: LatticeParams) -> int:
    return math.floor(
        profile.batch_deadline_s
        * profile.r_min_bps
        / (8.0 * envelope_bytes(profile, params))
    )


def wrap_limit(profile: Profile, params: LatticeParams) -> int:
    return (params.p - 1) // (2 * profile.coefficient_bound)


def peak_ram_bytes(batch_size: int, profile: Profile, params: LatticeParams) -> int:
    bitmap = math.ceil(batch_size * ciphertext_blocks(profile, params) / 8)
    return (
        params.ciphertext_bytes
        + profile.block_size
        + bitmap
        + profile.auth_workspace_bytes
        + profile.stack_ram_bytes
    )


def ram_limit(profile: Profile, params: LatticeParams, cap: int = 10 * 1024) -> int:
    for batch_size in range(1, 4_097):
        if peak_ram_bytes(batch_size, profile, params) > cap:
            return batch_size - 1
    return 4_096


def correctness_limit(profile: Profile, params: LatticeParams) -> int:
    for batch_size in range(1, 4_097):
        if batch_failure_log2(batch_size, profile.sigma_enc, params) > TARGET_BATCH_LOG2:
            return batch_size - 1
    return 4_096


@dataclass(frozen=True)
class CertificationReport:
    profile_id: int
    n_policy: int
    n_wrap: int
    n_correctness: int
    n_network: int
    n_ram: int
    n_effective: int
    eta_at_effective_limit: float
    failure_log2_at_effective_limit: float
    envelope_bytes_per_node: int
    peak_ram_at_effective_limit: int
    estimator_bits: float
    accepted: bool

    def to_dict(self) -> dict[str, int | float | bool]:
        return asdict(self)


def certify_profile(profile: Profile, params: LatticeParams) -> CertificationReport:
    profile.validate(params)
    limits = {
        "policy": profile.n_policy,
        "wrap": wrap_limit(profile, params),
        "correctness": correctness_limit(profile, params),
        "network": network_limit(profile, params),
        "ram": ram_limit(profile, params),
    }
    effective = min(limits.values())
    eta = cryptographic_utilization(effective, profile.sigma_enc, params)
    failure = batch_failure_log2(effective, profile.sigma_enc, params)
    accepted = (
        effective >= 1
        and eta <= 1.0
        and failure <= TARGET_BATCH_LOG2
        and profile.estimator_bits >= 128.0
        and peak_ram_bytes(effective, profile, params) <= 10 * 1024
    )
    return CertificationReport(
        profile.profile_id,
        limits["policy"],
        limits["wrap"],
        limits["correctness"],
        limits["network"],
        limits["ram"],
        effective,
        eta,
        failure,
        envelope_bytes(profile, params),
        peak_ram_bytes(effective, profile, params),
        profile.estimator_bits,
        accepted,
    )


def stress_rows(params: LatticeParams, sigma_enc: float = 3.2) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    for batch_size in (1, 8, 16, 32, 64):
        log2_failure = batch_failure_log2(batch_size, sigma_enc, params)
        rows.append(
            {
                "batch_size": batch_size,
                "log2_failure": log2_failure,
                "probability": 2.0**log2_failure,
            }
        )
    return rows

