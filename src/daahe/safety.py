# SPDX-License-Identifier: MIT
"""Hard admission gates for Eq. (3), with exact tuple and evidence binding.

An evidence artifact is a *claim supplied by the experimenter*. Hash checking
establishes provenance/integrity, not the mathematical validity of that claim.
No paper table, simulator measurement, or synthetic example is automatically a
certificate. A deployment must review the artifacts and their assumptions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields, is_dataclass
import hashlib
import json
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence


def _freeze(value: Any) -> Any:
    """Take an immutable deep snapshot of externally supplied configuration."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def _plain(value: Any) -> Any:
    """Serialize immutable dataclasses/mappings without deepcopy side effects."""
    if is_dataclass(value):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    return value


def canonical_digest(value: Any) -> str:
    """SHA3-256 of deterministic, finite JSON; suitable for local manifests."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         allow_nan=False, ensure_ascii=True).encode("ascii")
    return hashlib.sha3_256(payload).hexdigest()


def _finite(value: float, name: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    return result


@dataclass(frozen=True)
class Action:
    """One indivisible library tuple; components are never recombined online."""

    id: str
    rho: float
    delta_q: int
    batch_size: int
    block_bytes: int
    repair: float
    profile_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not isinstance(self.profile_id, str) or not self.id or not self.profile_id:
            raise ValueError("action and profile identifiers must be nonempty")
        if not 0 < _finite(self.rho, "rho") <= 1:
            raise ValueError("rho must be in (0, 1]")
        if type(self.delta_q) is not int or self.delta_q <= 0:
            raise ValueError("delta_q must be a positive integer")
        if type(self.batch_size) is not int or self.batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        if self.block_bytes not in (32, 64):
            raise ValueError("the paper only defines 32/64 byte blocks")
        if _finite(self.repair, "repair") < 0:
            raise ValueError("repair must be nonnegative")

    def vector(self) -> tuple[float | int | str, ...]:
        return (self.rho, self.delta_q, self.batch_size, self.block_bytes,
                self.repair, self.profile_id)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Action":
        return cls(**dict(value))

    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True)
class EvidenceArtifact:
    """Relative, traversal-free artifact path plus SHA-256 and claim method."""

    path: str
    sha256: str
    method: str

    def check(self, root: str | Path | None) -> tuple[bool, str]:
        if root is None:
            return False, "evidence root is not configured"
        relative = Path(self.path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            return False, "artifact path must be relative and traversal-free"
        if len(self.sha256) != 64 or any(c not in "0123456789abcdef" for c in self.sha256):
            return False, "artifact SHA-256 must contain 64 lowercase hex digits"
        if not self.method.strip():
            return False, "artifact claim method is missing"
        base = Path(root).resolve()
        path = (base / relative).resolve()
        if base not in path.parents:
            return False, "artifact resolves outside evidence root"
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            return False, f"artifact unavailable: {exc}"
        return (digest == self.sha256,
                "ok" if digest == self.sha256 else "artifact digest mismatch")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceArtifact":
        return cls(**dict(value))


REQUIRED_EVIDENCE = ("security", "decoding", "noise", "no_wrap", "memory", "airtime")


@dataclass(frozen=True)
class Certificate:
    """Numerical bounds for exactly one action, profile, and deployment context.

    ``external`` means externally supplied, reviewed bounds; it is not a claim
    that this package has formally proved them. ``synthetic`` is an explicitly
    unvalidated demonstration and can never produce a certified decision.
    The evidence must state the same complete action/profile/context identity.
    The bound for a batch applies to every roster of size <= max_batch_size.
    """

    action_digest: str
    profile_digest: str
    context_digest: str
    lambda_est_bits: float
    log2_epsilon_dec: float
    noise_bound: float
    tau_dec: float
    zeta: float
    single_node_plain_bound: int
    plaintext_modulus: int
    workspace_bytes: int
    airtime_s: float
    max_batch_size: int
    kind: str = "synthetic"
    evidence: Mapping[str, EvidenceArtifact] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", _freeze(self.evidence))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Certificate":
        fields = dict(value)
        fields["evidence"] = {
            str(k): EvidenceArtifact.from_dict(v)
            for k, v in fields.get("evidence", {}).items()
        }
        return cls(**fields)

    def to_dict(self) -> dict[str, Any]:
        return _plain(self)


@dataclass(frozen=True)
class RuntimeContext:
    """Current resource envelope and immutable deployment allowlist.

    ``strict=False`` permits synthetic demonstrations but preserves numerical
    safety gates and reports ``certified=False``. It does not permit missing
    action certificates, changed profiles, or a state outside the model cube.
    ``profile_digests`` must be full 256-bit immutable profile digests, not the
    short 96-bit on-wire ProfileID. ``context_digest`` binds the deployment
    assumptions (PHY, traffic, compiler/firmware, platform, security estimator,
    transport overhead/retries, and resource budgets).
    """

    strict: bool = True
    evidence_root: str | None = None
    profile_digests: Mapping[str, str] = field(default_factory=dict)
    context_digest: str = ""
    participant_count: int = 1
    max_workspace_bytes: int = 10 * 1024
    max_airtime_s: float = 1.0
    minimum_security_bits: float = 128.1
    maximum_log2_epsilon_dec: float = -128.0
    zcert_max: tuple[float, float, float] = (1.0, 1.0, 1.0)

    def __post_init__(self) -> None:
        if type(self.participant_count) is not int or self.participant_count <= 0:
            raise ValueError("participant_count must be a positive integer")
        if type(self.max_workspace_bytes) is not int or not 0 < self.max_workspace_bytes <= 10240:
            raise ValueError("workspace budget must be positive and <= 10 KiB")
        if _finite(self.max_airtime_s, "airtime budget") <= 0:
            raise ValueError("airtime budget must be positive")
        if _finite(self.minimum_security_bits, "security floor") < 128.1:
            raise ValueError("security floor cannot be below 128.1 bits")
        if _finite(self.maximum_log2_epsilon_dec, "decoding target") > -128:
            raise ValueError("decoding failure target cannot exceed 2^-128")
        if len(self.zcert_max) != 3 or any(_finite(v, "zcert") < 0 for v in self.zcert_max):
            raise ValueError("zcert_max must have three nonnegative finite components")
        object.__setattr__(self, "profile_digests", _freeze(self.profile_digests))
        object.__setattr__(self, "zcert_max", tuple(self.zcert_max))


@dataclass(frozen=True)
class SafetyResult:
    allowed: bool
    certified: bool
    reasons: tuple[str, ...]


class SafetyFilter:
    def __init__(self, certificates: Mapping[str, Certificate]):
        self.certificates = dict(certificates)

    def check(self, action: Action, runtime: RuntimeContext,
              state: Sequence[float] | None = None) -> SafetyResult:
        failures: list[str] = []
        if state is not None:
            if len(state) != 3 or any(not math.isfinite(float(v)) or v < 0
                                      for v in state):
                failures.append("invalid violation state")
            elif any(v > limit for v, limit in zip(state, runtime.zcert_max)):
                failures.append("state outside certified region; recertification required")
        cert = self.certificates.get(action.id)
        if cert is None:
            return SafetyResult(False, False, tuple(failures + ["missing action certificate"]))
        if cert.action_digest != action.digest():
            failures.append("certificate does not bind this complete action tuple")
        expected_profile = runtime.profile_digests.get(action.profile_id)
        if not expected_profile or cert.profile_digest != expected_profile:
            failures.append("immutable profile digest mismatch or missing allowlist entry")
        if not runtime.context_digest or cert.context_digest != runtime.context_digest:
            failures.append("deployment context digest mismatch or missing context")
        if cert.kind not in ("external", "synthetic"):
            failures.append("unknown certificate kind")
        if runtime.strict and cert.kind != "external":
            failures.append("synthetic bounds are not externally certified evidence")

        values = (cert.lambda_est_bits, cert.log2_epsilon_dec, cert.noise_bound,
                  cert.tau_dec, cert.zeta, cert.airtime_s)
        if any(not math.isfinite(float(v)) for v in values):
            failures.append("nonfinite certificate value")
        else:
            if cert.lambda_est_bits < runtime.minimum_security_bits:
                failures.append("M-LWE estimated security below required floor")
            if cert.log2_epsilon_dec > runtime.maximum_log2_epsilon_dec:
                failures.append("batch decoding failure bound exceeds target")
            if cert.zeta < 0 or cert.tau_dec - cert.zeta <= 0:
                failures.append("decoding safety margin is not strictly positive")
            if cert.noise_bound < 0 or cert.noise_bound > cert.tau_dec - cert.zeta:
                failures.append("batch decryption-noise bound exceeds safety margin")
            if cert.airtime_s <= 0 or cert.airtime_s > runtime.max_airtime_s:
                failures.append("airtime bound exceeds available budget")
        integer_fields = (cert.single_node_plain_bound, cert.plaintext_modulus,
                          cert.workspace_bytes, cert.max_batch_size)
        if any(type(v) is not int for v in integer_fields):
            failures.append("certificate count/size fields must be integers")
        else:
            if cert.plaintext_modulus != 65537 or cert.single_node_plain_bound < 0:
                failures.append("invalid plaintext modulus or coefficient bound")
            if action.batch_size * cert.single_node_plain_bound > (cert.plaintext_modulus - 1) // 2:
                failures.append("plaintext no-wrap bound violated")
            if not 0 < cert.workspace_bytes <= runtime.max_workspace_bytes:
                failures.append("streaming workspace exceeds available budget")
            if not 0 < runtime.participant_count <= action.batch_size <= cert.max_batch_size:
                failures.append("current roster or action batch exceeds certified capacity")

        verified = cert.kind == "external"
        if runtime.strict or cert.kind == "external":
            for name in REQUIRED_EVIDENCE:
                artifact = cert.evidence.get(name)
                if artifact is None:
                    failures.append(f"missing {name} evidence artifact")
                    verified = False
                    continue
                ok, detail = artifact.check(runtime.evidence_root)
                if not ok:
                    failures.append(f"{name}: {detail}")
                    verified = False
        return SafetyResult(not failures, verified and not failures, tuple(failures))


def violation_state(delay: float, loss: float, noise_bound: float, *,
                    delay_threshold: float, loss_threshold: float,
                    decoding_margin: float) -> tuple[float, float, float]:
    """Eq. (4); all inputs are current causal telemetry/bounds, not futures."""
    actual = tuple(_finite(v, "telemetry") for v in (delay, loss, noise_bound))
    limits = tuple(_finite(v, "threshold") for v in
                   (delay_threshold, loss_threshold, decoding_margin))
    if any(v < 0 for v in actual) or any(v <= 0 for v in limits):
        raise ValueError("telemetry must be nonnegative and thresholds positive")
    return tuple(max(v - t, 0.0) / t for v, t in zip(actual, limits))
