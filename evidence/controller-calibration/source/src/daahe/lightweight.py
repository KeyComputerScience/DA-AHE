# SPDX-License-Identifier: MIT
"""Authenticated plaintext path, explicitly trusting the aggregation gateway.

This path carries no end-to-end integrity claim against a compromised gateway.
Keys must be independent from protected-path keys and scoped by epoch. Callers
must additionally reject stale context/epoch and persist a replay check before
releasing a plaintext aggregate to an application.
"""
from dataclasses import dataclass
import hmac
from .profiles import canonical_json
from .protocol import Contributor, SignedTicket, frame, verify_ticket


@dataclass(frozen=True)
class PlainReport:
    source: Contributor
    values: tuple[int, ...]
    mac: bytes


def _message(signed: SignedTicket, source: Contributor, values):
    return frame(b"DAAHE/plain/v1", signed.ticket.digest,
                 canonical_json(source.object()), canonical_json(list(values)))


def authenticate(values, signed, source, key):
    values = tuple(values)
    if source not in signed.ticket.roster or not values or len(values) > 480:
        raise ValueError("invalid plaintext report")
    if any(type(v) is not int or not -(2**31) <= v < 2**31 for v in values):
        raise ValueError("values must be signed 32-bit integers")
    if len(key) < 32:
        raise ValueError("key needs 256 bits")
    return PlainReport(source, values, hmac.digest(key, _message(signed, source, values),
                                                "sha3_256")[:16])


def aggregate_plain(reports, signed, block_keys, verifier, library):
    verify_ticket(signed, verifier, library)
    received, total = [], None
    for report in reports:
        if len(received) >= len(signed.ticket.roster):
            raise ValueError("extra source")
        if report.source != signed.ticket.roster[len(received)]:
            raise ValueError("source order/roster invalid")
        expected = authenticate(report.values, signed, report.source,
                                block_keys[report.source.source_id]).mac
        if not hmac.compare_digest(expected, report.mac):
            raise ValueError("unauthenticated plaintext")
        if total is None:
            total = [0]*len(report.values)
        if len(total) != len(report.values):
            raise ValueError("dimension mismatch")
        total = [a+b for a,b in zip(total, report.values)]
        received.append(report.source)
    if tuple(received) != signed.ticket.roster:
        raise ValueError("incomplete roster")
    return tuple(total)

