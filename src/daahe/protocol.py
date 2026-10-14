# SPDX-License-Identifier: MIT
"""Algorithms 1-3, reference wire format, exact roster, durable replay suppression.

The JSON/framing choices complete unspecified manuscript details. This Python
implementation makes no 10-KiB or constant-time claim. Run safety certification
separately before deploying any profile; this module allows reference experiments.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import struct
from typing import Iterable

from .derivation import derive_matrix, derive_offset, linear_tag
from .mlwe import Ciphertext, decrypt, encrypt, iter_ciphertext_blocks
from .profiles import P, ProfileLibrary, canonical_json
from .signal import encode_channels, reconstruct_channels


def frame(*parts: bytes) -> bytes:
    return b"".join(struct.pack("<I", len(part)) + part for part in parts)


@dataclass(frozen=True, order=True)
class Contributor:
    source_id: str
    nonce: bytes

    def __post_init__(self):
        if (not self.source_id or len(self.source_id.encode("utf8")) > 128
                or not isinstance(self.nonce, bytes) or len(self.nonce) != 16):
            raise ValueError("source ID / nonce invalid")

    def object(self):
        return {"source_id": self.source_id, "nonce": self.nonce.hex()}


@dataclass(frozen=True)
class Ticket:
    epoch: int
    batch_id: int
    context: str
    profile_id: str
    profile_digest: str
    roster: tuple[Contributor, ...]
    batch_nonce: bytes
    block_bytes: int = 64

    def __post_init__(self):
        if type(self.epoch) is not int or type(self.batch_id) is not int:
            raise ValueError("noninteger ticket counter")
        if self.epoch < 0 or self.batch_id < 0 or not self.context or len(self.context) > 1024:
            raise ValueError("invalid context/counter")
        if len(self.profile_id) != 24 or len(self.profile_digest) != 64:
            raise ValueError("invalid profile identifier")
        bytes.fromhex(self.profile_id)
        bytes.fromhex(self.profile_digest)
        if self.profile_id != self.profile_digest[:24]:
            raise ValueError("profile index differs from full digest")
        if not 1 <= len(self.roster) <= 16 or tuple(sorted(self.roster)) != self.roster:
            raise ValueError("roster must be nonempty canonical order, at most 16")
        if len({s.source_id for s in self.roster}) != len(self.roster):
            raise ValueError("duplicate source in roster")
        if not isinstance(self.batch_nonce, bytes) or len(self.batch_nonce) != 32:
            raise ValueError("batch nonce must be 256 bits")
        if self.block_bytes not in (32, 64):
            raise ValueError("block length not allowlisted")

    def object(self):
        return {"wire_version": 1, "epoch": self.epoch, "batch_id": self.batch_id,
                "context": self.context, "profile_id": self.profile_id,
                "profile_digest": self.profile_digest,
                "roster": [s.object() for s in self.roster],
                "batch_nonce": self.batch_nonce.hex(), "block_bytes": self.block_bytes}

    def encode(self):
        return canonical_json(self.object())

    @property
    def digest(self) -> bytes:
        return hashlib.sha3_256(self.encode()).digest()


@dataclass(frozen=True)
class SignedTicket:
    ticket: Ticket
    signature: bytes


def issue_ticket(ticket: Ticket, signer) -> SignedTicket:
    return SignedTicket(ticket, signer.sign(frame(b"DAAHE/ticket/v1", ticket.digest)))


def verify_ticket(signed: SignedTicket, verifier, library: ProfileLibrary):
    ticket = signed.ticket
    if not verifier.verify(frame(b"DAAHE/ticket/v1", ticket.digest), signed.signature):
        raise ValueError("invalid ticket")
    profile = library.lookup(ticket.profile_id)
    if profile.digest != ticket.profile_digest or len(ticket.roster) > profile.nmax:
        raise ValueError("profile/roster mismatch")
    if len(ticket.roster) * profile.coefficient_bound > (P-1)//2:
        raise ValueError("batch exceeds no-wrap capacity")
    return profile


def pack_values(data, tag):
    values = tuple(data) + tuple(tag)
    if not values or len(values) > 512:
        raise ValueError("only one or two plaintext polynomials supported")
    if any(type(x) is not int or not 0 <= x < P for x in values):
        raise ValueError("noncanonical field element")
    padded = values + (0,) * ((-len(values)) % 256)
    return tuple(padded[i:i+256] for i in range(0, len(padded), 256))


def unpack_values(polys, L: int, tag_count: int = 16):
    values = tuple(x for poly in polys for x in poly)
    if len(values) != 256*((L+tag_count+255)//256):
        raise ValueError("unexpected plaintext polynomial count")
    if any(values[L+tag_count:]):
        raise ValueError("nonzero unused plaintext positions")
    return values[:L], values[L:L+tag_count]


@dataclass(frozen=True)
class Block:
    index: int
    total: int
    payload: bytes
    mac: bytes


def block_mac(key: bytes, ticket: Ticket, source: Contributor,
              index: int, total: int, payload: bytes) -> bytes:
    if len(key) < 32:
        raise ValueError("block key needs 256 bits")
    msg = frame(b"DAAHE/block/v1", ticket.digest, source.source_id.encode("utf8"),
                source.nonce, struct.pack("<II", index, total), payload)
    return hmac.digest(key, msg, "sha3_256")[:16]


@dataclass(frozen=True)
class SourceEnvelope:
    signed_ticket: SignedTicket
    source: Contributor
    blocks: tuple[Block, ...]


class SourceEmissionStore:
    """Durable, immutable source report binding and exact retransmission cache.

    A source may emit only one ciphertext for a given signed ticket/roster entry.
    Two different reports with the same affine-tag offset permit a compromised
    gateway to construct 2*c1-c2, whose tag authenticates 2*x1-x2. Sink-side Seen
    cannot prevent that forgery before the first acceptance. This store therefore
    commits the raw-payload binding before encryption and commits the winning
    ciphertext before returning it. Concurrent same-payload callers return the
    same cached envelope; different payloads are rejected, including after restart.

    A crash after binding but before caching permits only the same payload to
    resume. No uncached ciphertext is released. Protect this database against
    rollback/deletion together with source key and epoch state. Rotate the ticket
    for a new sample or key configuration. This host SQLite cache is not a board
    flash driver or a hardware anti-rollback implementation.

    The cache includes the original ticket signature. Retransmit that exact
    SignedTicket together with the cached blocks. Re-signing the same ticket body
    can produce a different ML-DSA signature but does not create a new ledger
    identity; this store still returns the original envelope. A newly authorized
    batch must change the signed batch nonce rather than merely re-sign its body.
    """

    def __init__(self, path):
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("durable source emission storage required")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS emissions ("
                       "ticket_digest BLOB NOT NULL, source_id TEXT NOT NULL, "
                       "nonce BLOB NOT NULL, payload_digest BLOB NOT NULL, envelope BLOB, "
                       "PRIMARY KEY(ticket_digest, source_id, nonce))")

    @staticmethod
    def _identity(ticket, source):
        return ticket.digest, source.source_id, source.nonce

    def _bind(self, ticket, source, payload_digest):
        identity = self._identity(ticket, source)
        with sqlite3.connect(self.path, timeout=30) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload_digest, envelope FROM emissions "
                             "WHERE ticket_digest=? AND source_id=? AND nonce=?",
                             identity).fetchone()
            if row is None:
                db.execute("INSERT INTO emissions "
                           "(ticket_digest, source_id, nonce, payload_digest) VALUES (?,?,?,?)",
                           (*identity, payload_digest))
                cached = None
            else:
                if not hmac.compare_digest(row[0], payload_digest):
                    raise ValueError("source ticket already bound to a different raw payload")
                cached = row[1]
        return cached

    def _cache_first(self, ticket, source, payload_digest, encoded):
        identity = self._identity(ticket, source)
        with sqlite3.connect(self.path, timeout=30) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload_digest, envelope FROM emissions "
                             "WHERE ticket_digest=? AND source_id=? AND nonce=?",
                             identity).fetchone()
            if row is None or not hmac.compare_digest(row[0], payload_digest):
                raise ValueError("source emission binding disappeared or changed")
            if row[1] is None:
                db.execute("UPDATE emissions SET envelope=? "
                           "WHERE ticket_digest=? AND source_id=? AND nonce=?",
                           (encoded, *identity))
                cached = encoded
            else:
                cached = row[1]
        return cached

    @staticmethod
    def _encode(envelope):
        return canonical_json({"signature": envelope.signed_ticket.signature.hex(),
                               "blocks": [[b.index, b.total, b.payload.hex(), b.mac.hex()]
                                          for b in envelope.blocks]})

    @staticmethod
    def _decode(encoded, signed_ticket, source, count):
        record = json.loads(encoded)
        if not isinstance(record, dict) or set(record) != {"signature", "blocks"}:
            raise ValueError("invalid source emission cache")
        signature = bytes.fromhex(record["signature"])
        rows = record["blocks"]
        if not signature or not isinstance(rows, list) or len(rows) != count:
            raise ValueError("incomplete source emission cache")
        blocks = []
        for index, row in enumerate(rows):
            if (not isinstance(row, list) or len(row) != 4
                    or type(row[0]) is not int or type(row[1]) is not int
                    or row[0] != index or row[1] != count):
                raise ValueError("invalid source emission cache block")
            payload, mac = bytes.fromhex(row[2]), bytes.fromhex(row[3])
            if len(payload) != signed_ticket.ticket.block_bytes or len(mac) != 16:
                raise ValueError("invalid source emission cache bytes")
            blocks.append(Block(index, count, payload, mac))
        original_signed = SignedTicket(signed_ticket.ticket, signature)
        return SourceEnvelope(original_signed, source, tuple(blocks))


def _quantize_raw(channels, profile):
    if len(channels) != 2 or any(len(c) != 240 for c in channels):
        raise ValueError("exactly two 240-sample integer channels required")
    values = []
    for channel in channels:
        for x in channel:
            if type(x) is not int:
                raise ValueError("integer sensor units required")
            q = (abs(x) + profile.delta_q//2)//profile.delta_q
            q = q if x >= 0 else -q
            if abs(q) > profile.coefficient_bound:
                raise ValueError("out-of-range quantized data")
            values.append(q)
    return tuple(values)


def encapsulate(channels, signed_ticket: SignedTicket, source: Contributor,
                pk, epoch_secret: bytes, block_key: bytes, verifier,
                library: ProfileLibrary, *, source_store: SourceEmissionStore) -> SourceEnvelope:
    """Emit once per ticket/source; retries return the original cached envelope.

    The durable source store is mandatory. A new raw sample requires a new signed
    ticket even if quantization happens to produce the same coefficient vector.
    Retrying an already cached entry returns its original SignedTicket/signature;
    pass that original signed ticket to aggregate. Re-signing an unchanged ticket
    body is not a new batch and cannot authorize a second source ciphertext.
    """
    if not isinstance(source_store, SourceEmissionStore):
        raise ValueError("a durable SourceEmissionStore is required")
    profile = verify_ticket(signed_ticket, verifier, library)
    ticket = signed_ticket.ticket
    if source not in ticket.roster:
        raise ValueError("unauthorized source")
    snapshot = tuple(tuple(channel) for channel in channels)
    x = (_quantize_raw(snapshot, profile) if profile.representation == "raw" else
         encode_channels(snapshot, profile.support, profile.delta_q, profile.coefficient_bound))
    payload_digest = hashlib.sha3_256(canonical_json(snapshot)).digest()
    J = 4096 * profile.polynomial_count // ticket.block_bytes
    cached = source_store._bind(ticket, source, payload_digest)
    if cached is not None:
        original = source_store._decode(cached, signed_ticket, source, J)
        verify_ticket(original.signed_ticket, verifier, library)
        return original
    xf = tuple(v % P for v in x)
    if profile.verify_integrity:
        matrix = derive_matrix(epoch_secret, ticket.digest, profile.L)
        offset = derive_offset(epoch_secret, ticket.digest, source.source_id, source.nonce)
        tag = linear_tag(matrix, xf, offset)
    else:
        tag = ()
    plaintexts = pack_values(xf, tag)
    if len(plaintexts) != profile.polynomial_count:
        raise ValueError("profile and packed polynomial counts disagree")
    blocks = []
    for plaintext in plaintexts:
        ct = encrypt(pk, plaintext, sigma=profile.sigma_enc)
        for payload in iter_ciphertext_blocks(ct, ticket.block_bytes):
            j = len(blocks)
            blocks.append(Block(j, J, payload,
                                block_mac(block_key, ticket, source, j, J, payload)))
    original = SourceEnvelope(signed_ticket, source, tuple(blocks))
    cached = source_store._cache_first(ticket, source, payload_digest,
                                     source_store._encode(original))
    original = source_store._decode(cached, signed_ticket, source, J)
    verify_ticket(original.signed_ticket, verifier, library)
    return original


@dataclass(frozen=True)
class GatewayAggregate:
    signed_ticket: SignedTicket
    contributors: tuple[Contributor, ...]
    ciphertext: bytes
    transport_mac: bytes


def aggregate_message(signed, contributors, ciphertext):
    return frame(b"DAAHE/aggregate/v1", signed.ticket.digest, signed.signature,
                 canonical_json([s.object() for s in contributors]), ciphertext)


def aggregate(envelopes: Iterable[SourceEnvelope], signed_ticket: SignedTicket,
              block_keys: dict[str, bytes], gateway_key: bytes,
              verifier, library: ProfileLibrary) -> GatewayAggregate:
    """Streaming ordered sources. Any late failure aborts this entire batch.

    Authentication precedes word addition; no partially accepted aggregate escapes.
    The reference SourceEnvelope holds all blocks; embedded C uses a single buffer.
    """
    profile = verify_ticket(signed_ticket, verifier, library)
    ticket = signed_ticket.ticket
    if len(gateway_key) < 32:
        raise ValueError("gateway key needs 256 bits")
    total_bytes = 4096 * profile.polynomial_count
    J = total_bytes//ticket.block_bytes
    accumulator = bytearray(total_bytes)
    received = []
    for envelope in envelopes:
        if envelope.signed_ticket != signed_ticket:
            raise ValueError("ticket substitution")
        source = envelope.source
        if (len(received) >= len(ticket.roster)
                or source != ticket.roster[len(received)] or len(envelope.blocks) != J):
            raise ValueError("missing, duplicate, noncanonical, or extra source")
        for expected_index, block in enumerate(envelope.blocks):
            if (block.index != expected_index or block.total != J
                    or len(block.payload) != ticket.block_bytes):
                raise ValueError("malformed block")
            expected = block_mac(block_keys[source.source_id], ticket, source,
                                 block.index, J, block.payload)
            if not hmac.compare_digest(expected, block.mac):
                raise ValueError("invalid block")
            start = expected_index*ticket.block_bytes
            for offset in range(0, ticket.block_bytes, 4):
                a = struct.unpack_from("<I", accumulator, start+offset)[0]
                b = struct.unpack_from("<I", block.payload, offset)[0]
                struct.pack_into("<I", accumulator, start+offset, (a+b) & 0xffffffff)
        received.append(source)
    contributors = tuple(received)
    if contributors != ticket.roster:
        raise ValueError("incomplete batch")
    ciphertext = bytes(accumulator)
    mac = hmac.digest(gateway_key, aggregate_message(signed_ticket, contributors, ciphertext),
                      "sha3_256")
    return GatewayAggregate(signed_ticket, contributors, ciphertext, mac)


class ReplayStore:
    """Persistent acceptance set. UNIQUE insert commits before releasing plaintext.

    Back up this database with key state; rollback to an old backup invalidates the
    replay guarantee. Cryptographic rejection never reserves an unused batch.
    Seen alone is an at-most-once acceptance mechanism: a crash after commit and
    before application delivery can lose a result. Production delivery needs a
    transactional result/outbox record and an idempotent trusted consumer.
    """
    def __init__(self, path):
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("durable replay storage required")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS seen (digest BLOB PRIMARY KEY)")

    def reserve(self, digest: bytes) -> bool:
        with sqlite3.connect(self.path, timeout=30) as db:
            db.execute("PRAGMA synchronous=FULL")
            try:
                db.execute("INSERT INTO seen(digest) VALUES (?)", (digest,))
            except sqlite3.IntegrityError:
                return False
        return True


@dataclass(frozen=True)
class Acceptance:
    ticket_digest: str
    quantized_aggregate: tuple[int, ...]
    reconstructed_channels: tuple
    integrity_verified: bool


class Sink:
    def __init__(self, sk, epoch_secret, gateway_key, verifier, library, replay_store,
                 *, epoch: int = 0, context: str = "demo-v1", allow_unverified=False):
        self.sk, self.epoch_secret, self.gateway_key = sk, epoch_secret, gateway_key
        self.verifier, self.library, self.replay_store = verifier, library, replay_store
        self.epoch, self.context = epoch, context
        self.allow_unverified = allow_unverified

    def accept(self, envelope: GatewayAggregate) -> Acceptance | None:
        """One rejection outcome; does not expose tags, decoded failures, or reasons.

        This is a uniform result API, NOT a constant-time Python implementation.
        Network code must never return internal exceptions to an adversary.
        """
        try:
            signed = envelope.signed_ticket
            ticket = signed.ticket
            if ticket.epoch != self.epoch or ticket.context != self.context:
                return None
            profile = verify_ticket(signed, self.verifier, self.library)
            if not profile.verify_integrity and not self.allow_unverified:
                return None
            if envelope.contributors != ticket.roster:
                return None
            if len(envelope.ciphertext) != 4096*profile.polynomial_count:
                return None
            expected = hmac.digest(self.gateway_key,
                aggregate_message(signed, envelope.contributors, envelope.ciphertext), "sha3_256")
            if not hmac.compare_digest(expected, envelope.transport_mac):
                return None
            polys = [decrypt(self.sk, Ciphertext.from_bytes(envelope.ciphertext[i:i+4096]))
                     for i in range(0, len(envelope.ciphertext), 4096)]
            x, tag = unpack_values(polys, profile.L, profile.tag_count)
            if profile.verify_integrity:
                matrix = derive_matrix(self.epoch_secret, ticket.digest, profile.L)
                offsets = [derive_offset(self.epoch_secret, ticket.digest, s.source_id, s.nonce)
                           for s in ticket.roster]
                offset = tuple(sum(o[j] for o in offsets) % P for j in range(16))
                expected_tag = linear_tag(matrix, x, offset)
                if not hmac.compare_digest(struct.pack("<16I", *tag),
                                           struct.pack("<16I", *expected_tag)):
                    return None
            centered = tuple(v if v <= P//2 else v-P for v in x)
            if any(abs(v) > len(ticket.roster)*profile.coefficient_bound for v in centered):
                return None
            if profile.representation == "raw":
                values = tuple(v*profile.delta_q for v in centered)
                reconstructed = (values[:240], values[240:])
            else:
                reconstructed = reconstruct_channels(centered, profile.support, profile.delta_q)
            if not self.replay_store.reserve(ticket.digest):
                return None
            return Acceptance(ticket.digest.hex(), centered, reconstructed,
                              profile.verify_integrity)
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, struct.error, OverflowError,
                sqlite3.Error):
            return None

