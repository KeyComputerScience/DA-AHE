from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac

import numpy as np

from .auth import (
    derive_auth_matrix,
    derive_label_mask,
    linear_tags,
    pack_codeword,
    unpack_codeword,
    verify_aggregate_tags,
)
from .codec import Db2Codec
from .mlwe import Ciphertext, PublicKey, SecretKey, decrypt, encrypt
from .params import LatticeParams, Profile
from .sampling import ResearchSampler
from .transport import (
    BatchTicket,
    CiphertextBlock,
    SignedTicket,
    TicketAuthority,
    aggregate_mac,
    split_authenticated_blocks,
    verify_block,
)


class ProtocolError(RuntimeError):
    pass


def _ticket_context(ticket: SignedTicket) -> bytes:
    return hashlib.sha256(ticket.signed_bytes()).digest()


def _node_label(ticket: BatchTicket, node_id: str) -> bytes:
    return (
        f"{ticket.epoch}|{ticket.batch_id}|{ticket.cluster_id}|"
        f"{ticket.profile_id}|{ticket.nonce}|{node_id}"
    ).encode()


@dataclass
class SensorNode:
    node_id: str
    block_key: bytes
    auth_secret: bytes
    mask_secret: bytes
    public_key: PublicKey
    ticket_verifier: TicketAuthority
    params: LatticeParams
    codec: Db2Codec

    def encapsulate(
        self,
        ticket: SignedTicket,
        profile: Profile,
        signal: np.ndarray,
        sampler: ResearchSampler,
    ) -> list[CiphertextBlock]:
        if not self.ticket_verifier.verify(ticket):
            raise ProtocolError("invalid sink ticket")
        if self.node_id not in ticket.ticket.roster:
            raise ProtocolError("node is not in the authorized roster")
        if ticket.ticket.profile_id != profile.profile_id:
            raise ProtocolError("ticket/profile mismatch")

        data = self.codec.compress(signal, profile)
        context = _ticket_context(ticket)
        auth_matrix = derive_auth_matrix(self.auth_secret, context, self.params)
        mask = derive_label_mask(
            self.mask_secret, _node_label(ticket.ticket, self.node_id), self.params
        )
        tags = linear_tags(auth_matrix, data, mask, self.params)
        codeword = pack_codeword(data, tags, self.params)
        ciphertext = encrypt(
            self.public_key, codeword, profile.sigma_enc, self.params, sampler
        )
        return split_authenticated_blocks(
            ciphertext.to_bytes(self.params),
            ticket,
            self.node_id,
            self.block_key,
            profile.block_size,
            self.params.tag_bytes,
        )


@dataclass(frozen=True)
class AggregateEnvelope:
    ticket: SignedTicket
    ciphertext: bytes
    gateway_tag: bytes


@dataclass
class StreamingGateway:
    block_keys: dict[str, bytes]
    gateway_key: bytes
    ticket_verifier: TicketAuthority
    params: LatticeParams

    def aggregate(
        self,
        ticket: SignedTicket,
        profile: Profile,
        blocks: list[CiphertextBlock],
    ) -> AggregateEnvelope:
        if not self.ticket_verifier.verify(ticket):
            raise ProtocolError("invalid sink ticket")
        if len(set(ticket.ticket.roster)) != len(ticket.ticket.roster):
            raise ProtocolError("batch roster contains duplicate identities")
        if ticket.ticket.profile_id != profile.profile_id:
            raise ProtocolError("ticket/profile mismatch")
        expected_total = self.params.ciphertext_bytes // profile.block_size
        expected_nodes = set(ticket.ticket.roster)
        if expected_nodes != set(self.block_keys).intersection(expected_nodes):
            raise ProtocolError("missing node verification key")

        accumulator = np.zeros(self.params.ciphertext_words, dtype=np.uint64)
        seen: set[tuple[str, int]] = set()
        for block in blocks:
            if block.node_id not in expected_nodes:
                raise ProtocolError("block from unauthorized node")
            if block.total != expected_total or not (0 <= block.index < expected_total):
                raise ProtocolError("invalid block index or total")
            if len(block.payload) != profile.block_size:
                raise ProtocolError("invalid block payload length")
            marker = (block.node_id, block.index)
            if marker in seen:
                raise ProtocolError("duplicate block")
            if not verify_block(
                block,
                ticket,
                self.block_keys[block.node_id],
                self.params.tag_bytes,
            ):
                raise ProtocolError("block authentication failure")
            seen.add(marker)
            words = np.frombuffer(block.payload, dtype="<u4").astype(np.uint64)
            offset = block.index * (profile.block_size // 4)
            accumulator[offset : offset + words.size] += words
            accumulator[offset : offset + words.size] &= np.uint64(0xFFFF_FFFF)

        expected = {
            (node_id, index)
            for node_id in expected_nodes
            for index in range(expected_total)
        }
        if seen != expected:
            raise ProtocolError("incomplete fixed-roster batch")
        raw = accumulator.astype("<u4").tobytes()
        return AggregateEnvelope(ticket, raw, aggregate_mac(self.gateway_key, ticket, raw))


@dataclass(frozen=True)
class SinkResult:
    aggregate_coefficients: np.ndarray
    reconstructed_signal: np.ndarray


@dataclass
class Sink:
    secret_key: SecretKey
    auth_secret: bytes
    mask_secret: bytes
    gateway_key: bytes
    ticket_verifier: TicketAuthority
    params: LatticeParams
    codec: Db2Codec
    seen_tickets: set[bytes] = field(default_factory=set)

    def open(self, envelope: AggregateEnvelope, profile: Profile) -> SinkResult:
        ticket = envelope.ticket
        if not self.ticket_verifier.verify(ticket):
            raise ProtocolError("invalid sink ticket")
        ticket_digest = _ticket_context(ticket)
        if ticket_digest in self.seen_tickets:
            raise ProtocolError("replayed batch ticket")
        if ticket.ticket.profile_id != profile.profile_id:
            raise ProtocolError("ticket/profile mismatch")
        expected_gateway_tag = aggregate_mac(
            self.gateway_key, ticket, envelope.ciphertext
        )
        if not hmac.compare_digest(expected_gateway_tag, envelope.gateway_tag):
            raise ProtocolError("gateway envelope authentication failure")

        ciphertext = Ciphertext.from_bytes(envelope.ciphertext, self.params)
        codeword = decrypt(self.secret_key, ciphertext, self.params)
        data_field, aggregate_tags = unpack_codeword(codeword, self.params)
        context = _ticket_context(ticket)
        auth_matrix = derive_auth_matrix(self.auth_secret, context, self.params)
        aggregate_mask = np.zeros(self.params.tag_count, dtype=np.int64)
        for node_id in ticket.ticket.roster:
            aggregate_mask += derive_label_mask(
                self.mask_secret, _node_label(ticket.ticket, node_id), self.params
            )
        aggregate_mask %= self.params.p
        if not verify_aggregate_tags(
            data_field,
            aggregate_tags,
            aggregate_mask,
            auth_matrix,
            self.params,
        ):
            raise ProtocolError("end-to-end linear authentication failure")
        self.seen_tickets.add(ticket_digest)
        centered_data = self.codec.field_to_centered(data_field)
        return SinkResult(
            centered_data,
            self.codec.reconstruct(centered_data, profile),
        )
