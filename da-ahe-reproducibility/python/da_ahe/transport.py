from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import struct
import time

from pqcrypto.sign import ml_dsa_44


@dataclass(frozen=True)
class BatchTicket:
    epoch: int
    batch_id: str
    cluster_id: str
    profile_id: int
    roster: tuple[str, ...]
    nonce: str
    issued_at: int

    def to_bytes(self) -> bytes:
        payload = {
            "batch_id": self.batch_id,
            "cluster_id": self.cluster_id,
            "epoch": self.epoch,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "profile_id": self.profile_id,
            "roster": list(self.roster),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def new(
        cls,
        epoch: int,
        batch_id: str,
        cluster_id: str,
        profile_id: int,
        roster: tuple[str, ...],
        nonce: str,
    ) -> "BatchTicket":
        return cls(epoch, batch_id, cluster_id, profile_id, roster, nonce, int(time.time()))


@dataclass(frozen=True)
class SignedTicket:
    ticket: BatchTicket
    signature: bytes

    def signed_bytes(self) -> bytes:
        body = self.ticket.to_bytes()
        return struct.pack("<I", len(body)) + body + self.signature


class TicketAuthority:
    """ML-DSA-44 ticket signer/verifier used by the paper instance."""

    def __init__(
        self,
        private_key: bytes | None,
        public_key: bytes,
    ) -> None:
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls) -> "TicketAuthority":
        public_key, private_key = ml_dsa_44.generate_keypair()
        return cls(private_key, public_key)

    def verifier(self) -> "TicketAuthority":
        return TicketAuthority(None, self._public_key)

    def sign(self, ticket: BatchTicket) -> SignedTicket:
        if self._private_key is None:
            raise ValueError("this authority has no signing key")
        digest = hashlib.sha3_256(ticket.to_bytes()).digest()
        message = b"DA-AHE/TICKET/v1" + digest
        return SignedTicket(ticket, ml_dsa_44.sign(self._private_key, message))

    def verify(self, signed: SignedTicket) -> bool:
        digest = hashlib.sha3_256(signed.ticket.to_bytes()).digest()
        message = b"DA-AHE/TICKET/v1" + digest
        return bool(ml_dsa_44.verify(self._public_key, message, signed.signature))


@dataclass(frozen=True)
class CiphertextBlock:
    node_id: str
    index: int
    total: int
    payload: bytes
    tag: bytes


def _block_mac_input(
    ticket: SignedTicket,
    node_id: str,
    index: int,
    total: int,
    payload: bytes,
) -> bytes:
    node = node_id.encode()
    ticket_hash = hashlib.sha3_256(ticket.signed_bytes()).digest()
    return (
        b"DA-AHE/BLOCK/"
        + ticket_hash
        + struct.pack("<H", len(node))
        + node
        + struct.pack("<II", index, total)
        + payload
    )


def split_authenticated_blocks(
    raw_ciphertext: bytes,
    ticket: SignedTicket,
    node_id: str,
    block_key: bytes,
    block_size: int,
    tag_bytes: int,
) -> list[CiphertextBlock]:
    if block_size <= 0 or len(raw_ciphertext) % block_size:
        raise ValueError("ciphertext length must be divisible by block size")
    total = len(raw_ciphertext) // block_size
    blocks: list[CiphertextBlock] = []
    for index in range(total):
        payload = raw_ciphertext[index * block_size : (index + 1) * block_size]
        message = _block_mac_input(ticket, node_id, index, total, payload)
        tag = hmac.new(block_key, message, hashlib.sha3_256).digest()[:tag_bytes]
        blocks.append(CiphertextBlock(node_id, index, total, payload, tag))
    return blocks


def verify_block(
    block: CiphertextBlock,
    ticket: SignedTicket,
    block_key: bytes,
    tag_bytes: int,
) -> bool:
    message = _block_mac_input(
        ticket, block.node_id, block.index, block.total, block.payload
    )
    expected = hmac.new(block_key, message, hashlib.sha3_256).digest()[:tag_bytes]
    return hmac.compare_digest(expected, block.tag)


def aggregate_mac(gateway_key: bytes, ticket: SignedTicket, ciphertext: bytes) -> bytes:
    return hmac.new(
        gateway_key,
        b"DA-AHE/AGG/" + ticket.signed_bytes() + ciphertext,
        hashlib.sha3_256,
    ).digest()[:16]
