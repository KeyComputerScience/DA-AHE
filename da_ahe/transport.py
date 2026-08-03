from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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
    """Executable signature adapter.

    Ed25519 keeps the reference self-contained. Replace this adapter with a
    post-quantum signature before deployment.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey | None,
        public_key: Ed25519PublicKey,
    ) -> None:
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def deterministic(cls, seed: bytes) -> "TicketAuthority":
        private_bytes = hashlib.sha256(b"DA-AHE/ticket/" + seed).digest()
        private = Ed25519PrivateKey.from_private_bytes(private_bytes)
        return cls(private, private.public_key())

    def verifier(self) -> "TicketAuthority":
        return TicketAuthority(None, self._public_key)

    def sign(self, ticket: BatchTicket) -> SignedTicket:
        if self._private_key is None:
            raise ValueError("this authority has no signing key")
        return SignedTicket(ticket, self._private_key.sign(ticket.to_bytes()))

    def verify(self, signed: SignedTicket) -> bool:
        try:
            self._public_key.verify(signed.signature, signed.ticket.to_bytes())
            return True
        except InvalidSignature:
            return False


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
    ticket_hash = hashlib.sha256(ticket.signed_bytes()).digest()
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
        tag = hmac.new(block_key, message, hashlib.sha256).digest()[:tag_bytes]
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
    expected = hmac.new(block_key, message, hashlib.sha256).digest()[:tag_bytes]
    return hmac.compare_digest(expected, block.tag)


def aggregate_mac(gateway_key: bytes, ticket: SignedTicket, ciphertext: bytes) -> bytes:
    return hmac.new(
        gateway_key,
        b"DA-AHE/AGG/" + ticket.signed_bytes() + ciphertext,
        hashlib.sha256,
    ).digest()[:16]

