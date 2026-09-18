import unittest

import numpy as np

from da_ahe.codec import Db2Codec
from da_ahe.mlwe import keygen
from da_ahe.params import LatticeParams, default_profiles
from da_ahe.protocol import (
    AggregateEnvelope,
    ProtocolError,
    SensorNode,
    Sink,
    StreamingGateway,
)
from da_ahe.sampling import ResearchSampler
from da_ahe.transport import (
    BatchTicket,
    CiphertextBlock,
    TicketAuthority,
    aggregate_mac,
)


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.params = LatticeParams()
        cls.profile = default_profiles()[0]
        cls.codec = Db2Codec(cls.params)
        cls.key_pair = keygen(cls.params, ResearchSampler(20), b"P" * 32)
        cls.authority = TicketAuthority.generate()
        cls.verifier = cls.authority.verifier()
        cls.roster = ("node-a", "node-b")
        cls.ticket = cls.authority.sign(
            BatchTicket.new(1, "batch-test", "cluster", 0, cls.roster, "nonce")
        )
        cls.auth_secret = b"A" * 32
        cls.mask_secret = b"X" * 32
        cls.gateway_key = b"G" * 32
        cls.block_keys = {"node-a": b"1" * 32, "node-b": b"2" * 32}

    def _blocks(self):
        blocks = []
        signals = []
        for index, node_id in enumerate(self.roster):
            x = np.arange(self.params.samples_per_channel)
            signal = np.vstack((
                np.sin(x / (5.0 + index)) * 100.0,
                np.cos(x / (7.0 + index)) * 80.0,
            ))
            signals.append(signal)
            node = SensorNode(
                node_id,
                self.block_keys[node_id],
                self.auth_secret,
                self.mask_secret,
                self.key_pair.public,
                self.verifier,
                self.params,
                self.codec,
            )
            blocks.extend(
                node.encapsulate(
                    self.ticket,
                    self.profile,
                    signal,
                    ResearchSampler(30 + index),
                )
            )
        return blocks, signals

    def _gateway(self):
        return StreamingGateway(
            self.block_keys,
            self.gateway_key,
            self.verifier,
            self.params,
        )

    def _sink(self):
        return Sink(
            self.key_pair.secret,
            self.auth_secret,
            self.mask_secret,
            self.gateway_key,
            self.verifier,
            self.params,
            self.codec,
        )

    def test_end_to_end_aggregate(self) -> None:
        blocks, signals = self._blocks()
        envelope = self._gateway().aggregate(self.ticket, self.profile, blocks)
        result = self._sink().open(envelope, self.profile)
        expected = np.sum(np.stack(signals), axis=0)
        rmse = float(np.sqrt(np.mean((result.reconstructed_signal - expected) ** 2)))
        self.assertLess(rmse, 30.0)
        self.assertEqual(len(envelope.ciphertext), 4_096)

    def test_block_tamper_is_rejected(self) -> None:
        blocks, _ = self._blocks()
        original = blocks[0]
        payload = bytes([original.payload[0] ^ 1]) + original.payload[1:]
        blocks[0] = CiphertextBlock(
            original.node_id,
            original.index,
            original.total,
            payload,
            original.tag,
        )
        with self.assertRaisesRegex(ProtocolError, "authentication"):
            self._gateway().aggregate(self.ticket, self.profile, blocks)

    def test_malicious_gateway_cannot_forge_linear_tags(self) -> None:
        blocks, _ = self._blocks()
        envelope = self._gateway().aggregate(self.ticket, self.profile, blocks)
        words = np.frombuffer(envelope.ciphertext, dtype="<u4").copy()
        first_v_word = self.params.k * self.params.d
        words[first_v_word] = np.uint32(
            (int(words[first_v_word]) + self.params.delta) & 0xFFFF_FFFF
        )
        modified = words.astype("<u4").tobytes()
        forged = AggregateEnvelope(
            envelope.ticket,
            modified,
            aggregate_mac(self.gateway_key, envelope.ticket, modified),
        )
        with self.assertRaisesRegex(ProtocolError, "linear authentication"):
            self._sink().open(forged, self.profile)

    def test_sink_rejects_replay(self) -> None:
        blocks, _ = self._blocks()
        envelope = self._gateway().aggregate(self.ticket, self.profile, blocks)
        sink = self._sink()
        sink.open(envelope, self.profile)
        with self.assertRaisesRegex(ProtocolError, "replayed"):
            sink.open(envelope, self.profile)


if __name__ == "__main__":
    unittest.main()
