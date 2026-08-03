from __future__ import annotations

import json
import math
import random

import numpy as np

from .certification import certify_profile, stress_rows
from .codec import Db2Codec
from .controller import (
    BoundedSoftmaxModel,
    Controller,
    candidate_actions,
    weak_ergodicity_constants,
)
from .mlwe import keygen
from .params import LatticeParams, default_profiles
from .protocol import SensorNode, Sink, StreamingGateway
from .sampling import ResearchSampler
from .transport import BatchTicket, TicketAuthority


def _signal(node_index: int, length: int) -> np.ndarray:
    x = np.arange(length, dtype=np.float64)
    return (
        120.0 * np.sin(2.0 * math.pi * (node_index + 1) * x / length)
        + 20.0 * np.cos(2.0 * math.pi * 3.0 * x / length)
        + node_index
    )


def run_demo() -> dict[str, object]:
    params = LatticeParams()
    profiles = default_profiles()
    profile = profiles[0]
    codec = Db2Codec(params)
    key_pair = keygen(params, ResearchSampler(10), b"A" * 32)
    authority = TicketAuthority.deterministic(b"paper-demo")
    verifier = authority.verifier()
    roster = tuple(f"node-{index}" for index in range(4))
    ticket = authority.sign(
        BatchTicket.new(1, "batch-0001", "cluster-a", profile.profile_id, roster, "n-1")
    )

    auth_secret = b"auth-secret-for-demo" * 2
    mask_secret = b"mask-secret-for-demo" * 2
    gateway_key = b"gateway-key-for-demo" * 2
    block_keys = {
        node_id: (f"block-key-{node_id}".encode() * 2)[:32] for node_id in roster
    }
    signals: list[np.ndarray] = []
    blocks = []
    for index, node_id in enumerate(roster):
        signal = _signal(index, params.d)
        signals.append(signal)
        node = SensorNode(
            node_id,
            block_keys[node_id],
            auth_secret,
            mask_secret,
            key_pair.public,
            verifier,
            params,
            codec,
        )
        blocks.extend(
            node.encapsulate(ticket, profile, signal, ResearchSampler(100 + index))
        )
    random.Random(7).shuffle(blocks)

    gateway = StreamingGateway(block_keys, gateway_key, verifier, params)
    envelope = gateway.aggregate(ticket, profile, blocks)
    sink = Sink(
        key_pair.secret,
        auth_secret,
        mask_secret,
        gateway_key,
        verifier,
        params,
        codec,
    )
    result = sink.open(envelope, profile)
    expected = np.sum(np.stack(signals), axis=0)
    rmse = float(np.sqrt(np.mean((result.reconstructed_signal - expected) ** 2)))

    reports = [certify_profile(candidate, params).to_dict() for candidate in profiles]
    actions = candidate_actions(profiles, params)
    model = BoundedSoftmaxModel(0.01)
    controller = Controller(params, model)
    distribution = np.array([1.0, 0.0, 0.0, 0.0, 0.0])
    fallback = actions[0]
    previous_eta = reports[fallback.profile.profile_id]["eta_at_effective_limit"]
    feedback = np.array([0.42, 0.03, previous_eta], dtype=np.float64)
    selected, objective, next_distribution = controller.choose(
        distribution, feedback, actions
    )

    return {
        "ciphertext_bytes": len(envelope.ciphertext),
        "blocks_per_node": params.ciphertext_bytes // profile.block_size,
        "roster_size": len(roster),
        "aggregate_verified": True,
        "reconstruction_rmse": rmse,
        "certification": reports,
        "stress_table": stress_rows(params),
        "controller": {
            "selected_profile": selected.profile.profile_id,
            "selected_batch_size": selected.batch_size,
            "mac_backoff": selected.mac_backoff,
            "route_intensity": selected.route_intensity,
            "objective": objective,
            "next_distribution": next_distribution.tolist(),
        },
        "weak_ergodicity": weak_ergodicity_constants(model.epsilon0),
        "warnings": [
            "research sampler and NumPy arithmetic are not production-safe",
            "replace Ed25519 ticket adapter with a post-quantum mechanism",
            "replace illustrative R_min and stack RAM with target measurements",
        ],
    }


def main() -> None:
    print(json.dumps(run_demo(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
