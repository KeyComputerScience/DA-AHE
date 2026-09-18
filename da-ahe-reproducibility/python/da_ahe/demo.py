from __future__ import annotations

import json
import math
import random

import numpy as np

from .certification import certify_profile, stress_rows
from .codec import Db2Codec
from .robust_control import RobustAction, RobustMarkovController
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
    authority = TicketAuthority.generate()
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
        signal = np.vstack(
            (_signal(index, params.samples_per_channel),
             _signal(index + 7, params.samples_per_channel))
        )
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
    def kernel(diagonal: float) -> np.ndarray:
        off = (1.0 - diagonal) / 4.0
        return np.full((5, 5), off) + np.eye(5) * (diagonal - off)

    actions = [
        RobustAction(
            "nominal", profiles[0], 16, 1.0, 0.0, kernel(.72),
            np.array([.04, .03, .04]), np.full(5, .02),
            np.array([.2, .8, .6, .9, 1.2]),
        ),
        RobustAction(
            "congested", profiles[2], 12, .5, 1.0, kernel(.80),
            np.array([.24, .22, .28]), np.full(5, .015),
            np.array([.5, .6, .6, .7, .8]),
        ),
        RobustAction(
            "fallback", profiles[0], 1, .5, 1.0, kernel(.82),
            np.array([.40, .40, .40]), np.full(5, .01),
            np.array([.5, .6, .6, .7, .8]),
        ),
    ]
    controller = RobustMarkovController(
        params, np.eye(3), .10, .02, .10, .80,
        np.array([[0,0,0],[.16,.10,.08],[.12,.08,.05],
                  [.25,.18,.12],[.38,.30,.20]]),
        "fallback",
    )
    distribution = np.array([1.0, 0.0, 0.0, 0.0, 0.0])
    selected = controller.select(np.zeros(3), distribution, actions, actions[0])
    objective = controller.objective(distribution, selected, actions[0])
    next_distribution = distribution @ selected.transition

    return {
        "ciphertext_bytes": len(envelope.ciphertext),
        "blocks_per_node": params.ciphertext_bytes // profile.block_size,
        "roster_size": len(roster),
        "aggregate_verified": True,
        "reconstruction_rmse": rmse,
        "certification": reports,
        "stress_table": stress_rows(params),
        "controller": {
            "selected_action": selected.name,
            "selected_profile": selected.profile.profile_id,
            "selected_batch_size": selected.batch_size,
            "sampling_ratio": selected.sampling_ratio,
            "route_repair": selected.route_repair,
            "objective": objective,
            "next_distribution": next_distribution.tolist(),
        },
        "robust_drift": {
            "gamma": controller.gamma,
            "beta": controller.beta,
            "epsilon_transition": controller.epsilon_transition,
        },
        "warnings": [
            "research sampler and NumPy arithmetic are not production-safe",
            "ML-DSA-44 is supplied by pqcrypto/liboqs-compatible bindings",
            "replace illustrative R_min and stack RAM with target measurements",
        ],
    }


def main() -> None:
    print(json.dumps(run_demo(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
