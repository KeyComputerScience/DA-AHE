"""Method-independent topology, source opportunities, and environmental traces."""
from __future__ import annotations

import json
import math
from pathlib import Path

from . import METHODS, STATUS
from .io import JsonlWriter, digest, file_hash, read_jsonl, uniform, write_json


def validate_config(c):
    if c.get("schema_version") != 1 or c.get("status") != STATUS:
        raise ValueError("unsupported schema or missing experimental status")
    if c.get("protocol_model_version") != 2:
        raise ValueError("requires fixed-preauthorized-roster protocol model version 2")
    parameters = c.get("cryptographic_parameters", {})
    for key in ("module_rank", "ring_degree", "n", "m", "q", "p"):
        if type(parameters.get(key)) is not int or parameters[key] <= 0:
            raise ValueError(f"cryptographic_parameters.{key} must be a positive integer")
    if parameters["n"] != parameters["module_rank"] * parameters["ring_degree"]:
        raise ValueError("flattened LWE dimension must equal module rank times ring degree")
    if parameters["q"] <= 1:
        raise ValueError("ciphertext coefficient modulus must exceed one")
    coefficient_bytes = ((parameters["q"] - 1).bit_length() + 7) // 8
    ciphertext_bytes = ((parameters["module_rank"] + 1) * parameters["ring_degree"] * coefficient_bytes)
    if c["protected_ciphertext_bytes"] != ciphertext_bytes:
        raise ValueError("protected ciphertext bytes do not match the declared MLWE tuple")
    if (c["security_estimator_summary"]["computed_estimator_bits"] <
            c["security_estimator_summary"]["required_estimator_bits"]):
        raise ValueError("bound security report does not meet the requested estimator threshold")
    if c["security_estimator_summary"]["full_system_certified"]:
        raise ValueError("security-estimator metadata cannot certify this synthetic system")
    if set(c["bound_evidence_artifacts"]) != {"security_profile", "security_report", "decoding_report"}:
        raise ValueError("security profile/report and decoding report bindings are required")
    for binding in c["bound_evidence_artifacts"].values():
        if len(binding["sha256"]) != 64 or any(v not in "0123456789abcdef" for v in binding["sha256"]):
            raise ValueError("invalid bound evidence artifact hash")
    if not c["methods"] or len(set(c["methods"])) != len(c["methods"]):
        raise ValueError("methods must be nonempty and unique")
    if set(c["methods"]) - set(METHODS):
        raise ValueError("unknown simulation method")
    if not c["evaluation_seeds"] or len(set(c["evaluation_seeds"])) != len(c["evaluation_seeds"]):
        raise ValueError("evaluation seeds must be nonempty and unique")
    if set(c["evaluation_seeds"]) & set(c["calibration_seeds"]):
        raise ValueError("calibration and evaluation seeds overlap")
    integers = ("nodes", "gateways", "queue_bytes_per_transmitter", "max_psdu_bytes",
                "backoff_slots", "local_contention_domains", "backhaul_contention_domains",
                "protected_ciphertext_bytes", "lightweight_payload_bytes")
    for key in integers:
        if type(c[key]) is not int or c[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    if c["gateways"] > c["nodes"]:
        raise ValueError("gateways cannot exceed source nodes")
    for key in ("duration_s", "sample_period_s", "control_interval_s", "report_deadline_s",
                "bit_rate_bps", "area_side_m", "repair_latency_s"):
        if not math.isfinite(c[key]) or c[key] <= 0:
            raise ValueError(f"{key} must be finite and positive")
    for key in ("protected_fraction", "contention_collision_per_extra_sender"):
        if not 0 <= c[key] <= 1:
            raise ValueError(f"{key} must be in [0,1]")
    if type(c["max_retries"]) is not int or c["max_retries"] < 0:
        raise ValueError("max_retries must be a nonnegative integer")
    if not math.isfinite(c["batch_ready_hold_s"]) or c["batch_ready_hold_s"] < 0:
        raise ValueError("all-members-ready hold must be finite and nonnegative")
    if c["control_interval_s"] >= c["report_deadline_s"]:
        raise ValueError("authorization window must be shorter than report lifetime")
    if c["drain_s"] < c["report_deadline_s"] + c["batch_ready_hold_s"]:
        raise ValueError("drain must cover report lifetime plus all-members-ready hold")
    d = c["disturbance"]
    if not 0 <= d["start_s"] < d["end_s"] < c["duration_s"]:
        raise ValueError("disturbance must end before source generation ends")
    for key in ("affected_gateway_fraction", "baseline_ber", "disturbed_ber",
                "baseline_external_tamper_probability", "disturbed_external_tamper_probability",
                "gateway_forgery_probability"):
        if not 0 <= d[key] <= 1:
            raise ValueError(f"disturbance.{key} must be in [0,1]")
    r = c["recovery"]
    if r["consecutive_windows"] < 1 or r["minimum_completed_reports"] < 1:
        raise ValueError("recovery requires positive window and sample counts")
    return c


def load_config(path):
    return validate_config(json.loads(Path(path).read_text()))


def validate_bound_artifacts(c, root, artifact_paths=None):
    """Verify immutable file hashes and tuple/capacity identity, not system safety."""
    artifacts = {}
    for name, binding in c["bound_evidence_artifacts"].items():
        path = (Path(artifact_paths[name]) if artifact_paths is not None else
                Path(root) / binding["path"])
        if file_hash(path) != binding["sha256"]:
            raise ValueError("bound cryptographic evidence checksum mismatch: " + name)
        artifacts[name] = json.loads(path.read_text())
    profile = artifacts["security_profile"]
    parameters = c["cryptographic_parameters"]
    if any(profile[key] != value for key, value in parameters.items()):
        raise ValueError("declared MLWE tuple differs from the bound security profile")
    if profile["ciphertext_bytes"] != c["protected_ciphertext_bytes"]:
        raise ValueError("wire length differs from the actual bound security profile")
    if (profile["security_report_sha256"] != c["bound_evidence_artifacts"]["security_report"]["sha256"] or
            profile["computed_estimator_bits"] != c["security_estimator_summary"]["computed_estimator_bits"]):
        raise ValueError("estimator label differs from the bound security report/profile")
    decoding = artifacts["decoding_report"]
    if decoding["status"] != "passed_decoding_tail_bound" or not decoding["source_unchanged_after_run"]:
        raise ValueError("decoding report did not complete with unchanged source")
    for key in ("module_rank", "ring_degree", "n", "q", "p", "sigma_key"):
        if decoding["inputs"][key] != parameters[key]:
            raise ValueError("decoding evidence uses a different cryptographic tuple")
    if decoding["security_report_binding"]["sha256"] != profile["security_report_sha256"]:
        raise ValueError("decoding/security report bindings disagree")
    expected = {(c["profile_encryption_sigmas"][name], size) for name, size in c["profile_batch_caps"].items()}
    observed = {(row["sigma_enc"], row["batch_size"]) for row in decoding["profiles"] if row["passed"]}
    if not expected <= observed:
        raise ValueError("configured encryption-noise/capacity library is not covered by the bound report")
    if c["decoding_probability_summary"]["probability_scope"] != decoding["probability_scope"]:
        raise ValueError("decoding probability scope differs from the actual bound report")
    return artifacts


def generate_exogenous(c, seed, output):
    """Write all environment inputs before any controller is instantiated."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    side = c["area_side_m"]
    gateways = [{"id": g, "x": side * uniform(seed, "topology_gateway_x", g),
                 "y": side * uniform(seed, "topology_gateway_y", g)}
                for g in range(c["gateways"])]
    nodes = []
    for i in range(c["nodes"]):
        x, y = side * uniform(seed, "topology_node_x", i), side * uniform(seed, "topology_node_y", i)
        nearest = min(gateways, key=lambda g: ((g["x"] - x)**2 + (g["y"] - y)**2, g["id"]))
        nodes.append({"id": i, "x": x, "y": y, "gateway": nearest["id"],
                      "distance_m": math.hypot(x - nearest["x"], y - nearest["y"]),
                      "protected": uniform(seed, "source_class", i) < c["protected_fraction"]})
    write_json(output / "topology.json", {"seed": seed, "sink": [side / 2, side / 2],
               "status": STATUS, "nodes": nodes, "gateways": gateways,
               "routing": "nearest gateway uplink, gateway primary/repairable alternate sink link"})
    opportunities = []
    for node in nodes:
        phase = c["sample_period_s"] * uniform(seed, "traffic_phase", node["id"])
        sample = 0
        while phase + sample * c["sample_period_s"] < c["duration_s"]:
            opportunities.append({"id": f"n{node['id']}:s{sample}", "node": node["id"],
                                  "sample": sample, "time_s": phase + sample * c["sample_period_s"],
                                  "sampling_uniform": uniform(seed, "sampling_admission", node["id"], sample)})
            sample += 1
    opportunities.sort(key=lambda row: (row["time_s"], row["node"], row["sample"]))
    with JsonlWriter(output / "traffic.jsonl.gz") as stream:
        for row in opportunities:
            stream.write(row)
    d = c["disturbance"]
    affected = set(sorted(range(c["gateways"]),
                          key=lambda g: uniform(seed, "outage_selection", g))[
                              :round(c["gateways"] * d["affected_gateway_fraction"])])
    # The bin multiplier is external interference, independent of method, action,
    # queue, packet count, and aggregation. No latent labels reach the controller.
    bins = math.ceil((c["duration_s"] + c["drain_s"]) / d["trajectory_bin_s"])
    disturbances = {"seed": seed, "affected_gateways": sorted(affected),
                    "start_s": d["start_s"], "end_s": d["end_s"],
                    "bin_s": d["trajectory_bin_s"],
                    "interference_multipliers": [[0.75 + 0.5 * uniform(seed, "interference", g, b)
                                                   for b in range(bins)]
                                                  for g in range(c["gateways"])],
                    "forgery_active": [[uniform(seed, "gateway_forgery", g, b) <
                                        d["gateway_forgery_probability"]
                                        for b in range(bins)] for g in range(c["gateways"])],
                    "random_streams": ["topology_gateway_x", "topology_gateway_y", "topology_node_x",
                                       "topology_node_y", "source_class", "traffic_phase",
                                       "sampling_admission", "outage_selection", "interference",
                                       "gateway_forgery", "frame_error", "collision", "backoff",
                                       "external_tamper"]}
    write_json(output / "disturbances.json", disturbances)
    files = {name: file_hash(output / name) for name in
             ("topology.json", "traffic.jsonl.gz", "disturbances.json")}
    manifest = {"seed": seed, "status": STATUS, "files": files,
                "exogenous_digest": digest(files), "source_opportunities": len(opportunities)}
    write_json(output / "manifest.json", manifest)
    return manifest


def read_exogenous(path):
    path = Path(path)
    manifest = json.loads((path / "manifest.json").read_text())
    for name, expected in manifest["files"].items():
        if file_hash(path / name) != expected:
            raise ValueError(f"exogenous artifact checksum mismatch: {name}")
    return (json.loads((path / "topology.json").read_text()),
            list(read_jsonl(path / "traffic.jsonl.gz")),
            json.loads((path / "disturbances.json").read_text()), manifest)
