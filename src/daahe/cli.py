# SPDX-License-Identifier: MIT
"""Offline artifact commands. Nothing runs automatically when the package imports."""
import argparse
from dataclasses import asdict, replace
import hmac
import json
import math
from pathlib import Path
import secrets
import sys


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False)+"\n")


def demo(args):
    """A functional scenario, never a network benchmark or security certificate."""
    from .mlwe import keygen
    from .profiles import example_profiles
    from .protocol import (Contributor, Ticket, Sink, ReplayStore, issue_ticket,
                           encapsulate, aggregate, aggregate_message)
    from .signatures import MLDSA44Signer, MLDSA44Verifier
    library = example_profiles()
    profiles = {p.name: p for p in library}
    profile = profiles[args.profile]
    if args.participants > profile.nmax:
        raise ValueError("participant count exceeds profile capacity")
    args.output.mkdir(parents=True, exist_ok=True)
    epoch_secret = secrets.token_bytes(32)
    gateway_key = secrets.token_bytes(32)
    keypair = keygen()
    roster = tuple(Contributor(f"node-{i:04}", secrets.token_bytes(16))
                   for i in range(args.participants))
    keys = {s.source_id: secrets.token_bytes(32) for s in roster}
    signals = {s.source_id: tuple(tuple(round(400+60*math.sin(2*math.pi*t/240+c)+i)
                             for t in range(240)) for c in (0,1))
               for i,s in enumerate(roster)}
    ticket = Ticket(0, 0, "demo-v1", profile.profile_id, profile.digest, roster,
                    secrets.token_bytes(32), args.block_bytes)
    with MLDSA44Signer.keygen() as signer:
        verifier = MLDSA44Verifier(signer.public_key)
        signed = issue_ticket(ticket, signer)
        envelopes = [encapsulate(signals[s.source_id], signed, s, keypair.public,
                                epoch_secret, keys[s.source_id], verifier, library) for s in roster]
        result = aggregate(envelopes, signed, keys, gateway_key, verifier, library)
        sink = Sink(keypair.secret, epoch_secret, gateway_key, verifier, library,
                    ReplayStore(args.output/"seen.sqlite"), allow_unverified=not profile.verify_integrity)
        # Compromised-gateway attack: retain a VALID transport MAC after modifying v.
        mutated = bytearray(result.ciphertext)
        index = 3*256*4  # first v word, not a u word
        value = (int.from_bytes(mutated[index:index+4], "little") + 65535) & 0xffffffff
        mutated[index:index+4] = value.to_bytes(4,"little")
        transport = hmac.digest(gateway_key,
            aggregate_message(signed, result.contributors, bytes(mutated)), "sha3_256")
        altered = replace(result, ciphertext=bytes(mutated), transport_mac=transport)
        tamper_result = sink.accept(altered) if profile.verify_integrity else None
        accepted = sink.accept(result)
        if accepted is None:
            raise RuntimeError("reference correctness check rejected honest aggregation")
        replay_rejected = sink.accept(result) is None
        truth = tuple(tuple(sum(signals[s.source_id][c][t] for s in roster)
                            for t in range(240)) for c in range(2))
        errors = [a-b for true_c,rec_c in zip(truth,accepted.reconstructed_channels)
                  for a,b in zip(true_c,rec_c)]
        total_energy = sum(v*v for channel in truth for v in channel)
        report = {"status":"reference_demo_only_uncertified", "profile":asdict(profile),
                  "ticket":ticket.object(), "ticket_signature_bytes":len(signed.signature),
                  "participants":args.participants,
                  "payload_bytes_per_report":4096*profile.polynomial_count,
                  "blocks_per_report":len(envelopes[0].blocks),
                  "block_mac_bytes_per_report":16*len(envelopes[0].blocks),
                  "honest_aggregate_accepted":True,
                  "compromised_gateway_modification_rejected":tamper_result is None
                    if profile.verify_integrity else "not_checked_without_hve",
                  "replay_rejected":replay_rejected,
                  "integrity_verified":accepted.integrity_verified,
                  "synthetic_aggregate_rmse":math.sqrt(sum(e*e for e in errors)/480),
                  "synthetic_aggregate_prd_percent":100*math.sqrt(sum(e*e for e in errors)/total_energy),
                  "quantized_aggregate":accepted.quantized_aggregate,
                  "reconstructed_channels":accepted.reconstructed_channels,
                  "limitations":["synthetic waveform, no measured CPS data",
                    "no benchmark, security certification or paper-result reproduction",
                    "rounded lifting does not commute exactly with summation",
                    "ticket signature and all headers are additional to ciphertext payload"]}
        write_json(args.output/"report.json", report)
        if (profile.verify_integrity and tamper_result is not None) or not replay_rejected:
            raise RuntimeError("reference integrity/replay scenario failed")
    print(f"Reference report: {args.output/'report.json'}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("demo", help="execute explicitly uncertified host protocol scenario")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--participants", type=int, default=3, choices=range(1,17))
    p.add_argument("--block-bytes", type=int, choices=(32,64), default=64)
    p.add_argument("--profile", choices=("pi0","pi1","pi2","fallback","without_intdb2","without_hve"), default="pi0")
    p = commands.add_parser("profiles", help="show immutable reconstructed profiles")
    p.add_argument("--output", type=Path)
    p = commands.add_parser("stats", help="analyze external paired packet-level runs")
    p.add_argument("csv", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--resamples", type=int, default=100000)
    p.add_argument("--bootstrap-seed", type=int, default=20261014)
    p = commands.add_parser("manifest", help="record file SHA256 checksums")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("verify-manifest", help="verify content hashes")
    p.add_argument("manifest", type=Path)
    p.add_argument("--root", type=Path, default=Path("."))
    p = commands.add_parser("audit", help="report missing original evidence; never implies validation")
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--output", type=Path)
    p = commands.add_parser("replay-control", help="causal CSV control replay, no network simulation")
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--telemetry", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--method", choices=("da-ahe","dpp","hys"), default="da-ahe")
    p.add_argument("--allow-synthetic", action="store_true")
    p = commands.add_parser("calibrate", help="fit empirical models on disjoint labeled traces")
    p.add_argument("--config",type=Path,required=True)
    p.add_argument("--training",type=Path,required=True)
    p.add_argument("--holdout",type=Path,required=True)
    p.add_argument("--evaluation-seeds",type=int,nargs="+",required=True)
    p.add_argument("--output",type=Path,required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            return demo(args)
        if args.command == "profiles":
            from .profiles import example_profiles
            data = [{**asdict(p),"profile_id":p.profile_id,"digest":p.digest}
                    for p in example_profiles()]
            if args.output:
                write_json(args.output,data)
            else:
                print(json.dumps(data,indent=2))
            return 0
        if args.command == "stats":
            from .statistics import load_metrics_csv, summarize
            data = summarize(load_metrics_csv(args.csv), resamples=args.resamples,
                             bootstrap_seed=args.bootstrap_seed)
            write_json(args.output,data)
            return 0
        if args.command == "replay-control":
            from .replay import replay_csv
            data = replay_csv(args.config,args.telemetry,method=args.method,
                              allow_synthetic=args.allow_synthetic)
            write_json(args.output,data)
            return 0 if data.get("completed_without_fail_closed",False) else 2
        if args.command == "calibrate":
            from .calibration import read_trace,calibrate
            from .safety import Action
            config = json.loads(args.config.read_text())
            actions = [Action.from_dict(a) for a in config["actions"]]
            nominal = config["model"]["transitions"]
            model = calibrate(read_trace(args.training), read_trace(args.holdout), actions,
                              evaluation_seeds=args.evaluation_seeds,
                              nominal_transitions=nominal,
                              kappa_z=config["model"].get("kappa_z",0.8),
                              zcert_max=config["model"].get("zcert_max",(1.0,1.0,1.0)))
            write_json(args.output,model.to_dict())
            return 0
        from .evidence import audit_readiness, build_manifest, verify_manifest
        if args.command == "manifest":
            build_manifest(args.root,args.output)
            return 0
        if args.command == "verify-manifest":
            data = verify_manifest(args.root,args.manifest)
            print(json.dumps(data,indent=2))
            return 0 if data.get("status") == "verified" else 2
        data = audit_readiness(args.root)
        if args.output:
            write_json(args.output,data)
        print(json.dumps(data,indent=2))
        return 0 if data.get("status") == "evidence_present_requires_execution_and_review" else 2
    except (ValueError,RuntimeError,KeyError,OSError,ImportError) as exc:
        print(f"daahe: {exc}",file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

