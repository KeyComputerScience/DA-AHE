#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute real-provider protocol trials; export public outcomes, never private keys.

These trials use fresh CSPRNG encryption/signature keys and synthetic waveforms.
They test protocol behavior. Host wall times are not nRF52840 measurements, and
observed successful decryptions do not establish a 2^-128 failure certificate.
"""
import argparse
import contextlib
import io
import json
from pathlib import Path
import platform
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from daahe.cli import demo
from daahe.independent_evidence import source_snapshot, utc_now, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--module-rank", type=int, choices=range(3,17), default=6)
    args = parser.parse_args()
    if args.output.exists() or args.trials < 1:
        parser.error("new output directory and positive trial count required")
    args.output.mkdir(parents=True)
    root = Path(__file__).resolve().parents[1]
    write_json(args.output / "source-snapshot.json", source_snapshot(root))
    journal = []
    with tempfile.TemporaryDirectory(prefix="daahe-protocol-private-") as scratch:
        for i in range(args.trials):
            profile = ("pi0", "pi1", "pi2")[i % 3]
            trial = Path(scratch) / f"trial-{i:03}"
            console = io.StringIO()
            started = time.perf_counter()
            with contextlib.redirect_stdout(console):
                demo(SimpleNamespace(output=trial, profile=profile, participants=3,
                                     block_bytes=64, module_rank=args.module_rank))
            report = json.loads((trial / "report.json").read_text())
            record = {"trial": i, "profile": profile, "status": "passed",
                      "host_wall_time_s": time.perf_counter() - started,
                      "honest_aggregate_accepted": report["honest_aggregate_accepted"],
                      "compromised_gateway_modification_rejected": report["compromised_gateway_modification_rejected"],
                      "replay_rejected": report["replay_rejected"],
                      "integrity_verified": report["integrity_verified"],
                      "ticket_signature_bytes": report["ticket_signature_bytes"]}
            write_json(args.output / f"trial-{i:03}.json", report)
            journal.append(record)
            print(json.dumps(record, sort_keys=True), flush=True)
    summary = {"schema_version": 1, "origin": "independent_reimplementation",
               "module_rank": args.module_rank,
               "paper_reproduced": False, "status": "passed", "trials": journal,
               "completed_utc": utc_now(), "platform": platform.platform(),
               "provider": "liboqs 0.16.0 / liboqs-python 0.16.0.1 / ML-DSA-44",
               "private_material_exported": False, "board_measured": False,
               "scope": "fresh-key synthetic protocol correctness, compromised-gateway modification and durable replay rejection; no security-strength or rare-failure estimate"}
    write_json(args.output / "summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
