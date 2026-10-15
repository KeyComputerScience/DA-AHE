#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate captured core-benchmark logs and their build/artifact binding.

This checks structure and known answers, not hardware authenticity or full
protocol/energy claims. Physical-board identity remains an operator assertion.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

BASE_OPERATIONS = (
    "empty_harness",
    "ring_mul_d256",
    "pack_l240",
    "linear_tag_l240_fixture_provider",
    "decode_d256",
)
UNSUPPORTED = {
    "mlwe_keygen_encrypt_decrypt",
    "mldsa44",
    "hmac_sha3",
    "shake_kdf",
    "intdb2",
    "network_radio",
    "energy",
    "full_protocol",
    "contiki_ng",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _integer(record: dict, name: str, low: int, high: int) -> int:
    value = record.get(name)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low}, {high}]")
    return value


def validated_parameters(metadata: dict) -> dict:
    if metadata.get("schema_version") != 2:
        raise ValueError(
            "rank-bound schema-version-2 build metadata required; legacy logs are not upgraded"
        )
    parameters = metadata.get("parameters")
    if not isinstance(parameters, dict):
        raise ValueError("compiled parameters missing from build metadata")
    rank = _integer(parameters, "module_rank", 3, 16)
    expected = {
        "module_rank": rank,
        "ring_degree": 256,
        "plaintext_modulus": 65537,
        "ciphertext_modulus": 2**32,
        "ciphertext_bytes": (rank + 1) * 256 * 4,
        "ciphertexts_per_stream": 1,
        "stream_roster_size": 16,
        "stream_block_bytes": 64,
    }
    if (
        parameters != expected
        or any(type(value) is not int for value in parameters.values())
        or metadata.get("identity", {}).get("parameters") != expected
    ):
        raise ValueError("compiled parameter tuple/rank/ciphertext size mismatch")
    if metadata.get("operations") != list(expected_operations(expected)):
        raise ValueError("build operation names do not bind the compiled ciphertext size")
    return expected


def expected_operations(parameters: dict) -> tuple[str, ...]:
    return BASE_OPERATIONS + (f"stream_16x{parameters['ciphertext_bytes']}_b64_fixture_callback",)


def validate_records(records: list[dict], metadata: dict) -> dict:
    parameters = validated_parameters(metadata)
    operations = expected_operations(parameters)
    if len(records) < 4 or any(
        not isinstance(r, dict) or r.get("schema_version") != 2 for r in records
    ):
        raise ValueError("complete rank-bound schema-version-2 JSON records required")
    boot, capabilities, complete = records[0], records[1], records[-1]
    if (
        boot.get("record") != "boot"
        or capabilities.get("record") != "capabilities"
        or complete.get("record") != "complete"
    ):
        raise ValueError("one boot, capabilities, samples, complete in that order required")
    build_id = metadata["build_id"]
    if boot.get("firmware_id") != build_id or boot.get("target") != "nrf52840":
        raise ValueError("boot firmware/target does not match the build")
    if boot.get("scope") != "embedded_core_microbenchmarks" or boot.get("clock_hz") != 64000000:
        raise ValueError("unexpected scope or nominal clock")
    if boot.get("parameters") != parameters or capabilities.get("parameters") != parameters:
        raise ValueError("UART parameters differ from the compiled rank/ciphertext size")
    repeats = _integer(boot, "repeats", 1, 1000)
    if repeats != metadata["repeats"]:
        raise ValueError("repeat count differs from compiled configuration")
    capacity = _integer(boot, "stack_capacity_bytes", 8192, 8192)
    if (
        capabilities.get("supported") != list(operations)
        or set(capabilities.get("unsupported", [])) != UNSUPPORTED
    ):
        raise ValueError("capabilities differ from the supported benchmark scope")
    samples = records[2:-1]
    if len(samples) != len(operations) * repeats:
        raise ValueError("missing or extra samples")
    counts = Counter()
    for seq, sample in enumerate(samples):
        operation = operations[seq // repeats]
        if sample.get("record") != "sample" or sample.get("firmware_id") != build_id:
            raise ValueError("unexpected record or firmware identity")
        if (
            _integer(sample, "seq", 0, 5999) != seq
            or sample.get("operation") != operation
            or _integer(sample, "repeat", 0, repeats - 1) != seq % repeats
        ):
            raise ValueError("sample order, sequence, operation or repetition mismatch")
        cycles = _integer(sample, "cycles", 1, (1 << 32) - 1)
        elapsed = _integer(sample, "elapsed_us", 0, 59999999)
        _integer(sample, "stack_hwm_bytes", 1, capacity - 32)
        for flag in ("stack_guard_ok", "result_ok", "irq_disabled"):
            if sample.get(flag) is not True:
                raise ValueError(f"failed or missing {flag}")
        # TIMER interval includes both captures and encloses the DWT interval.
        # Allow 2 us register-read granularity; reject wrap/inconsistent counters.
        if cycles > (elapsed + 2) * 64 or cycles < max(0, elapsed - 20) * 64:
            raise ValueError("cycle/TIMER mismatch or potential DWT wrap")
        counts[operation] += 1
    if (
        _integer(complete, "samples", 1, 6000) != len(samples)
        or _integer(complete, "failures", 0, 6000) != 0
    ):
        raise ValueError("incomplete or failed firmware run")
    summary = []
    for operation in operations:
        group = [r for r in samples if r["operation"] == operation]
        cycles = sorted(r["cycles"] for r in group)
        n = len(cycles)
        median = (cycles[(n - 1) // 2] + cycles[n // 2]) / 2
        summary.append(
            {
                "operation": operation,
                "samples": counts[operation],
                "cycles_min": cycles[0],
                "cycles_median": median,
                "cycles_max": cycles[-1],
                "stack_hwm_max_bytes": max(r["stack_hwm_bytes"] for r in group),
            }
        )
    return {
        "schema_version": 2,
        "status": "structurally_valid_operator_asserted_board_capture",
        "build_id": build_id,
        "scope": "embedded_core_microbenchmarks",
        "parameters": parameters,
        "summary": summary,
        "hardware_authenticity_attested": False,
        "full_protocol_measured": False,
        "energy_measured": False,
        "stack_scope": "dedicated PSP wrapper+kernel+post-timing known-answer checks",
        "cycle_scope": "wrapper dispatch+kernel, including DWT barriers; UART/setup/checks excluded",
        "overhead_subtracted": False,
    }


def verify_capture(capture_dir: Path, build_dir: Path) -> dict:
    capture = json.loads((capture_dir / "capture.json").read_text(encoding="utf-8"))
    metadata_path = build_dir / "build-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    parameters = validated_parameters(metadata)
    if (
        capture.get("schema_version") != 2
        or capture.get("acquisition") != "operator_asserted_physical_board_serial"
    ):
        raise ValueError(
            "a serial acquisition manifest is required, not imported or synthetic data"
        )
    if not isinstance(capture.get("board_id"), str) or not capture["board_id"].strip():
        raise ValueError("operator board identity missing")
    if capture.get("build_metadata_sha256") != sha256(metadata_path):
        raise ValueError("build metadata hash mismatch")
    if capture.get("firmware_id") != metadata.get("build_id"):
        raise ValueError("capture and build identity mismatch")
    if capture.get("parameters") != parameters:
        raise ValueError("capture parameter tuple differs from the selected build")
    for filename, key in (
        ("benchmark.elf", "elf_sha256"),
        ("benchmark.map", "map_sha256"),
        ("build.log", "build_log_sha256"),
    ):
        if sha256(build_dir / filename) != metadata.get(key):
            raise ValueError(f"{filename} hash mismatch")
    header = (build_dir / "benchmark.elf").read_bytes()[:52]
    if (
        len(header) != 52
        or header[:7] != b"\x7fELF\x01\x01\x01"
        or struct.unpack_from("<HH", header, 16) != (2, 40)
    ):
        raise ValueError("build artifact is not a little-endian ARM ELF32 executable")
    raw_path = capture_dir / "measurements.ndjson"
    if sha256(raw_path) != capture.get("raw_sha256"):
        raise ValueError("serial bytes hash mismatch")
    records = [json.loads(line) for line in raw_path.read_text(encoding="utf-8").splitlines()]
    return validate_records(records, metadata)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_dir", type=Path)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="New file; never overwrite a prior report")
    args = parser.parse_args()
    try:
        report = verify_capture(args.capture_dir, args.build_dir)
        rendered = json.dumps(report, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
        print(rendered, end="")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
