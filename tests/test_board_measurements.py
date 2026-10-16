# SPDX-License-Identifier: MIT
"""Host-only analytic fixtures. These tests never create board measurements."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import threading
import time

import pytest

try:
    import pty
except ImportError:
    pty = None


def require_posix_pty():
    if os.name != "posix" or pty is None:
        pytest.fail("POSIX pseudo-terminal support is required for the serial collector test; run on Linux/POSIX CI")


def native_compiler():
    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        pytest.fail("a native C compiler is required; install clang or gcc before running this suite")
    return compiler


def verifier():
    path = Path(__file__).resolve().parents[1] / "tools" / "verify_board_measurements.py"
    spec = importlib.util.spec_from_file_location("board_verifier", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def analytic_records(module_rank=3):
    tool = verifier()
    parameters = {
        "module_rank": module_rank,
        "ring_degree": 256,
        "plaintext_modulus": 65537,
        "ciphertext_modulus": 2**32,
        "ciphertext_bytes": (module_rank + 1) * 256 * 4,
        "ciphertexts_per_stream": 1,
        "stream_roster_size": 16,
        "stream_block_bytes": 64,
    }
    operations = tool.expected_operations(parameters)
    metadata = {
        "schema_version": 2,
        "build_id": f"{module_rank:064x}",
        "repeats": 2,
        "parameters": copy.deepcopy(parameters),
        "identity": {"parameters": copy.deepcopy(parameters)},
        "operations": list(operations),
    }
    records = [
        {
            "schema_version": 2,
            "record": "boot",
            "firmware_id": metadata["build_id"],
            "target": "nrf52840",
            "clock_hz": 64000000,
            "repeats": 2,
            "scope": "embedded_core_microbenchmarks",
            "stack_capacity_bytes": 8192,
            "parameters": copy.deepcopy(parameters),
        },
        {
            "schema_version": 2,
            "record": "capabilities",
            "supported": list(operations),
            "unsupported": sorted(tool.UNSUPPORTED),
            "parameters": copy.deepcopy(parameters),
        },
    ]
    for seq in range(12):
        records.append(
            {
                "schema_version": 2,
                "record": "sample",
                "firmware_id": metadata["build_id"],
                "seq": seq,
                "operation": operations[seq // 2],
                "repeat": seq % 2,
                "cycles": 640,
                "elapsed_us": 11,
                "stack_hwm_bytes": 128,
                "stack_guard_ok": True,
                "result_ok": True,
                "irq_disabled": True,
            }
        )
    records.append({"schema_version": 2, "record": "complete", "samples": 12, "failures": 0})
    return records, metadata


def test_host_fixture_scope_and_overhead_are_never_upgraded_to_full_protocol():
    records, metadata = analytic_records()
    result = verifier().validate_records(records, metadata)
    assert result["full_protocol_measured"] is False
    assert result["energy_measured"] is False
    assert result["hardware_authenticity_attested"] is False
    assert result["overhead_subtracted"] is False
    assert len(result["summary"]) == 6
    assert result["summary"][0]["cycles_median"] == 640


@pytest.mark.parametrize(
    "field,value",
    [
        ("firmware_id", "b" * 64),
        ("result_ok", False),
        ("irq_disabled", False),
        ("stack_guard_ok", False),
        ("stack_hwm_bytes", 8192),
        ("cycles", 0),
        ("cycles", 2**32),
        ("elapsed_us", 60000000),
        ("cycles", 1000000),
        ("seq", True),
        ("operation", "mldsa44"),
        ("repeat", 1),
    ],
)
def test_bad_known_answer_identity_boundary_or_sequence_rejected(field, value):
    records, metadata = analytic_records()
    records[2][field] = value
    with pytest.raises(ValueError):
        verifier().validate_records(records, metadata)


def test_incomplete_and_duplicate_sample_runs_rejected():
    records, metadata = analytic_records()
    with pytest.raises(ValueError, match="missing or extra"):
        verifier().validate_records(records[:4] + records[5:], metadata)
    with pytest.raises(ValueError, match="sequence"):
        duplicate = copy.deepcopy(records)
        duplicate[3] = copy.deepcopy(duplicate[2])
        verifier().validate_records(duplicate, metadata)


def test_boot_complete_and_capability_scope_required():
    records, metadata = analytic_records()
    for modified in (records[1:], records[:-1], [records[0], records[0], *records[2:]]):
        with pytest.raises(ValueError):
            verifier().validate_records(modified, metadata)
    records[1]["unsupported"].remove("energy")
    with pytest.raises(ValueError, match="capabilities"):
        verifier().validate_records(records, metadata)


def fixture_capture(tmp_path):
    """Only a temporary parser fixture; never retained in evidence/ as board data."""
    tool = verifier()
    records, metadata = analytic_records()
    build, capture = tmp_path / "build", tmp_path / "capture"
    build.mkdir()
    capture.mkdir()
    for name, key in (
        ("benchmark.elf", "elf_sha256"),
        ("benchmark.map", "map_sha256"),
        ("build.log", "build_log_sha256"),
    ):
        if name == "benchmark.elf":
            header = bytearray(52)
            header[:7] = b"\x7fELF\x01\x01\x01"
            struct.pack_into("<HH", header, 16, 2, 40)
            (build / name).write_bytes(
                header
            )  # Minimal header parser fixture, not executable code.
        else:
            (build / name).write_bytes(b"HOST-ONLY-PARSER-FIXTURE")
        metadata[key] = tool.sha256(build / name)
    (build / "build-metadata.json").write_text(json.dumps(metadata))
    (capture / "measurements.ndjson").write_text("".join(json.dumps(r) + "\n" for r in records))
    manifest = {
        "schema_version": 2,
        "acquisition": "operator_asserted_physical_board_serial",
        "board_id": "HOST-ONLY-TEST-FIXTURE",
        "firmware_id": metadata["build_id"],
        "parameters": metadata["parameters"],
        "build_metadata_sha256": tool.sha256(build / "build-metadata.json"),
        "raw_sha256": tool.sha256(capture / "measurements.ndjson"),
    }
    (capture / "capture.json").write_text(json.dumps(manifest))
    return build, capture


@pytest.mark.parametrize(
    "filename", ["benchmark.elf", "benchmark.map", "build.log", "build-metadata.json"]
)
def test_capture_rejects_any_changed_build_artifact(tmp_path, filename):
    build, capture = fixture_capture(tmp_path)
    with (build / filename).open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError):
        verifier().verify_capture(capture, build)


def test_capture_rejects_changed_serial_bytes_and_file_import(tmp_path):
    build, capture = fixture_capture(tmp_path)
    manifest = json.loads((capture / "capture.json").read_text())
    manifest["acquisition"] = "file_import"
    (capture / "capture.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="serial acquisition"):
        verifier().verify_capture(capture, build)
    manifest["acquisition"] = "operator_asserted_physical_board_serial"
    (capture / "capture.json").write_text(json.dumps(manifest))
    with (capture / "measurements.ndjson").open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ValueError, match="serial bytes hash"):
        verifier().verify_capture(capture, build)


def test_capture_rejects_non_arm_elf_even_with_matching_manifest(tmp_path):
    build, capture = fixture_capture(tmp_path)
    tool = verifier()
    (build / "benchmark.elf").write_bytes(b"not an ARM binary")
    metadata = json.loads((build / "build-metadata.json").read_text())
    metadata["elf_sha256"] = tool.sha256(build / "benchmark.elf")
    (build / "build-metadata.json").write_text(json.dumps(metadata))
    manifest = json.loads((capture / "capture.json").read_text())
    manifest["build_metadata_sha256"] = tool.sha256(build / "build-metadata.json")
    (capture / "capture.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="ARM ELF32"):
        tool.verify_capture(capture, build)


def test_serial_timeout_retains_literal_incomplete_host_fixture(tmp_path, monkeypatch):
    require_posix_pty()
    build, _ = fixture_capture(tmp_path)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "tools"))
    import collect_board_measurements as collector

    master, slave = pty.openpty()
    payload = b'{"schema_version":2,"record":"boot","test_only":true}\n'

    def send_fixture():
        time.sleep(0.15)
        os.write(master, payload)

    sender = threading.Thread(target=send_fixture)
    sender.start()
    output = tmp_path / "incomplete-host-only-fixture"
    try:
        with pytest.raises(ValueError, match="timed out"):
            collector.collect(os.ttyname(slave), output, build, "HOST-ONLY-PTY-TEST", 1)
        assert (output / "measurements.ndjson").read_bytes() == payload
        manifest = json.loads((output / "capture.json").read_text())
        assert manifest["complete_seen"] is False
        assert not (output / "verification.json").exists()
    finally:
        sender.join(timeout=2)
        os.close(master)
        os.close(slave)


@pytest.mark.parametrize("rank", [3, 6, 7, 9, 16])
def test_rank_bound_log_checks_derived_ciphertext_size_and_operation(rank):
    records, metadata = analytic_records(rank)
    result = verifier().validate_records(records, metadata)
    assert result["parameters"]["module_rank"] == rank
    assert result["parameters"]["ciphertext_bytes"] == (rank + 1) * 1024
    assert (
        result["summary"][-1]["operation"] == f"stream_16x{(rank + 1) * 1024}_b64_fixture_callback"
    )


def test_legacy_4096_uart_log_is_not_accepted_as_new_8192_even_with_relabelled_build_id():
    old_records, _ = analytic_records(3)
    _, new_metadata = analytic_records(7)
    for record in old_records:
        if "firmware_id" in record:
            record["firmware_id"] = new_metadata["build_id"]
    with pytest.raises(ValueError, match="UART parameters"):
        verifier().validate_records(old_records, new_metadata)


@pytest.mark.parametrize("index", [0, 1])
def test_boot_and_capabilities_both_bind_rank_and_payload(index):
    records, metadata = analytic_records(7)
    records[index]["parameters"]["ciphertext_bytes"] = 4096
    with pytest.raises(ValueError, match="UART parameters"):
        verifier().validate_records(records, metadata)


def test_new_schema_rejects_legacy_schema_and_misderived_metadata():
    records, metadata = analytic_records(7)
    legacy = copy.deepcopy(records)
    for record in legacy:
        record["schema_version"] = 1
    with pytest.raises(ValueError, match="schema-version-2"):
        verifier().validate_records(legacy, metadata)
    metadata["parameters"]["ciphertext_bytes"] = 4096
    metadata["identity"]["parameters"]["ciphertext_bytes"] = 4096
    with pytest.raises(ValueError, match="tuple/rank/ciphertext"):
        verifier().validate_records(records, metadata)


@pytest.mark.parametrize("rank", [3, 6, 7, 16])
def test_native_core_really_accepts_one_and_two_derived_ciphertexts(tmp_path, rank):
    compiler = native_compiler()
    root = Path(__file__).resolve().parents[1]
    binary = tmp_path / f"core-rank-{rank}"
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-DDAAHE_K={rank}",
            "-Iembedded",
            "embedded/daahe_core.c",
            "embedded/test_core.c",
            "-o",
            str(binary),
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    assert f"rank={rank} ciphertext_bytes={(rank + 1) * 1024}" in result.stdout


@pytest.mark.parametrize("rank", [2, 17])
def test_native_core_rejects_invalid_module_rank_at_compile_time(tmp_path, rank):
    compiler = native_compiler()
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            compiler,
            "-std=c11",
            f"-DDAAHE_K={rank}",
            "-Iembedded",
            "-c",
            "embedded/daahe_core.c",
            "-o",
            str(tmp_path / "bad.o"),
        ],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "DAAHE_K must be between 3 and 16" in result.stderr
