#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build an independent bare-metal core benchmark, preserving actual evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATHS = (
    "embedded/daahe_core.c",
    "embedded/daahe_core.h",
    "embedded/test_core.c",
    "firmware/nrf52840/benchmark.c",
    "firmware/nrf52840/startup.S",
    "firmware/nrf52840/runtime.c",
    "firmware/nrf52840/linker.ld",
    "firmware/build.py",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output: Path, compiler: str, native_cc: str, repeats: int, module_rank: int = 3) -> dict:
    if not 1 <= repeats <= 1000:
        raise ValueError("repeats must be between 1 and 1000")
    if type(module_rank) is not int or not 3 <= module_rank <= 16:
        raise ValueError("module rank must be an integer between 3 and 16")
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
    operations = [
        "empty_harness",
        "ring_mul_d256",
        "pack_l240",
        "linear_tag_l240_fixture_provider",
        "decode_d256",
        f"stream_16x{parameters['ciphertext_bytes']}_b64_fixture_callback",
    ]
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    with (output / "build.log").open("w", encoding="utf-8") as log:

        def run(args: list[str]) -> str:
            commands.append(args)
            log.write("$ " + repr(args) + "\n")
            log.flush()
            result = subprocess.run(
                args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            log.write(result.stdout)
            log.flush()
            if result.returncode:
                raise RuntimeError(
                    f"command failed with exit {result.returncode}; see {output / 'build.log'}"
                )
            return result.stdout

        version = run([compiler, "--version"])
        libgcc = Path(
            run(
                [
                    compiler,
                    "-mcpu=cortex-m4",
                    "-mthumb",
                    "-mfloat-abi=soft",
                    "-print-libgcc-file-name",
                ]
            ).strip()
        )
        libgcc_hash = sha256(libgcc)
        sources = [{"path": p, "sha256": sha256(ROOT / p)} for p in SOURCE_PATHS]
        identity = {
            "sources": sources,
            "compiler_version": version,
            "repeats": repeats,
            "parameters": parameters,
            "operations": operations,
            "libgcc_sha256": libgcc_hash,
            "target": "arm-none-eabi/cortex-m4/thumb/soft-float",
            "optimization": "-O2",
            "scope": "embedded_core_microbenchmarks",
        }
        build_id = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        native = output / "native_core_test"
        run(
            [
                native_cc,
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-Iembedded",
                f"-DDAAHE_K={module_rank}",
                "embedded/daahe_core.c",
                "embedded/test_core.c",
                "-o",
                str(native),
            ]
        )
        native_stdout = run([str(native)])
        common = [
            compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=soft",
            "-O2",
            "-g3",
            "-ffreestanding",
            "-fno-builtin",
            "-ffunction-sections",
            "-fdata-sections",
            "-fstack-usage",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Iembedded",
            f'-DFIRMWARE_BUILD_ID="{build_id}"',
            f"-DBENCH_REPEATS={repeats}",
            f"-DDAAHE_K={module_rank}",
            f"-DBENCH_CIPHER_BYTES={parameters['ciphertext_bytes']}",
        ]
        objects = []
        for p in (
            "firmware/nrf52840/startup.S",
            "firmware/nrf52840/runtime.c",
            "firmware/nrf52840/benchmark.c",
            "embedded/daahe_core.c",
        ):
            obj = output / (Path(p).stem + ".o")
            flags = [] if p.endswith(".S") else ["-std=c11", "-pedantic"]
            run(common + flags + ["-c", p, "-o", str(obj)])
            objects.append(str(obj))
        elf, map_file = output / "benchmark.elf", output / "benchmark.map"
        run(
            [
                compiler,
                "-mcpu=cortex-m4",
                "-mthumb",
                "-mfloat-abi=soft",
                "-nostdlib",
                "-Wl,--gc-sections",
                "-Wl,--build-id=none",
                f"-Wl,-Map={map_file}",
                "-Tfirmware/nrf52840/linker.ld",
                *objects,
                "-lgcc",
                "-o",
                str(elf),
            ]
        )
        prefix = str(Path(compiler).with_name(Path(compiler).name.removesuffix("gcc")))
        # Compiler must be an explicit arm-none-eabi-gcc path; no host objcopy fallback.
        size_stdout = run([prefix + "size", "-A", str(elf)])
        run([prefix + "objcopy", "-O", "ihex", str(elf), str(output / "benchmark.hex")])
        run([prefix + "objcopy", "-O", "binary", str(elf), str(output / "benchmark.bin")])
        readelf_stdout = run([prefix + "readelf", "-h", str(elf)])
        if "Machine:" not in readelf_stdout or "ARM" not in readelf_stdout:
            raise RuntimeError("output is not an ARM ELF")
        (output / "size.txt").write_text(size_stdout, encoding="utf-8")
        (output / "readelf.txt").write_text(readelf_stdout, encoding="utf-8")
        sections = {
            name: int(size)
            for name, size in re.findall(r"^(\.\S+)\s+(\d+)\s+\d+\s*$", size_stdout, re.M)
        }
        artifacts = [
            {"path": p.name, "sha256": sha256(p), "size": p.stat().st_size}
            for p in sorted(output.iterdir())
            if p.is_file() and p.name != "build.log"
        ]
        metadata = {
            "schema_version": 2,
            "status": "cross_compiled_native_core_test_passed_not_board_measured",
            "build_id": build_id,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "target": "nrf52840",
            "clock_hz": 64000000,
            "repeats": repeats,
            "parameters": parameters,
            "operations": operations,
            "identity": identity,
            "compiler_sha256": sha256(Path(compiler)),
            "libgcc_sha256": libgcc_hash,
            "native_test_stdout": native_stdout,
            "commands": commands,
            "scope": "independent_standalone_embedded_core_microbenchmarks",
            "paper_original_firmware": False,
            "contiki_ng": False,
            "hardware_execution": False,
            "energy_measurement": False,
            "elf_sha256": sha256(elf),
            "map_sha256": sha256(map_file),
            "artifacts": artifacts,
            "compiled_memory_bytes": {
                "flash_load_sections": sum(
                    sections.get(name, 0) for name in (".vectors", ".text", ".ARM.exidx", ".data")
                ),
                "static_ram_data_bss": sections.get(".data", 0) + sections.get(".bss", 0),
                "benchmark_psp_included_in_bss": 8192,
                "main_msp_reserved_separately": 4096,
                "scope": "compiled independent harness only; not measured stack or paper firmware",
            },
            "unsupported": [
                "ML-DSA-44",
                "HMAC-SHA3",
                "SHAKE/KDF",
                "M-LWE encryption",
                "IntDb2",
                "radio/network",
                "energy",
                "full DA-AHE protocol",
            ],
        }
    metadata["build_log_sha256"] = sha256(output / "build.log")
    (output / "build-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    (output / "board-pending.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "status": "pending_physical_board_capture",
                "build_id": build_id,
                "parameters": parameters,
                "samples_collected": 0,
                "cycles_measured": False,
                "stack_hwm_measured": False,
                "energy_measured": False,
                "reason": "No physical nRF52840 connected during this build.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="New directory; existing evidence is never overwritten",
    )
    parser.add_argument("--cc", default=os.environ.get("ARM_GCC", "arm-none-eabi-gcc"))
    parser.add_argument("--native-cc", default="clang")
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument(
        "--module-rank",
        type=int,
        choices=range(3, 17),
        default=3,
        help="Explicit module rank; 3 is a legacy default, not a security calibration",
    )
    args = parser.parse_args()
    compiler = shutil.which(args.cc)
    native = shutil.which(args.native_cc)
    if not compiler or not native:
        parser.error("ARM GCC and native C compiler must exist; see firmware/README.md")
    try:
        metadata = build(
            args.output.resolve(),
            str(Path(compiler).resolve()),
            native,
            args.repeats,
            args.module_rank,
        )
    except (ValueError, OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "build_id": metadata["build_id"],
                "status": metadata["status"],
                "output": str(args.output.resolve()),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
