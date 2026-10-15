#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture actual POSIX serial bytes after opening a nRF52840 DK virtual COM.

Open the collector BEFORE manually resetting the target. No file replay/import
mode exists. A serial stream is not cryptographic hardware attestation.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import select
import sys
import termios
import time
import tty

from verify_board_measurements import validated_parameters, verify_capture


def collect(port: str, output: Path, build_dir: Path, board_id: str, timeout: float) -> dict:
    if not board_id.strip() or not 1 <= timeout <= 3600:
        raise ValueError("nonempty board ID and timeout in [1,3600] seconds required")
    metadata_path = build_dir / "build-metadata.json"
    metadata_bytes = metadata_path.read_bytes()
    metadata = json.loads(metadata_bytes)
    parameters = validated_parameters(metadata)
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    fd = os.open(port, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    previous = termios.tcgetattr(fd)
    raw = bytearray()
    complete = False
    try:
        if not os.isatty(fd):
            raise ValueError("port must be a POSIX TTY")
        tty.setraw(fd)
        attrs = termios.tcgetattr(fd)
        attrs[2] |= termios.CLOCAL | termios.CREAD
        attrs[2] &= ~(termios.PARENB | termios.CSTOPB | termios.CSIZE)
        attrs[2] &= ~getattr(termios, "CRTSCTS", 0)
        attrs[2] |= termios.CS8
        attrs[4] = termios.B115200
        attrs[5] = termios.B115200
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        termios.tcflush(fd, termios.TCIFLUSH)
        print("Serial port open at 115200 8N1. Reset the physical board now.", file=sys.stderr)
        deadline = time.monotonic() + timeout
        parsed_lines = 0
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], min(1.0, max(0, deadline - time.monotonic())))
            if not ready:
                continue
            chunk = os.read(fd, 4096)
            if not chunk:
                continue
            raw.extend(chunk)
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError("serial capture exceeds 8 MiB limit")
            lines = raw.split(b"\n")
            for line in lines[parsed_lines:-1]:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("serial line must be a JSON object")
                if record.get("record") == "complete":
                    complete = True
            parsed_lines = len(lines) - 1
            if complete:
                break
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSANOW, previous)
        finally:
            os.close(fd)
        (output / "measurements.ndjson").write_bytes(raw)
        capture = {
            "schema_version": 2,
            "acquisition": "operator_asserted_physical_board_serial",
            "board_id": board_id,
            "port": port,
            "baud": 115200,
            "started_at_utc": started,
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
            "complete_seen": complete,
            "firmware_id": metadata["build_id"],
            "parameters": parameters,
            "build_metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "note": "Operator supplies board identity; bytes are not hardware-attested. Failed/incomplete captures retained.",
        }
        (output / "capture.json").write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
    if not complete:
        raise ValueError("timed out before complete record; incomplete evidence retained")
    report = verify_capture(output, build_dir)
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument(
        "--board-id", required=True, help="Physical board serial/asset ID, operator asserted"
    )
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New capture directory")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    try:
        report = collect(args.port, args.output, args.build_dir, args.board_id, args.timeout)
    except (OSError, ValueError, KeyError, TypeError, termios.error) as exc:
        print(f"capture failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "build_id": report["build_id"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
