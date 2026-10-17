#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a frozen declared controller; preserve failed numerical certificates.

No fitting, parameter repair, domain expansion or external-certificate promotion
occurs. A failed/unchecked certificate is written and exits 2. Use --verify-report
    to independently recompute an existing report without changing any evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from daahe.controller_certificate import (  # noqa: E402
    verify_controller_config, verify_saved_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", type=Path, required=True)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--output", type=Path)
    output.add_argument("--verify-report", type=Path)
    args = parser.parse_args()
    try:
        config = json.loads(args.controller.read_text(encoding="utf-8"))
        if args.verify_report:
            saved = json.loads(args.verify_report.read_text(encoding="utf-8"))
            result = verify_saved_report(config, saved)
            # Audit success and the scientific certificate outcome are separate:
            # faithfully preserved failure evidence is a successful recomputation.
            successful = result["matches_recomputation"]
        else:
            result = verify_controller_config(config)
            successful = result["status"] == "verified_declared_model"
        encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(encoded)
            print(json.dumps({"status": result["status"], "scope": result["scope"],
                              "output": str(args.output),
                              "full_system_certified": False}, sort_keys=True))
        else:
            print(encoded, end="")
        return 0 if successful else 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "input_error", "error": str(error),
                          "scope": "declared_model_only", "full_system_certified": False}),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
