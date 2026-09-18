#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

pattern = re.compile(
    r"DA_AHE_STACK_HWM role=(\w+) static=(\d+) stack=(\d+) peak=(\d+) ok=(\d+)"
)


def main():
    path = Path(sys.argv[1])
    records = []
    for line in path.read_text(errors="replace").splitlines():
        match = pattern.search(line)
        if match:
            role, static, stack, peak, ok = match.groups()
            records.append(
                {"role": role, "static_bytes": int(static),
                 "stack_hwm_bytes": int(stack), "peak_bytes": int(peak),
                 "selftest_ok": bool(int(ok))}
            )
    if not records:
        raise SystemExit("no valid stack-watermark records")
    maximum = max(records, key=lambda record: record["peak_bytes"])
    print(json.dumps({"records": records, "maximum": maximum}, indent=2))


if __name__ == "__main__":
    main()
