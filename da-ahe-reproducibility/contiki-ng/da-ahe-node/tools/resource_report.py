#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys


def main():
    elf = Path(sys.argv[1]).resolve()
    output = subprocess.check_output(["arm-none-eabi-size", "-A", str(elf)], text=True)
    summary = subprocess.check_output(["arm-none-eabi-size", str(elf)], text=True)
    sections = {}
    for line in output.splitlines():
        match = re.match(r"^([.A-Za-z0-9_\-]+)\s+(\d+)\s+", line.strip())
        if match:
            sections[match.group(1)] = int(match.group(2))
    fields = summary.splitlines()[1].split()
    text_bytes, data, bss = map(int, fields[:3])
    flash = text_bytes + data
    report = {
        "elf": elf.name,
        "flash_bytes": flash,
        "static_sram_bytes": data + bss,
        "data_bytes": data,
        "bss_bytes": bss,
        "linked_heap_reservation_bytes": sections.get(".heap", 0),
        "linked_stack_reservation_bytes": sections.get(".stack_dummy", 0),
        "sections": sections,
        "method": "GNU size convention: flash=text+data; static SRAM=data+bss; runtime peak requires the board stack-watermark log",
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
