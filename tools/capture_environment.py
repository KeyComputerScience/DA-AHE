#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Record installed versions and Git state; never dump environment secrets."""
import argparse
import datetime
import importlib.metadata
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def command(args):
    if not shutil.which(args[0]):
        return {"available": False}
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
        return {"returncode": r.returncode, "stdout": r.stdout[:20000],
                "stderr": r.stderr[:2000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": type(exc).__name__}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    data = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "python": sys.version, "platform": platform.platform(),
            "packages": {d.metadata["Name"]: d.version for d in importlib.metadata.distributions()},
            "git_revision": command(["git", "rev-parse", "HEAD"]),
            "git_status": command(["git", "status", "--porcelain"]),
            "compiler": command(["cc", "--version"]),
            "sage": command(["sage", "--version"])}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2, sort_keys=True)+"\n")


if __name__ == "__main__":
    main()

