#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build or verify a separate manifest for new independent experimental evidence."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from daahe.independent_evidence import bundle_manifest, verify_bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "verify"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    manifest = args.manifest or args.root / "manifest.json"
    result = (bundle_manifest(args.root, manifest) if args.mode == "build"
              else verify_bundle(args.root, manifest))
    if args.mode == "build":
        result = {"status": "created", "files": len(result["files"]), "manifest": str(manifest)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"created", "verified"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
