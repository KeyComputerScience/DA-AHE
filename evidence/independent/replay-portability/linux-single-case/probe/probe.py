"""Diagnostic only: exact cross-platform replay comparison, without tolerances."""
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parent


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def differences(a, b, path="$"):
    if type(a) is not type(b):
        yield {"path": path, "reason": "type", "expected": repr(a), "actual": repr(b)}
    elif isinstance(a, dict):
        if set(a) != set(b):
            yield {"path": path, "reason": "keys", "expected": sorted(a), "actual": sorted(b)}
        for key in sorted(set(a) & set(b)):
            yield from differences(a[key], b[key], path + "." + key)
    elif isinstance(a, list):
        if len(a) != len(b):
            yield {"path": path, "reason": "length", "expected": len(a), "actual": len(b)}
        for index, (left, right) in enumerate(zip(a, b)):
            yield from differences(left, right, path + "[" + str(index) + "]")
    elif a != b:
        item = {"path": path, "reason": "value", "expected": repr(a), "actual": repr(b)}
        if type(a) is float and math.isfinite(a) and math.isfinite(b):
            item["absolute_difference"] = abs(a - b)
            item["expected_ulp"] = math.ulp(a)
            item["difference_in_expected_ulps"] = abs(a - b) / math.ulp(a)
            item["expected_ieee754"] = struct.pack(">d", a).hex()
            item["actual_ieee754"] = struct.pack(">d", b).hex()
        yield item


identity = json.loads((ROOT / "identity.json").read_text())
source = ROOT / "source"
for name, expected in identity["source_hashes"].items():
    if sha(source / name) != expected:
        raise ValueError("source identity mismatch: " + name)
out = ROOT / "replayed"
out.mkdir(exist_ok=False)
env = os.environ.copy()
env["PYTHONPATH"] = str(source / "src") + os.pathsep + str(source)
env["PYTHONDONTWRITEBYTECODE"] = "1"
child = '''
import json,pathlib,sys
from simulation.engine import run_one
r=pathlib.Path(sys.argv[1])
run_one(json.loads((r/'config.json').read_text()),1004,'da-ahe',r/'exogenous/seed-1004',r/'replayed',r/'controller.json')
'''
subprocess.run([sys.executable, "-c", child, str(ROOT)], cwd=source, env=env, check=True)
reference = ROOT / "reference-epochs.jsonl.gz"
actual = out / "epochs.jsonl.gz"
expected_bytes = gzip.decompress(reference.read_bytes())
actual_bytes = gzip.decompress(actual.read_bytes())
expected_rows = [json.loads(line) for line in expected_bytes.splitlines()]
actual_rows = [json.loads(line) for line in actual_bytes.splitlines()]
diffs = list(differences(expected_rows, actual_rows))
report = {
    "diagnostic_only": True,
    "origin": "independent_reimplementation", "paper_reproduced": False,
    "seed": 1004, "method": "da-ahe", "source_digest": identity["source_digest"],
    "frozen_source_files_verified": len(identity["source_hashes"]),
    "environment": {"python": sys.version, "platform": platform.platform(),
                    "zlib_compile": zlib.ZLIB_VERSION, "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION},
    "raw_compressed_sha256": {name: {"expected": expected, "actual": sha(out / name),
                                            "equal": expected == sha(out / name)}
                             for name, expected in identity["raw_files"].items()},
    "epochs_uncompressed_sha256": {"expected": hashlib.sha256(expected_bytes).hexdigest(),
                                      "actual": hashlib.sha256(actual_bytes).hexdigest(),
                                      "equal": expected_bytes == actual_bytes},
    "epochs_parsed_records_exact": expected_rows == actual_rows and not diffs,
    "epochs_record_counts": {"expected": len(expected_rows), "actual": len(actual_rows)},
    "epochs_first_differences": diffs[:10], "epochs_difference_count": len(diffs),
    "tolerance_used": False,
}
(ROOT / "diagnostic.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
