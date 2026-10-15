"""Canonical, timestamp-free gzip and content identities for reproducible runs."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


class JsonlWriter:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.raw = Path(path).open("wb")
        self.compressed = gzip.GzipFile(filename="", mode="wb", fileobj=self.raw, mtime=0)
        self.stream = io.TextIOWrapper(self.compressed, encoding="utf-8", newline="\n")
        self.rows = 0

    def write(self, value):
        self.stream.write(encode(value) + "\n")
        self.rows += 1

    def close(self):
        self.stream.close()
        self.raw.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def read_jsonl(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def uniform(seed, stream, *key):
    """Counter-based independent streams; no method or mutable RNG position.

    Exogenous inputs are paired across methods. Endogenous aggregate membership
    may differ; its key is its canonical contributor set, not an event counter.
    """
    raw = hashlib.sha256(encode([seed, stream, *key]).encode()).digest()
    return (int.from_bytes(raw[:8], "big") + 0.5) / 2**64


def source_hashes(root):
    root = Path(root)
    paths = (list((root / "simulation").glob("*.py")) +
             list((root / "src/daahe").glob("*.py")) +
             [root / "tools/run_simulation_campaign.py",
              root / "tools/verify_simulation_campaign.py"])
    return {str(path.relative_to(root)): file_hash(path) for path in sorted(paths)}
