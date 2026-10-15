#!/usr/bin/env python3
"""Fetch the pinned historical independent evidence and verify its full contents.

The release assets are pieces of one uncompressed tar. This tool never treats
checksums as proof of original-paper reproduction or physical measurements.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CHUNK = 1024 * 1024


def sha256(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            result.update(block)
    return result.hexdigest()


def safe_relative(value):
    path = PurePosixPath(value)
    if (not value or "\\" in value or path.is_absolute() or
            any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("unsafe archive or manifest path: " + value)
    return path


def verify_parts(index, assets):
    whole = hashlib.sha256()
    total = 0
    for part in index["parts"]:
        name = safe_relative(part["name"])
        if len(name.parts) != 1:
            raise ValueError("release asset name must be a basename")
        path = assets / part["name"]
        if path.is_symlink() or not path.is_file() or path.stat().st_size != part["size"]:
            raise ValueError("release asset missing or size mismatch: " + str(path))
        single = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(CHUNK), b""):
                single.update(block)
                whole.update(block)
                total += len(block)
        if single.hexdigest() != part["sha256"]:
            raise ValueError("release asset checksum mismatch: " + str(path))
    if total != index["archive"]["size"] or whole.hexdigest() != index["archive"]["sha256"]:
        raise ValueError("joined archive checksum or size mismatch")


def download_parts(index, assets):
    assets.mkdir(parents=True, exist_ok=True)
    for part in index["parts"]:
        name = safe_relative(part["name"])
        if len(name.parts) != 1:
            raise ValueError("release asset name must be a basename")
        path = assets / part["name"]
        if path.is_file() and not path.is_symlink() and path.stat().st_size == part["size"]:
            if sha256(path) == part["sha256"]:
                continue
        if not part["url"].startswith("https://github.com/KeyComputerScience/DA-AHE/releases/download/"):
            raise ValueError("unexpected download origin")
        temporary = assets / (part["name"] + ".download")
        print("Downloading " + part["name"], flush=True)
        request = urllib.request.Request(part["url"], headers={"User-Agent": "DA-AHE-evidence-verifier"})
        try:
            with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as out:
                received = 0
                for block in iter(lambda: response.read(CHUNK), b""):
                    received += len(block)
                    if received > part["size"]:
                        raise ValueError("release asset exceeds expected size")
                    out.write(block)
            if temporary.stat().st_size != part["size"] or sha256(temporary) != part["sha256"]:
                raise ValueError("downloaded asset checksum or size mismatch")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


class JoinedParts(io.RawIOBase):
    """Read consecutive files without writing a second multi-gigabyte tar."""

    def __init__(self, paths):
        self.paths = iter(paths)
        self.current = None

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            raise ValueError("unbounded reads are not supported")
        chunks = []
        remaining = size
        while remaining:
            if self.current is None:
                try:
                    self.current = next(self.paths).open("rb")
                except StopIteration:
                    break
            block = self.current.read(remaining)
            if block:
                chunks.append(block)
                remaining -= len(block)
            else:
                self.current.close()
                self.current = None
        return b"".join(chunks)

    def close(self):
        if self.current is not None:
            self.current.close()
        super().close()


def extract_parts(index, assets, destination):
    if destination.exists():
        raise ValueError("extraction destination must not exist: " + str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".daahe-evidence-", dir=destination.parent))
    seen = set()
    files = 0
    total = 0
    prefix = PurePosixPath(index["archive"]["evidence_prefix"])
    try:
        with JoinedParts(assets / part["name"] for part in index["parts"]) as joined:
            with tarfile.open(fileobj=joined, mode="r|") as archive:
                for member in archive:
                    relative = safe_relative(member.name)
                    if relative != prefix and prefix not in relative.parents:
                        raise ValueError("archive member outside expected evidence prefix")
                    if member.name in seen:
                        raise ValueError("duplicate archive member: " + member.name)
                    seen.add(member.name)
                    path = stage.joinpath(*relative.parts)
                    if member.isdir():
                        path.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        total += member.size
                        files += 1
                        if total > index["archive"]["total_file_bytes"]:
                            raise ValueError("archive exceeds expected uncompressed size")
                        path.parent.mkdir(parents=True, exist_ok=True)
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise ValueError("archive member has no file contents")
                        with stream, path.open("xb") as out:
                            shutil.copyfileobj(stream, out, CHUNK)
                        if path.stat().st_size != member.size:
                            raise ValueError("truncated archive member")
                    else:
                        raise ValueError("links and special archive entries are forbidden")
        if files != index["archive"]["regular_files"] or total != index["archive"]["total_file_bytes"]:
            raise ValueError("archive file count or total size mismatch")
        stage.rename(destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def verify_contents(index, destination):
    evidence = destination / index["archive"]["evidence_prefix"]
    manifest = evidence / "manifest.json"
    if sha256(manifest) != index["archive"]["manifest_sha256"]:
        raise ValueError("evidence manifest checksum mismatch")
    entries = json.loads(manifest.read_text())["files"]
    if len(entries) != index["archive"]["listed_evidence_files"]:
        raise ValueError("evidence manifest entry count mismatch")
    listed = set()
    for entry in entries:
        relative = safe_relative(entry["path"])
        if entry["path"] in listed:
            raise ValueError("duplicate evidence manifest entry")
        listed.add(entry["path"])
        path = evidence.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file() or path.stat().st_size != entry["size"]:
            raise ValueError("evidence missing or size mismatch: " + entry["path"])
        if sha256(path) != entry["sha256"]:
            raise ValueError("evidence checksum mismatch: " + entry["path"])
    actual = {str(path.relative_to(evidence)) for path in evidence.rglob("*") if path.is_file()}
    if actual != listed | {"manifest.json"}:
        raise ValueError("unexpected or missing evidence files")
    campaign = destination / index["campaign"]["directory"]
    if sha256(campaign / "manifest.json") != index["campaign"]["manifest_sha256"]:
        raise ValueError("campaign manifest checksum mismatch")
    recorded = json.loads((campaign / "manifest.json").read_text())
    expected = index["campaign"]
    pairs = {(seed, method) for seed in expected["evaluation_seeds"] for method in expected["methods"]}
    observed = [(run["seed"], run["method"]) for run in recorded["runs"]]
    if len(observed) != expected["runs"] or len(set(observed)) != len(observed) or set(observed) != pairs:
        raise ValueError("campaign does not contain exactly the expected seed/method pairs")
    if (recorded["evaluation_seeds"] != expected["evaluation_seeds"] or
            recorded["methods"] != expected["methods"] or
            recorded["source_digest"] != expected["source_digest"] or
            len(recorded["source_hashes"]) != expected["source_files"]):
        raise ValueError("campaign seeds, methods, or frozen source identity mismatch")
    for name, digest in recorded["source_hashes"].items():
        relative = safe_relative(name)
        if sha256(campaign / "source" / relative) != digest:
            raise ValueError("frozen source checksum mismatch: " + name)
    return campaign


REPLAY_CHILD = r'''
import json, pathlib, sys, tempfile
from simulation.engine import run_one
from simulation.io import file_hash
campaign = pathlib.Path(sys.argv[1]); run = json.loads(sys.argv[2])
config = json.loads((campaign / "config.json").read_text())
expected = json.loads((campaign / run["directory"] / "manifest.json").read_text())["raw_files"]
with tempfile.TemporaryDirectory(prefix="daahe-frozen-replay-") as out:
    run_one(config, run["seed"], run["method"],
            campaign / "exogenous" / ("seed-" + str(run["seed"])), out,
            campaign / "controller.json")
    for name, digest in expected.items():
        if file_hash(pathlib.Path(out) / name) != digest:
            raise ValueError("deterministic replay mismatch: " + name)
print(json.dumps({"seed": run["seed"], "method": run["method"], "raw_files": len(expected), "passed": True}))
'''


def replay_frozen(campaign, jobs):
    source = campaign / "source"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(source / "src") + os.pathsep + str(source)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    runs = json.loads((campaign / "manifest.json").read_text())["runs"]

    def replay(run):
        result = subprocess.run([sys.executable, "-c", REPLAY_CHILD, str(campaign), json.dumps(run)],
                                cwd=source, env=env, text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(
                f"Frozen replay failed for seed={run['seed']} method={run['method']} "
                f"exit={result.returncode}\n"
                f"stdout (last 4000 characters):\n{result.stdout[-4000:]}\n"
                f"stderr (last 4000 characters):\n{result.stderr[-4000:]}"
            )
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        verified = list(pool.map(replay, runs))
    return {"verified_runs": len(verified), "deterministic_replay": True,
            "source": "archived_frozen_snapshot", "runs": verified}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=ROOT / "evidence/independent/publication.json")
    parser.add_argument("--assets-dir", type=Path, help="Use local parts; do not download")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "work/release-cache")
    parser.add_argument("--extract-dir", type=Path, required=True, help="Must be a new directory")
    parser.add_argument("--recompute", action="store_true", help="Rederive all 140 saved metrics from raw logs")
    parser.add_argument("--replay", action="store_true", help="Rerun all 140 cases using the frozen source")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--report", type=Path, help="Write a successful verification receipt")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    index = json.loads(args.index.read_text())
    assets = (args.assets_dir or args.cache_dir).resolve()
    if args.assets_dir is None:
        download_parts(index, assets)
    verify_parts(index, assets)
    destination = args.extract_dir.resolve()
    extract_parts(index, assets, destination)
    campaign = verify_contents(index, destination)
    report = {"archive_sha256": index["archive"]["sha256"], "archive_verified": True,
              "listed_evidence_files_verified": index["archive"]["listed_evidence_files"],
              "campaign_runs": index["campaign"]["runs"],
              "seeds": len(index["campaign"]["evaluation_seeds"]),
              "frozen_source_files_verified": index["campaign"]["source_files"],
              "source_digest": index["campaign"]["source_digest"],
              "origin": "independent_reimplementation", "paper_reproduced": False,
              "physical_board_samples": 0}
    if args.recompute:
        command = [sys.executable, str(ROOT / "tools/verify_simulation_campaign.py"), str(campaign),
                   "--jobs", str(args.jobs)]
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        report["raw_recomputation"] = json.loads(result.stdout)
    if args.replay:
        report["frozen_source_replay"] = replay_frozen(campaign, args.jobs)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text)
    print(text, end="")


if __name__ == "__main__":
    main()
