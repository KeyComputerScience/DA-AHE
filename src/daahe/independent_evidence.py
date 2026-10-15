# SPDX-License-Identifier: MIT
"""Independent execution receipts and byte manifests, never author attestations.

Hashes detect changed bytes. They cannot establish that a measurement is truthful,
that a mathematical proof is valid, or that these independent results are the
manuscript's historical experiments. No keys or process environment are exported.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

from .evidence import PRIVATE_SUFFIXES, _safe_path, sha256_file

SOURCE_DIRECTORIES = ("src", "daahe", "simulation", "firmware", "security", "tools", "embedded",
                      "tests", ".github", "configs", "experiments")
ROOT_SOURCE_FILES = ("pyproject.toml", "requirements-dev.txt", "requirements-pq.txt", "Makefile", "Dockerfile")
SOURCE_SUFFIXES = {".py", ".sage", ".c", ".h", ".S", ".ld", ".json", ".toml", ".yml", ".yaml"}
EXCLUDED_PARTS = {"__pycache__", ".git", "build", "private", "runs", "evidence", "external"}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def source_snapshot(root: Path) -> dict:
    root = root.resolve()
    files = []
    for directory in SOURCE_DIRECTORIES:
        base = root / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            relative = path.relative_to(root)
            if any(part in EXCLUDED_PARTS for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"source symlink forbidden: {relative}")
            if path.is_file() and (path.suffix in SOURCE_SUFFIXES or path.name in {"Makefile", "CMakeLists.txt"}):
                files.append({"path": relative.as_posix(), "sha256": sha256_file(path)})
    for name in ROOT_SOURCE_FILES:
        path = root / name
        if path.is_symlink():
            raise ValueError(f"source symlink forbidden: {name}")
        if path.is_file():
            files.append({"path": name, "sha256": sha256_file(path)})
    files.sort(key=lambda r: r["path"])
    payload = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"algorithm": "SHA256", "scope": list(SOURCE_DIRECTORIES), "root_files": list(ROOT_SOURCE_FILES),
            "digest": hashlib.sha256(payload).hexdigest(), "files": files}


def run_logged(command: list[str], root: Path, output: Path, timeout: float = 3600) -> dict:
    """Execute argv without a shell; preserve failed and timed-out attempts too."""
    if not command or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("nonempty command and positive timeout required")
    root = root.resolve()
    output = output.resolve()
    if output.exists():
        raise ValueError("execution output already exists; choose a new attempt directory")
    output.mkdir(parents=True)
    snapshot = source_snapshot(root)
    write_json(output / "source-snapshot.json", snapshot)
    receipt = {"schema_version": 1, "origin": "independent_reimplementation",
               "paper_reproduced": False, "command": command, "cwd": str(root),
               "started_utc": utc_now(), "platform": platform.platform(),
               "python": sys.version, "source_digest": snapshot["digest"],
               "timeout_s": timeout, "status": "running", "returncode": None}
    write_json(output / "execution.json", receipt)
    started = time.monotonic()
    with (output / "stdout.log").open("wb") as stdout, (output / "stderr.log").open("wb") as stderr:
        try:
            process = subprocess.Popen(command, cwd=root, stdout=stdout, stderr=stderr,
                                       start_new_session=os.name == "posix")
            receipt["process_id"] = process.pid
            receipt["process_group_id"] = process.pid if os.name == "posix" else None
            write_json(output / "execution.json", receipt)
            try:
                receipt["returncode"] = process.wait(timeout=timeout)
                receipt["status"] = "passed" if process.returncode == 0 else "failed"
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
                receipt["returncode"] = process.returncode
                receipt["status"] = "timed_out" if isinstance(exc, subprocess.TimeoutExpired) else "interrupted"
        except OSError as exc:
            receipt["status"] = "unavailable"
            receipt["error"] = f"{type(exc).__name__}: {exc}"
    receipt.update(finished_utc=utc_now(), wall_time_s=time.monotonic() - started,
                   stdout_sha256=sha256_file(output / "stdout.log"),
                   stderr_sha256=sha256_file(output / "stderr.log"))
    write_json(output / "execution.json", receipt)
    return receipt


def bundle_manifest(root: Path, manifest_path: Path) -> dict:
    root = root.resolve()
    manifest_path = manifest_path.resolve()
    if not manifest_path.is_relative_to(root):
        raise ValueError("manifest must be inside evidence root")
    if manifest_path.exists():
        raise ValueError("do not overwrite a published evidence manifest")
    records = []
    for path in sorted(root.rglob("*")):
        if path == manifest_path:
            continue
        relative = path.relative_to(root)
        if any(part in {"private", "__pycache__", ".git"} for part in relative.parts):
            continue
        if (path.name.endswith(PRIVATE_SUFFIXES) or path.name == ".env"
                or path.name.startswith(".env.")):
            raise ValueError(f"private-state/key file forbidden in a public evidence bundle: {relative}")
        if path.is_symlink():
            raise ValueError(f"evidence symlink forbidden: {relative}")
        if path.is_file():
            records.append({"path": relative.as_posix(), "size": path.stat().st_size,
                            "sha256": sha256_file(path)})
    result = {"schema_version": 1, "artifact_type": "independent-evidence-bundle",
              "origin": "independent_reimplementation", "paper_reproduced": False,
              "algorithm": "SHA256", "created_utc": utc_now(), "files": records,
              "scope": "listed public evidence bytes; no claim of historical provenance or proof validity"}
    write_json(manifest_path, result)
    return result


def verify_bundle(root: Path, manifest: Path) -> dict:
    root = root.resolve()
    data = json.loads(manifest.read_text())
    if (data.get("schema_version") != 1 or data.get("algorithm") != "SHA256"
            or data.get("artifact_type") != "independent-evidence-bundle"
            or data.get("origin") != "independent_reimplementation"
            or data.get("paper_reproduced") is not False or not isinstance(data.get("files"), list)):
        raise ValueError("invalid independent evidence manifest")
    seen, errors = set(), []
    for record in data["files"]:
        name = record["path"]
        path = _safe_path(root, name)
        if name in seen:
            raise ValueError(f"duplicate evidence path: {name}")
        seen.add(name)
        if not path.is_file():
            errors.append({"path": name, "reason": "missing"})
        elif path.stat().st_size != record["size"] or sha256_file(path) != record["sha256"]:
            errors.append({"path": name, "reason": "content_mismatch"})
    return {"status": "verified" if not errors else "failed", "checked_files": len(seen),
            "errors": errors, "paper_reproduced": False,
            "scope": "byte integrity only; execution, measurement and mathematical claims require separate checks"}
