# SPDX-License-Identifier: MIT
"""Hash manifests and fail-closed evidence readiness, independent of experiment execution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

IGNORED_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules",
                 "private", ".secrets", ".keys", "runs", "results"}
PRIVATE_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite-shm",
                    ".sqlite3-wal", ".sqlite3-shm")
REQUIRED_AUTHOR_ARTIFACTS = {
    "evaluation_seeds": "Original 20 independent evaluation seeds and separate calibration seeds",
    "omnet_source": "Author OMNeT++ 6.0 / INET 4.4 modules, NED topology, INI configurations and instrumentation",
    "traffic_disturbance": "Paired topology/traffic/disturbance traces including routing-link failure identities",
    "calibration": "Frozen transition/emission/cost models and uncertainty radii with calibration provenance",
    "certificates": "Profile support, action library and offline memory/airtime/no-wrap/noise/fallback certificates",
    "board_measurements": "nRF52840 raw cycle/energy/role-specific stack measurements and exact measurement boundaries",
    "firmware": "Author Contiki-NG implementation, build recipe, ELF and map files",
    "security_logs": "Pinned-estimator successful per-attack raw logs and Sage environment capture",
    "sensor_signals": "Ground-truth sensor traces and original integer Db2 lifting/filter/rounding/boundary definition",
    "packet_results": "Original packet-level traces and per-seed raw summaries for the manuscript figures",
}


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative:
        raise ValueError("manifest path must be a nonempty POSIX relative path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"..", ".", ""} for part in relative.split("/")) or ":" in pure.parts[0]:
        raise ValueError(f"unsafe manifest path: {relative}")
    result = root.joinpath(*pure.parts)
    for ancestor in (result, *result.parents):
        if ancestor == root:
            break
        if ancestor.is_symlink():
            raise ValueError(f"symlink forbidden in manifest: {relative}")
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"manifest path escapes root: {relative}")
    return result


def build_manifest(root: str | Path, output: str | Path | None = None) -> dict:
    """Hash regular source files. The manifest excludes itself and transient files.

    This records bytes only; a manifest is not a test log, authenticity signature,
    proof of reproduction, or proof of absence of implementation defects.
    """
    base = Path(root).resolve()
    target = Path(output).resolve() if output else None
    records = []
    for path in sorted(base.rglob("*")):
        relative = path.relative_to(base).as_posix()
        if (any(part in IGNORED_PARTS for part in path.relative_to(base).parts) or path == target
                or path.name.endswith(PRIVATE_SUFFIXES) or path.name == ".env" or path.name.startswith(".env.")):
            continue
        if path.is_symlink():
            raise ValueError(f"symlink forbidden: {relative}")
        if path.is_file():
            records.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    manifest = {"schema_version": 1, "algorithm": "SHA256", "scope": "source bytes; excludes manifest, transient/private directories, key/env/replay files and generated runs/results",
                "executed": False, "files": records}
    if target:
        if not target.is_relative_to(base):
            raise ValueError("manifest output must be inside root")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_manifest(root: str | Path, manifest: dict | str | Path) -> dict:
    base = Path(root).resolve()
    if not isinstance(manifest, dict):
        manifest = json.loads(Path(manifest).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("algorithm") != "SHA256" or not isinstance(manifest.get("files"), list):
        raise ValueError("unsupported manifest schema")
    seen, errors = set(), []
    for record in manifest["files"]:
        relative = record["path"]
        path = _safe_path(base, relative)
        if relative in seen:
            raise ValueError(f"duplicate manifest path: {relative}")
        seen.add(relative)
        if not path.is_file():
            errors.append({"path": relative, "reason": "missing"})
        elif path.stat().st_size != record["size"] or sha256_file(path) != record["sha256"]:
            errors.append({"path": relative, "reason": "content_mismatch"})
    return {"status": "verified" if not errors else "failed", "checked_files": len(seen), "errors": errors,
            "scope": "listed files only; verification does not execute project code"}


def audit_readiness(root: str | Path) -> dict:
    """Require checksummed author evidence before claiming paper reproduction.

    Evidence index format: {schema_version:1, artifacts:{role:[{path,sha256}]}}.
    Paths resolve relative to project root. Even complete presence/hash checks only
    produce `evidence_present_requires_execution_and_review`, never reproduced.
    """
    base = Path(root).resolve()
    index_path = base / "author_artifacts" / "evidence-index.json"
    artifacts = {}
    problems = []
    if index_path.is_file():
        try:
            if index_path.is_symlink():
                raise ValueError("symlink evidence index forbidden")
            index = json.loads(index_path.read_text(encoding="utf-8"))
            if index.get("schema_version") != 1 or not isinstance(index.get("artifacts"), dict):
                raise ValueError("invalid evidence-index schema")
            artifacts = index["artifacts"]
        except (ValueError, OSError) as exc:
            problems.append({"role": "evidence_index", "reason": str(exc)})
    for role, description in REQUIRED_AUTHOR_ARTIFACTS.items():
        records = artifacts.get(role)
        if not isinstance(records, list) or not records:
            problems.append({"role": role, "reason": "missing_author_artifact", "required": description})
            continue
        for record in records:
            try:
                path = _safe_path(base, record["path"])
                digest = record["sha256"]
                if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                    raise ValueError("invalid sha256")
                if not path.is_file() or sha256_file(path) != digest:
                    raise ValueError("file missing or hash mismatch")
            except (KeyError, TypeError, ValueError, OSError) as exc:
                problems.append({"role": role, "reason": str(exc)})
    return {"status": "blocked_incomplete_author_evidence" if problems else "evidence_present_requires_execution_and_review",
            "paper_reproduced": False, "tests_executed": False, "experiments_executed": False,
            "problems": problems, "note": "Presence and SHA256 checks do not validate author provenance or numerical claims."}
