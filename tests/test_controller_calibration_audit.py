"""Fail closed on tampering, missing cases and unsafe publication paths."""
import json

import pytest

from tools.verify_controller_calibration import safe_path, sha, verify_bytes


def write(root, name, value):
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value))
    return sha(target)


def byte_bundle(root):
    original = write(root, "original-config.json", {"nodes": 3000})
    effective = write(root, "input-config.json", {"nodes": 3000})
    controller = write(root, "input-controller.json", {"beta": .02})
    source = write(root, "source/src/model.json", {"fixed": True})
    case = {"partition": "training", "seed": 20000, "scenario": "normal"}
    plan = {"source_hashes": {"src/model.json": source}, "tasks": [case],
            "original_config_sha256": original, "input_config_sha256": effective,
            "controller_input_sha256": controller}
    plan_hash = write(root, "plan.json", plan)
    directory = "cases/training/seed-20000/normal/"
    config_hash = write(root, directory + "config.json", {"nodes": 3000})
    receipt = {**case, "completed": True, "files": {"config.json": config_hash,
                                                   "raw/events.jsonl.gz": "a" * 64}}
    receipt_hash = write(root, directory + "receipt.json", receipt)
    outputs = {"plan.json": plan_hash, "input-config.json": effective}
    manifest = {"completed": True, "source_unchanged_after_run": True,
                "plan_sha256": plan_hash, "outputs_sha256": outputs,
                "cases": [{**case, "receipt_sha256": receipt_hash}]}
    write(root, "manifest.json", manifest)
    return manifest


def test_compact_hash_commitment_is_distinct_from_missing_raw_verification(tmp_path):
    byte_bundle(tmp_path)
    verify_bytes(tmp_path)  # Missing raw can only be a commitment in compact mode.
    with pytest.raises(FileNotFoundError):
        verify_bytes(tmp_path, tmp_path)


def test_altered_input_or_frozen_source_is_rejected(tmp_path):
    byte_bundle(tmp_path)
    (tmp_path / "input-config.json").write_text('{"nodes": 5000}')
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_bytes(tmp_path)
    byte_bundle(tmp_path)
    (tmp_path / "source/src/model.json").write_text('{"fixed": false}')
    with pytest.raises(ValueError, match="source/src/model.json"):
        verify_bytes(tmp_path)


def test_incomplete_case_product_is_rejected(tmp_path):
    manifest = byte_bundle(tmp_path)
    manifest["cases"] = []
    write(tmp_path, "manifest.json", manifest)
    with pytest.raises(ValueError, match="case product"):
        verify_bytes(tmp_path)


def test_unsafe_paths_and_symlinks_cannot_escape_bundle(tmp_path):
    for name in ("../outside", "/absolute", "a/../../outside", "a\\outside"):
        with pytest.raises(ValueError):
            safe_path(tmp_path, name)
    (tmp_path / "link").symlink_to(tmp_path / "target")
    with pytest.raises(ValueError, match="symlink"):
        safe_path(tmp_path, "link")
