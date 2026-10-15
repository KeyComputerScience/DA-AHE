# SPDX-License-Identifier: MIT
"""Source-byte and missing-author-evidence checks; execution receipts are recorded separately."""
import pytest

from daahe.evidence import build_manifest, verify_manifest, audit_readiness


def test_manifest_detects_modified_and_missing_bytes(tmp_path):
    path = tmp_path/"source.py"
    path.write_text("original\n")
    manifest = build_manifest(tmp_path)
    assert verify_manifest(tmp_path, manifest)["status"] == "verified"
    path.write_text("modified\n")
    assert verify_manifest(tmp_path, manifest)["errors"][0]["reason"] == "content_mismatch"
    path.unlink()
    assert verify_manifest(tmp_path, manifest)["errors"][0]["reason"] == "missing"


@pytest.mark.parametrize("path", ["../secret", "/etc/passwd", "a/../secret", "a\\secret", "C:/secret", "a//b", "./a"])
def test_manifest_rejects_unsafe_paths(tmp_path, path):
    manifest = {"schema_version":1,"algorithm":"SHA256","files":[{"path":path,"size":0,"sha256":"0"*64}]}
    with pytest.raises(ValueError):
        verify_manifest(tmp_path, manifest)


def test_manifest_rejects_duplicate_paths_and_symlinks(tmp_path):
    path = tmp_path/"x"
    path.write_text("x")
    manifest = build_manifest(tmp_path)
    manifest["files"].append(dict(manifest["files"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        verify_manifest(tmp_path, manifest)
    (tmp_path/"alias").symlink_to(path)
    with pytest.raises(ValueError, match="symlink"):
        build_manifest(tmp_path)


def test_audit_does_not_confuse_source_package_with_paper_reproduction(tmp_path):
    (tmp_path/"README.md").write_text("Source only")
    report = audit_readiness(tmp_path)
    assert report["status"] == "blocked_incomplete_author_evidence"
    assert report["paper_reproduced"] is False
    assert report["tests_executed"] is False
    assert {p["role"] for p in report["problems"]} >= {"evaluation_seeds","omnet_source","firmware","packet_results","security_logs"}


def test_source_manifest_omits_private_keys_replay_and_generated_runs(tmp_path):
    (tmp_path/"source.py").write_text("# source fixture\n")
    for name in ("private","runs","results"):
        (tmp_path/name).mkdir()
        (tmp_path/name/"not-source.txt").write_text("test fixture")
    for name in ("secret.key","secret.pem",".env",".env.local","replay.sqlite","replay.sqlite-wal"):
        (tmp_path/name).write_text("test fixture")
    manifest = build_manifest(tmp_path)
    assert [record["path"] for record in manifest["files"]] == ["source.py"]


def test_manifest_cannot_overwrite_the_published_verification_baseline(tmp_path):
    (tmp_path/"source.py").write_text("original\n")
    target = tmp_path/"manifest.json"
    build_manifest(tmp_path, target)
    published = target.read_bytes()
    (tmp_path/"source.py").write_text("changed\n")
    with pytest.raises(ValueError, match="already exists"):
        build_manifest(tmp_path, target)
    assert target.read_bytes() == published
    assert verify_manifest(tmp_path, target)["status"] == "failed"
