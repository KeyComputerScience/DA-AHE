# SPDX-License-Identifier: MIT
"""Small synthetic archives exercise the public evidence integrity boundary.

These fixtures are parser/security tests, never published simulation results.
No test downloads assets or runs a simulated campaign.
"""
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest


@pytest.fixture(scope="module")
def verifier():
    path = Path(__file__).resolve().parents[1] / "tools/verify_published_evidence.py"
    spec = importlib.util.spec_from_file_location("published_evidence_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def archive_fixture(tmp_path, *, runs=None, extra_members=(), duplicate_manifest=False,
                    unlisted_file=False):
    """Build a self-consistent tiny two-seed/two-method release index and tar."""
    prefix = "evidence/independent"
    seeds = [11, 12]
    methods = ["da-ahe", "hys"]
    source = b"# synthetic verifier fixture\n"
    source_hashes = {"src/fixture.py": digest(source)}
    pairs = [{"seed": seed, "method": method, "directory": f"runs/{seed}/{method}"}
             for seed in seeds for method in methods]
    campaign = {"evaluation_seeds": seeds, "methods": methods,
                "source_digest": "synthetic-fixture-identity", "source_hashes": source_hashes,
                "runs": pairs if runs is None else runs}
    files = {"simulation/manifest.json": json_bytes(campaign),
             "simulation/source/src/fixture.py": source,
             "fixture-result.csv": b"synthetic-fixture-only\n"}
    entries = [{"path": name, "size": len(data), "sha256": digest(data)}
               for name, data in files.items()]
    if duplicate_manifest:
        entries.append(deepcopy(entries[0]))
    manifest = json_bytes({"files": entries})
    files["manifest.json"] = manifest
    if unlisted_file:
        files["unlisted.txt"] = b"not-listed-in-evidence-manifest\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(f"{prefix}/{name}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        for member, data in extra_members:
            archive.addfile(member, io.BytesIO(data) if data is not None else None)
    tar_bytes = stream.getvalue()
    assets = tmp_path / "assets"
    assets.mkdir()
    # Split through a tar header, rather than relying on aligned file boundaries.
    split = len(tar_bytes) // 2 + 137
    parts = []
    for number, data in enumerate((tar_bytes[:split], tar_bytes[split:]), start=1):
        name = f"fixture.tar.part{number}"
        (assets / name).write_bytes(data)
        parts.append({"name": name, "size": len(data), "sha256": digest(data)})
    index = {"archive": {"size": len(tar_bytes), "sha256": digest(tar_bytes),
                          "evidence_prefix": prefix, "regular_files": len(files),
                          "total_file_bytes": sum(map(len, files.values())),
                          "listed_evidence_files": len(entries),
                          "manifest_sha256": digest(manifest)},
             "parts": parts,
             "campaign": {"directory": f"{prefix}/simulation", "runs": 4,
                          "evaluation_seeds": seeds, "methods": methods,
                          "source_digest": campaign["source_digest"], "source_files": 1,
                          "manifest_sha256": digest(files["simulation/manifest.json"])}}
    return index, assets, tmp_path / "extracted"


def test_complete_split_archive_verifies_and_extracts_exact_campaign(verifier, tmp_path):
    index, assets, destination = archive_fixture(tmp_path)
    verifier.verify_parts(index, assets)
    verifier.extract_parts(index, assets, destination)
    campaign = verifier.verify_contents(index, destination)
    assert campaign == destination / "evidence/independent/simulation"
    assert json.loads((campaign / "manifest.json").read_text())["evaluation_seeds"] == [11, 12]
    assert not list(tmp_path.glob(".daahe-evidence-*"))


def test_same_size_corrupt_part_is_rejected_before_extraction(verifier, tmp_path):
    index, assets, destination = archive_fixture(tmp_path)
    part = assets / index["parts"][0]["name"]
    damaged = bytearray(part.read_bytes())
    damaged[100] ^= 1
    part.write_bytes(damaged)
    with pytest.raises(ValueError, match="checksum mismatch"):
        verifier.verify_parts(index, assets)
    assert not destination.exists()


@pytest.mark.parametrize("mutation", ["missing", "truncated", "symlink"])
def test_absent_truncated_or_linked_asset_is_rejected(verifier, tmp_path, mutation):
    index, assets, _ = archive_fixture(tmp_path)
    part = assets / index["parts"][0]["name"]
    data = part.read_bytes()
    part.unlink()
    if mutation == "truncated":
        part.write_bytes(data[:-1])
    elif mutation == "symlink":
        target = tmp_path / "linked-target"
        target.write_bytes(data)
        part.symlink_to(target)
    with pytest.raises(ValueError, match="missing or size mismatch"):
        verifier.verify_parts(index, assets)


def test_part_order_is_bound_to_complete_archive_hash(verifier, tmp_path):
    index, assets, _ = archive_fixture(tmp_path)
    index["parts"].reverse()
    with pytest.raises(ValueError, match="joined archive"):
        verifier.verify_parts(index, assets)


@pytest.mark.parametrize("name", ["../escaped", "nested/asset", "/absolute", r"..\escaped"])
def test_part_names_cannot_address_other_paths(verifier, tmp_path, name):
    index, assets, _ = archive_fixture(tmp_path)
    index["parts"][0]["name"] = name
    with pytest.raises(ValueError):
        verifier.verify_parts(index, assets)


@pytest.mark.parametrize("name", ["evidence/independent/../escaped", "/tmp/escaped",
                                 "other-prefix/escaped"])
def test_tar_paths_cannot_escape_expected_evidence_tree(verifier, tmp_path, name):
    member = tarfile.TarInfo(name)
    member.size = 1
    index, assets, destination = archive_fixture(tmp_path, extra_members=[(member, b"x")])
    with pytest.raises(ValueError, match="unsafe|outside expected"):
        verifier.extract_parts(index, assets, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".daahe-evidence-*"))


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_tar_links_and_special_entries_are_forbidden(verifier, tmp_path, kind):
    member = tarfile.TarInfo("evidence/independent/forbidden")
    member.type = kind
    member.linkname = "fixture-result.csv"
    index, assets, destination = archive_fixture(tmp_path, extra_members=[(member, None)])
    with pytest.raises(ValueError, match="links and special"):
        verifier.extract_parts(index, assets, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".daahe-evidence-*"))


def test_duplicate_tar_path_cannot_overwrite_an_existing_member(verifier, tmp_path):
    member = tarfile.TarInfo("evidence/independent/fixture-result.csv")
    member.size = 1
    index, assets, destination = archive_fixture(tmp_path, extra_members=[(member, b"x")])
    with pytest.raises(ValueError, match="duplicate archive member"):
        verifier.extract_parts(index, assets, destination)
    assert not destination.exists()


@pytest.mark.parametrize("field", ["regular_files", "total_file_bytes"])
def test_archive_cardinality_and_uncompressed_size_are_exact(verifier, tmp_path, field):
    index, assets, destination = archive_fixture(tmp_path)
    index["archive"][field] += 1
    with pytest.raises(ValueError, match="file count or total size"):
        verifier.extract_parts(index, assets, destination)
    assert not destination.exists()


def test_extraction_never_overwrites_an_existing_directory(verifier, tmp_path):
    index, assets, destination = archive_fixture(tmp_path)
    destination.mkdir()
    sentinel = destination / "existing"
    sentinel.write_text("preserve")
    with pytest.raises(ValueError, match="destination must not exist"):
        verifier.extract_parts(index, assets, destination)
    assert sentinel.read_text() == "preserve"


def test_same_size_extracted_evidence_tampering_is_rejected(verifier, tmp_path):
    index, assets, destination = archive_fixture(tmp_path)
    verifier.extract_parts(index, assets, destination)
    target = destination / "evidence/independent/fixture-result.csv"
    target.write_bytes(b"X" + target.read_bytes()[1:])
    with pytest.raises(ValueError, match="evidence checksum mismatch"):
        verifier.verify_contents(index, destination)


def test_self_consistent_duplicate_manifest_entry_is_rejected(verifier, tmp_path):
    index, assets, destination = archive_fixture(tmp_path, duplicate_manifest=True)
    verifier.extract_parts(index, assets, destination)
    with pytest.raises(ValueError, match="duplicate evidence manifest entry"):
        verifier.verify_contents(index, destination)


def test_self_consistent_archive_with_unlisted_evidence_is_rejected(verifier, tmp_path):
    index, assets, destination = archive_fixture(tmp_path, unlisted_file=True)
    verifier.extract_parts(index, assets, destination)
    with pytest.raises(ValueError, match="unexpected or missing evidence files"):
        verifier.verify_contents(index, destination)


@pytest.mark.parametrize("runs", [
    [{"seed": 11, "method": "da-ahe"}, {"seed": 11, "method": "hys"},
     {"seed": 12, "method": "da-ahe"}],
    [{"seed": 11, "method": "da-ahe"}, {"seed": 11, "method": "hys"},
     {"seed": 12, "method": "da-ahe"}, {"seed": 12, "method": "da-ahe"}],
    [{"seed": 11, "method": "da-ahe"}, {"seed": 11, "method": "hys"},
     {"seed": 12, "method": "da-ahe"}, {"seed": 13, "method": "hys"}],
])
def test_campaign_requires_exact_seed_method_cartesian_product(verifier, tmp_path, runs):
    # All byte-level checks pass: semantic omission/duplication still must fail.
    index, assets, destination = archive_fixture(tmp_path, runs=runs)
    verifier.verify_parts(index, assets)
    verifier.extract_parts(index, assets, destination)
    with pytest.raises(ValueError, match="exactly the expected seed/method pairs"):
        verifier.verify_contents(index, destination)


def test_frozen_source_identity_is_separate_from_evidence_hashes(verifier, tmp_path):
    index, assets, destination = archive_fixture(tmp_path)
    verifier.extract_parts(index, assets, destination)
    index["campaign"]["source_digest"] = "different-expected-source"
    with pytest.raises(ValueError, match="frozen source identity mismatch"):
        verifier.verify_contents(index, destination)


def test_failed_frozen_replay_reports_case_and_bounded_child_diagnostics(verifier, tmp_path):
    # Execute an actual failing child from a synthetic source snapshot. A real
    # verifier failure must expose its case and traceback, rather than just the
    # generic CalledProcessError produced by capture_output/check=True.
    campaign = tmp_path / "campaign"
    source = campaign / "source/simulation"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("")
    (source / "io.py").write_text("def file_hash(path):\n    return 'synthetic-fixture'\n")
    (source / "engine.py").write_text(
        "def run_one(*args):\n"
        "    print('omitted-prefix' + 'X' * 5000 + 'retained-tail')\n"
        "    raise RuntimeError('synthetic-replay-failure')\n"
    )
    run = {"seed": 11, "method": "da-ahe", "directory": "runs/11/da-ahe"}
    run_dir = campaign / run["directory"]
    run_dir.mkdir(parents=True)
    raw_files = {name: "synthetic-fixture" for name in
                 ("events.jsonl.gz", "packets.jsonl.gz", "reports.jsonl.gz", "epochs.jsonl.gz")}
    (run_dir / "manifest.json").write_text(json.dumps({"raw_files": raw_files}))
    (campaign / "manifest.json").write_text(json.dumps({"runs": [run]}))
    (campaign / "config.json").write_text("{}")
    with pytest.raises(RuntimeError) as failure:
        verifier.replay_frozen(campaign, jobs=1)
    message = str(failure.value)
    assert "seed=11 method=da-ahe exit=1" in message
    assert "synthetic-replay-failure" in message
    assert "retained-tail" in message
    assert "omitted-prefix" not in message
    assert message.count("X") <= 4000


@pytest.mark.parametrize("jobs", [1, 4])
@pytest.mark.parametrize("missing", ["events.jsonl.gz", "packets.jsonl.gz",
                                    "reports.jsonl.gz", "epochs.jsonl.gz"])
def test_frozen_replay_rejects_missing_raw_hash_before_simulating(verifier, tmp_path, missing, jobs):
    campaign = tmp_path / "campaign"
    source = campaign / "source/simulation"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("")
    (source / "io.py").write_text("def file_hash(path):\n    return 'synthetic-fixture'\n")
    (source / "engine.py").write_text(
        "def run_one(*args):\n    raise RuntimeError('unexpectedly simulated incomplete manifest')\n"
    )
    run = {"seed": 11, "method": "da-ahe", "directory": "runs/11/da-ahe"}
    run_dir = campaign / run["directory"]
    run_dir.mkdir(parents=True)
    raw_files = {name: "synthetic-fixture" for name in
                 ("events.jsonl.gz", "packets.jsonl.gz", "reports.jsonl.gz", "epochs.jsonl.gz")}
    del raw_files[missing]
    (run_dir / "manifest.json").write_text(json.dumps({"raw_files": raw_files}))
    (campaign / "manifest.json").write_text(json.dumps({"runs": [run]}))
    (campaign / "config.json").write_text("{}")
    with pytest.raises(RuntimeError, match="must list exactly all four raw gzip files") as failure:
        verifier.replay_frozen(campaign, jobs=jobs)
    assert "unexpectedly simulated" not in str(failure.value)
