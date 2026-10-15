"""CLI provenance, process pairing and independent campaign audit integration."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from simulation.exogenous import load_config
from simulation.io import file_hash, write_json
from tools.verify_simulation_campaign import verify

ROOT = Path(__file__).resolve().parents[1]


def test_parallel_campaign_and_independent_full_replay(tmp_path):
    config = load_config(ROOT / "simulation/config.json")
    config.update(nodes=4, gateways=2, local_contention_domains=2,
                  backhaul_contention_domains=2, evaluation_seeds=[16, 17],
                  methods=["da-ahe", "without_markov"])
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    output = tmp_path / "campaign"
    subprocess.run([sys.executable, str(ROOT / "tools/run_simulation_campaign.py"),
                    "--config", str(config_path), "--output", str(output), "--jobs", "2"],
                   cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
    result = verify(output, replay=True)
    assert result["verified_runs"] == 4
    assert result["independent_raw_recomputation"] and result["deterministic_replay"]
    manifest = json.loads((output / "manifest.json").read_text())
    assert [(r["seed"], r["method"]) for r in manifest["runs"]] == [
        (16, "da-ahe"), (16, "without_markov"), (17, "da-ahe"), (17, "without_markov")]
    assert manifest["completed"]
    assert (output / "source/simulation/engine.py").exists()
    refusal = subprocess.run([sys.executable, str(ROOT / "tools/run_simulation_campaign.py"),
                              "--config", str(config_path), "--output", str(output)],
                             cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert refusal.returncode != 0 and "never overwritten" in refusal.stderr


def test_parallel_raw_verifier_matches_serial_for_paired_campaign(tmp_path):
    config = load_config(ROOT / "simulation/config.json")
    config.update(nodes=4, gateways=2, local_contention_domains=2,
                  backhaul_contention_domains=2, evaluation_seeds=[116, 117],
                  methods=["da-ahe", "without_markov"])
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    output = tmp_path / "parallel-audit-campaign"
    subprocess.run([sys.executable, str(ROOT / "tools/run_simulation_campaign.py"),
                    "--config", str(config_path), "--output", str(output), "--jobs", "2"],
                   cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
    serial = verify(output, jobs=1)
    parallel = verify(output, jobs=2)
    assert parallel == serial
    assert parallel["verified_runs"] == 4
    assert parallel["independent_raw_recomputation"]
    assert not parallel["deterministic_replay"]


@pytest.mark.parametrize("jobs", [1, 4])
@pytest.mark.parametrize("missing", ["events.jsonl.gz", "packets.jsonl.gz",
                                    "reports.jsonl.gz", "epochs.jsonl.gz"])
def test_self_consistent_manifest_cannot_omit_raw_hash(tmp_path, missing, jobs):
    config = load_config(ROOT / "simulation/config.json")
    config.update(nodes=4, gateways=2, local_contention_domains=2,
                  backhaul_contention_domains=2, evaluation_seeds=[216], methods=["da-ahe"])
    config_path = tmp_path / "config.json"
    write_json(config_path, config)
    output = tmp_path / "campaign"
    subprocess.run([sys.executable, str(ROOT / "tools/run_simulation_campaign.py"),
                    "--config", str(config_path), "--output", str(output), "--jobs", "1"],
                   cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
    manifest = json.loads((output / "manifest.json").read_text())
    run = manifest["runs"][0]
    run_path = output / run["directory"] / "manifest.json"
    run_manifest = json.loads(run_path.read_text())
    del run_manifest["raw_files"][missing]
    write_json(run_path, run_manifest)
    # Bind the modified bytes in the campaign too: a checksum mismatch must not
    # be the reason an omitted raw artifact is rejected.
    run["manifest_sha256"] = file_hash(run_path)
    write_json(output / "manifest.json", manifest)
    with pytest.raises(ValueError, match="must list exactly all four raw gzip files"):
        verify(output, replay=True, jobs=jobs)
