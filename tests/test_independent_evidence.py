import json
from pathlib import Path
import sys
import time
import signal
import subprocess

import pytest

from daahe.independent_evidence import bundle_manifest, run_logged, source_snapshot, verify_bundle


def test_real_execution_and_failure_are_logged_without_success_promotion(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    passed = run_logged([sys.executable, "-c", "print('actual-output')"], root, tmp_path / "pass")
    failed = run_logged([sys.executable, "-c", "raise SystemExit(7)"], root, tmp_path / "fail")
    assert passed["status"] == "passed" and passed["returncode"] == 0
    assert (tmp_path / "pass/stdout.log").read_text().strip() == "actual-output"
    assert failed["status"] == "failed" and failed["returncode"] == 7
    assert failed["paper_reproduced"] is False
    with pytest.raises(ValueError, match="already exists"):
        run_logged([sys.executable, "-c", "pass"], root, tmp_path / "pass")


def test_timed_out_and_unavailable_commands_are_preserved(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    timed = run_logged([sys.executable, "-c", "import time; time.sleep(5)"], root,
                       tmp_path / "timeout", timeout=.05)
    absent = run_logged([str(tmp_path / "missing-executable")], root, tmp_path / "absent")
    assert timed["status"] == "timed_out"
    assert absent["status"] == "unavailable" and absent["returncode"] is None


def test_bundle_detects_missing_and_tampered_results(tmp_path):
    (tmp_path / "result.csv").write_text("seed,loss\n1001,0.3\n")
    target = tmp_path / "manifest.json"
    bundle_manifest(tmp_path, target)
    assert verify_bundle(tmp_path, target)["status"] == "verified"
    (tmp_path / "result.csv").write_text("seed,loss\n1001,0.0\n")
    assert verify_bundle(tmp_path, target)["errors"][0]["reason"] == "content_mismatch"
    (tmp_path / "result.csv").unlink()
    assert verify_bundle(tmp_path, target)["errors"][0]["reason"] == "missing"
    with pytest.raises(ValueError, match="overwrite"):
        bundle_manifest(tmp_path, target)


def test_manifest_does_not_promote_independent_results_to_historical_reproduction(tmp_path):
    (tmp_path / "results.json").write_text("{}")
    target = tmp_path / "manifest.json"
    data = bundle_manifest(tmp_path, target)
    data["paper_reproduced"] = True
    target.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="invalid independent"):
        verify_bundle(tmp_path, target)


def test_source_snapshot_covers_tests_assembly_dependencies_and_checkout_shim(tmp_path):
    for name in ("tests/test_case.py", "firmware/startup.S", "daahe/__init__.py",
                 ".github/workflows/test.yml", "pyproject.toml", "requirements-pq.txt"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("original")
    before = source_snapshot(tmp_path)
    assert len(before["files"]) == 6
    (tmp_path / "tests/test_case.py").write_text("changed")
    assert source_snapshot(tmp_path)["digest"] != before["digest"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process group semantics")
def test_timeout_stops_descendants_before_they_can_mutate_evidence(tmp_path):
    child = "import time,pathlib;time.sleep(.4);pathlib.Path('survived').write_text('bad')"
    parent = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);time.sleep(5)"
    result = run_logged([sys.executable, "-c", parent], tmp_path, tmp_path / "timeout", timeout=.15)
    time.sleep(.45)
    assert result["status"] == "timed_out"
    assert not (tmp_path / "survived").exists()


@pytest.mark.parametrize("name", ["secret.key", "replay.sqlite", ".env", ".env.local"])
def test_public_manifest_rejects_accidental_private_material(tmp_path, name):
    (tmp_path / name).write_text("private fixture")
    with pytest.raises(ValueError, match="private-state/key"):
        bundle_manifest(tmp_path, tmp_path / "manifest.json")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX interrupt semantics")
def test_interrupted_wrapper_finalizes_receipt_and_stops_its_job(tmp_path):
    cli = Path(__file__).resolve().parents[1] / "tools/run_logged.py"
    output = tmp_path / "interrupted"
    command = [sys.executable, str(cli), "--root", str(tmp_path), "--output", str(output),
               "--", sys.executable, "-c", "import time;time.sleep(20)"]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(200):
            try:
                receipt = json.loads((output / "execution.json").read_text())
                if receipt.get("process_id"):
                    break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            time.sleep(.01)
        else:
            raise AssertionError("child job did not start")
        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=5) == 2
        receipt = json.loads((output / "execution.json").read_text())
        assert receipt["status"] == "interrupted"
        assert receipt["finished_utc"] and receipt["returncode"] != 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
