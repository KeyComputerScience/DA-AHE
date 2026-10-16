# SPDX-License-Identifier: MIT
"""CI trigger policy and pytest report handling, independent of experiment data."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def trigger_tool():
    path = ROOT / "tools/check_ci_triggers.py"
    spec = importlib.util.spec_from_file_location("ci_trigger_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_workflow(root, event_config=None, job_extra="", step_extra=""):
    path = root / ".github/workflows/checks.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    events = event_config if event_config is not None else "  pull_request:\n  push:\n    branches: [main]\n"
    path.write_text("name: Required checks\non:\n" + events + "jobs:\n  required:\n"
                    "    runs-on: ubuntu-24.04\n" + job_extra + "    steps:\n"
                    "      - run: python -m pytest --strict-ci\n" + step_extra,
                    encoding="utf-8")
    return path


def test_main_push_and_every_pr_allow_artifact_upload_after_failure(tmp_path):
    write_workflow(tmp_path, job_extra="    if: always()\n",
                   step_extra="      - uses: actions/upload-artifact@pinned\n"
                              "        if: ${{ always() }}\n")
    result = trigger_tool().assess(tmp_path)
    assert result["status"] == "passed_ci_trigger_policy"
    assert result["paper_reproduced"] is False
    assert result["full_system_certified"] is False


def test_active_repository_workflows_satisfy_the_trigger_policy():
    result = trigger_tool().assess(ROOT)
    assert result["errors"] == [], result["errors"]


def test_unfiltered_event_list_also_covers_required_triggers(tmp_path):
    path = write_workflow(tmp_path)
    path.write_text("on: [pull_request, push]\njobs:\n  check:\n    runs-on: ubuntu-24.04\n"
                    "    steps:\n      - run: true\n", encoding="utf-8")
    assert trigger_tool().assess(tmp_path)["errors"] == []


@pytest.mark.parametrize("event", ["pull_request", "push"])
def test_missing_required_event_is_rejected(tmp_path, event):
    remaining = "push" if event == "pull_request" else "pull_request"
    write_workflow(tmp_path, f"  {remaining}:\n")
    result = trigger_tool().assess(tmp_path)
    assert any(row["location"].endswith(f"on.{event}") for row in result["errors"])


@pytest.mark.parametrize("event,filter_line", [
    ("push", "branches: [other]"), ("push", "branches-ignore: [main]"),
    ("push", "paths: ['src/**']"), ("push", "paths-ignore: ['docs/**']"),
    ("push", "tags: ['v*']"), ("pull_request", "branches: [main]"),
    ("pull_request", "types: [opened]"), ("pull_request", "paths: ['src/**']"),
])
def test_event_suppression_filters_are_rejected(tmp_path, event, filter_line):
    other = "pull_request" if event == "push" else "push"
    write_workflow(tmp_path, f"  {event}:\n    {filter_line}\n  {other}:\n")
    assert trigger_tool().assess(tmp_path)["status"] == "failed_ci_trigger_policy"


@pytest.mark.parametrize("job_extra,step_extra", [
    ("    if: github.event_name == 'push'\n", ""),
    ("", "        if: github.ref == 'refs/heads/main'\n"),
    ("    continue-on-error: true\n", ""),
    ("", "        continue-on-error: false\n"),
])
def test_conditional_or_error_suppression_is_rejected(tmp_path, job_extra, step_extra):
    write_workflow(tmp_path, job_extra=job_extra, step_extra=step_extra)
    assert trigger_tool().assess(tmp_path)["status"] == "failed_ci_trigger_policy"


def test_duplicate_yaml_keys_cannot_hide_trigger_filters(tmp_path):
    path = write_workflow(tmp_path)
    path.write_text(path.read_text() + "on: [pull_request, push]\n", encoding="utf-8")
    result = trigger_tool().assess(tmp_path)
    assert any("unique strings" in row["reason"] for row in result["errors"])


@pytest.mark.parametrize("pair", [("skip", "ci"), ("ci", "skip"), ("no", "ci"),
                                  ("skip", "actions"), ("actions", "skip")])
def test_commit_directives_are_rejected_in_active_source_and_event(tmp_path, pair):
    write_workflow(tmp_path)
    marker = "[" + " ".join(pair) + "]"
    source = tmp_path / "tools/unsafe.txt"
    source.parent.mkdir()
    source.write_text(marker, encoding="utf-8")
    result = trigger_tool().assess(tmp_path, {"commits": [{"message": "change " + marker}]})
    assert {row["location"] for row in result["errors"]} == {
        "tools/unsafe.txt", "event.commit_messages[0]"}


def test_commit_trailer_and_head_commit_are_checked(tmp_path):
    write_workflow(tmp_path)
    trailer = "-".join(("skip", "checks")) + ": true"
    result = trigger_tool().assess(tmp_path, {"head_commit": {"message": "change\n\n" + trailer}})
    assert result["event_commit_messages_checked"] == 1
    assert result["errors"][0]["location"] == "event.commit_messages[0]"


@pytest.mark.parametrize("directory", [
    ".github", "src", "daahe", "tests", "tools", "security", "simulation",
    "embedded", "firmware", "configs", "config", "experiments", "experiment", "docs",
])
@pytest.mark.parametrize("directive_kind", ["bracket", "trailer"])
def test_every_active_source_directory_rejects_commit_directives(tmp_path, directory, directive_kind):
    write_workflow(tmp_path)
    if directive_kind == "bracket":
        directive = "[" + " ".join(("skip", "ci")) + "]"
    else:
        directive = "-".join(("skip", "checks")) + ": true"
    relative = Path(directory) / "nested" / "guard-fixture.json"
    source = tmp_path / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(json.dumps({"guard_fixture": directive}), encoding="utf-8")
    result = trigger_tool().assess(tmp_path)
    assert {row["location"] for row in result["errors"]} == {relative.as_posix()}


@pytest.mark.parametrize("directory", ["configs", "config", "experiments", "experiment", "security", "simulation"])
def test_sampling_outcomes_and_certificate_flags_are_not_ci_directives(tmp_path, directory):
    write_workflow(tmp_path)
    source = tmp_path / directory / "scientific-state.json"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(json.dumps({"sampling_skipped": 7, "certified": False,
                                  "control_model_certified": False,
                                  "full_system_certified": False}), encoding="utf-8")
    assert trigger_tool().assess(tmp_path)["errors"] == []


def test_archived_evidence_is_excluded_and_checker_does_not_flag_itself(tmp_path):
    write_workflow(tmp_path)
    marker = "[" + " ".join(("skip", "ci")) + "]"
    for relative in ("evidence/history/source/example.py", "docs/archive/example.md"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(marker, encoding="utf-8")
    tool = trigger_tool()
    assert tool.assess(tmp_path)["errors"] == []
    assert not tool.has_commit_directive((ROOT / "tools/check_ci_triggers.py").read_text())
    assert not tool.has_commit_directive(Path(__file__).read_text())


def run_child_pytest(root, test_source, arguments=(), ci=False):
    (root / "conftest.py").write_bytes((ROOT / "tests/conftest.py").read_bytes())
    (root / "test_policy.py").write_text(test_source, encoding="utf-8")
    (root / "pytest.ini").write_text("[pytest]\nmarkers =\n    pq: provider suite\n", encoding="utf-8")
    environment = os.environ.copy()
    for name in ("CI", "GITHUB_ACTIONS", "PYTEST_ADDOPTS"):
        environment.pop(name, None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    if ci:
        environment["GITHUB_ACTIONS"] = "true"
    return subprocess.run([sys.executable, "-m", "pytest", "-q", *arguments],
                          cwd=root, env=environment, capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize("phase", ["test", "collection"])
def test_strict_ci_fails_for_both_test_and_collection_reports(tmp_path, phase):
    if phase == "test":
        source = "import pytest\n@pytest.mark." + "skip(reason='coverage fixture')\n" \
                 "def test_missing_coverage(): pass\n"
    else:
        source = "import pytest\npytest." + "skip('coverage fixture', allow_module_level=True)\n"
        (tmp_path / "test_pass.py").write_text("def test_present(): pass\n", encoding="utf-8")
    result = run_child_pytest(tmp_path, source, ("--strict-ci",))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "skipped reports are missing coverage" in result.stdout


def test_ci_environment_enforces_report_policy_without_extra_flag(tmp_path):
    source = "import pytest\n@pytest.mark." + "skip(reason='coverage fixture')\n" \
             "def test_missing_coverage(): pass\n"
    result = run_child_pytest(tmp_path, source, ci=True)
    assert result.returncode == 1, result.stdout + result.stderr


def test_marker_selection_is_deselection_not_missing_report_coverage(tmp_path):
    source = "import pytest\n@pytest.mark.pq\ndef test_provider(): pass\n" \
             "def test_host(): pass\n"
    result = run_child_pytest(tmp_path, source, ("--strict-ci", "-m", "not pq"), ci=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed, 1 deselected" in result.stdout
