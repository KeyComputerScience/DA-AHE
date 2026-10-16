#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check PR/main-branch CI triggers and reject coverage-suppression mechanisms.

Only active source files and workflow files are scanned for commit directives.
Immutable evidence, archived documentation and frozen source snapshots are not
rewritten or scanned. Event-payload checks cover only supplied commit messages;
they do not claim to inspect every commit in a pull request.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PRIMARY_BRANCH = "main"
SOURCE_DIRECTORIES = (".github", "src", "daahe", "tests", "tools", "security",
                      "simulation", "embedded", "firmware", "configs", "docs")
EXCLUDED_PARTS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv",
                  "venv", "node_modules", "external", "build", "dist", "runs",
                  "evidence", "archive", "archives", "snapshots", "source-snapshot"}
SOURCE_SUFFIXES = {".py", ".sage", ".c", ".h", ".S", ".ld", ".json", ".toml",
                   ".yml", ".yaml", ".md", ".txt", ".sh", ".tex"}


def commit_directive_patterns():
    # Assemble the directives so this checker does not flag its own source.
    pairs = (("skip", "ci"), ("ci", "skip"), ("no", "ci"),
             ("skip", "actions"), ("actions", "skip"))
    alternatives = "|".join(re.escape(" ".join(pair)) for pair in pairs)
    bracketed = re.escape("[") + r"\s*(?:" + alternatives + r")\s*" + re.escape("]")
    trailer = re.escape("-".join(("skip", "checks"))) + r"\s*:\s*true\b"
    return (re.compile(bracketed, re.IGNORECASE), re.compile(trailer, re.IGNORECASE))


def has_commit_directive(text):
    return any(pattern.search(text) for pattern in commit_directive_patterns())


def _load_workflow(path):
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for the CI trigger guard; install the dev extra") from exc

    class UniqueLoader(yaml.BaseLoader):
        pass

    def mapping(loader, node):
        result = {}
        for key, value in loader.construct_pairs(node):
            if not isinstance(key, str) or key in result:
                raise ValueError("workflow mapping keys must be unique strings")
            result[key] = value
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid workflow YAML: {exc}") from exc


def _always(condition):
    value = str(condition).strip()
    if value.startswith("${{") and value.endswith("}}"):
        value = value[3:-2].strip()
    return re.sub(r"\s+", "", value).lower() in ("always()", "true")


def _inspect_nodes(value, location, errors):
    if isinstance(value, dict):
        for key, child in value.items():
            child_location = f"{location}.{key}"
            if key in ("continue-on-error", "paths-ignore"):
                errors.append({"location": child_location, "reason": "coverage suppression is forbidden"})
            if key == "if" and not _always(child):
                errors.append({"location": child_location,
                               "reason": "conditional execution can suppress a required check"})
            _inspect_nodes(child, child_location, errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _inspect_nodes(child, f"{location}[{index}]", errors)


def _source_files(root):
    paths = set()
    for directory in SOURCE_DIRECTORIES:
        base = root / directory
        if base.is_dir():
            paths.update(path for path in base.rglob("*") if path.is_file())
    paths.update(path for path in root.iterdir() if path.is_file())
    for path in sorted(paths):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.suffix in SOURCE_SUFFIXES or path.name in {"Makefile", "CMakeLists.txt", "Dockerfile"}:
            yield path


def _commit_messages(event):
    if not isinstance(event, dict):
        raise ValueError("GitHub event payload must be an object")
    commits = event.get("commits", [])
    if not isinstance(commits, list):
        raise ValueError("GitHub event commits must be a list")
    candidates = list(commits)
    head = event.get("head_commit")
    if head is not None:
        candidates.append(head)
    messages = []
    for commit in candidates:
        if not isinstance(commit, dict) or not isinstance(commit.get("message"), str):
            raise ValueError("GitHub event commit entries require string messages")
        messages.append(commit["message"])
    return messages


def assess(root, event=None):
    root = Path(root).resolve()
    errors = []
    directory = root / ".github/workflows"
    workflows = sorted({*directory.glob("*.yml"), *directory.glob("*.yaml")})
    if not workflows:
        errors.append({"location": ".github/workflows", "reason": "no workflows found"})
    for path in workflows:
        location = path.relative_to(root).as_posix()
        try:
            workflow = _load_workflow(path)
            if not isinstance(workflow, dict):
                raise ValueError("workflow must be an object")
            trigger = workflow.get("on")
            if isinstance(trigger, list):
                events = {name: None for name in trigger if isinstance(name, str)}
            elif isinstance(trigger, dict):
                events = trigger
            else:
                events = {}
            for name in ("pull_request", "push"):
                if name not in events:
                    errors.append({"location": f"{location}.on.{name}", "reason": "required trigger missing"})
                elif events[name] not in (None, "", {}) and not (
                        name == "push" and events[name] == {"branches": [PRIMARY_BRANCH]}):
                    errors.append({"location": f"{location}.on.{name}",
                                   "reason": "required trigger must cover every PR or every main-branch change without suppression filters"})
            jobs = workflow.get("jobs")
            if not isinstance(jobs, dict) or not jobs:
                errors.append({"location": f"{location}.jobs", "reason": "workflow requires jobs"})
            _inspect_nodes(workflow, location, errors)
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append({"location": location, "reason": str(exc)})

    for path in _source_files(root):
        if path.is_symlink():
            errors.append({"location": path.relative_to(root).as_posix(),
                           "reason": "active-source symlink cannot bypass directive inspection"})
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        if has_commit_directive(content):
            errors.append({"location": path.relative_to(root).as_posix(),
                           "reason": "commit directive suppressing CI is forbidden in active source"})

    messages = [] if event is None else _commit_messages(event)
    for index, message in enumerate(messages):
        if has_commit_directive(message):
            errors.append({"location": f"event.commit_messages[{index}]",
                           "reason": "commit directive suppressing CI is forbidden"})
    return {
        "schema_version": 1,
        "status": "passed_ci_trigger_policy" if not errors else "failed_ci_trigger_policy",
        "workflow_paths": [path.relative_to(root).as_posix() for path in workflows],
        "event_commit_messages_checked": len(messages),
        "errors": errors,
        "paper_reproduced": False,
        "physical_board_measurements_verified": False,
        "full_system_certified": False,
        "scope": "Static checks for every PR and main-branch push, active-source directives and supplied event commit messages only; immutable evidence is excluded.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--event", type=Path,
                        default=Path(os.environ["GITHUB_EVENT_PATH"]) if os.environ.get("GITHUB_EVENT_PATH") else None)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        event = json.loads(args.event.read_text(encoding="utf-8")) if args.event else None
        report = assess(args.root, event)
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        report = {"schema_version": 1, "status": "failed_ci_trigger_policy", "errors": [str(exc)],
                  "paper_reproduced": False, "physical_board_measurements_verified": False,
                  "full_system_certified": False}
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["status"] == "passed_ci_trigger_policy" else 2


if __name__ == "__main__":
    raise SystemExit(main())
