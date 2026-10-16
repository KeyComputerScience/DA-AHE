# SPDX-License-Identifier: MIT
"""CI treats every skipped report as missing coverage, including collection."""
from __future__ import annotations

import os

import pytest


def _ci_enabled() -> bool:
    return any(os.environ.get(name, "").strip().lower() not in ("", "0", "false", "no")
               for name in ("CI", "GITHUB_ACTIONS"))


def pytest_addoption(parser):
    parser.addoption("--strict-ci", action="store_true", default=False,
                     help="Fail the session on any skipped test or collection report (automatic in CI).")


class StrictCIReports:
    def __init__(self):
        self.skipped = []

    def pytest_runtest_logreport(self, report):
        if report.skipped:
            self.skipped.append((report.nodeid, report.when))

    def pytest_collectreport(self, report):
        if report.skipped:
            self.skipped.append((report.nodeid, "collection"))

    def pytest_sessionfinish(self, session, exitstatus):
        if self.skipped and session.exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter):
        if self.skipped:
            terminalreporter.write_sep("=", "strict CI: skipped reports are missing coverage", red=True)
            for nodeid, phase in self.skipped:
                terminalreporter.write_line(f"{nodeid} [{phase}]", red=True)


def pytest_configure(config):
    if config.getoption("strict_ci") or _ci_enabled():
        config.pluginmanager.register(StrictCIReports(), "daahe-strict-ci-reports")
