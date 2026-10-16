# SPDX-License-Identifier: MIT
"""No-wrap reports identify the active tuple without promoting arithmetic to proof."""
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys

from daahe.mlwe import DEFAULT_PARAMETERS


def test_no_wrap_output_binds_active_parameters_and_preserves_certificate_scope(tmp_path):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "bounds.json"
    result = subprocess.run([sys.executable, str(root / "tools/check_reference_bounds.py"),
                             "--output", str(output)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text())
    assert report["encryption_parameters"] == asdict(DEFAULT_PARAMETERS)
    assert report["encryption_parameters"]["k"] == 6
    assert report["ciphertext_bytes"] == 7168
    assert report["paper_reproduced"] is False
    assert report["full_system_certified"] is False
    assert "does not certify security, decoding, timing, energy or workspace" in report["parameter_scope"]
    assert all(row["no_wrap_arithmetic_passed"] and not row["certified"]
               and row["remaining_gates"] for row in report["profiles"])
    published = output.read_bytes()
    repeated = subprocess.run([sys.executable, str(root / "tools/check_reference_bounds.py"),
                               "--output", str(output)], capture_output=True, text=True)
    assert repeated.returncode != 0
    assert output.read_bytes() == published
