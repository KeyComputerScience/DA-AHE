# SPDX-License-Identifier: MIT
"""Checkout shim: use the same canonical sources as the installed package."""
from pathlib import Path

__path__ = [str(Path(__file__).resolve().parent.parent / "src" / "daahe")]
__version__ = "0.3.0"

