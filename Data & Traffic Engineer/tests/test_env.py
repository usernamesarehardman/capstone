"""
Environment tests — maps to TEST_CHECKLIST.md "Environment" section.
Run from Data & Traffic Engineer directory: python tests/test_env.py
"""

from __future__ import annotations

import os
import subprocess
import sys

# Run from role directory
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROLE_DIR = os.path.dirname(TESTS_DIR)
if os.getcwd() != ROLE_DIR:
    os.chdir(ROLE_DIR)
if ROLE_DIR not in sys.path:
    sys.path.insert(0, ROLE_DIR)


def test_python_version():
    """Python 3.8+ available."""
    assert sys.version_info >= (3, 8), "Python 3.8+ required"


def test_tshark_on_path():
    """tshark on PATH (skip if not installed; checklist item remains manual)."""
    try:
        r = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert r.returncode == 0, "tshark --version should succeed"
    except FileNotFoundError:
        print("SKIP test_tshark_on_path: tshark not on PATH; install Wireshark/tshark for full checklist")


def test_pyshark_optional():
    """(Optional) PyShark import works."""
    try:
        import pyshark  # noqa: F401
    except ImportError:
        # Optional; skip or pass
        pass


def test_required_imports():
    """Required packages import (pandas, numpy)."""
    import pandas as pd  # noqa: F401
    import numpy as np   # noqa: F401
    assert pd is not None and np is not None


def run():
    test_python_version()
    test_tshark_on_path()
    test_pyshark_optional()
    test_required_imports()
    print("test_env: all passed")


if __name__ == "__main__":
    run()
