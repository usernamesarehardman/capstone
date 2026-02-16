"""
Documentation/CLI tests — maps to TEST_CHECKLIST "Documentation and Paths" (--help).
Run from Data & Traffic Engineer: python tests/test_docs.py
"""

from __future__ import annotations

import os
import subprocess
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROLE_DIR = os.path.dirname(TESTS_DIR)
if os.getcwd() != ROLE_DIR:
    os.chdir(ROLE_DIR)
if ROLE_DIR not in sys.path:
    sys.path.insert(0, ROLE_DIR)


def run_help(script: str) -> str:
    cmd = [sys.executable, os.path.join(ROLE_DIR, script), "--help"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd=ROLE_DIR)
    assert r.returncode == 0, f"{script} --help failed: {r.stderr}"
    return r.stdout


def test_capture_help():
    out = run_help("capture.py")
    assert "capture" in out.lower() and ("--root" in out or "root" in out)
    assert "--interface" in out or "-i" in out


def test_parse_pcaps_help():
    out = run_help("parse_pcaps.py")
    assert "pcap" in out.lower()
    assert "--pcap-root" in out or "pcap-root" in out


def test_build_dataset_help():
    out = run_help("build_dataset.py")
    assert "parsed" in out.lower() or "dataset" in out.lower()
    assert "--parsed-dir" in out or "parsed-dir" in out


def test_rebuild_dataset_help():
    out = run_help("rebuild_dataset.py")
    assert "pcap" in out.lower() or "rebuild" in out.lower()
    assert "--pcap-root" in out or "pcap-root" in out


def run():
    test_capture_help()
    test_parse_pcaps_help()
    test_build_dataset_help()
    test_rebuild_dataset_help()
    print("test_docs: all passed")


if __name__ == "__main__":
    run()
