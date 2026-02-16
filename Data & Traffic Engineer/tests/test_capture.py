"""
Tests for capture.py — maps to TEST_CHECKLIST "capture.py" section.
Requires tshark and a valid interface (e.g. 0). Skips if tshark missing.
Run from Data & Traffic Engineer: python tests/test_capture.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROLE_DIR = os.path.dirname(TESTS_DIR)
if os.getcwd() != ROLE_DIR:
    os.chdir(ROLE_DIR)
if ROLE_DIR not in sys.path:
    sys.path.insert(0, ROLE_DIR)


def tshark_available() -> bool:
    try:
        r = subprocess.run(["tshark", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def test_list_interfaces():
    """capture.py --list-interfaces prints at least one line (or exits 0)."""
    if not tshark_available():
        print("SKIP test_capture: tshark not found")
        return
    r = subprocess.run(
        [sys.executable, os.path.join(ROLE_DIR, "capture.py"), "--list-interfaces"],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=ROLE_DIR,
    )
    assert r.returncode == 0, f"capture --list-interfaces failed: {r.stderr}"
    lines = [l for l in (r.stdout or "").strip().splitlines() if l.strip()]
    assert len(lines) >= 1, "Expected at least one interface from tshark -D"


def test_capture_defense_off():
    """Short capture writes defense_off/site_01/visit_001.pcap."""
    if not tshark_available():
        print("SKIP test_capture: tshark not found")
        return
    with tempfile.TemporaryDirectory(prefix="wf_capture_") as tmp:
        r = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "capture.py"),
                "--root", tmp,
                "--interface", "0",
                "--site-id", "site_01",
                "--visit-id", "visit_001",
                "--duration", "2",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=ROLE_DIR,
        )
        assert r.returncode == 0, f"capture failed: {r.stderr}"
        pcap = os.path.join(tmp, "defense_off", "site_01", "visit_001.pcap")
        assert os.path.isfile(pcap), f"Expected {pcap} to exist"


def test_capture_defense_on():
    """Capture with --defense-on writes defense_on/site_01/visit_001.pcap."""
    if not tshark_available():
        print("SKIP test_capture: tshark not found")
        return
    with tempfile.TemporaryDirectory(prefix="wf_capture_") as tmp:
        r = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "capture.py"),
                "--root", tmp,
                "--interface", "0",
                "--site-id", "site_01",
                "--visit-id", "visit_001",
                "--duration", "2",
                "--defense-on",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=ROLE_DIR,
        )
        assert r.returncode == 0, f"capture --defense-on failed: {r.stderr}"
        pcap = os.path.join(tmp, "defense_on", "site_01", "visit_001.pcap")
        assert os.path.isfile(pcap), f"Expected {pcap} to exist"


def run():
    test_list_interfaces()
    test_capture_defense_off()
    test_capture_defense_on()
    print("test_capture: all passed")


if __name__ == "__main__":
    run()
