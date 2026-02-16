"""
Tests for rebuild_dataset.py — maps to TEST_CHECKLIST "rebuild_dataset.py" section.
Runs full pipeline from PCAP root. Requires tshark and a working interface. Skips if capture fails.
Run from Data & Traffic Engineer: python tests/test_rebuild.py
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


def test_rebuild_from_pcap_root():
    """rebuild_dataset --pcap-root data --output-dir dataset produces parsed + feature artifacts."""
    if not tshark_available():
        print("SKIP test_rebuild: tshark not found")
        return
    with tempfile.TemporaryDirectory(prefix="wf_rebuild_") as tmp:
        pcap_root = os.path.join(tmp, "data")
        out_dir = os.path.join(tmp, "dataset")
        os.makedirs(os.path.join(pcap_root, "defense_off", "site_01"), exist_ok=True)
        cap = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "capture.py"),
                "--root", pcap_root,
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
        if cap.returncode != 0 or not os.path.isfile(os.path.join(pcap_root, "defense_off", "site_01", "visit_001.pcap")):
            print("SKIP test_rebuild: could not create test PCAP")
            return
        r = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "rebuild_dataset.py"),
                "--pcap-root", pcap_root,
                "--output-dir", out_dir,
            ],
            capture_output=True,
            text=True,
            timeout=90,
            cwd=ROLE_DIR,
        )
        assert r.returncode == 0, f"rebuild_dataset failed: {r.stderr}"
        # Default: parsed goes to <output-dir>/parsed
        parsed_dir = os.path.join(out_dir, "parsed")
        assert os.path.isfile(os.path.join(parsed_dir, "manifest.csv")), "parsed/manifest.csv"
        assert os.path.isfile(os.path.join(out_dir, "X_train.npy")), "X_train.npy"
        assert os.path.isfile(os.path.join(out_dir, "overhead_per_session.csv")), "overhead_per_session.csv"


def test_rebuild_custom_parsed_dir():
    """rebuild_dataset with --parsed-dir and --output-dir puts parsed and dataset in specified dirs."""
    if not tshark_available():
        print("SKIP test_rebuild: tshark not found")
        return
    with tempfile.TemporaryDirectory(prefix="wf_rebuild2_") as tmp:
        pcap_root = os.path.join(tmp, "data")
        parsed_dir = os.path.join(tmp, "my_parsed")
        out_dir = os.path.join(tmp, "my_dataset")
        os.makedirs(os.path.join(pcap_root, "defense_off", "site_01"), exist_ok=True)
        cap = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "capture.py"),
                "--root", pcap_root,
                "--interface", "0",
                "--site-id", "site_01",
                "--visit-id", "visit_001",
                "--duration", "2",
            ],
            capture_output=True,
            timeout=15,
            cwd=ROLE_DIR,
        )
        if cap.returncode != 0 or not os.path.isfile(os.path.join(pcap_root, "defense_off", "site_01", "visit_001.pcap")):
            print("SKIP test_rebuild custom dirs: could not create test PCAP")
            return
        r = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "rebuild_dataset.py"),
                "--pcap-root", pcap_root,
                "--output-dir", out_dir,
                "--parsed-dir", parsed_dir,
            ],
            capture_output=True,
            text=True,
            timeout=90,
            cwd=ROLE_DIR,
        )
        assert r.returncode == 0, f"rebuild_dataset failed: {r.stderr}"
        assert os.path.isfile(os.path.join(parsed_dir, "manifest.csv")), "my_parsed/manifest.csv"
        assert os.path.isfile(os.path.join(out_dir, "X_train.npy")), "my_dataset/X_train.npy"


def run():
    test_rebuild_from_pcap_root()
    test_rebuild_custom_parsed_dir()
    print("test_rebuild: all passed")


if __name__ == "__main__":
    run()
