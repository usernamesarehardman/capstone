"""
Tests for parse_pcaps.py — maps to TEST_CHECKLIST "parse_pcaps.py" section.
Uses a short live capture to get one PCAP, then runs parser. Skips if tshark missing.
Run from Data & Traffic Engineer: python tests/test_parse.py
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


def test_parse_produces_manifest_and_session():
    """Parse PCAPs -> manifest.csv and per-session CSV with timestamp, size, direction."""
    if not tshark_available():
        print("SKIP test_parse: tshark not found")
        return
    with tempfile.TemporaryDirectory(prefix="wf_parse_") as tmp:
        pcap_root = os.path.join(tmp, "data")
        out_dir = os.path.join(tmp, "parsed")
        os.makedirs(os.path.join(pcap_root, "defense_off", "site_01"), exist_ok=True)
        # Create one PCAP via short capture
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
        if cap.returncode != 0:
            print("SKIP test_parse: capture failed (no interface?)")
            return
        pcap_path = os.path.join(pcap_root, "defense_off", "site_01", "visit_001.pcap")
        if not os.path.isfile(pcap_path):
            print("SKIP test_parse: no pcap produced")
            return
        r = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "parse_pcaps.py"),
                "--pcap-root", pcap_root,
                "--output-dir", out_dir,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=ROLE_DIR,
        )
        assert r.returncode == 0, f"parse_pcaps failed: {r.stderr}"
        manifest_path = os.path.join(out_dir, "manifest.csv")
        assert os.path.isfile(manifest_path), f"Expected {manifest_path}"
        with open(manifest_path) as f:
            header = f.readline().strip().lower()
        for col in ["site_id", "visit_id", "defense_on", "pcap_path", "packet_count", "total_bytes"]:
            assert col in header, f"manifest should have column {col}"
        session_csv = os.path.join(out_dir, "defense_off", "site_01", "visit_001.csv")
        assert os.path.isfile(session_csv), f"Expected session file {session_csv}"
        with open(session_csv) as f:
            sess_header = f.readline().strip().lower()
        for col in ["timestamp", "size", "direction"]:
            assert col in sess_header, f"session CSV should have {col}"


def run():
    test_parse_produces_manifest_and_session()
    print("test_parse: all passed")


if __name__ == "__main__":
    run()
