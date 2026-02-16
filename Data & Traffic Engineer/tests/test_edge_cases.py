"""
Edge-case and robustness tests — maps to TEST_CHECKLIST "Edge Cases / Robustness".
Run from Data & Traffic Engineer: python tests/test_edge_cases.py
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


def test_parse_empty_pcap_root():
    """parse_pcaps with empty pcap-root (no defense_off/defense_on dirs): no crash."""
    with tempfile.TemporaryDirectory(prefix="wf_edge_") as tmp:
        empty_root = os.path.join(tmp, "empty")
        out_dir = os.path.join(tmp, "parsed")
        os.makedirs(empty_root, exist_ok=True)
        r = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "parse_pcaps.py"),
                "--pcap-root", empty_root,
                "--output-dir", out_dir,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=ROLE_DIR,
        )
        assert r.returncode == 0, f"parse_pcaps on empty root should exit 0: {r.stderr}"
        # Manifest may be missing or empty
        manifest_path = os.path.join(out_dir, "manifest.csv")
        if os.path.isfile(manifest_path):
            with open(manifest_path) as f:
                lines = f.readlines()
            assert len(lines) <= 1, "manifest should have at most header when no PCAPs"


def test_build_dataset_empty_manifest():
    """build_dataset with manifest that has no rows: exits with message or 1, no crash."""
    with tempfile.TemporaryDirectory(prefix="wf_edge_") as tmp:
        parsed_dir = os.path.join(tmp, "parsed")
        out_dir = os.path.join(tmp, "dataset")
        os.makedirs(parsed_dir, exist_ok=True)
        with open(os.path.join(parsed_dir, "manifest.csv"), "w") as f:
            f.write("site_id,visit_id,defense_on,pcap_path,packet_count,total_bytes\n")
        r = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "build_dataset.py"),
                "--parsed-dir", parsed_dir,
                "--output-dir", out_dir,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=ROLE_DIR,
        )
        # Script may exit 0 (empty output) or 1 (error message); must not crash
        assert r.returncode in (0, 1), "build_dataset should exit 0 or 1, not crash"


def test_build_dataset_only_bad_sessions():
    """build_dataset with manifest where all sessions have too few packets: no crash."""
    import csv
    with tempfile.TemporaryDirectory(prefix="wf_edge_") as tmp:
        parsed_dir = os.path.join(tmp, "parsed")
        out_dir = os.path.join(tmp, "dataset")
        os.makedirs(os.path.join(parsed_dir, "defense_off", "site_01"), exist_ok=True)
        with open(os.path.join(parsed_dir, "manifest.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["site_id", "visit_id", "defense_on", "pcap_path", "packet_count", "total_bytes"])
            w.writerow(["site_01", "visit_001", "0", "defense_off/site_01/visit_001.pcap", "3", "300"])
        with open(os.path.join(parsed_dir, "defense_off", "site_01", "visit_001.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "size", "direction"])
            for i in range(3):
                w.writerow([0.0, 100, 1])
        r = subprocess.run(
            [
                sys.executable,
                os.path.join(ROLE_DIR, "build_dataset.py"),
                "--parsed-dir", parsed_dir,
                "--output-dir", out_dir,
                "--min-packets", "100",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=ROLE_DIR,
        )
        assert r.returncode in (0, 1), "should not crash"


def test_capture_invalid_interface():
    """capture.py with invalid --interface: tshark error; script reports failure (non-zero exit)."""
    r = subprocess.run(
        [
            sys.executable,
            os.path.join(ROLE_DIR, "capture.py"),
            "--root", os.path.join(tempfile.gettempdir(), "wf_nonexistent_capture"),
            "--interface", "nonexistent_interface_99999",
            "--site-id", "site_01",
            "--visit-id", "visit_001",
            "--duration", "1",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=ROLE_DIR,
    )
    assert r.returncode != 0, "capture with invalid interface should fail"


def run():
    test_parse_empty_pcap_root()
    test_build_dataset_empty_manifest()
    test_build_dataset_only_bad_sessions()
    test_capture_invalid_interface()
    print("test_edge_cases: all passed")


if __name__ == "__main__":
    run()
