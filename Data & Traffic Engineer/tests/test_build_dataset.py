"""
Tests for build_dataset.py — maps to TEST_CHECKLIST "build_dataset.py" section.
Builds a minimal parsed/ dir (manifest + one session CSV), then runs build_dataset.
Run from Data & Traffic Engineer: python tests/test_build_dataset.py
"""

from __future__ import annotations

import os
import sys
import tempfile

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROLE_DIR = os.path.dirname(TESTS_DIR)
if os.getcwd() != ROLE_DIR:
    os.chdir(ROLE_DIR)
if ROLE_DIR not in sys.path:
    sys.path.insert(0, ROLE_DIR)


def test_build_dataset_produces_artifacts():
    """After parsing, build_dataset produces X_train/val/test.npy, metadata CSVs, overhead."""
    import subprocess
    import csv
    with tempfile.TemporaryDirectory(prefix="wf_build_") as tmp:
        parsed_dir = os.path.join(tmp, "parsed")
        out_dir = os.path.join(tmp, "dataset")
        os.makedirs(os.path.join(parsed_dir, "defense_off", "site_01"), exist_ok=True)
        # Manifest: enough sessions so 70/15/15 split gives >= 1 per split (use 10)
        manifest_path = os.path.join(parsed_dir, "manifest.csv")
        visit_ids = [f"visit_{i:03d}" for i in range(1, 11)]
        with open(manifest_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["site_id", "visit_id", "defense_on", "pcap_path", "packet_count", "total_bytes"])
            for vid in visit_ids:
                w.writerow(["site_01", vid, "0", f"defense_off/site_01/{vid}.pcap", "50", "5000"])
        # Session CSVs: 50 rows each so they pass min_packets
        for vid in visit_ids:
            session_path = os.path.join(parsed_dir, "defense_off", "site_01", f"{vid}.csv")
            with open(session_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["timestamp", "size", "direction"])
                for i in range(50):
                    w.writerow([0.0 + i * 0.01, 100 + (i % 10) * 10, 1 if i % 2 == 0 else -1])
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
        assert r.returncode == 0, f"build_dataset failed: {r.stderr}"
        assert os.path.isfile(os.path.join(out_dir, "X_train.npy")), "X_train.npy"
        assert os.path.isfile(os.path.join(out_dir, "X_val.npy")), "X_val.npy"
        assert os.path.isfile(os.path.join(out_dir, "X_test.npy")), "X_test.npy"
        assert os.path.isfile(os.path.join(out_dir, "metadata_train.csv")), "metadata_train.csv"
        assert os.path.isfile(os.path.join(out_dir, "metadata_val.csv")), "metadata_val.csv"
        assert os.path.isfile(os.path.join(out_dir, "metadata_test.csv")), "metadata_test.csv"
        overhead_path = os.path.join(out_dir, "overhead_per_session.csv")
        assert os.path.isfile(overhead_path), "overhead_per_session.csv"
        with open(overhead_path) as f:
            h = f.readline().strip().lower()
        assert "packet_count" in h and "total_bytes" in h


def test_build_dataset_feature_shape():
    """X_train has rank 2 and second dim = 3 * max_packets (default 6000)."""
    import subprocess
    import csv
    import numpy as np
    with tempfile.TemporaryDirectory(prefix="wf_build2_") as tmp:
        parsed_dir = os.path.join(tmp, "parsed")
        out_dir = os.path.join(tmp, "dataset")
        os.makedirs(os.path.join(parsed_dir, "defense_off", "site_01"), exist_ok=True)
        visit_ids = [f"visit_{i:03d}" for i in range(1, 11)]
        with open(os.path.join(parsed_dir, "manifest.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["site_id", "visit_id", "defense_on", "pcap_path", "packet_count", "total_bytes"])
            for vid in visit_ids:
                w.writerow(["site_01", vid, "0", f"defense_off/site_01/{vid}.pcap", "50", "5000"])
        for vid in visit_ids:
            with open(os.path.join(parsed_dir, "defense_off", "site_01", f"{vid}.csv"), "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["timestamp", "size", "direction"])
                for i in range(50):
                    w.writerow([0.0 + i * 0.01, 100, 1])
        subprocess.run(
            [sys.executable, os.path.join(ROLE_DIR, "build_dataset.py"), "--parsed-dir", parsed_dir, "--output-dir", out_dir],
            capture_output=True,
            timeout=30,
            cwd=ROLE_DIR,
            check=True,
        )
        X = np.load(os.path.join(out_dir, "X_train.npy"))
        assert X.ndim == 2, f"Expected rank 2, got {X.ndim}"
        # Default max_packets=2000 -> 6000 features per sample
        assert X.shape[1] == 6000, f"Expected second dim 6000, got {X.shape[1]}"


def run():
    test_build_dataset_produces_artifacts()
    test_build_dataset_feature_shape()
    print("test_build_dataset: all passed")


if __name__ == "__main__":
    run()
