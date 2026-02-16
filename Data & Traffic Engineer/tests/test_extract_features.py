"""
Unit tests for extract_features — maps to TEST_CHECKLIST "extract_features.py (unit-level)".
Run from Data & Traffic Engineer: python tests/test_extract_features.py
"""

from __future__ import annotations

import os
import sys

import pandas as pd

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROLE_DIR = os.path.dirname(TESTS_DIR)
if os.getcwd() != ROLE_DIR:
    os.chdir(ROLE_DIR)
if ROLE_DIR not in sys.path:
    sys.path.insert(0, ROLE_DIR)

from extract_features import DEFAULT_MAX_PACKETS, session_to_vector


def test_session_to_vector_shape():
    """Output shape = 3 * max_packets when include_iat=True."""
    df = pd.DataFrame({
        "timestamp": [0.0, 0.1, 0.2],
        "size": [100, 200, 150],
        "direction": [1, -1, 1],
    })
    v = session_to_vector(df, max_packets=10, include_iat=True)
    expected_len = 10 + 10 + 10
    assert v.shape == (expected_len,), f"expected shape ({expected_len},), got {v.shape}"
    assert v.dtype == "float32"


def test_session_to_vector_no_iat():
    """Shape = 2 * max_packets when include_iat=False."""
    df = pd.DataFrame({
        "timestamp": [0.0, 0.1],
        "size": [100, 200],
        "direction": [1, -1],
    })
    v = session_to_vector(df, max_packets=5, include_iat=False)
    assert v.shape == (10,)


def test_session_to_vector_truncate():
    """More packets than max_packets -> truncate to max_packets."""
    n = 100
    df = pd.DataFrame({
        "timestamp": [float(i) * 0.01 for i in range(n)],
        "size": [100] * n,
        "direction": [1] * n,
    })
    v = session_to_vector(df, max_packets=20, include_iat=True)
    assert v.shape == (60,)  # 20*3


def run():
    test_session_to_vector_shape()
    test_session_to_vector_no_iat()
    test_session_to_vector_truncate()
    print("test_extract_features: all passed")


if __name__ == "__main__":
    run()
