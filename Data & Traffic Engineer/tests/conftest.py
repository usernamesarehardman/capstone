"""
Pytest conftest: ensure tests run with Data & Traffic Engineer as cwd so imports work.
"""

from __future__ import annotations

import os
import sys

# Parent of tests/ = Data & Traffic Engineer
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROLE_DIR = os.path.dirname(TESTS_DIR)

if os.getcwd() != ROLE_DIR:
    os.chdir(ROLE_DIR)
if ROLE_DIR not in sys.path:
    sys.path.insert(0, ROLE_DIR)
