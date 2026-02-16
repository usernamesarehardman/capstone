# Scripted Tests for Data & Traffic Engineer Pipeline

These tests align with [../TEST_CHECKLIST.md](../TEST_CHECKLIST.md). Run them from the **Data & Traffic Engineer** directory (parent of `tests/`).

## How to run

From `Data & Traffic Engineer`:

```bash
# Run all test scripts
python -m pytest tests/ -v

# Or run each script directly (no pytest required)
python tests/test_env.py
python tests/test_extract_features.py
python tests/test_docs.py
python tests/test_capture.py
python tests/test_parse.py
python tests/test_build_dataset.py
python tests/test_rebuild.py
python tests/test_edge_cases.py
```

Some tests require **tshark** and a valid capture interface (e.g. `0` or loopback). They are skipped if tshark is missing or capture fails.

## Mapping to TEST_CHECKLIST.md

| Test script | Checklist section |
|-------------|-------------------|
| test_env.py | Environment |
| test_capture.py | capture.py |
| test_parse.py | parse_pcaps.py |
| test_extract_features.py | extract_features.py (unit-level) |
| test_build_dataset.py | build_dataset.py |
| test_rebuild.py | rebuild_dataset.py |
| test_edge_cases.py | Edge Cases / Robustness |
| test_docs.py | Documentation and Paths (--help) |

## Dependencies

- Python 3.8+
- Installed: `pip install -r ../requirements.txt`
- Optional: `pytest` for `python -m pytest tests/`
- For capture/parse/rebuild tests: **tshark** on PATH and a working interface
