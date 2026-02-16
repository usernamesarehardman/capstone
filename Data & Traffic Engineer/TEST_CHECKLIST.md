# WF-Guard Data & Traffic Engineer — Test Checklist

Use this checklist to verify pipeline functionality. Work through in order where steps depend on prior outputs.

**Scripted tests:** Run automated tests from the `Data & Traffic Engineer` directory:
`python tests/test_env.py` … `python tests/test_edge_cases.py`  
See [tests/README.md](tests/README.md) for full list and `python -m pytest tests/ -v`.

---

## Environment

- [ ] Python 3.8+ available: `python --version`
- [ ] Venv created and activated; `pip install -r requirements.txt` runs without error
- [ ] `tshark` on PATH: `tshark --version`
- [ ] (Optional) PyShark import works: `python -c "import pyshark; print('ok')"`

---

## capture.py

- [ ] `python capture.py --list-interfaces` prints at least one interface (no crash)
- [ ] Run a short capture (e.g. 5 seconds) to a test path:
  - `python capture.py --root data --interface 0 --site-id site_01 --visit-id visit_001 --duration 5`
- [ ] File exists: `data/defense_off/site_01/visit_001.pcap`
- [ ] Repeat with `--defense-on`; file exists: `data/defense_on/site_01/visit_001.pcap`
- [ ] Capture stops after `--duration` (no hang)
- [ ] (Optional) With Tor Browser open and loading a page, run capture and confirm PCAP has non-zero packets (open in Wireshark or run tshark -r file -c 5)

---

## parse_pcaps.py

- [ ] With at least one PCAP under `data/defense_off/site_01/` (and optionally `data/defense_on/`), run:
  - `python parse_pcaps.py --pcap-root data --output-dir parsed`
- [ ] No unhandled exception
- [ ] `parsed/manifest.csv` exists and has columns: site_id, visit_id, defense_on, pcap_path, packet_count, total_bytes
- [ ] At least one row in manifest
- [ ] Per-session file exists, e.g. `parsed/defense_off/site_01/visit_001.csv`
- [ ] Session CSV has columns: timestamp, size, direction; non-empty rows
- [ ] (Optional) Run with `--format parquet`; corresponding `.parquet` files created
- [ ] (Optional) Run with `--use-tshark`; parsing still completes (for environments without PyShark)

---

## extract_features.py (unit-level)

- [ ] Import and run on a tiny DataFrame:
  - `python -c "import pandas as pd; from extract_features import session_to_vector; df=pd.DataFrame({'timestamp':[0,0.1,0.2],'size':[100,200,150],'direction':[1,-1,1]}); v=session_to_vector(df, max_packets=10); print(v.shape)"`
- [ ] Output shape is as expected (e.g. 30 for max_packets=10 and include_iat=True: 10+10+10)

---

## build_dataset.py

- [ ] After parsing (parsed/ and manifest.csv exist), run:
  - `python build_dataset.py --parsed-dir parsed --output-dir dataset`
- [ ] No unhandled exception
- [ ] `dataset/X_train.npy`, `dataset/X_val.npy`, `dataset/X_test.npy` exist
- [ ] Load and check shape: `python -c "import numpy as np; x=np.load('dataset/X_train.npy'); print(x.shape)"` — rank 2, second dim = 3 * max_packets (default 6000)
- [ ] `dataset/metadata_train.csv`, `metadata_val.csv`, `metadata_test.csv` exist and have session metadata
- [ ] `dataset/overhead_per_session.csv` exists with packet_count and total_bytes columns
- [ ] (Optional) Run with `--no-balance`; run completes
- [ ] (Optional) Run with `--min-packets 100`; if all sessions have &lt; 100 packets, output is empty or reduced (no crash)

---

## rebuild_dataset.py

- [ ] With raw PCAPs in `data/` (defense_off/ and/or defense_on/ layout), run:
  - `python rebuild_dataset.py --pcap-root data --output-dir dataset`
- [ ] Step 1 (parsing) runs and writes to parsed dir (default `dataset/parsed` or explicit `--parsed-dir`)
- [ ] Step 2 (build_dataset) runs and writes feature matrices to `dataset/`
- [ ] Same artifacts as running parse_pcaps + build_dataset separately
- [ ] (Optional) Run with `--parsed-dir my_parsed --output-dir my_dataset`; parsed output in `my_parsed`, feature output in `my_dataset`

---

## Edge Cases / Robustness

- [ ] parse_pcaps with empty `--pcap-root` (no defense_off/defense_on dirs): no crash; manifest empty or missing
- [ ] parse_pcaps with a single empty or corrupt PCAP: script continues; failed file reported or skipped
- [ ] build_dataset with manifest that has no rows or only bad (too few packets) sessions: exits with message or empty output (no crash)
- [ ] capture.py with invalid `--interface`: tshark error; script reports failure

---

## Documentation and Paths

- [ ] DESIGN.md describes layout and manifest schema; matches script behavior
- [ ] DATA_PIPELINE.md commands (venv, parse, build, rebuild) match script CLI options
- [ ] All script `--help` outputs are readable and accurate

---

## Sign-off

- [ ] All critical items above checked
- [ ] Notes / issues (if any): _________________________________________________
