# WF-Guard Data Pipeline — Reproduction and Usage

This document describes how to reproduce the dataset and run the full pipeline from raw PCAPs to feature files and overhead metrics.

## Prerequisites

- **Python**: 3.8+
- **Wireshark/tshark**: Installed and on PATH (used for live capture and optionally for parsing).
- **Tor Browser**: For generating traffic; when Defense is ON, configure it to use the Defense proxy (e.g. 127.0.0.1:PORT). See Defense & Integration Engineer docs for proxy setup.

### Python Environment

From the `Data & Traffic Engineer` directory:

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

### Interface Verification

1. List capture interfaces: `tshark -D`
2. Start Tor Browser (and optionally the defense proxy). Load a page.
3. Run a short capture on the interface that carries Tor/proxy traffic, e.g.:
   ```bash
   tshark -i <interface> -w test.pcap -c 100
   ```
4. Confirm packets are present. Document the interface name or index in DESIGN.md or here.

## Directory Layout and Naming

- **Root**: e.g. `data/` or `pcaps/` (configurable in scripts).
- **Layout**: `{defense_on|defense_off}/{site_id}/visit_{visit_id}.pcap`
- **Manifest**: CSV or JSON with columns `site_id`, `visit_id`, `defense_on`, `pcap_path`, optional `capture_duration_s`. See DESIGN.md for full schema.

## Pipeline Steps

### 1. Capture (Raw PCAPs)

- **Script**: `capture.py`
- **Usage**: Start capture before loading a URL in Tor Browser; stop after a fixed timeout or network idle. PCAPs are written to the agreed layout. Toggle Defense ON/OFF via the Defense proxy as needed; use separate runs or folders for each.
- **Output**: PCAP files under `defense_off/<site_id>/` and `defense_on/<site_id>/`.

### 2. Parse (PCAP → Per-Session Series)

- **Script**: `parse_pcaps.py`
- **Input**: Root directory containing `defense_off/` and `defense_on/` with PCAPs.
- **Process**: Read each PCAP; extract timestamps, packet sizes, and direction (e.g. +1 outbound / -1 inbound); filter to Tor-related traffic only (filter documented in script and DESIGN.md).
- **Output**: Per-session structured data (CSV or Parquet): `timestamp`, `size`, `direction` per packet, plus session metadata (site_id, visit_id, defense_on). Optional manifest of parsed sessions.

### 3. Feature Extraction and Dataset Build

- **Script**: `build_dataset.py` (and/or `extract_features.py`)
- **Input**: Parsed session files (or manifest).
- **Process**:
  - Build packet size sequences, direction encoding (+1/-1), and inter-packet timing.
  - Pad or truncate to fixed length; normalize as needed.
  - Quality checks: drop or flag incomplete/corrupted captures; enforce balance (equal samples per site and Defense ON/OFF).
  - Split into train/validation/test with no visit leakage.
- **Output**: Feature matrices (e.g. NumPy or CSV) for train/val/test; optional overhead export (packet counts, total bytes per session).

### 4. Rebuild from Raw PCAPs

- **Script**: `rebuild_dataset.py`
- **Usage**: Point at root of raw PCAPs; runs parsing → feature extraction → split in sequence.
- **Output**: Same as step 3; ensures the dataset can be reproduced from PCAPs only.

## Reproducing the Dataset from PCAPs

1. Install prerequisites and Python deps (see above).
2. Place raw PCAPs in the agreed layout under a root directory.
3. Run:
   ```bash
   python rebuild_dataset.py --pcap-root <path_to_pcaps> --output-dir <path_to_output>
   ```
4. Optionally run steps 2 and 3 separately:
   ```bash
   python parse_pcaps.py --pcap-root <path_to_pcaps> --output-dir parsed
   python build_dataset.py --parsed-dir parsed --output-dir dataset
   ```
   Or use `rebuild_dataset.py` once: parsed output goes to `--parsed-dir` or `<output-dir>/parsed` by default.

## Defense Comparison and Overhead

- **Matched ON vs OFF**: Use the same site set and same number of visits per site for Defense ON and OFF so accuracy comparison is fair.
- **Overhead metrics**: Export packet counts and total bytes per session (and optionally per site / Defense ON vs OFF) for the Defense & Integration Engineer to compute bandwidth cost and latency (e.g. page load time).

## File Reference

| File | Purpose |
|------|--------|
| DESIGN.md | Interface choice, directory layout, naming, labeling scheme |
| requirements.txt | Python dependencies |
| capture.py | Live traffic capture per visit |
| parse_pcaps.py | PCAP → timestamps, sizes, directions (Tor-only) |
| build_dataset.py | Feature extraction, quality, balance, train/val/test split |
| extract_features.py | Core feature extraction (may be called by build_dataset.py) |
| rebuild_dataset.py | Full pipeline: parse → features → split from PCAP root |
| DATA_PIPELINE.md | This document |
