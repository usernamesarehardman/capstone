# WF-Guard Data & Traffic Engineer — Design Note

This document records design decisions for the traffic capture, storage, and labeling scheme used in the WF-Guard capstone pipeline.

## Environment

- **Python**: 3.8+
- **Capture/parsing**: Wireshark/tshark (required for live capture), PyShark for Python bindings. Scapy is an optional alternative for parsing.
- **Interface**: Tor traffic is captured on the interface that carries Tor (and optionally the defense proxy) traffic. Typical choices:
  - **Windows**: The network adapter used by Tor (e.g. where Tor Browser sends traffic). May be Ethernet or Wi-Fi; verify with `tshark -D` and use the interface index or name that sees traffic to Tor’s SOCKS port (default 9150 for Tor Browser) or through the defense proxy (e.g. 127.0.0.1).
  - **Loopback (127.0.0.1)**: If the defense proxy runs locally, capture on loopback to see Tor Browser → proxy → Tor; confirm the proxy listens on a known host/port (e.g. 127.0.0.1:PORT).
- **Verification**: Run a short tshark capture while loading a page in Tor Browser and confirm packets appear; document the chosen interface name/index in this file or in DATA_PIPELINE.md.

## Directory Layout

All raw PCAPs and derived data live under a single root (e.g. `data/` or `pcaps/`). Layout:

```
<root>/
  defense_off/
    <site_id>/
      visit_<visit_id>.pcap
  defense_on/
    <site_id>/
      visit_<visit_id>.pcap
```

- **site_id**: Zero-padded identifier for the monitored site (e.g. `site_01`, `site_02`). Fixed set of sites; same sites used for both Defense ON and OFF.
- **visit_id**: Zero-padded per-site visit index (e.g. `visit_001`, `visit_002`). Each file is one page load / one visit.
- **Defense ON vs OFF**: Separate top-level folders so the label is explicit from path; Defense Engineer toggles proxy so that “Defense ON” captures go under `defense_on/` and “Defense OFF” under `defense_off/`.

## Naming Convention

- **PCAP files**: `visit_<visit_id>.pcap` (e.g. `visit_001.pcap`).
- **Site folders**: `<site_id>` (e.g. `site_01`).
- **Parsed output**: Same logical naming; e.g. parsed CSVs/Parquet can use `visit_<visit_id>.csv` under `parsed/defense_off/<site_id>/` and `parsed/defense_on/<site_id>/`, or a single manifest that references these paths.

## Labeling Scheme

A **manifest** (CSV or JSON) lists every captured (and later, every parsed) session. Suggested schema:

| Field               | Type   | Description                                      |
|---------------------|--------|--------------------------------------------------|
| `site_id`           | string | e.g. `site_01`                                  |
| `visit_id`          | string | e.g. `visit_001`                                |
| `defense_on`        | bool   | True if from `defense_on/`, False if `defense_off/` |
| `pcap_path`         | string | Relative path from root to the PCAP file        |
| `capture_duration_s`| float  | Optional; duration of capture in seconds        |

- **Site IDs and visit IDs**: Defined upfront; fixed number of monitored sites and fixed (equal) number of samples per site for both Defense ON and OFF to avoid class imbalance.
- **Defense ON vs OFF**: Inferred from path (`defense_on` vs `defense_off`) and recorded in the manifest for downstream feature extraction and splitting.

## Sites and Balance

- **Monitored sites**: Fixed list (e.g. 10–50 sites); document the mapping from site_id to URL or category if needed for evaluation.
- **Samples**: Equal number of visits per site; equal number of visits with Defense ON and OFF per site (e.g. N visits per site per defense state).
- **Reproducibility**: Same machine and Tor Browser profile when capturing; Defense Engineer documents proxy port and toggle steps so “Defense ON” is consistent (see DATA_PIPELINE.md).

## Tor-Only Filter (Parsing)

- **Parsing pipeline** will filter to Tor-related traffic only. Options (to be documented in the parser and DATA_PIPELINE.md):
  - By destination port (e.g. Tor Browser SOCKS 9150, or proxy port when Defense ON).
  - By process (if available on the platform).
  - By excluding known non-Tor flows (e.g. DNS to non-Tor resolvers).
- Exact filter (e.g. tshark display filter or scapy logic) will be specified in `parse_pcaps.py` and DATA_PIPELINE.md.
