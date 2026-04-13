# WF-Guard — Live Demo Environment

Unified pipeline for the WF-Guard capstone demo. All components live in this
directory: traffic sniffer, feature extractor, ML classifier, defense proxy,
and real-time dashboard.

---

## Prerequisites

**Tor** (WSL/Linux)
```bash
sudo apt install tor
sudo systemctl start tor
```

Optionally enable identity rotation — add to `/etc/tor/torrc`:
```
ControlPort 9051
CookieAuthentication 1
```
Then `sudo systemctl restart tor`.

**Python venv** (already created)
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

**Scapy raw socket access** (one-time setup)
```bash
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)
```
This lets the venv Python sniff packets without running streamlit as root.

---

## Step 1 — Train the model

Requires `curated_raw_dataset.csv`. The script will find it automatically if
the repo structure is intact; otherwise copy it into `demo/`.

```bash
python evaluate_models.py
```

Outputs `model.joblib`, `scaler.joblib`, and `label_map.json` into this directory.

---

## Step 2 — Run the defense proxy (optional, separate terminal)

```bash
python defense_proxy.py
```

This routes traffic through Tor with cover traffic and header randomization.
Press `D` + Enter to toggle defense on/off. The dashboard's defense toggle
is independent — both can be used together for the demo.

---

## Step 3 — Launch the dashboard

**Fake data mode** (no Tor required, good for UI testing):
```bash
# DATA_SOURCE = "fake" in dashboard.py (default)
streamlit run dashboard.py
```

**Real data mode** (live Tor traffic):
```bash
# Set DATA_SOURCE = "real" in dashboard.py first
streamlit run dashboard.py
```

Open `http://localhost:8501`, click **▶ Start**, and browse through Tor Browser
or any Tor-routed application. The dashboard will predict the site from live
traffic and show confidence drop when the WF-Guard toggle is enabled.

---

## Step 4 — Run the Phase 5 evaluation

```bash
python evaluate.py
```

Benchmarks bandwidth and latency overhead with defense ON vs OFF. Outputs a
report to the terminal and saves `evaluation_results.txt`.

---

## Directory Layout

```
demo/
├── dashboard.py          ← Streamlit real-time UI
├── defense_proxy.py      ← Tor SOCKS5 proxy with anti-fingerprinting
├── dataset_manager.py    ← pcap ingestion + traffic profiling
├── extract_features.py   ← scapy packets → model vector + display dict
├── evaluate_models.py    ← RandomForest training + artifact export
├── evaluate.py           ← Phase 5 bandwidth/latency evaluation
├── requirements.txt
├── data/                 ← drop .pcap files here for learned timing
├── models/               ← auto-created by dataset_manager.py
└── docs/
    ├── defense.md        ← defense proxy setup and kill switch guide
    ├── dashboard.md      ← dashboard architecture and integration guide
    └── ml-guide.md       ← model training and artifact reference
```

---

## Tor Port Reference

| Port | Used by |
| --- | --- |
| `9050` | Tor daemon SOCKS5 (default in this demo) |
| `9051` | Tor control port (identity rotation) |
| `9150` | Tor Browser SOCKS5 (change `TOR_PORT` in dashboard.py if using Tor Browser) |
