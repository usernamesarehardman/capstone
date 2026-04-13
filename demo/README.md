# WF-Guard — Live Demo Environment

Unified pipeline for the WF-Guard capstone demo. All runnable components
live in `scripts/`: traffic sniffer, feature extractor, ML classifier,
defense proxy, and real-time dashboard.

---

## Prerequisites

### Python

Fresh WSL Ubuntu does not ship a `python` binary. Install it once:

```bash
sudo apt update
sudo apt install python3 python3-venv python-is-python3
```

`python-is-python3` creates the `python` → `python3` symlink system-wide.
Once the `.venv` is activated, `python` also works inside the venv.

### Tor

WSL does not run `systemd` by default, so `systemctl` will not work.
Use `service` instead:

```bash
sudo apt install tor
sudo service tor start
sudo service tor status    # confirm it is running
```

To enable identity rotation add to `/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 1
```

Then `sudo service tor restart`.

### Python venv

```bash
# From demo/
source .venv/bin/activate
pip install -r requirements.txt
```

### Scapy raw socket access (one-time)

Grants packet capture without running streamlit as root:

```bash
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)
```

---

## Step 1 — Train the model

Run from `demo/scripts/` with the venv active. The script searches for
`curated_raw_dataset.csv` in `scripts/`, `Machine Learning Engineer/`, and
`Data & Traffic Engineer/initial_dataset/` automatically.

```bash
cd scripts
python evaluate_models.py
```

Outputs into `demo/scripts/`:
- `model.joblib`
- `scaler.joblib`
- `label_map.json`

---

## Step 2 — Run the defense proxy (separate terminal, optional)

```bash
cd scripts
python defense_proxy.py
```

Type `D` + Enter to toggle defense on/off. This process is independent of
the dashboard — run both simultaneously for the full demo effect.

---

## Step 3 — Launch the dashboard

**Fake data mode** (no Tor required, good for UI verification):

```bash
# DATA_SOURCE = "fake" in scripts/dashboard.py (default)
cd scripts
streamlit run dashboard.py
```

**Real data mode** (live Tor traffic):

```bash
# Set DATA_SOURCE = "real" in scripts/dashboard.py first
# Ensure Tor is running: sudo service tor start
cd scripts
streamlit run dashboard.py
```

Open `http://localhost:8501`, click **▶ Start**, then browse through Tor.
The dashboard predicts the current site from live traffic and shows
confidence drop when the WF-Guard toggle is enabled.

---

## Step 4 — Phase 5 evaluation

```bash
cd scripts
python evaluate.py
```

Benchmarks bandwidth and latency overhead with defense ON vs OFF. Saves
`evaluation_results.txt` in `demo/scripts/`.

---

## Directory Layout

```
demo/
├── .gitignore
├── README.md
├── requirements.txt
├── docs/
│   ├── dashboard.md      dashboard architecture + integration guide
│   ├── defense.md        defense proxy setup and kill switch reference
│   └── ml-guide.md       model training and artifact reference
└── scripts/
    ├── dashboard.py
    ├── defense_proxy.py
    ├── dataset_manager.py
    ├── extract_features.py
    ├── evaluate_models.py
    ├── evaluate.py
    └── data/             drop .pcap files here for learned timing
```

---

## Tor Port Reference

| Port | Used by |
| --- | --- |
| `9050` | Tor daemon SOCKS5 (default in this demo) |
| `9051` | Tor control port (identity rotation) |
| `9150` | Tor Browser SOCKS5 — change `TOR_PORT` in `dashboard.py` if using Tor Browser |
