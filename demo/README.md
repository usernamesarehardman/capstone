# WF-Guard — Live Demo Environment

Unified pipeline for the WF-Guard capstone demo. All runnable scripts live in
`scripts/`; trained model artifacts land in `models/`; training datasets live
in `data/`; inference logs are written to `logs/`.

---

## Prerequisites

### Python

Fresh WSL Ubuntu does not ship a `python` binary. Install it once:

```bash
sudo apt update
sudo apt install python3 python3-venv python-is-python3
```

`python-is-python3` creates the `python → python3` symlink system-wide.
Once the `.venv` is activated, `python` also works inside the venv.

### Tor

```bash
sudo apt install tor

# Option 1 — SysV init (most WSL installs)
sudo service tor start

# Option 2 — run directly (always works)
tor &
```

Confirm Tor is routing before proceeding:

```bash
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
# Should return a Tor exit IP, not your real IP
```

To enable identity rotation between page loads, add to `/etc/tor/torrc`:

```text
ControlPort 9051
CookieAuthentication 1
```

Then restart: `sudo service tor restart`.

### Python venv

```bash
# From demo/
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Scapy raw socket access (one-time, re-run after pip upgrades)

Grants packet capture without running Streamlit as root:

```bash
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)

# Verify:
getcap $(readlink -f .venv/bin/python)
# Expected: .../python3.x = cap_net_raw+eip
```

---

## Step 1 — Train the model

```bash
cd demo
python scripts/evaluate_models.py
```

Reads `data/curated_raw_dataset.csv` by default. Saves artifacts to `models/`:

- `model.joblib`
- `scaler.joblib`
- `label_map.json`
- `confusion_matrix.csv`

Other dataset options:

```bash
# Fresh-collected Tor data (after running collect_fresh.py)
python scripts/evaluate_models.py --dataset scripts/collect/dataset.csv

# WFLib public dataset (download CW.npz from https://zenodo.org/records/13732130)
python scripts/evaluate_models.py --dataset data/CW.npz

# Fewer trees for faster iteration
python scripts/evaluate_models.py --trees 200 --test-size 0.2
```

---

## Step 2 — Launch the dashboard

```bash
streamlit run scripts/dashboard.py
```

Open `http://localhost:8501`. All controls are in the sidebar:

| Control | Description |
| --- | --- |
| **Data Source** | Fake (simulated, no Tor needed) or Real (live eth0 capture) |
| **Enable WF-Guard** toggle | Turns defense on/off — controls cover traffic and timing jitter |
| **▶ Start / ⏹ Stop** | Starts or stops the capture worker |

**Fake mode** works immediately with no Tor. Demonstrates defense contrast
using synthetic traffic shaped per site profile.

**Real mode** requires Tor running and `traffic_gen.py` in a second terminal.
The dashboard sniffs on `eth0` — the same interface used during data collection.

Dashboard metrics:

| Metric | Description |
| --- | --- |
| Top-1 Accuracy | Fraction of inferences where prediction == ground truth |
| Top-3 Accuracy | Fraction where correct class was in the top 3 predictions |
| Avg GT Confidence | Mean probability assigned to the correct class regardless of rank |

---

## Step 3 — Run the traffic generator (Real mode only)

Real mode requires full browser page loads. The model was trained on
Firefox-over-Tor traffic (HTML + CSS + JS + images + sub-resources). Plain
`requests.get()` produces a single-document pattern the model cannot classify.

**Install browser dependencies (once):**

```bash
sudo apt install firefox-esr -y

# Install geckodriver — pre-downloaded in drivers/
tar -xf drivers/geckodriver-v0.35.0-linux64.tar.gz
sudo mv geckodriver /usr/local/bin/
```

**Run in a separate terminal:**

```bash
python scripts/traffic_gen.py            # all ~40 sites (browser mode)
python scripts/traffic_gen.py --demo     # 15 high-recall sites only (recommended)
python scripts/traffic_gen.py --once     # one full rotation then exit
```

`traffic_gen.py` writes the current site to `/tmp/wfguard_gt.txt` before each
page load so the dashboard can track ground-truth accuracy in real time.

---

## Step 4 — Collect fresh training data (optional)

```bash
python scripts/collect/collect_fresh.py             # 15 demo sites, 20 traces each
python scripts/collect/collect_fresh.py --traces 50 # more traces (better accuracy)
python scripts/collect/collect_fresh.py --all        # all 40 sites
```

Writes to `scripts/collect/dataset.csv`. Then retrain:

```bash
python scripts/evaluate_models.py --dataset scripts/collect/dataset.csv
```

---

## Step 5 — Analyze inference logs

After a dashboard session, `logs/inference_log.jsonl` contains a structured
record of every classified window.

```bash
python scripts/analyze_log.py                  # full session report
python scripts/analyze_log.py --source real    # real-mode entries only
python scripts/analyze_log.py --defense off    # pre-defense baseline
python scripts/analyze_log.py --csv report.csv # export per-site table
```

Report includes: top-1/3/5 accuracy, GT rank distribution, average GT
confidence (correct vs wrong), defense impact comparison, per-site breakdown.

---

## Step 6 — Evaluation suite

### Bandwidth / latency overhead

```bash
python scripts/evaluate.py
```

Benchmarks defense ON vs. OFF across five test URLs. Saves `evaluation_results.txt` in `scripts/`.

### Time-to-decision curve (required by rubric)

```bash
python scripts/time_to_decision.py
python scripts/time_to_decision.py --output results/ttd.csv
```

Evaluates accuracy at window sizes 25–1000 packets using the trained model.

### Open-world evaluation (FPR against unmonitored sites)

```bash
python scripts/open_world_eval.py --monitored 20
python scripts/open_world_eval.py --monitored 20 --output results/open_world.csv
```

### Multi-tab robustness test

```bash
python scripts/robustness_test.py
python scripts/robustness_test.py --contamination 0,25,50 --output results/robustness.csv
```

---

## Directory Layout

```text
demo/
├── README.md                    ← This file
├── requirements.txt             ← All Python dependencies
│
├── scripts/                     ← All runnable Python scripts
│   ├── dashboard.py             ← Streamlit UI — all controls via sidebar
│   ├── evaluate_models.py       ← Model trainer (RF + CUMUL features)
│   ├── extract_features.py      ← 113-feature extractor for live inference
│   ├── traffic_gen.py           ← Headless Firefox traffic generator
│   ├── analyze_log.py           ← Inference log reporter (top-1/3/5, per-site)
│   ├── defense_proxy.py         ← Cover traffic + timing jitter library
│   ├── evaluate.py              ← Bandwidth/latency overhead benchmark
│   ├── time_to_decision.py      ← Accuracy vs. packet-window-size curve
│   ├── open_world_eval.py       ← Open-world FPR evaluation
│   ├── robustness_test.py       ← Multi-tab trace interleaving test
│   ├── dataset_manager.py       ← pcap ingestion and traffic profiling
│   └── collect/
│       └── collect_fresh.py     ← Fresh Tor traffic collector
│
├── data/                        ← Training datasets
│   └── curated_raw_dataset.csv  ← Curated 40-site signed trace dataset
│                                   (CW.npz gitignored — download separately)
│
├── models/                      ← Trained WF classifier artifacts (gitignored)
│   ├── model.joblib             ← Trained RandomForest
│   ├── scaler.joblib            ← Fitted StandardScaler
│   ├── label_map.json           ← {index: site_name} for all classes
│   └── confusion_matrix.csv     ← Per-class test accuracy
│
├── logs/                        ← Runtime inference log (gitignored)
│   └── inference_log.jsonl      ← Written by dashboard.py; read by analyze_log.py
│
├── drivers/                     ← Browser drivers
│   └── geckodriver-*.tar.gz     ← geckodriver for Firefox automation
│
└── docs/                        ← Component documentation
    ├── dashboard.md             ← Dashboard architecture + integration guide
    ├── defense.md               ← Defense proxy setup reference
    ├── ml-guide.md              ← Model training, features, and artifact guide
    └── team-brief.md            ← Team overview and role responsibilities
```

---

## Tor Port Reference

| Port | Used by |
| --- | --- |
| `9050` | Tor daemon SOCKS5 (traffic_gen.py, defense_proxy.py, evaluate.py) |
| `9051` | Tor control port (circuit identity rotation via stem) |
| `9150` | Tor Browser SOCKS5 — update `TOR_PORT` in `dashboard.py` if using Tor Browser |
