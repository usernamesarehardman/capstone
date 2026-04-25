# WF-Guard — Reproduction Guide

Step-by-step instructions for reproducing all results from scratch.
Tested on WSL2 Ubuntu 22.04 with Python 3.11.

---

## Prerequisites

### System packages

```bash
sudo apt update
sudo apt install python3 python3-venv python-is-python3 tor firefox-esr -y
```

### geckodriver

```bash
# Pre-downloaded in demo/drivers/
cd demo
tar -xf drivers/geckodriver-v0.35.0-linux64.tar.gz
sudo mv geckodriver /usr/local/bin/
```

### Python environment

```bash
cd demo
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Raw socket capability (real-mode only)

```bash
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)
# Verify: getcap $(readlink -f .venv/bin/python)
```

### Tor (real-mode only)

```bash
# Option A — SysV init
sudo service tor start

# Option B — run directly
tor &

# Confirm routing (should return a Tor exit IP, not your real IP)
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org

# Enable identity rotation between page loads (optional)
# Add to /etc/tor/torrc:
#   ControlPort 9051
#   CookieAuthentication 1
# Then: sudo service tor restart
```

---

## Step 1 — Train the classifier

```bash
cd demo
source .venv/bin/activate

# Default: uses demo/data/curated_raw_dataset.csv
python scripts/evaluate_models.py

# With cross-validation (adds per-fold accuracy report)
python scripts/evaluate_models.py --cross-val 5

# Faster iteration (fewer trees)
python scripts/evaluate_models.py --trees 200
```

Artifacts saved to `demo/models/`:

| File | Description |
| --- | --- |
| `model.joblib` | Trained RandomForest (1000 trees) |
| `scaler.joblib` | Fitted StandardScaler |
| `label_map.json` | `{index: site_name}` for all classes |
| `confusion_matrix.csv` | Per-class test accuracy |

Expected output: `Top-1 Accuracy ≥ 90%` on the curated dataset.

---

## Step 2 — Launch the dashboard

```bash
streamlit run scripts/dashboard.py
```

Open `http://localhost:8501`.

| Mode | Description |
| --- | --- |
| **Fake** | No Tor required. Simulated traffic with heuristic classifier. |
| **Real** | Requires Tor + `traffic_gen.py`. Live eth0 capture → RF inference. |

---

## Step 3 — Generate real traffic (Real mode only)

In a second terminal:

```bash
source .venv/bin/activate

# Recommended: 15 high-recall sites, continuous loop
python scripts/traffic_gen.py --demo

# All ~40 sites
python scripts/traffic_gen.py

# Single rotation then exit
python scripts/traffic_gen.py --once
```

`traffic_gen.py` writes the current site name to `/tmp/wfguard_gt.txt` so the
dashboard can compute ground-truth accuracy in real time.

---

## Step 4 — Collect fresh training data (optional)

To retrain on new Tor traces instead of the curated dataset:

```bash
# 20 traces × 15 demo sites
python scripts/collect/collect_fresh.py

# 50 traces × all 40 sites (better accuracy, ~2 h)
python scripts/collect/collect_fresh.py --traces 50 --all
```

Writes to `scripts/collect/dataset.csv`.  Retrain:

```bash
python scripts/evaluate_models.py --dataset scripts/collect/dataset.csv
```

---

## Step 5 — Analyze inference logs

After a dashboard session, the log is at `demo/logs/inference_log.jsonl`.

```bash
python scripts/analyze_log.py                  # full session report
python scripts/analyze_log.py --source real    # real-mode entries only
python scripts/analyze_log.py --defense off    # pre-defense baseline
python scripts/analyze_log.py --csv report.csv # export per-site table
```

Report includes: top-1/3/5 accuracy, GT rank distribution, average GT
confidence, defense impact comparison, per-site breakdown.

---

## Step 6 — Evaluation suite

### Bandwidth / latency overhead

```bash
python scripts/evaluate.py
```

Runs five test URLs with defense ON vs. OFF, measures bandwidth and latency.
Saves `scripts/evaluation_results.txt`.

### Time-to-decision curve

```bash
python scripts/time_to_decision.py
# Optional: write CSV for plotting
python scripts/time_to_decision.py --output results/ttd.csv
```

Evaluates accuracy at window sizes 25–1000 packets using the same trained model.

### Open-world evaluation (FPR)

```bash
# Split dataset: 20 monitored sites vs. remainder as unmonitored
python scripts/open_world_eval.py --monitored 20

# Export TPR-FPR tradeoff table
python scripts/open_world_eval.py --monitored 20 --output results/open_world.csv
```

### Multi-tab robustness test

```bash
python scripts/robustness_test.py
# Customise contamination levels
python scripts/robustness_test.py --contamination 0,10,25,50
```

---

## Dataset Alternatives

| Dataset | How to use |
| --- | --- |
| `demo/data/curated_raw_dataset.csv` | Default — included in repo |
| Fresh-collected traces | `scripts/collect/collect_fresh.py` → `evaluate_models.py --dataset ...` |
| CW.npz (WFLib public dataset) | Download from [Zenodo](https://zenodo.org/records/13732130), place in `demo/data/`, run `evaluate_models.py --dataset data/CW.npz` |

---

## Expected Results (curated dataset, 1000 trees)

| Metric | Expected range |
| --- | --- |
| Closed-world top-1 accuracy | 88–95 % |
| Closed-world top-3 accuracy | 95–99 % |
| 5-fold CV accuracy | 86–93 % ± < 3 % |
| Open-world FPR @ 0.5 threshold | 5–20 % |
| Accuracy at 100 packets | 40–65 % |
| Accuracy at 400 packets | 75–90 % |
| Accuracy at 50 % contamination | 30–55 % |

---

## Port Reference

| Port | Service |
| --- | --- |
| `9050` | Tor SOCKS5 (default) |
| `9051` | Tor control port (identity rotation) |
| `9150` | Tor Browser SOCKS5 — update `TOR_PORT` in `dashboard.py` if using Tor Browser |
| `8501` | Streamlit dashboard |
