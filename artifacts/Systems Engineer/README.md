# WF-Guard: Real-Time Website Fingerprinting Dashboard

A Streamlit-based real-time dashboard for the WF-Guard capstone project. Visualizes live website fingerprinting attacks against Tor traffic, with integrated defense toggling, confidence tracking, and feature inspection.

---

## Quick Start

```bash
source venv/Scripts/activate  
pip install streamlit pandas numpy
streamlit run dashboard.py
```

Then open `http://localhost:8501` in your browser.

---

## Project Structure

```md
dashboard.py        ← Single-file Streamlit app
README.md           ← This file
DOCUMENTATION.md    ← Architecture, integration guide, and API
```

---

## Configuration

At the top of `dashboard.py`:

| Variable | Default | Description |
| --- | --- | --- |
| `DATA_SOURCE` | `"fake"` | `"fake"` for simulated data, `"real"` for live capture |
| `TOR_PORT` | `9150` | Port to sniff for Tor client traffic |
| `WINDOW_SIZE` | `100` | Packets per feature extraction window |
| `POLL_INTERVAL` | `0.5` | Seconds between UI refresh cycles |
| `MONITORED_SITES` | 8 sites | List of sites the classifier can predict |

---

## Switching to Real Data

1. Set `DATA_SOURCE = "real"` at the top of the file
2. Implement `RealDataSource.get_next_result()` — see `DOCUMENTATION.md` for the full integration guide
3. Ensure your trained model and `extract_features.py` are accessible from the same directory

---

## Controls

| Control | Description |
| --- | --- |
| **▶ Start** | Launches the background capture/inference worker thread |
| **⏹ Stop** | Gracefully stops the worker thread |
| **WF-Guard Toggle** | Simulates defense mode — flattens classifier confidence |

---

## Requirements

- Python 3.10+
- `streamlit >= 1.32`
- `pandas`
- `numpy`

For real data mode, additionally:

- `scapy`
- `scikit-learn` or your model's framework (PyTorch, etc.)
- Root/sudo access for packet capture
