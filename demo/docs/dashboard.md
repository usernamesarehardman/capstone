# Dashboard Architecture and Integration Guide

## Architecture Overview

```text
┌─────────────────────────────────────────────┐
│              Streamlit UI Layer             │
│  Metrics / Charts / Logs / Feature Expander │
└────────────────────┬────────────────────────┘
                     │ polls queue on each rerun
┌────────────────────▼────────────────────────┐
│           CaptureWorker (Thread)            │
│  Runs in background, pushes InferenceResult │
│  objects to result_queue every POLL_INTERVAL│
└────────────────────┬────────────────────────┘
                     │ calls get_next_result()
┌────────────────────▼────────────────────────┐
│         Data Source (swappable)             │
│  FakeDataSource  ←──── DATA_SOURCE = "fake" │
│  RealDataSource  ←──── DATA_SOURCE = "real" │
└─────────────────────────────────────────────┘
```

---

## Key Configuration (top of scripts/dashboard.py)

| Variable | Default | Description |
| --- | --- | --- |
| `DATA_SOURCE` | `"fake"` | `"fake"` for simulated data, `"real"` for live capture |
| `TOR_PORT` | `9050` | Tor daemon port on Linux/WSL (use `9150` for Tor Browser) |
| `WINDOW_SIZE` | `100` | Packets captured per inference window |
| `POLL_INTERVAL` | `0.5` | Seconds between UI refresh cycles |
| `MODEL_DIR` | `scripts/` directory | Where `model.joblib`, `scaler.joblib`, `label_map.json` are loaded from |

---

## Switching to Real Data

1. Run `python evaluate_models.py` from `demo/scripts/` to generate model artifacts.
2. Set `DATA_SOURCE = "real"` in `scripts/dashboard.py`.
3. Confirm Tor is running:

   ```bash
   sudo service tor status
   ```

4. Grant scapy raw socket access (one-time, run from `demo/`):

   ```bash
   sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)
   ```

5. Launch from `demo/scripts/`:

   ```bash
   streamlit run dashboard.py
   ```

---

## RealDataSource Integration

`RealDataSource.get_next_result()` does the following on each inference cycle:

1. Sniffs `WINDOW_SIZE` TCP packets on `TOR_PORT` via `scapy.AsyncSniffer` (15s timeout)
2. Calls `extract_features(packets)` → `(model_vector [56 elements], display_dict [14 keys])`
3. Scales the model vector with the loaded `StandardScaler`
4. Runs `model.predict_proba()` → probability distribution over all 40 site classes
5. Returns `InferenceResult` with prediction, confidence, probabilities, and display features

---

## Session State Reference

| Key | Type | Description |
| --- | --- | --- |
| `running` | `bool` | Whether the capture worker is active |
| `result_queue` | `queue.Queue` | Thread-safe channel from worker to UI |
| `worker` | `CaptureWorker \| None` | Reference to active worker |
| `logs` | `list[str]` | Rolling log lines (last 20 shown) |
| `total_packets` | `int` | Cumulative packet count since last start |
| `accuracy_trend` | `list[float]` | Confidence values over time |
| `last_result` | `InferenceResult \| None` | Most recent result |
| `defense_active` | `bool` | Current defense toggle state |

---

## Feature Alignment

The dashboard displays a 14-key human-readable dict (`display_dict`) from `extract_features.py`.
The model receives a separate 56-element vector. Both are computed simultaneously by
`extract_features(packets)` which returns `(model_vector, display_dict)`.

The 14 display features (`FEATURE_NAMES` in `dashboard.py`):
`total_packets`, `total_bytes`, `outgoing_packets`, `incoming_packets`,
`outgoing_bytes`, `incoming_bytes`, `mean_packet_size`, `std_packet_size`,
`mean_inter_arrival_ms`, `std_inter_arrival_ms`, `burst_count`, `max_burst_size`,
`outgoing_ratio`, `bytes_ratio`

---

## Known Limitations

| Limitation | Impact | Workaround |
| --- | --- | --- |
| Streamlit reruns entire script on interaction | Brief UI flicker | Use `st.fragment` in Streamlit ≥ 1.37 for partial reruns |
| Thread cannot write directly to session state | Updates happen at rerun time | By design — queue pattern is correct |
| `POLL_INTERVAL` controls both capture rate and UI refresh | Reducing increases CPU | Keep at 0.5s; tune for real traffic volume |
| Real capture requires raw socket access | Must grant `setcap` or run as root | `sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)` |
| Site list in fake mode is hardcoded (8 sites) | Fake predictions only cover 8 classes | Real mode uses `label_map.json` (40 classes) automatically |
