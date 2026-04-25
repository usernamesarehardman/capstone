# WF-Guard Dashboard — Technical Documentation

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Component Reference](#component-reference)
3. [Fake Data System](#fake-data-system)
4. [Real Data Integration Guide](#real-data-integration-guide)
5. [Session State Reference](#session-state-reference)
6. [Known Limitations](#known-limitations)

---

## Architecture Overview

The dashboard separates concerns into three layers:

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

**Why a background thread?**
Streamlit reruns the entire script on every user interaction. A long-running capture loop would block the UI thread. The `CaptureWorker` runs as a daemon thread, decoupled from Streamlit's execution model, and communicates via a thread-safe `queue.Queue`.

**Auto-rerun loop:**
When the system is running, the bottom of the script calls `st.rerun()` after a short sleep. This creates a polling loop that drains the queue and refreshes the UI without user interaction.

---

## Component Reference

### `InferenceResult` (dataclass)

The canonical output object passed from any data source to the UI.

| Field | Type | Description |
| --- | --- | --- |
| `timestamp` | `float` | Unix timestamp of inference |
| `prediction` | `str` | Top predicted site label |
| `confidence` | `float` | Probability of top prediction (0–1) |
| `probabilities` | `dict[str, float]` | Full probability distribution over all sites |
| `packets_in_window` | `int` | Number of packets in this feature window |
| `features` | `dict[str, float]` | Raw feature vector (mirrors `FEATURE_NAMES`) |
| `defense_active` | `bool` | Whether WF-Guard defense was active at inference time |

### `PacketRecord` (dataclass)

Internal representation of a single packet (used by `FakeDataSource`; mirrors what scapy would provide).

| Field | Type | Description |
| --- | --- | --- |
| `timestamp` | `float` | Packet capture time |
| `size` | `int` | Payload size in bytes |
| `direction` | `str` | `"outgoing"` or `"incoming"` |
| `inter_arrival` | `float` | Time since previous packet (ms) |

### `CaptureWorker`

Manages the background thread lifecycle.

```python
worker = CaptureWorker(result_queue, defense_active_fn)
worker.start()   # launches daemon thread
worker.stop()    # sets stop event; thread exits cleanly on next iteration
```

The `defense_active_fn` parameter is a zero-argument callable returning `bool`. It is called on every inference cycle so the defense state can be toggled live without restarting the worker.

---

## Fake Data System

`FakeDataSource` generates statistically plausible Tor-like traffic without requiring real captures or a trained model.

### Site Profiles

Each monitored site has a traffic fingerprint defined by four parameters:

| Parameter | Description |
| --- | --- |
| `mean_size` | Mean packet size (bytes) |
| `std_size` | Standard deviation of packet size |
| `burst_rate` | Frequency of burst behavior (higher = more bursty) |
| `incoming_bias` | Fraction of packets that are incoming (download-heavy sites score higher) |

These parameters are intentionally distinct so the fake classifier produces meaningful, non-random predictions:

| Site | Mean Size | Incoming Bias | Notes |
| --- | --- | --- | --- |
| `youtube.com` | x | x | Large packets, very download-heavy |
| `wikipedia.org` | x | x | Large response pages |
| `amazon.com` | x | x | Mixed content |
| `github.com` | x | x | Smaller, more balanced |
| `twitter.com` | x | x | Small payloads, balanced |

### Feature Extraction

`FakeDataSource.extract_features()` computes the following over a window of `WINDOW_SIZE` packets:

| Feature | Computation |
| --- | --- |
| `total_packets` | `len(packets)` |
| `total_bytes` | Sum of all packet sizes |
| `outgoing_packets` / `incoming_packets` | Count by direction |
| `outgoing_bytes` / `incoming_bytes` | Sum by direction |
| `mean_packet_size` / `std_packet_size` | `np.mean` / `np.std` of sizes |
| `mean_inter_arrival_ms` / `std_inter_arrival_ms` | `np.mean` / `np.std` of IATs |
| `burst_count` | Number of gaps > 50ms (each gap = new burst) |
| `max_burst_size` | Largest consecutive run under 50ms gap |
| `outgoing_ratio` | `outgoing_packets / total_packets` |
| `bytes_ratio` | `outgoing_bytes / total_bytes` |

> **Note:** This feature set is designed to mirror what `extract_features.py` in the main pipeline should produce. When integrating real data, ensure the feature names and ordering match `FEATURE_NAMES` in the config section.

### Fake Model

`fake_model_predict()` scores each site by comparing the extracted features against that site's profile, then applies softmax-style normalization to produce a probability distribution.

When defense is active, scores are replaced with uniform noise (range 0.05–0.25), simulating the effect of padding/obfuscation on classifier confidence.

### Site Rotation

`FakeDataSource` simulates browsing sessions by rotating the "active site" every 8–15 inference windows, producing visible transitions in the confidence chart.

---

## Real Data Integration Guide

To connect the dashboard to the actual pipeline:

### Step 1: Set the data source

```python
DATA_SOURCE = "real"   # top of dashboard.py
```

### Step 2: Implement `RealDataSource.get_next_result()`

```python
import scapy.all as scapy
import joblib
import numpy as np
from extract_features import extract_features   # your pipeline module

MODEL_PATH = "model.pkl"
model = joblib.load(MODEL_PATH)

class RealDataSource:
    def __init__(self, defense_active_fn):
        self.defense_active_fn = defense_active_fn

    def get_next_result(self) -> InferenceResult:
        # 1. Capture a window of packets from Tor port
        packets = scapy.sniff(
            filter=f"tcp port {TOR_PORT}",
            count=WINDOW_SIZE,
            timeout=10,
        )

        # 2. Convert to PacketRecord list (or pass raw to extract_features)
        #    extract_features should accept scapy packets directly
        features = extract_features(packets)   # returns dict matching FEATURE_NAMES

        # 3. Build feature vector in correct order
        feature_vector = np.array([features[f] for f in FEATURE_NAMES]).reshape(1, -1)

        # 4. Run inference
        probs_array = model.predict_proba(feature_vector)[0]
        probs = dict(zip(MONITORED_SITES, probs_array))
        prediction = max(probs, key=probs.get)
        confidence = probs[prediction]

        return InferenceResult(
            timestamp=time.time(),
            prediction=prediction,
            confidence=confidence,
            probabilities=probs,
            packets_in_window=len(packets),
            features=features,
            defense_active=self.defense_active_fn(),
        )
```

### Step 3: Permissions

Scapy requires root for raw packet capture:

```bash
sudo streamlit run dashboard.py
# or grant cap_net_raw to python:
sudo setcap cap_net_raw+eip $(which python3)
```

### Step 4: Verify feature alignment

Run this sanity check before integrating:

```python
from extract_features import extract_features
import scapy.all as scapy

pkts = scapy.sniff(filter="tcp port 9150", count=100, timeout=10)
features = extract_features(pkts)

# All keys should be present
missing = set(FEATURE_NAMES) - set(features.keys())
assert not missing, f"Missing features: {missing}"
print("Feature alignment OK")
```

---

## Session State Reference

All persistent state lives in `st.session_state`. Never access these with `[]` without ensuring `init_state()` has run first — use `.get(key, default)` in any context that might be called before initialization (e.g., lambda callbacks passed to threads).

| Key | Type | Description |
| --- | --- | --- |
| `running` | `bool` | Whether the capture worker is active |
| `result_queue` | `queue.Queue` | Thread-safe channel from worker to UI |
| `worker` | `CaptureWorker \| None` | Reference to active worker (for stopping) |
| `logs` | `list[str]` | Rolling log lines displayed in the log panel |
| `total_packets` | `int` | Cumulative packet count since last start |
| `accuracy_trend` | `list[float]` | Confidence values over time (drives line chart) |
| `last_result` | `InferenceResult \| None` | Most recent result (drives metrics + bar chart) |
| `defense_active` | `bool` | Current defense toggle state |

---

## Known Limitations

| Limitation | Impact | Workaround |
| --- | --- | --- |
| Streamlit reruns entire script on interaction | Brief UI flicker during rerun | Acceptable for prototype; use `st.fragment` in Streamlit ≥ 1.37 for partial reruns |
| Thread cannot write directly to session state | All UI updates happen via queue drain at rerun time | By design — queue pattern is correct approach |
| `POLL_INTERVAL` controls both capture rate and UI refresh | Reducing it increases CPU usage | Keep at 0.5s for fake mode; tune for real capture based on traffic volume |
| Real capture requires root | Deployment friction | Use `setcap` or run inside a dedicated capture service and forward results via socket/IPC |
| Site list is hardcoded | Must match model's training label set | Update `MONITORED_SITES` to match your dataset labels before real integration |
