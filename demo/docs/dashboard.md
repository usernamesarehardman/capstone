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
│  FakeDataSource  ←──── sidebar: Fake        │
│  RealDataSource  ←──── sidebar: Real        │
└─────────────────────────────────────────────┘
```

---

## Key Configuration (top of scripts/dashboard.py)

| Variable | Default | Description |
| --- | --- | --- |
| `TOR_PORT` | `9050` | Tor daemon SOCKS5 port (use `9150` for Tor Browser) |
| `WINDOW_SIZE` | `100` | Packets captured per inference window |
| `POLL_INTERVAL` | `0.5` | Seconds between UI refresh cycles |
| `SNIFF_IFACE` | `"eth0"` | Interface to sniff for real mode — must match training data capture interface |
| `MODEL_DIR` | `scripts/` directory | Where `model.joblib`, `scaler.joblib`, `label_map.json` are loaded from |

Data source is selected via the sidebar radio — there is no `DATA_SOURCE`
variable to edit in the file.

---

## FakeDataSource

Simulates traffic entirely in Python — no Tor or packet capture required.

On init, `FakeDataSource` reads `label_map.json` and builds `self.labels`
(same 40-site list as `RealDataSource`). It generates per-site traffic
profiles seeded deterministically from the site name via `_make_profile()`.

**Defense OFF:** the current site scores 0.60–0.85 raw; all others score
0.002–0.008. After normalization the predicted site shows ~65–80% confidence
with a clear spike in the probability chart.

**Defense ON:** all sites score uniform 0.05–0.25. After normalization the
winner shows ~2–4% confidence — no site can be distinguished.

Defense state is read from `_defense_enabled` (a `threading.Event` from
`defense_proxy.py`), not from `st.session_state`. Streamlit session state
is not accessible from background worker threads (`ScriptRunContext` warning
in logs is expected and harmless).

---

## RealDataSource

Live capture on `SNIFF_IFACE` (`eth0`) using `scapy.AsyncSniffer`.

**Why eth0, not lo:**
Training data was collected with `tcpdump -i eth0 tcp` (see
`archive/Data & Traffic Engineer/collect.py`). Tor circuit traffic — the
encrypted cells traveling between the local machine and Tor guard nodes —
flows through `eth0`. The Tor SOCKS5 proxy connection between client
processes and the Tor daemon flows through loopback (`lo`), but that traffic
was not used for training.

`RealDataSource.get_next_result()` per inference cycle:

1. Sniffs `WINDOW_SIZE` TCP packets on `eth0` (no port filter — Tor guard
   connections use ports 443/9001, not 9050)
2. Raises `RuntimeError` if 0 packets captured within 15s timeout
3. Calls `extract_features(packets, tor_port=TOR_PORT)` →
   `(model_vector [56 elements], display_dict [14 keys])`
4. Scales model vector with `StandardScaler`
5. Runs `model.predict_proba()` → distribution over 40 classes
6. Returns `InferenceResult`

**Traffic generator requirement:**
`traffic_gen.py` must be running in a separate terminal. The model was
trained on Firefox full page loads (all sub-resources). Simple
`requests.get()` traffic produces a single-document pattern the model
was not trained on and will not classify correctly.

---

## Direction Detection in extract_features.py

`packets_to_trace()` assigns direction by comparing packet IP addresses
to the local machine IP (auto-detected via UDP socket):

- `src == local_ip` → outgoing (+size)
- otherwise → incoming (−size)

**Loopback special case:** when both src and dst are `127.x.x.x` (traffic
between local processes), IP-based direction is ambiguous. In this case
TCP port is used: packets addressed *to* `tor_port` are outgoing, packets
from `tor_port` are incoming. This path is not triggered in normal real-mode
operation (which uses eth0).

---

## Session State Reference

| Key | Type | Description |
| --- | --- | --- |
| `running` | `bool` | Whether the capture worker is active |
| `data_source` | `str` | `"fake"` or `"real"` |
| `result_queue` | `queue.Queue` | Thread-safe channel from worker to UI |
| `worker` | `CaptureWorker \| None` | Reference to active worker |
| `logs` | `list[str]` | Rolling log lines (last 20 shown) |
| `total_packets` | `int` | Cumulative packet count since last start |
| `accuracy_trend` | `list[float]` | Confidence values over time |
| `last_result` | `InferenceResult \| None` | Most recent result |
| `defense_active` | `bool` | Sidebar toggle state (UI display only) |

`defense_active` in session state drives the sidebar display only.
The actual defense behavior is controlled by `_defense_enabled`
(threading.Event in defense_proxy.py), which the sidebar toggle
sets/clears directly.

---

## Feature Alignment

`extract_features(packets)` returns two simultaneous outputs:

- `model_vector`: 56-element `np.ndarray` passed to `model.predict_proba()`
- `display_dict`: 14-key dict shown in the "Last Feature Vector" expander

The 14 display features (`FEATURE_NAMES` in `dashboard.py`):
`total_packets`, `total_bytes`, `outgoing_packets`, `incoming_packets`,
`outgoing_bytes`, `incoming_bytes`, `mean_packet_size`, `std_packet_size`,
`mean_inter_arrival_ms`, `std_inter_arrival_ms`, `burst_count`,
`max_burst_size`, `outgoing_ratio`, `bytes_ratio`

---

## Known Limitations

| Limitation | Impact | Workaround |
| --- | --- | --- |
| Streamlit reruns entire script on interaction | Brief UI flicker | Use `st.fragment` in Streamlit ≥ 1.37 for partial reruns |
| Worker thread cannot write to session state | Defense state read via threading.Event, not session state | By design — `_defense_enabled` is the correct cross-thread mechanism |
| Real mode requires browser-level traffic | `requests.get()` is not classified accurately | Run `traffic_gen.py` (browser mode) in a separate terminal |
| Real mode capture requires raw socket access | Must re-grant after pip upgrades | `sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)` |
| `eth0` interface name assumed | Will fail on systems using different interface names | Check with `ip a`; update `SNIFF_IFACE` in dashboard.py if needed |
