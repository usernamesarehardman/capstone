# ML Guide — Model Training, Artifacts, and Feature Reference

---

## Dataset

`curated_raw_dataset.csv` is included in `demo/scripts/`. No manual path
changes are needed. `evaluate_models.py` searches in this order:

1. `demo/scripts/` (default — file is included here)
2. `archive/Machine Learning Engineer/` (fallback)
3. `archive/Data & Traffic Engineer/initial_dataset/` (fallback)

**Dataset format:** Each row is one traffic trace.

```
website_label, pkt_1, pkt_2, ..., pkt_1500
```

Each `pkt_N` value is a **signed IP-layer packet length** (`p[IP].len`):
- Positive → outgoing packet (client IP matches source)
- Negative → incoming packet
- Zero → padding (trace shorter than 1500 packets)

Traces were collected with `tcpdump -i eth0 tcp` while Firefox loaded full
pages through Tor (see `archive/Data & Traffic Engineer/collect.py`).
Client IP is identified from `packets[0][IP].src` in each pcap.

---

## Training

```bash
# From demo/scripts/ with venv active
python evaluate_models.py
```

Outputs into `demo/scripts/`:

| File | Description |
| --- | --- |
| `model.joblib` | Trained RandomForest (1000 estimators) |
| `scaler.joblib` | Fitted StandardScaler |
| `label_map.json` | `{int_index: site_name}` for 40 classes |
| `confusion_matrix.csv` | Per-class prediction counts on 20% test split |

Pre-trained artifacts are committed. Re-run only if you change the dataset
or model parameters.

---

## Feature Vector (56 elements)

Extracted by `extract_features.py` from a window of scapy packets.
Mirrors `extract_wf_features()` in `evaluate_models.py` exactly.

| Index | Feature | Description |
| --- | --- | --- |
| 0 | `total_count` | Non-zero packets in trace |
| 1 | `out_count` | Outgoing packets |
| 2 | `in_count` | Incoming packets |
| 3 | `out_ratio` | Outgoing fraction |
| 4 | `size_ratio` | Outgoing bytes / incoming bytes |
| 5 | `avg_out_burst` | Mean outgoing burst length |
| 6 | `avg_in_burst` | Mean incoming burst length |
| 7 | `max_burst` | Largest burst (either direction) |
| 8 | `burst_count` | Number of direction-change bursts |
| 9 | `bin_tiny` | Packets < 100 B |
| 10 | `bin_medium` | Packets 100–999 B |
| 11 | `bin_large` | Packets ≥ 1000 B |
| 12 | `size_mean` | Mean signed packet size |
| 13 | `size_std` | Std of signed packet size |
| 14 | `cumsum_mean` | Mean of cumulative sum trace |
| 15 | `cumsum_std` | Std of cumulative sum trace |
| 16–55 | `pkt_00`–`pkt_39` | First 40 raw signed packet sizes (zero-padded) |

---

## Training vs. Inference Size Convention

**Training** (`build_csv.py`): uses `p[IP].len` — the IP-layer datagram
length, excluding the 14-byte Ethernet header.

**Inference** (`extract_features.py`): uses `len(pkt)` — Scapy's total
packet length, which includes the Ethernet header (+14 bytes per packet).

This introduces a systematic ~14-byte offset per packet in the `pkt_00`–
`pkt_39` raw features. The offset is small relative to typical packet sizes
(40–1500 bytes) and does not significantly affect classification accuracy.

---

## Real-Mode Traffic Requirement

The model was trained on **browser page loads** — headless Firefox fetching
full pages through Tor, capturing all sub-resources (CSS, JS, images). The
traffic generator must reproduce this pattern for real-mode classification
to work correctly.

**Correct:** `python traffic_gen.py` (headless Firefox, browser mode)

**Incorrect:** `python traffic_gen.py --simple` (bare `requests.get()` —
loads HTML only, produces a completely different traffic pattern that the
model was not trained on)

The capture interface must also be `eth0` (not `lo`) to match the training
capture interface. This is set in `SNIFF_IFACE` in `dashboard.py`.

---

## Dashboard Integration

`dashboard.py` (`RealDataSource`) loads these files at startup:

- `model.joblib`
- `scaler.joblib`
- `label_map.json`

If any are missing, `RealDataSource.__init__` raises `FileNotFoundError`
before the UI loads. Run `evaluate_models.py` first to regenerate.

---

## Model Performance

From `confusion_matrix.csv` (20% holdout, 40 classes):

Strong classes (near-perfect): `wikipedia`, `duckduckgo`, `theguardian`

Weaker classes: `apache`, `loc`, `cdc`, `upenn` (confused with structurally
similar academic/government sites)

Overall test-set accuracy is visible in the terminal output of
`evaluate_models.py` (Top-1 and Top-5 accuracy).
