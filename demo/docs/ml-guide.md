# ML Guide — Model Training and Artifacts

---

## Dataset

`evaluate_models.py` looks for `curated_raw_dataset.csv` in this order:

1. `demo/curated_raw_dataset.csv` (same directory)
2. `Machine Learning Engineer/curated_raw_dataset.csv`
3. `Data & Traffic Engineer/initial_dataset/curated_raw_dataset.csv`

If none are found, copy the file into `demo/` manually.

---

## Training

```bash
# From demo/ with venv active
python evaluate_models.py
```

Outputs:

| File | Description |
| --- | --- |
| `model.joblib` | Trained RandomForest (1000 estimators) |
| `scaler.joblib` | Fitted StandardScaler |
| `label_map.json` | `{int_index: site_name}` for 40 classes |
| `confusion_matrix.csv` | Per-class prediction counts |

These files are gitignored — regenerate them on each machine by running
`evaluate_models.py`.

---

## Feature Vector

The model uses a **56-element** feature vector extracted by `extract_features.py`:

| Index | Feature | Description |
| --- | --- | --- |
| 0 | `total_count` | Non-zero packets in trace |
| 1 | `out_count` | Outgoing packets |
| 2 | `in_count` | Incoming packets |
| 3 | `out_ratio` | Outgoing fraction |
| 4 | `size_ratio` | Outgoing bytes / incoming bytes |
| 5 | `avg_out_burst` | Mean outgoing burst length |
| 6 | `avg_in_burst` | Mean incoming burst length |
| 7 | `max_burst` | Largest burst |
| 8 | `burst_count` | Number of direction-change bursts |
| 9–11 | `bin_tiny/medium/large` | Packet size histogram (< 100 B, 100–999 B, ≥ 1000 B) |
| 12 | `size_mean` | Mean signed packet size |
| 13 | `size_std` | Std of signed packet size |
| 14 | `cumsum_mean` | Mean of cumulative sum trace |
| 15 | `cumsum_std` | Std of cumulative sum trace |
| 16–55 | `pkt_00`–`pkt_39` | First 40 raw signed packet sizes (zero-padded) |

---

## Dashboard Integration

`dashboard.py` (`RealDataSource`) loads these three files at startup:
- `model.joblib`
- `scaler.joblib`
- `label_map.json`

If any are missing the dashboard will raise `FileNotFoundError` on startup
before the UI loads — run `evaluate_models.py` first.

---

## Model Performance (from confusion_matrix.csv)

Run `analyze_results.py` (from the Machine Learning Engineer directory) to
see per-site accuracy ranked from best to worst:

```bash
python ../Machine\ Learning\ Engineer/analyze_results.py
```

Or copy `analyze_results.py` into `demo/` and run it directly.
