# WF-Guard

Real-time website fingerprinting detection and defense system for Tor traffic.
Capstone project — OU Polytechnic Institute, Cybersecurity, Spring 2026.

## What It Does

WF-Guard demonstrates that a passive adversary can identify which website a
user is browsing over Tor by analyzing encrypted traffic metadata — packet
sizes, timing, and direction — without ever decrypting the connection. It then
actively defends against this attack by injecting cover traffic and timing
jitter to obscure the fingerprint.

**System components:**

| Component | Description |
| --- | --- |
| **Classifier** | Random Forest on 113 CUMUL features, ~40–95 sites |
| **Feature extractor** | Capture-length-invariant signed trace → feature vector |
| **Defense proxy** | SOCKS5 proxy with cover traffic and timing noise |
| **Dashboard** | Real-time Streamlit UI for live fingerprinting and defense |
| **Traffic generator** | Headless Firefox-over-Tor for real evaluation traffic |
| **Log analyzer** | Offline top-1/3/5 accuracy and per-site reporting |

## Quick Start

See [demo/README.md](demo/README.md) for full setup. The short version:

```bash
cd demo
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Train the classifier
python scripts/evaluate_models.py

# Launch dashboard (fake mode — no Tor required)
streamlit run scripts/dashboard.py
```

## Repository Layout

```text
capstone/
├── demo/                        ← Active demo environment (start here)
│   ├── README.md                ← Full setup and usage guide
│   ├── requirements.txt         ← All Python dependencies
│   ├── scripts/                 ← Runnable Python scripts
│   │   ├── dashboard.py         ← Streamlit UI
│   │   ├── evaluate_models.py   ← Model trainer
│   │   ├── extract_features.py  ← Live feature extractor
│   │   ├── traffic_gen.py       ← Firefox-over-Tor traffic generator
│   │   ├── analyze_log.py       ← Inference log reporter
│   │   ├── defense_proxy.py     ← Cover traffic + timing jitter
│   │   ├── evaluate.py          ← Phase 5 bandwidth/latency benchmark
│   │   ├── dataset_manager.py   ← pcap ingestion and traffic profiling
│   │   └── collect/
│   │       └── collect_fresh.py ← Fresh training data collector
│   ├── data/                    ← Training datasets (curated CSV; CW.npz gitignored)
│   ├── models/                  ← Trained artifacts (gitignored — regenerate)
│   ├── logs/                    ← Inference log output (gitignored)
│   ├── drivers/                 ← geckodriver binary
│   └── docs/                    ← Component documentation
│       ├── dashboard.md
│       ├── defense.md
│       ├── ml-guide.md
│       └── team-brief.md
│
├── artifacts/                   ← Per-role development history (read-only reference)
│   ├── Data & Traffic Engineer/
│   ├── Defense & Integration Engineer/
│   ├── Machine Learning Engineer/
│   └── Systems Engineer/
│
└── docs/
    └── REFERENCES.md
```

## Team Roles

| Role | Primary Deliverable |
| --- | --- |
| Data & Traffic Engineer | Tor packet capture, signed trace CSV pipeline |
| Machine Learning Engineer | CUMUL feature extraction, Random Forest classifier |
| Defense & Integration Engineer | Defense proxy, cover traffic, Tor integration |
| Systems Engineer | Real-time Streamlit dashboard |

## Key Design Decisions

- **CUMUL features** (Panchenko et al., 2016) — 100 interpolated cumulative-sum
  points, normalized by total bytes for capture-length invariance. Replaces raw
  packet-head features that drifted as websites changed CDN and content.
- **Capture-length normalization** — all aggregate features (bins, burst density,
  cumsum stats) are divided by packet count so the model generalizes across
  different window sizes and collection conditions.
- **Ground-truth side-channel** — `traffic_gen.py` writes the current site name
  to `/tmp/wfguard_gt.txt` before each page load; the dashboard reads it for
  live rolling accuracy tracking.
- **Structured inference logging** — every classified window is appended to
  `logs/inference_log.jsonl` with gt_rank, gt_confidence, and top-3 predictions
  for offline analysis via `analyze_log.py`.

## References

See [docs/REFERENCES.md](docs/REFERENCES.md) and the `../literature/` directory
for cited papers, including the CUMUL, k-fingerprinting, and Deep Fingerprinting
works this project builds on.
