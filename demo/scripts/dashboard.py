"""
WF-Guard: Real-Time Website Fingerprinting Dashboard
=====================================================
Streamlit dashboard for live website fingerprinting demonstration.

Architecture:
  - FakeDataSource: simulated traffic + heuristic classifier (no Tor needed)
  - RealDataSource: live scapy capture on eth0 + trained RandomForest
  - CaptureWorker: background thread pushing InferenceResults to a queue
  - Streamlit UI: sole control surface — data source, defense, start/stop

Defense state is controlled exclusively by the sidebar toggle.
Cover traffic is started/stopped with the worker.

Usage:
    streamlit run dashboard.py
    streamlit run dashboard.py -- --source real
    streamlit run dashboard.py -- --source fake

Options (passed after --):
    --source fake|real   Default data source on load (default: fake).
                         Can be overridden in the sidebar at any time.
"""

import argparse
import json
import os
import sys
import streamlit as st
import pandas as pd
import numpy as np
import threading
import queue
import time
import random
from dataclasses import dataclass, field
from typing import Optional

# Defense proxy as a library — UI is the only control surface
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defense_proxy import _defense_enabled, start_cover_traffic, stop_cover_traffic

# parse_known_args so Streamlit's own argv entries don't cause errors
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--source", choices=["fake", "real"], default="fake",
                     help="Default data source (fake or real).")
_CLI, _ = _parser.parse_known_args()

# ── CONFIG ──────────────────────────────────────────────────────────────────
TOR_PORT      = 9050      # Tor daemon on Linux/WSL (9150 for Tor Browser)
WINDOW_SIZE   = 750       # packets per feature window (matches training median ~736)
POLL_INTERVAL = 0.5       # seconds between UI refresh
SNIFF_IFACE   = "eth0"    # Tor circuit traffic exits on eth0 (matches training data)

_SCRIPTS_DIR       = os.path.dirname(os.path.abspath(__file__))
_DEMO_DIR          = os.path.dirname(_SCRIPTS_DIR)
MODEL_DIR          = os.path.join(_DEMO_DIR, "models")   # demo/models/
GROUND_TRUTH_FILE  = "/tmp/wfguard_gt.txt"
LOG_FILE           = os.path.join(_DEMO_DIR, "logs", "inference_log.jsonl")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)     # ensure demo/logs/ exists

# ── DATA STRUCTURES ──────────────────────────────────────────────────────────
@dataclass
class InferenceResult:
    timestamp: float
    prediction: str
    confidence: float
    probabilities: dict
    packets_in_window: int
    features: dict
    defense_active: bool
    ground_truth: Optional[str] = None
    capture_s: Optional[float] = None    # seconds spent capturing the packet window
    latency_ms: Optional[float] = None   # milliseconds from features-ready to prediction

@dataclass
class PacketRecord:
    timestamp: float
    size: int
    direction: str           # "outgoing" | "incoming"
    inter_arrival: float     # ms

# ── FEATURE NAMES (14-key display dict from extract_features.py) ─────────────
FEATURE_NAMES = [
    "total_packets", "total_bytes",
    "outgoing_packets", "incoming_packets",
    "outgoing_bytes", "incoming_bytes",
    "mean_packet_size", "std_packet_size",
    "mean_inter_arrival_ms", "std_inter_arrival_ms",
    "burst_count", "max_burst_size",
    "outgoing_ratio", "bytes_ratio",
]

# ── FAKE DATA SOURCE ─────────────────────────────────────────────────────────
class FakeDataSource:
    """
    Simulated traffic source — no Tor required.
    Mirrors RealDataSource init: loads label_map.json to drive the site list,
    then generates synthetic packet windows and a heuristic classifier.
    """

    def __init__(self, defense_active_fn):
        self.defense_active_fn = defense_active_fn
        import json
        with open(os.path.join(MODEL_DIR, "label_map.json")) as f:
            lmap = json.load(f)
        self.labels = [lmap[str(i)] for i in range(len(lmap))]
        self._profiles = {site: self._make_profile(site) for site in self.labels}
        self.current_site = random.choice(self.labels)
        self._counter = 0

    @staticmethod
    def _make_profile(site: str) -> dict:
        """Deterministic per-site traffic profile seeded from the site name."""
        rng = random.Random(hash(site) & 0xFFFFFFFF)
        return dict(
            mean_size=rng.randint(400, 1400),
            std_size=rng.randint(100, 450),
            incoming_bias=round(rng.uniform(0.50, 0.88), 2),
        )

    def _rotate_site(self):
        self._counter += 1
        if self._counter >= random.randint(8, 15):
            self.current_site = random.choice(self.labels)
            self._counter = 0

    def _generate_window(self):
        profile = self._profiles[self.current_site]
        packets, t = [], time.time()
        for _ in range(WINDOW_SIZE):
            direction = "incoming" if random.random() < profile["incoming_bias"] else "outgoing"
            size = max(40, min(1500, int(np.random.normal(profile["mean_size"], profile["std_size"]))))
            iat  = max(0.1, np.random.exponential(10))
            t   += iat / 1000.0
            packets.append(PacketRecord(t, size, direction, iat))
        return packets

    def _extract_features(self, packets):
        sizes = [p.size for p in packets]
        iats  = [p.inter_arrival for p in packets]
        out   = [p for p in packets if p.direction == "outgoing"]
        inc   = [p for p in packets if p.direction == "incoming"]
        bursts = current = 1
        max_b  = 1
        for i in range(1, len(packets)):
            if packets[i].inter_arrival < 50:
                current += 1
                max_b = max(max_b, current)
            else:
                bursts += 1
                current = 1
        ob, ib = sum(p.size for p in out), sum(p.size for p in inc)
        tb = ob + ib
        return {
            "total_packets": len(packets), "total_bytes": tb,
            "outgoing_packets": len(out),  "incoming_packets": len(inc),
            "outgoing_bytes": ob,           "incoming_bytes": ib,
            "mean_packet_size": float(np.mean(sizes)),
            "std_packet_size":  float(np.std(sizes)),
            "mean_inter_arrival_ms": float(np.mean(iats)),
            "std_inter_arrival_ms":  float(np.std(iats)),
            "burst_count": bursts, "max_burst_size": max_b,
            "outgoing_ratio": len(out) / len(packets) if packets else 0,
            "bytes_ratio":    ob / tb if tb else 0,
        }

    def _predict(self, features):
        # Use the thread-safe Event — st.session_state is not accessible
        # from background worker threads (ScriptRunContext missing).
        defense = _defense_enabled.is_set()
        if defense:
            # Defense on: uniform low-confidence scores across all sites —
            # simulates the classifier being unable to fingerprint the traffic.
            raw = {s: random.uniform(0.05, 0.25) for s in self.labels}
        else:
            # Defense off: simulate a well-trained classifier correctly
            # identifying the current site with high confidence.
            # Runner-up scores are kept very small so the current site
            # normalizes to ~65–80% even with 40 competing labels.
            raw = {s: random.uniform(0.002, 0.008) for s in self.labels}
            raw[self.current_site] = random.uniform(0.60, 0.85)
        total = sum(max(v, 0.001) for v in raw.values())
        probs = {s: max(v, 0.001) / total for s, v in raw.items()}
        pred  = max(probs, key=probs.get)
        return pred, probs[pred], probs

    def get_next_result(self):
        self._rotate_site()
        packets  = self._generate_window()
        features = self._extract_features(packets)
        pred, conf, probs = self._predict(features)
        return InferenceResult(
            timestamp=time.time(), prediction=pred, confidence=conf,
            probabilities=probs, packets_in_window=len(packets),
            features=features, defense_active=_defense_enabled.is_set(),
            ground_truth=self.current_site,
        )


# ── REAL DATA SOURCE ──────────────────────────────────────────────────────────
class RealDataSource:
    """
    Live capture on SNIFF_IFACE → extract_features → model inference.
    Requires model.joblib, scaler.joblib, label_map.json in MODEL_DIR.
    Generate with: python evaluate_models.py
    """
    def __init__(self, defense_active_fn):
        self.defense_active_fn = defense_active_fn
        import joblib, json
        self.model  = joblib.load(os.path.join(MODEL_DIR, "model.joblib"))
        self.scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
        with open(os.path.join(MODEL_DIR, "label_map.json")) as f:
            lmap = json.load(f)
        self.labels = [lmap[str(i)] for i in range(len(lmap))]

    def get_next_result(self):
        from scapy.all import AsyncSniffer
        from extract_features import extract_features

        t_capture_start = time.time()
        sniffer = AsyncSniffer(
            iface=SNIFF_IFACE,
            filter="tcp",        # Tor circuit traffic on eth0 uses guard-node ports (443/9001), not 9050
            count=WINDOW_SIZE,
            timeout=60,
        )
        sniffer.start()
        sniffer.join()
        capture_s = time.time() - t_capture_start
        packets = list(sniffer.results or [])

        if not packets:
            raise RuntimeError(
                f"No packets captured on '{SNIFF_IFACE}' (tcp port {TOR_PORT}, 15s timeout). "
                "Run traffic_gen.py in a separate terminal to generate Tor traffic."
            )

        model_vec, display_dict = extract_features(packets, tor_port=TOR_PORT)
        scaled = self.scaler.transform([model_vec])

        t_inf_start = time.time()
        probs_arr   = self.model.predict_proba(scaled)[0]
        latency_ms  = (time.time() - t_inf_start) * 1000

        probs     = dict(zip(self.labels, probs_arr))
        prediction = max(probs, key=probs.get)
        confidence = probs[prediction]

        ground_truth = None
        try:
            with open(GROUND_TRUTH_FILE) as f:
                ground_truth = f.read().strip() or None
        except OSError:
            pass

        return InferenceResult(
            timestamp=time.time(), prediction=prediction, confidence=confidence,
            probabilities=probs, packets_in_window=len(packets),
            features=display_dict, defense_active=self.defense_active_fn(),
            ground_truth=ground_truth, capture_s=round(capture_s, 3),
            latency_ms=round(latency_ms, 2),
        )


# ── CAPTURE WORKER ────────────────────────────────────────────────────────────
class CaptureWorker:
    def __init__(self, result_queue: queue.Queue, defense_active_fn, data_source: str = "fake"):
        self._queue      = result_queue
        self._stop_event = threading.Event()
        source_cls       = FakeDataSource if data_source == "fake" else RealDataSource
        self._source     = source_cls(defense_active_fn)
        self._thread     = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _loop(self):
        while not self._stop_event.is_set():
            try:
                result = self._source.get_next_result()
                self._queue.put(result)
            except Exception as e:
                self._queue.put(e)
            time.sleep(POLL_INTERVAL)


# ── SESSION STATE ─────────────────────────────────────────────────────────────
def init_state():
    defaults = {
        "running":            False,
        "data_source":        _CLI.source,
        "result_queue":       queue.Queue(),
        "worker":             None,
        "logs":               ["[INIT] System ready. Select a mode and press Start."],
        "total_packets":      0,
        "conf_trend":         [],   # list of {"Prediction Conf": float, "GT Conf": float|None}
        "correct_count":      0,
        "top3_correct_count": 0,
        "gt_conf_sum":        0.0,
        "inference_count":    0,
        "last_result":        None,
        "defense_active":     False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ── PAGE SETUP ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WF-Guard: Real-Time Attack Dashboard",
    page_icon="🛡️",
    layout="wide",
)
st.markdown("""
<style>
[data-testid="stMetric"] { background: #1e2130; padding: 15px; border-radius: 8px; border-left: 4px solid #4e73df; }
.log-box { font-family: monospace; font-size: 0.82rem; background: #0e1117; padding: 12px; border-radius: 6px; color: #00ff88; }
</style>
""", unsafe_allow_html=True)

init_state()


# ── SIDEBAR ───────────────────────────────────────────────────────────────────
st.sidebar.title("🎮 WF-Guard Controls")
st.sidebar.markdown("---")

# ── Data source selector (locked while running) ───────────────────────────────
st.sidebar.subheader("Data Source")
data_source = st.sidebar.radio(
    "mode",
    ["Fake", "Real"],
    index=0 if st.session_state["data_source"] == "fake" else 1,
    disabled=st.session_state["running"],
    label_visibility="collapsed",
)
st.session_state["data_source"] = data_source.lower()

if data_source == "Fake":
    st.sidebar.info("🟡 Simulated data — no Tor required")
else:
    st.sidebar.info("🟢 Live Tor sniffer — Tor must be running")

st.sidebar.markdown("---")

# ── Defense toggle — sole controller of _defense_enabled ─────────────────────
st.sidebar.subheader("WF-Guard Defense")
defense_toggle = st.sidebar.toggle("Enable WF-Guard")
st.session_state["defense_active"] = defense_toggle

# Sync to defense_proxy threading.Event — this is the only place it is set
if defense_toggle:
    _defense_enabled.set()
    st.sidebar.success("DEFENSE: ON — Cover traffic + timing jitter active")
else:
    _defense_enabled.clear()
    st.sidebar.error("DEFENSE: OFF — Vulnerable")

st.sidebar.markdown("---")

# ── Start / Stop ──────────────────────────────────────────────────────────────
col_start, col_stop = st.sidebar.columns(2)
start_btn = col_start.button("▶ Start", use_container_width=True)
stop_btn  = col_stop.button("⏹ Stop",  use_container_width=True)

if start_btn and not st.session_state["running"]:
    src = st.session_state["data_source"]
    st.session_state["result_queue"]       = queue.Queue()
    st.session_state["conf_trend"]         = []
    st.session_state["correct_count"]      = 0
    st.session_state["top3_correct_count"] = 0
    st.session_state["gt_conf_sum"]        = 0.0
    st.session_state["inference_count"]    = 0
    st.session_state["total_packets"]      = 0
    st.session_state["logs"] = [
        f"[{time.strftime('%H:%M:%S')}] Started — source: {src.upper()}"
    ]
    worker = CaptureWorker(
        result_queue=st.session_state["result_queue"],
        defense_active_fn=lambda: st.session_state.get("defense_active", False),
        data_source=src,
    )
    worker.start()
    start_cover_traffic()  # controlled by _defense_enabled; idles when defense is OFF
    st.session_state["worker"]  = worker
    st.session_state["running"] = True

if stop_btn and st.session_state["running"]:
    stop_cover_traffic()
    if st.session_state["worker"]:
        st.session_state["worker"].stop()
    st.session_state["running"] = False
    st.session_state["logs"].append(f"[{time.strftime('%H:%M:%S')}] Stopped.")


# ── DRAIN QUEUE ───────────────────────────────────────────────────────────────
latest_result: Optional[InferenceResult] = st.session_state["last_result"]

while not st.session_state["result_queue"].empty():
    item = st.session_state["result_queue"].get_nowait()
    if isinstance(item, Exception):
        st.session_state["logs"].append(f"[ERROR] {item}")
        continue

    latest_result = item
    st.session_state["last_result"]    = item
    st.session_state["total_packets"] += item.packets_in_window

    ts    = time.strftime('%H:%M:%S', time.localtime(item.timestamp))
    dflag = " [DEF ON]" if item.defense_active else ""

    gt_rank = None
    gt_conf = None
    in_top3 = False
    in_top5 = False

    if item.ground_truth is not None:
        sorted_probs = sorted(item.probabilities.items(), key=lambda x: -x[1])
        # Rank of ground-truth class (1-based; len+1 if absent from label map)
        gt_rank = next(
            (i + 1 for i, (s, _) in enumerate(sorted_probs) if s == item.ground_truth),
            len(sorted_probs) + 1,
        )
        gt_conf = item.probabilities.get(item.ground_truth, 0.0)
        in_top3 = gt_rank <= 3
        in_top5 = gt_rank <= 5
        top3    = [[s, round(p, 4)] for s, p in sorted_probs[:3]]
        correct = item.prediction == item.ground_truth

        st.session_state["inference_count"]    += 1
        st.session_state["gt_conf_sum"]        += gt_conf
        if correct:
            st.session_state["correct_count"]      += 1
        if in_top3:
            st.session_state["top3_correct_count"] += 1

        result_flag = (
            f" ✓ (gt_conf={gt_conf:.1%})" if correct
            else f" ✗ (gt={item.ground_truth}, rank={gt_rank}, gt_conf={gt_conf:.1%})"
        )

        # Write structured log entry
        log_entry = {
            "ts":               item.timestamp,
            "source":           st.session_state["data_source"],
            "prediction":       item.prediction,
            "confidence":       round(item.confidence, 4),
            "ground_truth":     item.ground_truth,
            "gt_rank":          gt_rank,
            "gt_confidence":    round(gt_conf, 4),
            "in_top3":          in_top3,
            "in_top5":          in_top5,
            "top3":             top3,
            "defense_active":   item.defense_active,
            "packets_in_window": item.packets_in_window,
            "capture_s":        item.capture_s,
            "latency_ms":       item.latency_ms,
        }
        try:
            with open(LOG_FILE, "a") as _lf:
                _lf.write(json.dumps(log_entry) + "\n")
        except OSError:
            pass  # non-fatal — dashboard keeps running if log write fails
    else:
        result_flag = ""

    st.session_state["conf_trend"].append({
        "Prediction Conf": item.confidence,
        "GT Conf":         gt_conf,
    })
    st.session_state["logs"].append(
        f"[{ts}]{dflag} → {item.prediction} ({item.confidence:.1%}){result_flag}"
        f" | pkts={item.packets_in_window}"
    )


# ── MAIN UI ───────────────────────────────────────────────────────────────────
src_label = st.session_state["data_source"].upper()
status    = "🟢 Running" if st.session_state["running"] else "🔴 Stopped"
st.title("🛡️ WF-Guard: Real-Time Website Fingerprinting")
st.caption(f"Source: **{src_label}** | {status}")

# ── METRICS ───────────────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
if latest_result:
    n_inf  = st.session_state["inference_count"]
    n_cor  = st.session_state["correct_count"]
    n_top3 = st.session_state["top3_correct_count"]
    gt_avg = (st.session_state["gt_conf_sum"] / n_inf) if n_inf > 0 else None
    acc1_str  = f"{n_cor/n_inf:.1%} ({n_cor}/{n_inf})"   if n_inf > 0 else "—"
    acc3_str  = f"{n_top3/n_inf:.1%} ({n_top3}/{n_inf})" if n_inf > 0 else "—"
    gtc_str   = f"{gt_avg:.1%}" if gt_avg is not None else "—"
    m1.metric("Prediction",        latest_result.prediction)
    m2.metric("Confidence",        f"{latest_result.confidence:.1%}")
    m3.metric("Packets Processed", st.session_state["total_packets"])
    m4.metric("Inferences",        n_inf if n_inf > 0 else "—")
    a1, a2, a3 = st.columns(3)
    a1.metric("Top-1 Accuracy",    acc1_str)
    a2.metric("Top-3 Accuracy",    acc3_str)
    a3.metric("Avg GT Confidence", gtc_str,
              help="Average probability assigned to the correct class, "
                   "regardless of whether it was the top prediction.")
else:
    m1.metric("Prediction",        "Waiting...")
    m2.metric("Confidence",        "—")
    m3.metric("Packets Processed", 0)
    m4.metric("Inferences",        "—")
    a1, a2, a3 = st.columns(3)
    a1.metric("Top-1 Accuracy",    "—")
    a2.metric("Top-3 Accuracy",    "—")
    a3.metric("Avg GT Confidence", "—")

st.markdown("---")

# ── CHARTS ───────────────────────────────────────────────────────────────────
v1, v2 = st.columns([2, 1])

with v1:
    st.subheader("📈 Confidence Over Time")
    trend = st.session_state["conf_trend"]
    if trend:
        chart_df = pd.DataFrame(trend).rename_axis("Sample")
        # Drop GT Conf column if no ground truth was available this session
        if chart_df["GT Conf"].isna().all():
            chart_df = chart_df[["Prediction Conf"]]
        st.line_chart(chart_df)
    else:
        st.info("Press Start to see live confidence trend.")

with v2:
    st.subheader("🕵️ Classifier Probabilities")
    if latest_result:
        prob_df = (
            pd.DataFrame({"Site": list(latest_result.probabilities.keys()),
                          "Probability": list(latest_result.probabilities.values())})
            .set_index("Site")
            .sort_values("Probability", ascending=False)
        )
        st.bar_chart(prob_df)
    else:
        st.info("Waiting for first inference...")

st.markdown("---")

# ── FEATURE SNAPSHOT ─────────────────────────────────────────────────────────
if latest_result:
    with st.expander("🔬 Last Feature Vector", expanded=False):
        feat_df = pd.DataFrame(latest_result.features.items(), columns=["Feature", "Value"])
        feat_df["Value"] = feat_df["Value"].apply(lambda x: f"{x:.3f}" if isinstance(x, float) else x)
        st.dataframe(feat_df, width="stretch", hide_index=True)

# ── LOGS ─────────────────────────────────────────────────────────────────────
st.subheader("📟 Real-Time Logs")
st.markdown(
    '<div class="log-box">' + "<br>".join(st.session_state["logs"][-20:]) + "</div>",
    unsafe_allow_html=True,
)

# ── AUTO-RERUN ───────────────────────────────────────────────────────────────
if st.session_state["running"]:
    time.sleep(POLL_INTERVAL)
    st.rerun()
