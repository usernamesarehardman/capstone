"""
WF-Guard: Real-Time Website Fingerprinting Dashboard
=====================================================
Architecture:
  - FakeDataSource (drop-in for real scapy capture): generates realistic
    packet bursts, feature vectors, and model predictions
  - RealDataSource: live scapy capture + trained RandomForest inference
  - CaptureWorker: background thread that pushes results to a queue
  - Streamlit UI: polls queue and updates all placeholders

To switch from fake to real data:
  1. Run evaluate_models.py to generate model.joblib, scaler.joblib, label_map.json
  2. Start Tor:  sudo systemctl start tor
  3. Set DATA_SOURCE = "real" below
  4. Run: sudo $(which streamlit) run dashboard.py
         (or use setcap — see docs/dashboard.md)
"""

import os
import streamlit as st
import pandas as pd
import numpy as np
import threading
import queue
import time
import random
from dataclasses import dataclass, field
from typing import Optional

# ── CONFIG ──────────────────────────────────────────────────────────────────
DATA_SOURCE = "fake"   # "fake" | "real"
TOR_PORT    = 9050     # Tor daemon default on Linux/WSL (use 9150 for Tor Browser)
WINDOW_SIZE = 100      # packets per feature window
POLL_INTERVAL = 0.5   # seconds between UI refresh

# Model artifacts live in the same directory as this script
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

MONITORED_SITES = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "wikipedia.org",
    "twitter.com",
    "reddit.com",
    "github.com",
]

# ── DATA STRUCTURES ──────────────────────────────────────────────────────────
@dataclass
class InferenceResult:
    timestamp: float
    prediction: str
    confidence: float
    probabilities: dict          # {site: prob}
    packets_in_window: int
    features: dict               # raw feature vector snapshot
    defense_active: bool

@dataclass
class PacketRecord:
    timestamp: float
    size: int
    direction: str               # "outgoing" | "incoming"
    inter_arrival: float         # ms

# ── FEATURE NAMES (mirrors what extract_features.py produces for display) ────
FEATURE_NAMES = [
    "total_packets",
    "total_bytes",
    "outgoing_packets",
    "incoming_packets",
    "outgoing_bytes",
    "incoming_bytes",
    "mean_packet_size",
    "std_packet_size",
    "mean_inter_arrival_ms",
    "std_inter_arrival_ms",
    "burst_count",
    "max_burst_size",
    "outgoing_ratio",
    "bytes_ratio",
]

# ── FAKE DATA SOURCE ─────────────────────────────────────────────────────────
class FakeDataSource:
    """
    Generates statistically plausible Tor traffic patterns per site.
    Each site has a distinct traffic signature (size distribution, burst pattern)
    to make the fake model predictions meaningful rather than purely random.
    """
    SITE_PROFILES = {
        "google.com":    dict(mean_size=800,  std_size=300, burst_rate=0.3, incoming_bias=0.6),
        "youtube.com":   dict(mean_size=1400, std_size=200, burst_rate=0.7, incoming_bias=0.85),
        "facebook.com":  dict(mean_size=900,  std_size=400, burst_rate=0.4, incoming_bias=0.65),
        "amazon.com":    dict(mean_size=1100, std_size=350, burst_rate=0.35, incoming_bias=0.7),
        "wikipedia.org": dict(mean_size=1300, std_size=150, burst_rate=0.2, incoming_bias=0.75),
        "twitter.com":   dict(mean_size=700,  std_size=250, burst_rate=0.5, incoming_bias=0.55),
        "reddit.com":    dict(mean_size=1000, std_size=300, burst_rate=0.45, incoming_bias=0.68),
        "github.com":    dict(mean_size=950,  std_size=280, burst_rate=0.25, incoming_bias=0.60),
    }

    def __init__(self, defense_active_fn):
        self.defense_active_fn = defense_active_fn
        self.current_site = random.choice(MONITORED_SITES)
        self.site_rotation_counter = 0

    def _rotate_site(self):
        self.site_rotation_counter += 1
        if self.site_rotation_counter >= random.randint(8, 15):
            self.current_site = random.choice(MONITORED_SITES)
            self.site_rotation_counter = 0

    def generate_packet_window(self) -> list[PacketRecord]:
        profile = self.SITE_PROFILES[self.current_site]
        packets = []
        t = time.time()
        for _ in range(WINDOW_SIZE):
            direction = "incoming" if random.random() < profile["incoming_bias"] else "outgoing"
            size = max(40, int(np.random.normal(profile["mean_size"], profile["std_size"])))
            size = min(size, 1500)
            iat = max(0.1, np.random.exponential(10))
            t += iat / 1000.0
            packets.append(PacketRecord(
                timestamp=t,
                size=size,
                direction=direction,
                inter_arrival=iat,
            ))
        return packets

    def extract_features(self, packets: list[PacketRecord]) -> dict:
        sizes = [p.size for p in packets]
        iats  = [p.inter_arrival for p in packets]
        out   = [p for p in packets if p.direction == "outgoing"]
        inc   = [p for p in packets if p.direction == "incoming"]

        bursts, current_burst = 1, 1
        max_burst = 1
        for i in range(1, len(packets)):
            if packets[i].inter_arrival < 50:
                current_burst += 1
                max_burst = max(max_burst, current_burst)
            else:
                bursts += 1
                current_burst = 1

        out_bytes = sum(p.size for p in out)
        inc_bytes = sum(p.size for p in inc)
        total_bytes = out_bytes + inc_bytes

        return {
            "total_packets":        len(packets),
            "total_bytes":          total_bytes,
            "outgoing_packets":     len(out),
            "incoming_packets":     len(inc),
            "outgoing_bytes":       out_bytes,
            "incoming_bytes":       inc_bytes,
            "mean_packet_size":     float(np.mean(sizes)),
            "std_packet_size":      float(np.std(sizes)),
            "mean_inter_arrival_ms": float(np.mean(iats)),
            "std_inter_arrival_ms": float(np.std(iats)),
            "burst_count":          bursts,
            "max_burst_size":       max_burst,
            "outgoing_ratio":       len(out) / len(packets) if packets else 0,
            "bytes_ratio":          out_bytes / total_bytes if total_bytes else 0,
        }

    def fake_model_predict(self, features: dict, true_site: str) -> tuple[str, float, dict]:
        defense = bool(self.defense_active_fn())
        if defense:
            raw = {s: random.uniform(0.05, 0.25) for s in MONITORED_SITES}
        else:
            raw = {}
            for site, profile in self.SITE_PROFILES.items():
                size_match = 1.0 - min(
                    abs(features["mean_packet_size"] - profile["mean_size"]) / profile["mean_size"], 1.0
                )
                bias_match = 1.0 - abs(features["incoming_packets"] / features["total_packets"] - profile["incoming_bias"])
                raw[site] = (size_match * 0.6 + bias_match * 0.4) + random.uniform(-0.1, 0.1)

        total = sum(max(v, 0.01) for v in raw.values())
        probs = {s: max(v, 0.01) / total for s, v in raw.items()}
        prediction = max(probs, key=probs.get)
        confidence = probs[prediction]
        return prediction, confidence, probs

    def get_next_result(self) -> InferenceResult:
        self._rotate_site()
        packets  = self.generate_packet_window()
        features = self.extract_features(packets)
        pred, conf, probs = self.fake_model_predict(features, self.current_site)

        return InferenceResult(
            timestamp=time.time(),
            prediction=pred,
            confidence=conf,
            probabilities=probs,
            packets_in_window=len(packets),
            features=features,
            defense_active=self.defense_active_fn(),
        )


# ── REAL DATA SOURCE ──────────────────────────────────────────────────────────
class RealDataSource:
    """
    Live packet capture → feature extraction → model inference.

    Requires in the same directory:
        model.joblib    — trained RandomForest
        scaler.joblib   — fitted StandardScaler
        label_map.json  — {int_index: site_name}

    Generate those artifacts first:
        python evaluate_models.py

    Scapy needs raw socket access. Either run streamlit as root:
        sudo $(which streamlit) run dashboard.py
    Or grant the capability once:
        sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)
    """

    def __init__(self, defense_active_fn):
        self.defense_active_fn = defense_active_fn
        import joblib, json
        self.model  = joblib.load(os.path.join(MODEL_DIR, "model.joblib"))
        self.scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
        with open(os.path.join(MODEL_DIR, "label_map.json")) as f:
            lmap = json.load(f)
        # JSON keys are always strings; convert to ordered list
        self.labels = [lmap[str(i)] for i in range(len(lmap))]

    def get_next_result(self) -> InferenceResult:
        from scapy.all import AsyncSniffer
        from extract_features import extract_features

        sniffer = AsyncSniffer(
            filter=f"tcp port {TOR_PORT}",
            count=WINDOW_SIZE,
            timeout=15,
        )
        sniffer.start()
        sniffer.join()
        packets = list(sniffer.results or [])

        model_vec, display_dict = extract_features(packets)
        scaled    = self.scaler.transform([model_vec])
        probs_arr = self.model.predict_proba(scaled)[0]

        probs      = dict(zip(self.labels, probs_arr))
        prediction = max(probs, key=probs.get)
        confidence = probs[prediction]

        return InferenceResult(
            timestamp=time.time(),
            prediction=prediction,
            confidence=confidence,
            probabilities=probs,
            packets_in_window=len(packets),
            features=display_dict,
            defense_active=self.defense_active_fn(),
        )


# ── CAPTURE WORKER (background thread) ───────────────────────────────────────
class CaptureWorker:
    def __init__(self, result_queue: queue.Queue, defense_active_fn):
        self._queue = result_queue
        self._stop_event = threading.Event()
        source_cls = FakeDataSource if DATA_SOURCE == "fake" else RealDataSource
        self._source = source_cls(defense_active_fn)
        self._thread = threading.Thread(target=self._loop, daemon=True)

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


# ── SESSION STATE INIT ────────────────────────────────────────────────────────
def init_state():
    defaults = {
        "running":         False,
        "result_queue":    queue.Queue(),
        "worker":          None,
        "logs":            ["[INIT] System initialized.", f"[INIT] Data source: {DATA_SOURCE.upper()}", "[INIT] Waiting to start..."],
        "total_packets":   0,
        "accuracy_trend":  [],
        "last_result":     None,
        "defense_active":  False,
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
st.sidebar.title("🎮 System Controls")
st.sidebar.markdown("---")

st.sidebar.subheader("Input Source")
source_label = "🟡 Fake Data (Testing)" if DATA_SOURCE == "fake" else "🟢 Live Sniffer"
st.sidebar.info(source_label)

st.sidebar.markdown("---")
st.sidebar.subheader("Tor-Integrated Defense")
defense_toggle = st.sidebar.toggle("Enable WF-Guard (Padding/Obfuscation)")
st.session_state["defense_active"] = defense_toggle

if defense_toggle:
    st.sidebar.success("DEFENSE: ON — Injecting dummy packets")
else:
    st.sidebar.error("DEFENSE: OFF — Vulnerable")

st.sidebar.markdown("---")
col_start, col_stop = st.sidebar.columns(2)
start_btn = col_start.button("▶ Start",  use_container_width=True)
stop_btn  = col_stop.button("⏹ Stop",   use_container_width=True)

if start_btn and not st.session_state["running"]:
    st.session_state["result_queue"]  = queue.Queue()
    st.session_state["accuracy_trend"] = []
    st.session_state["total_packets"]  = 0
    st.session_state["logs"]           = [f"[{time.strftime('%H:%M:%S')}] System started. Source: {DATA_SOURCE.upper()}"]
    worker = CaptureWorker(
        result_queue=st.session_state["result_queue"],
        defense_active_fn=lambda: st.session_state.get("defense_active", False),
    )
    worker.start()
    st.session_state["worker"]  = worker
    st.session_state["running"] = True

if stop_btn and st.session_state["running"]:
    if st.session_state["worker"]:
        st.session_state["worker"].stop()
    st.session_state["running"] = False
    st.session_state["logs"].append(f"[{time.strftime('%H:%M:%S')}] System stopped.")


# ── DRAIN QUEUE ───────────────────────────────────────────────────────────────
latest_result: Optional[InferenceResult] = st.session_state["last_result"]

while not st.session_state["result_queue"].empty():
    item = st.session_state["result_queue"].get_nowait()
    if isinstance(item, Exception):
        st.session_state["logs"].append(f"[ERROR] {item}")
        continue
    latest_result = item
    st.session_state["last_result"]   = item
    st.session_state["total_packets"] += item.packets_in_window
    st.session_state["accuracy_trend"].append(item.confidence)

    ts = time.strftime('%H:%M:%S', time.localtime(item.timestamp))
    defense_str = " [DEFENSE ON]" if item.defense_active else ""
    st.session_state["logs"].append(
        f"[{ts}]{defense_str} → {item.prediction} ({item.confidence:.1%}) "
        f"| pkts={item.packets_in_window} | bursts={item.features.get('burst_count', '?')}"
    )


# ── MAIN UI ───────────────────────────────────────────────────────────────────
st.title("🛡️ WF-Guard: Real-Time Website Fingerprinting")
st.caption(f"Data source: **{DATA_SOURCE.upper()}** | Status: {'🟢 Running' if st.session_state['running'] else '🔴 Stopped'}")

# ── METRICS ROW ──────────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)

if latest_result:
    m1.metric("Current Prediction",  latest_result.prediction)
    m2.metric("Confidence Score",     f"{latest_result.confidence:.1%}")
    m3.metric("Packets Processed",    st.session_state["total_packets"])
    trend = st.session_state["accuracy_trend"]
    delta = None
    if len(trend) >= 2:
        delta = f"{(trend[-1] - trend[-2]):+.1%}"
    m4.metric("Last Confidence Δ", f"{trend[-1]:.1%}" if trend else "—", delta=delta)
else:
    m1.metric("Current Prediction",  "Waiting...")
    m2.metric("Confidence Score",     "—")
    m3.metric("Packets Processed",    0)
    m4.metric("Last Confidence Δ",   "—")

st.markdown("---")

# ── CHARTS ROW ───────────────────────────────────────────────────────────────
v1, v2 = st.columns([2, 1])

with v1:
    st.subheader("📈 Confidence Over Time")
    trend = st.session_state["accuracy_trend"]
    if trend:
        chart_df = pd.DataFrame({
            "Confidence": trend,
            "Sample":     list(range(len(trend))),
        }).set_index("Sample")
        st.line_chart(chart_df)
    else:
        st.info("Start the system to see live confidence trend.")

with v2:
    st.subheader("🕵️ Classifier Probabilities")
    if latest_result:
        prob_df = pd.DataFrame({
            "Site":        list(latest_result.probabilities.keys()),
            "Probability": list(latest_result.probabilities.values()),
        }).set_index("Site").sort_values("Probability", ascending=False)
        st.bar_chart(prob_df)
    else:
        st.info("Waiting for first inference...")

st.markdown("---")

# ── FEATURE SNAPSHOT ─────────────────────────────────────────────────────────
if latest_result:
    with st.expander("🔬 Last Feature Vector", expanded=False):
        feat_df = pd.DataFrame(
            latest_result.features.items(),
            columns=["Feature", "Value"]
        )
        feat_df["Value"] = feat_df["Value"].apply(lambda x: f"{x:.3f}" if isinstance(x, float) else x)
        st.dataframe(feat_df, use_container_width=True, hide_index=True)

# ── LOGS ─────────────────────────────────────────────────────────────────────
st.subheader("📟 Real-Time Logs")
log_lines = st.session_state["logs"][-20:]
st.markdown(
    f'<div class="log-box">' + "<br>".join(log_lines) + '</div>',
    unsafe_allow_html=True,
)

# ── AUTO-RERUN WHILE RUNNING ──────────────────────────────────────────────────
if st.session_state["running"]:
    time.sleep(POLL_INTERVAL)
    st.rerun()
