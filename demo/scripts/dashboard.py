"""
WF-Guard: Real-Time Website Fingerprinting Dashboard
=====================================================
Architecture:
  - FakeDataSource: simulated traffic + fake classifier (no Tor needed)
  - RealDataSource: live scapy capture on loopback + trained RandomForest
  - CaptureWorker: background thread pushing InferenceResults to a queue
  - Streamlit UI: sole control surface — data source, defense, start/stop

Defense state is controlled exclusively by the sidebar toggle.
Cover traffic is started/stopped with the worker.
No kill switch, no file edits required during the demo.
"""

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

# ── CONFIG ──────────────────────────────────────────────────────────────────
TOR_PORT      = 9050      # Tor daemon on Linux/WSL (9150 for Tor Browser)
WINDOW_SIZE   = 100       # packets per feature window
POLL_INTERVAL = 0.5       # seconds between UI refresh
SNIFF_IFACE   = "lo"      # WSL: SOCKS5 traffic flows through loopback
MODEL_DIR     = os.path.dirname(os.path.abspath(__file__))

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
    probabilities: dict
    packets_in_window: int
    features: dict
    defense_active: bool

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
    SITE_PROFILES = {
        "google.com":    dict(mean_size=800,  std_size=300, incoming_bias=0.6),
        "youtube.com":   dict(mean_size=1400, std_size=200, incoming_bias=0.85),
        "facebook.com":  dict(mean_size=900,  std_size=400, incoming_bias=0.65),
        "amazon.com":    dict(mean_size=1100, std_size=350, incoming_bias=0.7),
        "wikipedia.org": dict(mean_size=1300, std_size=150, incoming_bias=0.75),
        "twitter.com":   dict(mean_size=700,  std_size=250, incoming_bias=0.55),
        "reddit.com":    dict(mean_size=1000, std_size=300, incoming_bias=0.68),
        "github.com":    dict(mean_size=950,  std_size=280, incoming_bias=0.60),
    }

    def __init__(self, defense_active_fn):
        self.defense_active_fn = defense_active_fn
        self.current_site = random.choice(MONITORED_SITES)
        self._counter = 0

    def _rotate_site(self):
        self._counter += 1
        if self._counter >= random.randint(8, 15):
            self.current_site = random.choice(MONITORED_SITES)
            self._counter = 0

    def _generate_window(self):
        profile = self.SITE_PROFILES[self.current_site]
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
        defense = bool(self.defense_active_fn())
        if defense:
            raw = {s: random.uniform(0.05, 0.25) for s in MONITORED_SITES}
        else:
            raw = {}
            for site, p in self.SITE_PROFILES.items():
                sm = 1.0 - min(abs(features["mean_packet_size"] - p["mean_size"]) / p["mean_size"], 1.0)
                bm = 1.0 - abs(features["incoming_packets"] / features["total_packets"] - p["incoming_bias"])
                raw[site] = (sm * 0.6 + bm * 0.4) + random.uniform(-0.1, 0.1)
        total = sum(max(v, 0.01) for v in raw.values())
        probs = {s: max(v, 0.01) / total for s, v in raw.items()}
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
            features=features, defense_active=self.defense_active_fn(),
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

        sniffer = AsyncSniffer(
            iface=SNIFF_IFACE,
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
        probs     = dict(zip(self.labels, probs_arr))
        prediction = max(probs, key=probs.get)
        confidence = probs[prediction]

        return InferenceResult(
            timestamp=time.time(), prediction=prediction, confidence=confidence,
            probabilities=probs, packets_in_window=len(packets),
            features=display_dict, defense_active=self.defense_active_fn(),
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
        "running":        False,
        "data_source":    "fake",
        "result_queue":   queue.Queue(),
        "worker":         None,
        "logs":           ["[INIT] System ready. Select a mode and press Start."],
        "total_packets":  0,
        "accuracy_trend": [],
        "last_result":    None,
        "defense_active": False,
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
    st.session_state["result_queue"]   = queue.Queue()
    st.session_state["accuracy_trend"] = []
    st.session_state["total_packets"]  = 0
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
    st.session_state["accuracy_trend"].append(item.confidence)
    ts  = time.strftime('%H:%M:%S', time.localtime(item.timestamp))
    dflag = " [DEF ON]" if item.defense_active else ""
    st.session_state["logs"].append(
        f"[{ts}]{dflag} → {item.prediction} ({item.confidence:.1%})"
        f" | pkts={item.packets_in_window} | bursts={item.features.get('burst_count','?')}"
    )


# ── MAIN UI ───────────────────────────────────────────────────────────────────
src_label = st.session_state["data_source"].upper()
status    = "🟢 Running" if st.session_state["running"] else "🔴 Stopped"
st.title("🛡️ WF-Guard: Real-Time Website Fingerprinting")
st.caption(f"Source: **{src_label}** | {status}")

# ── METRICS ───────────────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
if latest_result:
    m1.metric("Prediction",        latest_result.prediction)
    m2.metric("Confidence",        f"{latest_result.confidence:.1%}")
    m3.metric("Packets Processed", st.session_state["total_packets"])
    trend = st.session_state["accuracy_trend"]
    delta = f"{(trend[-1] - trend[-2]):+.1%}" if len(trend) >= 2 else None
    m4.metric("Confidence Δ",      f"{trend[-1]:.1%}" if trend else "—", delta=delta)
else:
    m1.metric("Prediction",        "Waiting...")
    m2.metric("Confidence",        "—")
    m3.metric("Packets Processed", 0)
    m4.metric("Confidence Δ",      "—")

st.markdown("---")

# ── CHARTS ───────────────────────────────────────────────────────────────────
v1, v2 = st.columns([2, 1])

with v1:
    st.subheader("📈 Confidence Over Time")
    trend = st.session_state["accuracy_trend"]
    if trend:
        st.line_chart(pd.DataFrame({"Confidence": trend}).rename_axis("Sample"))
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
        st.dataframe(feat_df, use_container_width=True, hide_index=True)

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
