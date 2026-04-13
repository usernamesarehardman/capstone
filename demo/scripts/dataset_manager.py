"""
dataset_manager.py
==================
Handles pcap trace ingestion, feature extraction, traffic classification,
and feeding learned patterns back into tor_proxy.py.

Designed to grow — swap in real models as your capstone develops.

Requirements:
    pip install scapy pandas numpy scikit-learn joblib

Optional (better pcap perf):
    pip install pyshark          # Wireshark bindings
    pip install dpkt             # Lightweight pcap parsing
"""

import os
import time
import random
import logging
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

log = logging.getLogger("dataset_manager")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_HERE      = Path(__file__).parent
DATA_DIR   = _HERE / "data"        # Drop pcap files here
MODEL_DIR  = _HERE / "models"      # Saved model artifacts
DATA_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)

# Traffic type labels (extend as needed)
TRAFFIC_LABELS = {
    0: "browser_idle",
    1: "browser_active",
    2: "api_call",
    3: "media_stream",
    4: "fingerprint_probe",   # What we want to detect + evade
}


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class FlowRecord:
    """Represents a single TCP/UDP flow extracted from a pcap."""
    src_ip:           str
    dst_ip:           str
    src_port:         int
    dst_port:         int
    protocol:         str
    packet_count:     int
    total_bytes:      int
    duration_ms:      float
    inter_arrival_mean: float   # Mean time between packets (ms)
    inter_arrival_std:  float   # Variance — high = bursty, low = steady
    packet_size_mean:   float
    packet_size_std:    float
    bytes_per_second:   float
    label:            Optional[int] = None   # Set after classification


@dataclass
class TrafficProfile:
    """
    Learned behavioral profile derived from traces.
    Used by tor_proxy.py to shape outgoing request timing.
    """
    name:                str
    inter_request_delays: list[float] = field(default_factory=list)  # seconds
    burst_sizes:          list[int]   = field(default_factory=list)  # packets per burst
    think_times:          list[float] = field(default_factory=list)  # pause between bursts
    typical_payload_sizes: list[int]  = field(default_factory=list)

    def sample_delay(self) -> float:
        """Return a realistic inter-request delay sampled from the profile."""
        if not self.inter_request_delays:
            return random.uniform(0.5, 2.5)
        # Weighted sample with small gaussian noise for naturalness
        base = random.choice(self.inter_request_delays)
        noise = np.random.normal(0, base * 0.1)
        return max(0.05, base + noise)

    def sample_think_time(self) -> float:
        """Longer pause to simulate a human 'reading' between requests."""
        if not self.think_times:
            return random.uniform(2.0, 8.0)
        return max(0.5, random.choice(self.think_times) + np.random.normal(0, 0.3))


# ---------------------------------------------------------------------------
# pcap Parsing
# ---------------------------------------------------------------------------

class PcapParser:
    """
    Reads pcap files and extracts per-flow features for ML training.

    Usage:
        parser = PcapParser("data/capture.pcap")
        flows  = parser.extract_flows()
        df     = parser.to_dataframe(flows)
    """

    def __init__(self, pcap_path: str):
        self.path = Path(pcap_path)
        if not self.path.exists():
            raise FileNotFoundError(f"pcap not found: {self.path}")

    def extract_flows(self) -> list[FlowRecord]:
        """Parse pcap and group packets into flows by 5-tuple."""
        log.info("Reading pcap: %s", self.path)
        packets = rdpcap(str(self.path))
        log.info("Loaded %d packets", len(packets))

        # Group packets by flow key (src_ip, dst_ip, src_port, dst_port, proto)
        flows: dict[tuple, list] = {}
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else None
            if not proto:
                continue
            layer = pkt[TCP] if proto == "TCP" else pkt[UDP]
            key = (pkt[IP].src, pkt[IP].dst, layer.sport, layer.dport, proto)
            flows.setdefault(key, []).append(pkt)

        records = []
        for (src_ip, dst_ip, sp, dp, proto), pkts in flows.items():
            record = self._flow_to_record(src_ip, dst_ip, sp, dp, proto, pkts)
            if record:
                records.append(record)

        log.info("Extracted %d flows from pcap", len(records))
        return records

    def _flow_to_record(self, src_ip, dst_ip, sp, dp, proto, pkts) -> Optional[FlowRecord]:
        if len(pkts) < 2:
            return None

        timestamps = sorted([float(p.time) for p in pkts])
        sizes      = [len(p) for p in pkts]
        iats_ms    = [(timestamps[i+1] - timestamps[i]) * 1000
                      for i in range(len(timestamps) - 1)]
        duration_ms = (timestamps[-1] - timestamps[0]) * 1000

        return FlowRecord(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=sp, dst_port=dp, protocol=proto,
            packet_count=len(pkts),
            total_bytes=sum(sizes),
            duration_ms=round(duration_ms, 3),
            inter_arrival_mean=round(float(np.mean(iats_ms)), 3),
            inter_arrival_std=round(float(np.std(iats_ms)), 3),
            packet_size_mean=round(float(np.mean(sizes)), 3),
            packet_size_std=round(float(np.std(sizes)), 3),
            bytes_per_second=round(sum(sizes) / max(duration_ms / 1000, 0.001), 3),
        )

    @staticmethod
    def to_dataframe(flows: list[FlowRecord]) -> pd.DataFrame:
        return pd.DataFrame([f.__dict__ for f in flows])


# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------

FEATURE_COLS = [
    "packet_count", "total_bytes", "duration_ms",
    "inter_arrival_mean", "inter_arrival_std",
    "packet_size_mean", "packet_size_std",
    "bytes_per_second",
]

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derive additional features that help distinguish fingerprint probes
    from normal traffic.
    """
    df = df.copy()

    # Regularity score: low std/mean ratio = machine-like (suspicious)
    df["iat_regularity"] = df["inter_arrival_std"] / (df["inter_arrival_mean"] + 1e-9)

    # Size entropy proxy: very uniform sizes = likely automated
    df["size_uniformity"] = df["packet_size_std"] / (df["packet_size_mean"] + 1e-9)

    # Short high-volume flows are common in fingerprint probes
    df["intensity"] = df["total_bytes"] / (df["duration_ms"] + 1e-9)

    # Flag well-known fingerprinting ports
    fp_ports = {80, 443, 8080, 8443}
    df["is_fp_port"] = df["dst_port"].apply(lambda p: int(p in fp_ports))

    return df

FULL_FEATURE_COLS = FEATURE_COLS + ["iat_regularity", "size_uniformity", "intensity", "is_fp_port"]


# ---------------------------------------------------------------------------
# ML Models
# ---------------------------------------------------------------------------

class FingerprintDetector:
    """
    Anomaly detector — flags flows that look like fingerprinting probes.
    Uses IsolationForest (unsupervised) so it works without labeled data.

    Once you have labels, swap in a supervised model via TrafficClassifier.
    """

    MODEL_PATH = MODEL_DIR / "fingerprint_detector.joblib"

    def __init__(self):
        self.model = Pipeline([
            ("scaler", StandardScaler()),
            ("iso",    IsolationForest(contamination=0.05, random_state=42, n_jobs=-1)),
        ])
        self.trained = False

    def train(self, df: pd.DataFrame):
        df = extract_features(df)
        X  = df[FULL_FEATURE_COLS].fillna(0)
        log.info("Training FingerprintDetector on %d flows...", len(X))
        self.model.fit(X)
        self.trained = True
        joblib.dump(self.model, self.MODEL_PATH)
        log.info("Model saved → %s", self.MODEL_PATH)

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        """Returns array: 1 = normal, -1 = anomaly (likely fingerprint probe)."""
        if not self.trained:
            self.load()
        df = extract_features(df)
        X  = df[FULL_FEATURE_COLS].fillna(0)
        return self.model.predict(X)

    def load(self):
        if self.MODEL_PATH.exists():
            self.model   = joblib.load(self.MODEL_PATH)
            self.trained = True
            log.info("Loaded FingerprintDetector from %s", self.MODEL_PATH)
        else:
            raise FileNotFoundError("No saved model found. Train first.")


class TrafficClassifier:
    """
    Supervised classifier — assigns traffic type labels to flows.
    Requires labeled training data (set flow.label before training).

    Labels: see TRAFFIC_LABELS at top of file.
    """

    MODEL_PATH = MODEL_DIR / "traffic_classifier.joblib"

    def __init__(self):
        self.model = Pipeline([
            ("scaler", StandardScaler()),
            ("rf",     RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)),
        ])
        self.trained = False

    def train(self, df: pd.DataFrame):
        if "label" not in df.columns or df["label"].isna().all():
            raise ValueError("DataFrame must have a 'label' column for supervised training.")
        df = extract_features(df)
        labeled = df.dropna(subset=["label"])
        X = labeled[FULL_FEATURE_COLS].fillna(0)
        y = labeled["label"].astype(int)
        log.info("Training TrafficClassifier on %d labeled flows...", len(X))
        self.model.fit(X, y)
        self.trained = True
        joblib.dump(self.model, self.MODEL_PATH)
        log.info("Model saved → %s", self.MODEL_PATH)

    def predict(self, df: pd.DataFrame) -> list[str]:
        """Returns human-readable traffic type labels."""
        if not self.trained:
            self.load()
        df = extract_features(df)
        X  = df[FULL_FEATURE_COLS].fillna(0)
        preds = self.model.predict(X)
        return [TRAFFIC_LABELS.get(p, "unknown") for p in preds]

    def load(self):
        if self.MODEL_PATH.exists():
            self.model   = joblib.load(self.MODEL_PATH)
            self.trained = True
        else:
            raise FileNotFoundError("No saved classifier found. Train first.")


# ---------------------------------------------------------------------------
# Traffic Profile Builder
# ---------------------------------------------------------------------------

def build_traffic_profile(df: pd.DataFrame, name: str = "learned") -> TrafficProfile:
    """
    Distill a pcap DataFrame into a TrafficProfile that tor_proxy.py
    can use for realistic request timing and pacing.
    """
    profile = TrafficProfile(name=name)

    if "inter_arrival_mean" in df.columns:
        # Convert ms → seconds, filter outliers
        iats = df["inter_arrival_mean"].dropna() / 1000.0
        iats = iats[iats < iats.quantile(0.95)]   # remove extreme outliers
        profile.inter_request_delays = iats.round(3).tolist()

    if "packet_count" in df.columns:
        profile.burst_sizes = df["packet_count"].dropna().astype(int).tolist()

    if "duration_ms" in df.columns:
        think = df["duration_ms"].dropna() / 1000.0
        think = think[think < think.quantile(0.90)]
        profile.think_times = think.round(3).tolist()

    if "packet_size_mean" in df.columns:
        profile.typical_payload_sizes = (
            df["packet_size_mean"].dropna().astype(int).tolist()
        )

    log.info(
        "Built TrafficProfile '%s' — %d delay samples, %d burst samples",
        name, len(profile.inter_request_delays), len(profile.burst_sizes),
    )
    return profile


# ---------------------------------------------------------------------------
# Dataset Manager (main interface)
# ---------------------------------------------------------------------------

class DatasetManager:
    """
    Top-level interface used by tor_proxy.py.

    Workflow:
        dm = DatasetManager()
        dm.load_pcap("data/capture.pcap")
        dm.train_models()
        profile = dm.get_profile()

        # In tor_proxy.py:
        delay = profile.sample_delay()
    """

    def __init__(self):
        self.flows:      list[FlowRecord]   = []
        self.df:         Optional[pd.DataFrame] = None
        self.detector    = FingerprintDetector()
        self.classifier  = TrafficClassifier()
        self.profile:    Optional[TrafficProfile] = None

    def load_pcap(self, path: str, label: int = None):
        """
        Parse a pcap file and append its flows to the dataset.
        Optionally set a ground-truth label for supervised training.
        """
        parser = PcapParser(path)
        new_flows = parser.extract_flows()
        if label is not None:
            for f in new_flows:
                f.label = label
        self.flows.extend(new_flows)
        self._rebuild_df()
        return self

    def load_directory(self, directory: str = "data"):
        """Load all .pcap / .pcapng files from a directory."""
        d = Path(directory)
        files = list(d.glob("*.pcap")) + list(d.glob("*.pcapng"))
        if not files:
            log.warning("No pcap files found in %s", d)
            return self
        for f in files:
            log.info("Loading %s", f.name)
            self.load_pcap(str(f))
        return self

    def _rebuild_df(self):
        self.df = PcapParser.to_dataframe(self.flows)

    def train_models(self):
        """Train anomaly detector (always) + classifier (if labels exist)."""
        if self.df is None or self.df.empty:
            raise RuntimeError("No data loaded. Call load_pcap() first.")

        self.detector.train(self.df)

        if "label" in self.df.columns and not self.df["label"].isna().all():
            self.classifier.train(self.df)
        else:
            log.info("No labels found — skipping supervised classifier training.")

        self.profile = build_traffic_profile(self.df)
        return self

    def analyze(self) -> pd.DataFrame:
        """
        Run anomaly detection on loaded flows.
        Returns DataFrame with anomaly flags and traffic type predictions.
        """
        if self.df is None:
            raise RuntimeError("No data loaded.")

        result = self.df.copy()
        result["anomaly"] = self.detector.predict(self.df)
        result["anomaly_label"] = result["anomaly"].map({1: "normal", -1: "⚠ probe"})

        if self.classifier.trained:
            result["traffic_type"] = self.classifier.predict(self.df)

        flagged = (result["anomaly"] == -1).sum()
        log.info("Analysis complete — %d / %d flows flagged as anomalous", flagged, len(result))
        return result

    def get_profile(self) -> TrafficProfile:
        """Return the learned traffic profile for use in tor_proxy.py."""
        if self.profile is None:
            if self.df is not None:
                self.profile = build_traffic_profile(self.df)
            else:
                log.warning("No data loaded — returning default profile.")
                self.profile = TrafficProfile(name="default")
        return self.profile

    def summary(self):
        """Print a quick summary of loaded data."""
        if self.df is None:
            print("No data loaded.")
            return
        df = extract_features(self.df)
        print(f"\n{'='*50}")
        print(f"  Dataset Summary")
        print(f"{'='*50}")
        print(f"  Flows loaded      : {len(df)}")
        print(f"  Unique src IPs    : {df['src_ip'].nunique()}")
        print(f"  Avg packet count  : {df['packet_count'].mean():.1f}")
        print(f"  Avg flow duration : {df['duration_ms'].mean():.1f} ms")
        print(f"  Avg IAT           : {df['inter_arrival_mean'].mean():.1f} ms")
        print(f"  Protocols         : {df['protocol'].value_counts().to_dict()}")
        if "label" in df.columns:
            print(f"  Label distribution: {df['label'].value_counts().to_dict()}")
        print(f"{'='*50}\n")


# ---------------------------------------------------------------------------
# Integration hook for tor_proxy.py
# ---------------------------------------------------------------------------

def get_proxy_delay(manager: DatasetManager) -> float:
    """
    Convenience function — call this from tor_proxy.py's fetch()
    instead of random.uniform() once your dataset is loaded.

    Example in tor_proxy.py:
        from dataset_manager import DatasetManager, get_proxy_delay
        dm = DatasetManager().load_pcap("data/capture.pcap")
        ...
        sleep_for = get_proxy_delay(dm)
    """
    return manager.get_profile().sample_delay()


# ---------------------------------------------------------------------------
# Example / Test Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    dm = DatasetManager()

    pcap_files = list(Path("data").glob("*.pcap")) + list(Path("data").glob("*.pcapng"))

    if pcap_files:
        dm.load_directory("data")
        dm.summary()
        dm.train_models()

        results = dm.analyze()
        probes  = results[results["anomaly"] == -1]
        print(f"Flagged {len(probes)} potential fingerprint probes:\n")
        print(probes[["src_ip", "dst_ip", "dst_port", "packet_count",
                       "inter_arrival_mean", "anomaly_label"]].to_string(index=False))

        profile = dm.get_profile()
        print(f"\nSample proxy delays from learned profile:")
        for _ in range(5):
            print(f"  {profile.sample_delay():.3f}s")
    else:
        print("No pcap files found in ./data/")
        print("Drop .pcap or .pcapng files into the data/ folder and re-run.")
        print("\nTesting with synthetic data...")

        # Synthetic demo when no pcaps are available
        np.random.seed(42)
        n = 200
        synthetic = pd.DataFrame({
            "src_ip":              ["1.2.3.4"] * n,
            "dst_ip":              ["5.6.7.8"] * n,
            "src_port":            np.random.randint(1024, 65535, n),
            "dst_port":            np.random.choice([80, 443, 8080], n),
            "protocol":            ["TCP"] * n,
            "packet_count":        np.random.randint(2, 50, n),
            "total_bytes":         np.random.randint(100, 50000, n),
            "duration_ms":         np.random.exponential(500, n),
            "inter_arrival_mean":  np.random.exponential(100, n),
            "inter_arrival_std":   np.random.exponential(30, n),
            "packet_size_mean":    np.random.normal(512, 200, n).clip(40),
            "packet_size_std":     np.random.exponential(100, n),
            "bytes_per_second":    np.random.exponential(1000, n),
            "label":               None,
        })

        dm.flows = []
        dm.df    = synthetic
        dm.train_models()
        dm.summary()

        profile = dm.get_profile()
        print("Sample delays from synthetic profile:")
        for _ in range(5):
            print(f"  {profile.sample_delay():.3f}s")
