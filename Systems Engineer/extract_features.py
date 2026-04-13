"""
extract_features.py
===================
Real-time website fingerprinting feature extractor for WF-Guard.

Converts a window of raw scapy packets into:
  - A 56-element numpy array for model.predict_proba()  (matches evaluate_models.py)
  - A 14-key display dict matching dashboard.py FEATURE_NAMES

Usage (inside RealDataSource):
    from extract_features import extract_features

    packets = list(AsyncSniffer(filter=f"tcp port {TOR_PORT}", count=WINDOW_SIZE))
    model_vector, display_dict = extract_features(packets)
    probs = model.predict_proba([model_vector])[0]
"""

import socket
from typing import List, Optional, Tuple

import numpy as np

# ---------------------------------------------------------------------------
# Public feature name list (56 names, in order, matching the model vector)
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "total_count",
    "out_count",
    "in_count",
    "out_ratio",
    "size_ratio",
    "avg_out_burst",
    "avg_in_burst",
    "max_burst",
    "burst_count",
    "bin_tiny",       # packets < 100 B
    "bin_medium",     # packets 100–999 B
    "bin_large",      # packets >= 1000 B
    "size_mean",
    "size_std",
    "cumsum_mean",
    "cumsum_std",
    # First 40 raw packet values (signed, zero-padded)
    *[f"pkt_{i:02d}" for i in range(40)],
]  # len == 56


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_local_ip() -> str:
    """Return the local machine's primary IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def packets_to_trace(packets, local_ip: Optional[str] = None) -> np.ndarray:
    """
    Convert a list of scapy packets to a signed trace array.

    Each element represents one packet:
      +size  if the packet originated from local_ip  (outgoing)
      -size  otherwise                                (incoming)

    Packets without an IP layer are skipped.

    Args:
        packets:  List of scapy packet objects.
        local_ip: Local machine IP for direction detection.
                  Auto-detected via UDP socket if None.

    Returns:
        np.ndarray of signed float64 packet sizes.
    """
    if local_ip is None:
        local_ip = _get_local_ip()

    trace = []
    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue
        size = float(len(pkt))
        if pkt["IP"].src == local_ip:
            trace.append(size)
        else:
            trace.append(-size)

    return np.array(trace, dtype=np.float64)


def _extract_wf_features(trace: np.ndarray) -> list:
    """
    Extract the 56-feature vector used by the Random Forest model.

    Mirrors evaluate_models.extract_wf_features() exactly.
    The original has a minor bug (returns [0]*52 on empty trace);
    corrected here to [0.0]*56.

    Args:
        trace: Signed packet-size array from packets_to_trace().

    Returns:
        List of 56 floats.
    """
    non_zero = trace[trace != 0]
    if non_zero.size == 0:
        return [0.0] * 56

    out_pkts = non_zero[non_zero > 0]
    in_pkts  = non_zero[non_zero < 0]

    total_count = len(non_zero)
    out_count   = len(out_pkts)
    in_count    = len(in_pkts)

    out_ratio  = out_count / total_count if total_count > 0 else 0.0
    size_ratio = (float(np.sum(out_pkts)) / float(abs(np.sum(in_pkts)))
                  if in_count > 0 else 0.0)

    bins = [
        int(np.sum(np.abs(non_zero) < 100)),
        int(np.sum((np.abs(non_zero) >= 100) & (np.abs(non_zero) < 1000))),
        int(np.sum(np.abs(non_zero) >= 1000)),
    ]

    # Burst detection
    signs = np.sign(non_zero)
    bursts: list = []
    curr_sign = signs[0]
    curr_len  = 0
    for s in signs:
        if s == curr_sign:
            curr_len += 1
        else:
            bursts.append(int(curr_len * curr_sign))
            curr_sign, curr_len = s, 1
    bursts.append(int(curr_len * curr_sign))

    avg_out_burst = (float(np.mean([b for b in bursts if b > 0]))
                     if any(b > 0 for b in bursts) else 0.0)
    avg_in_burst  = (float(np.mean([abs(b) for b in bursts if b < 0]))
                     if any(b < 0 for b in bursts) else 0.0)
    max_burst     = float(np.max(np.abs(bursts)))

    cumsum = np.cumsum(non_zero)
    stats  = [
        float(np.mean(non_zero)),
        float(np.std(non_zero)),
        float(np.mean(cumsum)),
        float(np.std(cumsum)),
    ]

    head = np.pad(
        non_zero[:40],
        (0, max(0, 40 - len(non_zero))),
        mode="constant",
    )

    return [
        float(total_count), float(out_count), float(in_count),
        out_ratio, size_ratio,
        avg_out_burst, avg_in_burst, max_burst, float(len(bursts)),
    ] + bins + stats + head.tolist()


def _extract_display_features(packets, trace: np.ndarray) -> dict:
    """
    Compute the 14 human-readable features that match dashboard.py FEATURE_NAMES.

    These are shown in the dashboard's feature inspection table and stored in
    InferenceResult.features — they are NOT passed to the model.

    Args:
        packets: Original scapy packet list (used for timestamps).
        trace:   Signed trace array from packets_to_trace().

    Returns:
        Dict with exactly 14 keys matching dashboard.py FEATURE_NAMES.
    """
    non_zero = trace[trace != 0]

    if non_zero.size == 0:
        return {
            "total_packets":        0.0,
            "total_bytes":          0.0,
            "outgoing_packets":     0.0,
            "incoming_packets":     0.0,
            "outgoing_bytes":       0.0,
            "incoming_bytes":       0.0,
            "mean_packet_size":     0.0,
            "std_packet_size":      0.0,
            "mean_inter_arrival_ms": 0.0,
            "std_inter_arrival_ms":  0.0,
            "burst_count":          0.0,
            "max_burst_size":       0.0,
            "outgoing_ratio":       0.0,
            "bytes_ratio":          0.0,
        }

    out_pkts = non_zero[non_zero > 0]
    in_pkts  = non_zero[non_zero < 0]

    total_count  = float(len(non_zero))
    out_count    = float(len(out_pkts))
    in_count     = float(len(in_pkts))
    total_bytes  = float(np.sum(np.abs(non_zero)))
    out_bytes    = float(np.sum(out_pkts))
    in_bytes     = float(abs(np.sum(in_pkts)))
    out_ratio    = out_count / total_count if total_count > 0 else 0.0
    bytes_ratio  = out_bytes / in_bytes if in_bytes > 0 else 0.0

    # Inter-arrival times from packet timestamps (milliseconds)
    mean_iat = 0.0
    std_iat  = 0.0
    timestamps = []
    for pkt in packets:
        if hasattr(pkt, "time"):
            timestamps.append(float(pkt.time))
    if len(timestamps) >= 2:
        timestamps.sort()
        iats = np.diff(timestamps) * 1000.0  # seconds → ms
        mean_iat = float(np.mean(iats))
        std_iat  = float(np.std(iats))

    # Burst stats (reuse same logic as _extract_wf_features)
    signs = np.sign(non_zero)
    bursts: list = []
    curr_sign = signs[0]
    curr_len  = 0
    for s in signs:
        if s == curr_sign:
            curr_len += 1
        else:
            bursts.append(int(curr_len * curr_sign))
            curr_sign, curr_len = s, 1
    bursts.append(int(curr_len * curr_sign))

    burst_count   = float(len(bursts))
    max_burst_size = float(np.max(np.abs(bursts)))

    return {
        "total_packets":         total_count,
        "total_bytes":           total_bytes,
        "outgoing_packets":      out_count,
        "incoming_packets":      in_count,
        "outgoing_bytes":        out_bytes,
        "incoming_bytes":        in_bytes,
        "mean_packet_size":      float(np.mean(np.abs(non_zero))),
        "std_packet_size":       float(np.std(np.abs(non_zero))),
        "mean_inter_arrival_ms": mean_iat,
        "std_inter_arrival_ms":  std_iat,
        "burst_count":           burst_count,
        "max_burst_size":        max_burst_size,
        "outgoing_ratio":        out_ratio,
        "bytes_ratio":           bytes_ratio,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(
    packets,
    local_ip: Optional[str] = None,
) -> Tuple[np.ndarray, dict]:
    """
    Convert a window of scapy packets into model and display features.

    Args:
        packets:  List of scapy packet objects (e.g. from AsyncSniffer).
        local_ip: Local machine IP for direction detection.
                  Auto-detected if None.

    Returns:
        (model_vector, display_dict)

        model_vector : np.ndarray, shape (56,), dtype float64
            Pass directly to model.predict_proba([model_vector]).

        display_dict : dict[str, float]
            14 keys matching dashboard.py FEATURE_NAMES.
            Store in InferenceResult.features for the dashboard table.

    Example:
        from scapy.all import AsyncSniffer
        from extract_features import extract_features

        sniffer = AsyncSniffer(filter="tcp port 9150", count=100)
        sniffer.start()
        sniffer.join()
        model_vector, display_dict = extract_features(sniffer.results)
        probs = model.predict_proba([model_vector])[0]
    """
    trace        = packets_to_trace(packets, local_ip)
    wf_values    = _extract_wf_features(trace)
    model_vector = np.array(wf_values, dtype=np.float64)
    display_dict = _extract_display_features(packets, trace)
    return model_vector, display_dict
