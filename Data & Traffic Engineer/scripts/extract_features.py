"""
WF-Guard: Feature extraction from per-session packet series.

Builds:
- Packet size sequence (first N packets or fixed window)
- Direction encoding (+1 / -1)
- Inter-packet timing (gaps between consecutive packets)

Output: fixed-length vectors (pad or truncate), optionally normalized.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# Default sequence length for WF (pad or truncate to this)
DEFAULT_MAX_PACKETS = 2000


def compute_inter_packet_times(timestamps: pd.Series) -> np.ndarray:
    """Compute inter-packet gaps in seconds. First gap is 0."""
    ts = np.asarray(timestamps, dtype=float)
    if len(ts) < 2:
        return np.zeros(len(ts))
    gaps = np.diff(ts)
    return np.concatenate([[0.0], gaps])


def extract_session_features(
    df: pd.DataFrame,
    max_packets: int = DEFAULT_MAX_PACKETS,
    normalize_sizes: bool = True,
    normalize_times: bool = True,
    size_scale: float | None = None,
    time_scale: float | None = None,
) -> dict[str, np.ndarray]:
    """
    Extract features from one session DataFrame (columns: timestamp, size, direction).

    Returns dict with:
      - sizes: (max_packets,) int or float
      - directions: (max_packets,) +1 / -1
      - iat: (max_packets,) inter-arrival times in seconds
    Padding: zeros for sizes/directions, zero for iat. Truncation: take first max_packets.
    """
    sizes = np.asarray(df["size"].values, dtype=np.float64)
    directions = np.asarray(df["direction"].values, dtype=np.float64)
    timestamps = df["timestamp"].values
    iat = compute_inter_packet_times(pd.Series(timestamps))

    n = len(sizes)
    if n > max_packets:
        sizes = sizes[:max_packets]
        directions = directions[:max_packets]
        iat = iat[:max_packets]
    elif n < max_packets:
        pad = max_packets - n
        sizes = np.pad(sizes, (0, pad), constant_values=0)
        directions = np.pad(directions, (0, pad), constant_values=0)
        iat = np.pad(iat, (0, pad), constant_values=0)

    if normalize_sizes and size_scale is not None and size_scale > 0:
        sizes = sizes / size_scale
    elif normalize_sizes and np.max(sizes) > 0:
        sizes = sizes / (np.max(sizes) or 1.0)

    if normalize_times and time_scale is not None and time_scale > 0:
        iat = iat / time_scale
    elif normalize_times and np.max(iat) > 0:
        iat = iat / (np.max(iat) or 1.0)

    return {
        "sizes": sizes,
        "directions": directions,
        "iat": iat,
    }


def session_to_vector(
    df: pd.DataFrame,
    max_packets: int = DEFAULT_MAX_PACKETS,
    normalize_sizes: bool = True,
    normalize_times: bool = True,
    include_iat: bool = True,
) -> np.ndarray:
    """
    Flatten one session into a single feature vector for ML.
    Layout: [sizes (max_packets), directions (max_packets), iat (max_packets)] if include_iat else [sizes, directions].
    """
    feats = extract_session_features(
        df, max_packets=max_packets,
        normalize_sizes=normalize_sizes,
        normalize_times=normalize_times,
    )
    parts = [feats["sizes"], feats["directions"]]
    if include_iat:
        parts.append(feats["iat"])
    return np.concatenate(parts).astype(np.float32)
