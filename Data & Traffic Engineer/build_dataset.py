"""
WF-Guard: Build dataset from parsed sessions — feature extraction, quality checks, balance, split.

Reads manifest and parsed session files; produces train/val/test feature matrices and
overhead stats (packet counts, bytes per session). Ensures no visit leakage between splits.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from extract_features import (
    DEFAULT_MAX_PACKETS,
    extract_session_features,
    session_to_vector,
)

# Quality: drop sessions with fewer than this many packets
MIN_PACKETS = 10

# Split ratios (train / val / test)
TRAIN_RATIO = 0.7
VAL_RATIO = 0.15
TEST_RATIO = 0.15


def load_parsed_session(parsed_root: str, defense_on: bool, site_id: str, visit_id: str, format: str = "csv") -> pd.DataFrame | None:
    """Load one parsed session CSV or Parquet. Returns None if missing or empty."""
    defense_dir = "defense_on" if defense_on else "defense_off"
    base = os.path.join(parsed_root, defense_dir, site_id, visit_id)
    path_csv = base + ".csv"
    path_parquet = base + ".parquet"
    if format == "parquet" and os.path.isfile(path_parquet):
        df = pd.read_parquet(path_parquet)
    elif os.path.isfile(path_csv):
        df = pd.read_csv(path_csv)
    else:
        return None
    if df.empty or "timestamp" not in df.columns or "size" not in df.columns or "direction" not in df.columns:
        return None
    return df


def build_features_and_metadata(
    manifest: pd.DataFrame,
    parsed_root: str,
    max_packets: int = DEFAULT_MAX_PACKETS,
    min_packets: int = MIN_PACKETS,
    format: str = "csv",
) -> tuple[list[np.ndarray], list[dict], list[int]]:
    """
    For each row in manifest, load parsed session, run quality check, extract feature vector.
    Returns (feature_vectors, metadata_dicts, dropped_indices).
    """
    vectors = []
    metadata = []
    dropped = []

    for i, row in manifest.iterrows():
        df = load_parsed_session(
            parsed_root,
            defense_on=bool(row["defense_on"]),
            site_id=row["site_id"],
            visit_id=row["visit_id"],
            format=format,
        )
        if df is None or len(df) < min_packets:
            dropped.append(i)
            continue
        vec = session_to_vector(df, max_packets=max_packets, include_iat=True)
        vectors.append(vec)
        metadata.append({
            "site_id": row["site_id"],
            "visit_id": row["visit_id"],
            "defense_on": row["defense_on"],
            "packet_count": int(row.get("packet_count", len(df))),
            "total_bytes": int(row.get("total_bytes", df["size"].sum())),
        })
    return vectors, metadata, dropped


def enforce_balance(vectors: list[np.ndarray], metadata: list[dict]) -> tuple[list[np.ndarray], list[dict]]:
    """
    Balance so equal samples per (site_id, defense_on). Trims to minimum count per group.
    """
    df = pd.DataFrame(metadata)
    if df.empty:
        return vectors, metadata
    counts = df.groupby(["site_id", "defense_on"]).size()
    min_per_group = int(counts.min()) if len(counts) else 0
    if min_per_group == 0:
        return vectors, metadata
    indices = []
    for (site_id, defense_on), group in df.groupby(["site_id", "defense_on"]):
        take = group.index[:min_per_group].tolist()
        indices.extend(take)
    indices = sorted(indices)
    return [vectors[j] for j in indices], [metadata[j] for j in indices]


def split_no_leakage(
    vectors: list[np.ndarray],
    metadata: list[dict],
    train_ratio: float = TRAIN_RATIO,
    val_ratio: float = VAL_RATIO,
    test_ratio: float = TEST_RATIO,
    seed: int = 42,
) -> tuple[list[int], list[int], list[int]]:
    """
    Split by visit: all packets of a (site_id, visit_id) go to one split. Returns train/val/test indices.
    """
    rng = np.random.default_rng(seed)
    df = pd.DataFrame(metadata)
    df["_idx"] = range(len(metadata))
    # Unique visits (site_id, visit_id)
    visits = df[["site_id", "visit_id"]].drop_duplicates()
    n = len(visits)
    perm = rng.permutation(n)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    n_test = n - n_train - n_val
    train_visits = visits.iloc[perm[:n_train]]
    val_visits = visits.iloc[perm[n_train : n_train + n_val]]
    test_visits = visits.iloc[perm[n_train + n_val :]]

    def indices_for_visit_set(visit_df):
        merge = df.merge(visit_df, on=["site_id", "visit_id"])
        return merge["_idx"].tolist()

    train_idx = indices_for_visit_set(train_visits)
    val_idx = indices_for_visit_set(val_visits)
    test_idx = indices_for_visit_set(test_visits)
    return train_idx, val_idx, test_idx


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build WF-Guard dataset: features, balance, train/val/test split.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--parsed-dir", default="parsed", help="Directory containing manifest.csv and parsed sessions")
    parser.add_argument("--output-dir", default="dataset", help="Output directory for feature matrices and manifests")
    parser.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS, help="Pad/truncate to this many packets")
    parser.add_argument("--min-packets", type=int, default=MIN_PACKETS, help="Drop sessions with fewer packets")
    parser.add_argument("--no-balance", action="store_true", help="Skip balancing by site/defense")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for split")
    parser.add_argument("--format", choices=("csv", "parquet"), default="csv", help="Parsed session format")
    args = parser.parse_args()

    manifest_path = os.path.join(args.parsed_dir, "manifest.csv")
    if not os.path.isfile(manifest_path):
        print(f"Manifest not found: {manifest_path}. Run parse_pcaps.py first.", file=sys.stderr)
        return 1

    manifest = pd.read_csv(manifest_path)
    if manifest.empty:
        print("Manifest is empty.", file=sys.stderr)
        return 1

    vectors, metadata, dropped = build_features_and_metadata(
        manifest,
        args.parsed_dir,
        max_packets=args.max_packets,
        min_packets=args.min_packets,
        format=args.format,
    )
    if dropped:
        print(f"Dropped {len(dropped)} sessions (quality).", file=sys.stderr)

    if not vectors:
        print("No sessions left after quality filter.", file=sys.stderr)
        return 1

    if not args.no_balance:
        vectors, metadata = enforce_balance(vectors, metadata)
        print(f"After balance: {len(vectors)} sessions.")

    train_idx, val_idx, test_idx = split_no_leakage(
        vectors, metadata, seed=args.seed,
    )

    os.makedirs(args.output_dir, exist_ok=True)

    X_train = np.stack([vectors[i] for i in train_idx])
    X_val = np.stack([vectors[i] for i in val_idx])
    X_test = np.stack([vectors[i] for i in test_idx])

    np.save(os.path.join(args.output_dir, "X_train.npy"), X_train)
    np.save(os.path.join(args.output_dir, "X_val.npy"), X_val)
    np.save(os.path.join(args.output_dir, "X_test.npy"), X_test)

    meta_train = [metadata[i] for i in train_idx]
    meta_val = [metadata[i] for i in val_idx]
    meta_test = [metadata[i] for i in test_idx]

    pd.DataFrame(meta_train).to_csv(os.path.join(args.output_dir, "metadata_train.csv"), index=False)
    pd.DataFrame(meta_val).to_csv(os.path.join(args.output_dir, "metadata_val.csv"), index=False)
    pd.DataFrame(meta_test).to_csv(os.path.join(args.output_dir, "metadata_test.csv"), index=False)

    # Overhead export: packet counts and total bytes per session (all splits)
    overhead = pd.DataFrame(metadata)
    overhead_path = os.path.join(args.output_dir, "overhead_per_session.csv")
    overhead.to_csv(overhead_path, index=False)
    print(f"Overhead stats -> {overhead_path}")

    print(f"Train {len(train_idx)} | Val {len(val_idx)} | Test {len(test_idx)}")
    print(f"Feature shape: {X_train.shape}")
    print(f"Saved to {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
