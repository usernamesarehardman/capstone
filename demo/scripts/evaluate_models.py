"""
evaluate_models.py
==================
WF-Guard model trainer — trains and evaluates the Random Forest classifier.

Reads a signed-trace dataset (.csv or .npz), extracts 116-element CUMUL
feature vectors, trains a Random Forest, and saves model artifacts for the
dashboard.

Usage:
    python evaluate_models.py                                # default dataset
    python evaluate_models.py --dataset collect/dataset.csv # fresh-collected
    python evaluate_models.py --dataset /path/to/CW.npz     # WFLib public set
    python evaluate_models.py --trees 500 --test-size 0.1
    python evaluate_models.py --output-dir /tmp/wfguard-model

Options:
    --dataset PATH      Input dataset (.csv or .npz). Default: curated_raw_dataset.csv
    --trees N           RandomForest estimator count (default: 1000).
    --test-size F       Holdout fraction for evaluation (default: 0.2).
    --output-dir PATH   Directory for saved artifacts (default: demo/models/).
    --site-names PATH   JSON {int_label: site_name} for NPZ datasets (optional).

Outputs:
    model.joblib          — trained RandomForest
    scaler.joblib         — fitted StandardScaler
    label_map.json        — {index: site_name} mapping
    confusion_matrix.csv  — per-class accuracy breakdown
"""

import argparse
import csv
import json
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    top_k_accuracy_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_DEMO_DIR    = os.path.dirname(_SCRIPTS_DIR)
_DEFAULT_OUT = os.path.join(_DEMO_DIR, "models")   # demo/models/


def find_dataset(filename="curated_raw_dataset.csv"):
    """
    Search for the dataset file in standard locations (checked in order):
      1. demo/data/             — canonical location after repo reorganization
      2. demo/scripts/          — legacy / same-dir copy
      3. demo/scripts/collect/  — fresh-collected dataset from collect_fresh.py
      4. artifacts/ fallbacks   — original per-role dataset archives
    """
    here     = _SCRIPTS_DIR
    demo     = _DEMO_DIR
    capstone = os.path.dirname(demo)

    candidates = [
        os.path.join(demo, "data", filename),
        os.path.join(here, filename),
        os.path.join(here, "collect", filename),
        os.path.join(capstone, "artifacts", "Machine Learning Engineer", filename),
        os.path.join(capstone, "artifacts", "Data & Traffic Engineer", "initial_dataset", filename),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    return filename  # let the caller surface the FileNotFoundError

def cumul_interpolate(trace: np.ndarray, n_points: int = 100) -> list:
    """Interpolate the normalized cumulative sum of a signed trace to n_points positions.
    CUMUL representation (Panchenko et al., 2016).
    Normalized by total bytes so the output is capture-length invariant:
    same traffic shape yields the same curve regardless of how many packets
    were captured — the key property for train/inference consistency."""
    if len(trace) == 0:
        return [0.0] * n_points
    cumsum     = np.cumsum(trace)
    total_bytes = float(np.sum(np.abs(trace)))
    if total_bytes > 0:
        cumsum = cumsum / total_bytes   # scale to [-1, 1] range
    x_orig = np.linspace(0, 1, len(cumsum))
    x_new  = np.linspace(0, 1, n_points)
    return np.interp(x_new, x_orig, cumsum).tolist()


def extract_wf_features(trace):
    """113-element feature vector for the Random Forest model.
    Layout: 6 scale-free stats | 3 bin fractions | 1 burst density | 2 per-pkt cumsum stats | 100 CUMUL points

    All features are normalized to be capture-length invariant:
    absolute counts (total/out/in) replaced with ratios; bins and burst_count
    divided by total_count; CUMUL normalized by total bytes."""
    non_zero = trace[trace != 0]
    if non_zero.size == 0:
        return [0.0] * 113

    out_pkts = non_zero[non_zero > 0]
    in_pkts  = non_zero[non_zero < 0]
    total_count = len(non_zero)
    out_count   = len(out_pkts)
    in_count    = len(in_pkts)

    out_ratio  = out_count / total_count if total_count > 0 else 0
    size_ratio = np.sum(out_pkts) / abs(np.sum(in_pkts)) if in_count > 0 else 0

    # Bin fractions (normalize by total_count so they're capture-length invariant)
    bins = [
        np.sum(np.abs(non_zero) < 100)   / total_count,
        np.sum((np.abs(non_zero) >= 100) & (np.abs(non_zero) < 1000)) / total_count,
        np.sum(np.abs(non_zero) >= 1000) / total_count,
    ]

    signs = np.sign(non_zero)
    bursts = []
    curr_len, curr_sign = 0, signs[0]
    for s in signs:
        if s == curr_sign:
            curr_len += 1
        else:
            bursts.append(curr_len * curr_sign)
            curr_sign, curr_len = s, 1
    bursts.append(curr_len * curr_sign)

    avg_out_b    = np.mean([b for b in bursts if b > 0]) if any(b > 0 for b in bursts) else 0
    avg_in_b     = np.mean([abs(b) for b in bursts if b < 0]) if any(b < 0 for b in bursts) else 0
    max_b        = np.max(np.abs(bursts))
    burst_density = len(bursts) / total_count   # bursts per packet (capture-length invariant)

    cumsum = np.cumsum(non_zero)
    # Per-packet cumsum stats (divide by total_count to normalize for capture length)
    stats  = [np.mean(non_zero), np.std(non_zero),
              np.mean(cumsum) / total_count, np.std(cumsum) / total_count]
    cumul  = cumul_interpolate(non_zero, 100)

    return [
        out_ratio, size_ratio,
        avg_out_b, avg_in_b, max_b, burst_density,
    ] + bins + stats + cumul

def load_dataset(csv_path):
    """Robust loader that handles variable headers."""
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        return [], []

    X, y = [], []
    print(f"[*] Starting deep scan of {os.path.basename(csv_path)}...")

    with open(csv_path, "r", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # consume header

        row_count = 0
        for row in reader:
            if not row or len(row) < 5:
                continue
            label = row[0].strip()
            try:
                trace = np.array(
                    [float(v) if (v and v.strip()) else 0 for v in row[1:]],
                    dtype=np.float64
                )
                if np.any(trace):
                    X.append(extract_wf_features(trace))
                    y.append(label)
                    row_count += 1
            except ValueError:
                continue

            if row_count % 100 == 0 and row_count > 0:
                print(f"    [+] Processed {row_count} rows...")

    return np.array(X, dtype=np.float64), np.array(y)


def load_npz_dataset(npz_path, site_names=None):
    """Load a WFLib-format NPZ dataset (e.g. CW.npz from Zenodo).

    Expected NPZ keys:
        X : array of shape (n_samples, seq_len)
            Each value is direction * timestamp (±float).
            Tor cells are fixed 512 bytes, so we convert to direction * 512
            to match the signed-packet-size format the features expect.
        y : array of shape (n_samples,) with integer class labels.

    Args:
        npz_path   : Path to the .npz file.
        site_names : Optional dict {int_label: "site_name"} loaded from a
                     companion JSON file (--site-names). If None, labels are
                     stored as zero-padded integers ("000", "001", ...) so that
                     LabelEncoder sorts them numerically rather than
                     lexicographically.

    Download from: https://zenodo.org/records/13732130

    Note: CW.npz does not include a public label→site-name mapping. Labels will
    appear as zero-padded integers in the dashboard unless a site_names mapping
    is provided via --site-names.
    """
    if not os.path.exists(npz_path):
        raise FileNotFoundError(f"NPZ dataset not found: {npz_path}")

    print(f"[*] Loading NPZ dataset: {os.path.basename(npz_path)}...")
    data  = np.load(npz_path, allow_pickle=True)
    X_raw = data["X"]
    y_int = data["y"].astype(int)

    X, y = [], []
    for i, (seq, label) in enumerate(zip(X_raw, y_int)):
        seq = np.asarray(seq, dtype=np.float64)
        # direction * timestamp → direction * 512 bytes (fixed Tor cell size)
        trace = np.sign(seq) * 512.0
        trace = trace[trace != 0]
        if trace.size > 0:
            X.append(extract_wf_features(trace))
            # Zero-pad so LabelEncoder sorts numerically, not lexicographically.
            # Substitute site name if a mapping was provided.
            name = site_names.get(label, f"{label:03d}") if site_names else f"{label:03d}"
            y.append(name)
        if (i + 1) % 1000 == 0:
            print(f"    [+] Processed {i + 1} rows...")

    print(f"[*] Loaded {len(X)} samples across {len(np.unique(y))} classes.")
    return np.array(X, dtype=np.float64), np.array(y)

def main():
    parser = argparse.ArgumentParser(
        description="WF-Guard model trainer — trains and evaluates the Random Forest classifier.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python evaluate_models.py\n"
            "  python evaluate_models.py --dataset collect/dataset.csv\n"
            "  python evaluate_models.py --dataset /path/to/CW.npz\n"
            "  python evaluate_models.py --dataset /path/to/CW.npz --site-names sites.json\n"
            "  python evaluate_models.py --trees 500 --test-size 0.1\n"
            "  python evaluate_models.py --output-dir /tmp/wfguard-model\n"
        ),
    )
    parser.add_argument(
        "--dataset", default="curated_raw_dataset.csv", metavar="PATH",
        help="Training dataset: .csv (signed trace rows) or .npz (WFLib format). "
             "Default: curated_raw_dataset.csv",
    )
    parser.add_argument(
        "--trees", type=int, default=1000, metavar="N",
        help="Number of RandomForest estimators (default: 1000).",
    )
    parser.add_argument(
        "--test-size", type=float, default=0.2, metavar="FLOAT",
        help="Fraction of data held out for evaluation (default: 0.2).",
    )
    parser.add_argument(
        "--output-dir", default=None, metavar="PATH",
        help="Directory to write model.joblib, scaler.joblib, label_map.json, "
             f"confusion_matrix.csv. Default: {_DEFAULT_OUT}",
    )
    parser.add_argument(
        "--site-names", default=None, metavar="PATH",
        help="JSON file mapping integer NPZ labels to site names "
             "{\"0\": \"wikipedia\", ...}. Only used with .npz datasets.",
    )
    parser.add_argument(
        "--cross-val", type=int, default=0, metavar="N",
        help="Run N-fold stratified cross-validation in addition to the standard "
             "train/test split. Prints per-fold accuracy and mean ± std. "
             "Recommended: 5 or 10. Default: off (0).",
    )
    args = parser.parse_args()

    site_names = None
    if args.site_names:
        with open(args.site_names) as f:
            site_names = {int(k): v for k, v in json.load(f).items()}

    target_file = find_dataset(args.dataset)
    print(f"[*] Resolved path: {target_file}")

    if target_file.endswith(".npz"):
        X, y_raw = load_npz_dataset(target_file, site_names=site_names)
    else:
        X, y_raw = load_dataset(target_file)

    if len(X) == 0:
        print("\n[!] ERROR: No samples loaded.")
        print("[?] CSV: ensure the first column contains the site name.")
        print("[?] NPZ: ensure the file has 'X' and 'y' keys.")
        return

    print(f"[*] Found {len(X)} samples across {len(np.unique(y_raw))} classes.")

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)

    # ── Optional cross-validation ──────────────────────────────────────────────
    if args.cross_val > 1:
        print(f"\n[*] {args.cross_val}-fold stratified cross-validation "
              f"({args.trees} trees per fold)...")
        _cv_scaler = StandardScaler()
        _X_cv      = _cv_scaler.fit_transform(X)
        _cv        = StratifiedKFold(n_splits=args.cross_val, shuffle=True, random_state=42)
        _cv_model  = RandomForestClassifier(n_estimators=args.trees, n_jobs=-1, random_state=42)
        _cv_scores = cross_val_score(_cv_model, _X_cv, y, cv=_cv, scoring="accuracy", n_jobs=-1)
        print(f"    CV Accuracy : {_cv_scores.mean():.4f} ± {_cv_scores.std():.4f}")
        print(f"    Per-fold    : {' | '.join(f'{s:.4f}' for s in _cv_scores)}")
        print()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    print(f"[*] Training Random Forest on {len(X_train)} samples "
          f"({args.trees} trees, {args.test_size:.0%} held out)...")
    model = RandomForestClassifier(n_estimators=args.trees, n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    probs  = model.predict_proba(X_test)

    print("\n" + "=" * 45)
    print("FINAL EVALUATION RESULTS")
    print("-" * 45)
    print(f"Top-1 Accuracy: {accuracy_score(y_test, y_pred):.2%}")
    print(f"Top-5 Accuracy: {top_k_accuracy_score(y_test, probs, k=5, labels=np.unique(y)):.2%}")
    print("=" * 45)

    out_dir = args.output_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)

    cm_df = pd.DataFrame(
        confusion_matrix(y_test, y_pred),
        index=encoder.classes_,
        columns=encoder.classes_,
    )
    cm_df.to_csv(os.path.join(out_dir, "confusion_matrix.csv"))

    joblib.dump(model,  os.path.join(out_dir, "model.joblib"))
    joblib.dump(scaler, os.path.join(out_dir, "scaler.joblib"))
    label_map = {i: cls for i, cls in enumerate(encoder.classes_.tolist())}
    with open(os.path.join(out_dir, "label_map.json"), "w") as f:
        json.dump(label_map, f, indent=2)
    print(f"[*] Saved model.joblib, scaler.joblib, label_map.json, confusion_matrix.csv → {out_dir}")

if __name__ == "__main__":
    main()
