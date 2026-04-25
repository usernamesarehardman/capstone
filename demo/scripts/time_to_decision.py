"""
time_to_decision.py
===================
Time-to-decision curve: accuracy vs. packet-window size.

Trains one Random Forest on the full curated dataset, then re-evaluates the
held-out test set by truncating each trace to N packets before re-extracting
features.  Because all features are capture-length invariant (ratios, fractions,
normalized CUMUL), the same trained model can classify shorter windows — letting
us measure where accuracy saturates and report the minimum viable window size.

Usage:
    python time_to_decision.py
    python time_to_decision.py --dataset ../data/curated_raw_dataset.csv
    python time_to_decision.py --windows 50,100,200,400,600,800
    python time_to_decision.py --trees 500 --output results/ttd.csv

Options:
    --dataset PATH     Training CSV (default: auto-locate curated_raw_dataset.csv)
    --windows LIST     Comma-separated packet counts to evaluate (default: preset)
    --trees N          RF estimators (default: 1000)
    --test-size F      Hold-out fraction (default: 0.2)
    --output PATH      Write CSV results to this path (default: print only)
"""

import argparse
import csv
import os
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, top_k_accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Reuse feature code from the same scripts/ directory
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from evaluate_models import find_dataset, load_dataset, load_npz_dataset, extract_wf_features

DEFAULT_WINDOWS = [25, 50, 75, 100, 150, 200, 300, 400, 500, 600, 750, 1000]


def truncate_and_refeature(raw_traces: list, n_packets: int) -> np.ndarray:
    """Extract features from the first n_packets packets of each raw trace."""
    X = []
    for trace in raw_traces:
        trunc = trace[:n_packets]
        X.append(extract_wf_features(trunc))
    return np.array(X, dtype=np.float64)


def load_raw_traces(csv_path: str):
    """Load raw signed traces (not yet featurised) from a CSV dataset."""
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        return [], []

    raw_traces, labels = [], []
    with open(csv_path, "r", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if not row or len(row) < 5:
                continue
            label = row[0].strip()
            try:
                trace = np.array(
                    [float(v) if (v and v.strip()) else 0 for v in row[1:]],
                    dtype=np.float64,
                )
                trace = trace[trace != 0]
                if trace.size > 0:
                    raw_traces.append(trace)
                    labels.append(label)
            except ValueError:
                continue

    return raw_traces, np.array(labels)


def main():
    parser = argparse.ArgumentParser(
        description="Time-to-decision curve: accuracy vs. packet-window size.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dataset", default="curated_raw_dataset.csv", metavar="PATH")
    parser.add_argument(
        "--windows", default=None, metavar="LIST",
        help=f"Comma-separated window sizes. Default: {','.join(map(str, DEFAULT_WINDOWS))}",
    )
    parser.add_argument("--trees", type=int, default=1000, metavar="N")
    parser.add_argument("--test-size", type=float, default=0.2, metavar="F")
    parser.add_argument("--output", default=None, metavar="PATH",
                        help="Write CSV results table to this path.")
    args = parser.parse_args()

    windows = (
        [int(w.strip()) for w in args.windows.split(",")]
        if args.windows else DEFAULT_WINDOWS
    )

    target = find_dataset(args.dataset)
    print(f"[*] Dataset: {target}")

    if target.endswith(".npz"):
        X_full, y_raw = load_npz_dataset(target)
        # For NPZ we don't have raw traces; featurise once and note limitation
        print("[!] NPZ format: truncation not available — evaluating full traces only.")
        encoder = LabelEncoder()
        y = encoder.fit_transform(y_raw)
        scaler = StandardScaler()
        X_sc = scaler.fit_transform(X_full)
        X_tr, X_te, y_tr, y_te = train_test_split(
            X_sc, y, test_size=args.test_size, random_state=42, stratify=y
        )
        model = RandomForestClassifier(n_estimators=args.trees, n_jobs=-1, random_state=42)
        model.fit(X_tr, y_te)
        acc = accuracy_score(y_te, model.predict(X_te))
        print(f"[*] Full-trace accuracy: {acc:.2%}")
        return

    raw_traces, y_raw = load_raw_traces(target)
    if not raw_traces:
        print("[!] No traces loaded — check dataset path.")
        return

    print(f"[*] Loaded {len(raw_traces)} raw traces across {len(np.unique(y_raw))} classes.")

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)

    # Train on full-length features so the model sees the richest signal
    X_full = np.array([extract_wf_features(t) for t in raw_traces], dtype=np.float64)
    idx_tr, idx_te = train_test_split(
        np.arange(len(raw_traces)), test_size=args.test_size,
        random_state=42, stratify=y,
    )
    y_tr, y_te = y[idx_tr], y[idx_te]

    scaler = StandardScaler()
    X_tr   = scaler.fit_transform(X_full[idx_tr])
    X_te_full = scaler.transform(X_full[idx_te])

    print(f"[*] Training RF ({args.trees} trees) on {len(idx_tr)} full-trace samples...")
    model = RandomForestClassifier(n_estimators=args.trees, n_jobs=-1, random_state=42)
    model.fit(X_tr, y_tr)

    test_traces = [raw_traces[i] for i in idx_te]
    all_labels  = np.arange(len(encoder.classes_))

    print()
    print(f"{'Window':>8}  {'Top-1':>7}  {'Top-3':>7}  {'Top-5':>7}  {'Median trace len':>17}")
    print("-" * 55)

    results = []
    for n in windows:
        X_te_n = truncate_and_refeature(test_traces, n)
        X_te_n = scaler.transform(X_te_n)
        y_pred  = model.predict(X_te_n)
        probs   = model.predict_proba(X_te_n)
        acc1 = accuracy_score(y_te, y_pred)
        acc3 = top_k_accuracy_score(y_te, probs, k=3, labels=all_labels)
        acc5 = top_k_accuracy_score(y_te, probs, k=5, labels=all_labels)
        med_len = int(np.median([min(len(t), n) for t in test_traces]))
        print(f"{n:>8}  {acc1:>6.1%}  {acc3:>6.1%}  {acc5:>6.1%}  {med_len:>17}")
        results.append({
            "window_packets": n,
            "top1_accuracy":  round(acc1, 4),
            "top3_accuracy":  round(acc3, 4),
            "top5_accuracy":  round(acc5, 4),
            "median_trace_len": med_len,
        })

    # Full-trace baseline
    y_pred_full = model.predict(X_te_full)
    probs_full  = model.predict_proba(X_te_full)
    acc1f = accuracy_score(y_te, y_pred_full)
    acc3f = top_k_accuracy_score(y_te, probs_full, k=3, labels=all_labels)
    acc5f = top_k_accuracy_score(y_te, probs_full, k=5, labels=all_labels)
    med_full = int(np.median([len(t) for t in test_traces]))
    print(f"{'full':>8}  {acc1f:>6.1%}  {acc3f:>6.1%}  {acc5f:>6.1%}  {med_full:>17}")
    results.append({
        "window_packets": "full",
        "top1_accuracy":  round(acc1f, 4),
        "top3_accuracy":  round(acc3f, 4),
        "top5_accuracy":  round(acc5f, 4),
        "median_trace_len": med_full,
    })

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"\n[*] Results saved → {args.output}")


if __name__ == "__main__":
    main()
