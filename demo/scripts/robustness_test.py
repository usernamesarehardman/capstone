"""
robustness_test.py
==================
Multi-tab robustness test: accuracy under interleaved-site conditions.

In real Tor usage, a user may have multiple tabs open simultaneously.  This
creates a mixed traffic stream where packets from site A and site B are
interleaved.  A classifier trained on single-site traces will degrade; this
script quantifies how much.

Method:
  1. For each test sample, randomly pair it with a sample from a *different* site.
  2. Merge the two raw traces by interleaving packets (simulating two concurrent
     Tor circuits sharing the same observable link).
  3. Re-extract features from the merged trace and run inference.
  4. Compare accuracy at three contamination levels:
       - 0 %  (clean, single site — baseline)
       - 25 % (minority site contributes 25 % of packets)
       - 50 % (equal mix — two sites, randomly interleaved)
  5. Report top-1 and top-3 accuracy at each level.

Usage:
    python robustness_test.py
    python robustness_test.py --dataset ../data/curated_raw_dataset.csv
    python robustness_test.py --contamination 0,25,50,75
    python robustness_test.py --pairs 200 --output results/robustness.csv

Options:
    --dataset PATH         Training CSV (default: auto-locate)
    --contamination LIST   Comma-separated % of minority packets (default: 0,25,50)
    --pairs N              Number of test pairs to evaluate per level (default: 300)
    --trees N              RF estimators (default: 1000)
    --test-size F          Hold-out fraction (default: 0.2)
    --output PATH          Write CSV results to this path (optional)
    --seed N               Random seed (default: 42)
"""

import argparse
import csv
import os
import sys
import random
import numpy as np
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, top_k_accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from evaluate_models import find_dataset, extract_wf_features
from time_to_decision import load_raw_traces


def interleave(trace_a: np.ndarray, trace_b: np.ndarray,
               contamination: float, rng: random.Random) -> np.ndarray:
    """Return a merged trace where `contamination` fraction of packets come
    from trace_b (the 'contaminant').  Packets are randomly shuffled together
    to simulate a mixed Tor link observable."""
    if contamination <= 0:
        return trace_a
    if contamination >= 1:
        return trace_b

    n_total  = len(trace_a)
    n_b      = max(1, int(n_total * contamination))
    n_a      = n_total - n_b

    sample_a = trace_a[:n_a] if len(trace_a) >= n_a else np.resize(trace_a, n_a)
    sample_b = trace_b[:n_b] if len(trace_b) >= n_b else np.resize(trace_b, n_b)
    merged   = np.concatenate([sample_a, sample_b])

    idx = list(range(len(merged)))
    rng.shuffle(idx)
    return merged[idx]


def main():
    parser = argparse.ArgumentParser(
        description="Multi-tab robustness test: accuracy under trace interleaving.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dataset", default="curated_raw_dataset.csv", metavar="PATH")
    parser.add_argument(
        "--contamination", default="0,25,50", metavar="LIST",
        help="Comma-separated contamination percentages (default: 0,25,50).",
    )
    parser.add_argument("--pairs", type=int, default=300, metavar="N",
                        help="Number of test pairs per contamination level (default: 300).")
    parser.add_argument("--trees", type=int, default=1000, metavar="N")
    parser.add_argument("--test-size", type=float, default=0.2, metavar="F")
    parser.add_argument("--output", default=None, metavar="PATH")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    contamination_levels = [int(c.strip()) / 100.0
                            for c in args.contamination.split(",")]

    target = find_dataset(args.dataset)
    print(f"[*] Dataset: {target}")

    if target.endswith(".npz"):
        print("[!] NPZ format not supported for robustness test (raw traces required).")
        return

    raw_traces, y_raw = load_raw_traces(target)
    if not raw_traces:
        print("[!] No traces loaded.")
        return

    print(f"[*] Loaded {len(raw_traces)} raw traces across {len(np.unique(y_raw))} classes.")

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)

    # Train on full features
    X_full = np.array([extract_wf_features(t) for t in raw_traces], dtype=np.float64)
    idx_tr, idx_te = train_test_split(
        np.arange(len(raw_traces)), test_size=args.test_size,
        random_state=args.seed, stratify=y,
    )
    y_tr, y_te = y[idx_tr], y[idx_te]

    scaler = StandardScaler()
    X_tr   = scaler.fit_transform(X_full[idx_tr])

    print(f"[*] Training RF ({args.trees} trees) on {len(idx_tr)} samples...")
    model = RandomForestClassifier(n_estimators=args.trees, n_jobs=-1, random_state=args.seed)
    model.fit(X_tr, y_tr)

    # Build per-class pool of test traces for sampling contaminants
    test_traces = [raw_traces[i] for i in idx_te]
    class_pool  = defaultdict(list)
    for i, (trace, label) in enumerate(zip(test_traces, y_te)):
        class_pool[label].append((i, trace))

    all_labels = np.arange(len(encoder.classes_))
    rng        = random.Random(args.seed)

    print()
    print(f"{'Contam %':>9}  {'Top-1':>7}  {'Top-3':>7}  {'n_pairs':>8}")
    print("-" * 38)

    results = []
    for level in contamination_levels:
        y_pred_list  = []
        y_true_list  = []
        probs_list   = []
        pairs_done   = 0

        for i, (trace_a, label_a) in enumerate(zip(test_traces, y_te)):
            if pairs_done >= args.pairs:
                break

            # Pick a contaminant from a *different* class
            other_classes = [c for c in class_pool if c != label_a]
            if not other_classes:
                continue
            contam_class = rng.choice(other_classes)
            _, trace_b   = rng.choice(class_pool[contam_class])

            merged   = interleave(trace_a, trace_b, level, rng)
            feat_vec = extract_wf_features(merged)
            X_scaled = scaler.transform([feat_vec])
            prob_vec = model.predict_proba(X_scaled)[0]
            pred     = np.argmax(prob_vec)

            y_pred_list.append(pred)
            y_true_list.append(label_a)
            probs_list.append(prob_vec)
            pairs_done += 1

        if not y_pred_list:
            continue

        y_pred_arr  = np.array(y_pred_list)
        y_true_arr  = np.array(y_true_list)
        probs_arr   = np.array(probs_list)

        acc1 = accuracy_score(y_true_arr, y_pred_arr)
        acc3 = top_k_accuracy_score(y_true_arr, probs_arr, k=3, labels=all_labels)
        pct  = int(level * 100)

        print(f"{pct:>8}%  {acc1:>6.1%}  {acc3:>6.1%}  {pairs_done:>8}")
        results.append({
            "contamination_pct": pct,
            "top1_accuracy":     round(acc1, 4),
            "top3_accuracy":     round(acc3, 4),
            "n_pairs":           pairs_done,
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
