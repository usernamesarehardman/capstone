"""
open_world_eval.py
==================
Open-world evaluation: false-positive rate on unmonitored traffic.

In a closed-world evaluation the classifier only ever sees sites it was
trained on.  The open-world setting is more realistic: the adversary trains
on a set of *monitored* sites, but the victim may visit *any* site.  Traffic
from unmonitored sites must not be mistakenly identified as a monitored site.

This script:
  1. Splits the dataset into a "monitored" set (first M sites alphabetically)
     and an "unmonitored" remainder.
  2. Trains the RF on the monitored set with a rejection threshold.
  3. Evaluates:
       - Closed-world accuracy on held-out monitored samples
       - False-positive rate (FPR): unmonitored samples classified as monitored
       - True-positive rate (TPR / recall) on monitored samples at the threshold
  4. Sweeps the confidence threshold to produce a TPR-FPR tradeoff table
     (ROC-style for the binary monitored/unmonitored decision).

Usage:
    python open_world_eval.py
    python open_world_eval.py --monitored 20
    python open_world_eval.py --monitored 20 --threshold 0.5
    python open_world_eval.py --dataset ../data/curated_raw_dataset.csv

Options:
    --dataset PATH     Training CSV (default: auto-locate curated_raw_dataset.csv)
    --monitored N      Number of sites treated as monitored (default: 20)
    --threshold F      Single confidence threshold for reporting (default: sweep)
    --trees N          RF estimators (default: 1000)
    --test-size F      Held-out fraction per class (default: 0.2)
    --output PATH      Write CSV tradeoff table to this path (optional)
"""

import argparse
import csv
import os
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from evaluate_models import find_dataset, load_dataset, load_npz_dataset


def main():
    parser = argparse.ArgumentParser(
        description="Open-world evaluation: FPR on unmonitored Tor traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dataset", default="curated_raw_dataset.csv", metavar="PATH")
    parser.add_argument("--monitored", type=int, default=20, metavar="N",
                        help="Number of sites treated as monitored (default: 20).")
    parser.add_argument("--threshold", type=float, default=None, metavar="F",
                        help="Fixed confidence threshold.  Default: sweep 0.1–0.9.")
    parser.add_argument("--trees", type=int, default=1000, metavar="N")
    parser.add_argument("--test-size", type=float, default=0.2, metavar="F")
    parser.add_argument("--output", default=None, metavar="PATH")
    args = parser.parse_args()

    target = find_dataset(args.dataset)
    print(f"[*] Dataset: {target}")

    if target.endswith(".npz"):
        X, y_raw = load_npz_dataset(target)
    else:
        X, y_raw = load_dataset(target)

    if len(X) == 0:
        print("[!] No samples loaded.")
        return

    # Sort sites deterministically and split into monitored / unmonitored
    all_sites = sorted(np.unique(y_raw))
    n_total   = len(all_sites)
    n_mon     = min(args.monitored, n_total - 1)   # need at least 1 unmonitored site
    monitored_sites   = set(all_sites[:n_mon])
    unmonitored_sites = set(all_sites[n_mon:])

    print(f"[*] {n_total} total sites → {n_mon} monitored, "
          f"{len(unmonitored_sites)} unmonitored")

    # Partition samples
    X_np   = np.array(X, dtype=np.float64)
    y_np   = np.array(y_raw)
    mon_mask = np.array([s in monitored_sites for s in y_np])

    X_mon, y_mon = X_np[mon_mask], y_np[mon_mask]
    X_unm         = X_np[~mon_mask]          # no labels needed for unmonitored

    if len(X_unm) == 0:
        print("[!] No unmonitored samples — increase dataset or decrease --monitored.")
        return

    # Encode monitored labels
    encoder = LabelEncoder()
    y_enc   = encoder.fit_transform(y_mon)

    X_tr, X_te_mon, y_tr, y_te_mon = train_test_split(
        X_mon, y_enc, test_size=args.test_size, random_state=42, stratify=y_enc,
    )
    scaler = StandardScaler()
    X_tr       = scaler.fit_transform(X_tr)
    X_te_mon   = scaler.transform(X_te_mon)
    X_te_unm   = scaler.transform(X_unm)

    print(f"[*] Training RF ({args.trees} trees) on {len(X_tr)} monitored samples...")
    model = RandomForestClassifier(n_estimators=args.trees, n_jobs=-1, random_state=42)
    model.fit(X_tr, y_tr)

    # Closed-world accuracy (monitored test set, no threshold)
    cw_acc = accuracy_score(y_te_mon, model.predict(X_te_mon))
    print(f"\n[*] Closed-world accuracy (monitored only): {cw_acc:.2%}")

    # Get max confidence for each sample — this is the "decision confidence"
    probs_mon = model.predict_proba(X_te_mon)
    probs_unm = model.predict_proba(X_te_unm)
    conf_mon  = probs_mon.max(axis=1)
    conf_unm  = probs_unm.max(axis=1)

    # Sweep thresholds
    thresholds = (
        [args.threshold]
        if args.threshold is not None
        else [round(t, 2) for t in np.arange(0.10, 0.95, 0.05)]
    )

    print()
    print(f"{'Threshold':>10}  {'TPR (recall)':>13}  {'FPR':>7}  {'Precision':>10}")
    print("-" * 47)

    rows = []
    for thresh in thresholds:
        # TPR: monitored samples above threshold with correct prediction
        correct_mon = model.predict(X_te_mon) == y_te_mon
        tp = np.sum((conf_mon >= thresh) & correct_mon)
        tpr = tp / len(y_te_mon) if len(y_te_mon) > 0 else 0.0

        # FPR: unmonitored samples classified as monitored (above threshold)
        fp = np.sum(conf_unm >= thresh)
        fpr = fp / len(conf_unm) if len(conf_unm) > 0 else 0.0

        # Precision: of all "monitored" decisions, how many were actually correct
        total_positives = tp + fp
        precision = tp / total_positives if total_positives > 0 else 0.0

        print(f"{thresh:>10.2f}  {tpr:>12.1%}  {fpr:>6.1%}  {precision:>10.1%}")
        rows.append({
            "threshold":   thresh,
            "tpr_recall":  round(tpr, 4),
            "fpr":         round(fpr, 4),
            "precision":   round(precision, 4),
        })

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n[*] TPR-FPR table saved → {args.output}")


if __name__ == "__main__":
    main()
