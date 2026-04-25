"""
analyze_log.py
==============
Offline reporter for WF-Guard inference logs.

Reads inference_log.jsonl (written by dashboard.py) and prints a structured
report covering accuracy at multiple ranks, per-site breakdown, defense impact,
and confidence diagnostics.

Usage:
    python analyze_log.py
    python analyze_log.py --log /path/to/inference_log.jsonl
    python analyze_log.py --source real      # filter to real-mode entries only
    python analyze_log.py --defense off      # filter to defense-off entries only
    python analyze_log.py --csv report.csv   # also dump per-site table to CSV

Columns in inference_log.jsonl:
    ts               Unix timestamp of the inference
    source           "fake" | "real"
    prediction       Top-1 predicted site
    confidence       Probability of the top-1 prediction
    ground_truth     Actual site (from traffic_gen.py ground-truth file)
    gt_rank          Rank of the correct class (1 = correct, 2 = runner-up, …)
    gt_confidence    Probability assigned to the correct class
    in_top3          true if correct class was in top-3 predictions
    in_top5          true if correct class was in top-5 predictions
    top3             [[site, prob], …] for the three highest predictions
    defense_active   true if WF-Guard defense was enabled during this inference
    packets_in_window Number of packets in the capture window
"""

import argparse
import json
import os
import sys
from collections import defaultdict

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

HERE        = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG = os.path.join(os.path.dirname(HERE), "logs", "inference_log.jsonl")


def load_log(path: str, source_filter=None, defense_filter=None) -> list[dict]:
    if not os.path.exists(path):
        print(f"[!] Log file not found: {path}")
        sys.exit(1)

    entries = []
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                print(f"[!] Skipping malformed line {i}")
                continue
            if source_filter and e.get("source") != source_filter:
                continue
            if defense_filter == "on"  and not e.get("defense_active"):
                continue
            if defense_filter == "off" and e.get("defense_active"):
                continue
            entries.append(e)

    return entries


def accuracy_block(entries: list[dict]) -> dict:
    """Compute top-1/3/5 accuracy and GT confidence stats."""
    n = len(entries)
    if n == 0:
        return {}
    top1  = sum(1 for e in entries if e.get("gt_rank") == 1)
    top3  = sum(1 for e in entries if e.get("in_top3"))
    top5  = sum(1 for e in entries if e.get("in_top5"))
    gt_cs = [e["gt_confidence"] for e in entries if "gt_confidence" in e]
    correct_cs   = [e["gt_confidence"] for e in entries if e.get("gt_rank") == 1]
    incorrect_cs = [e["gt_confidence"] for e in entries if e.get("gt_rank", 1) != 1]

    return {
        "n":              n,
        "top1":           top1,
        "top3":           top3,
        "top5":           top5,
        "avg_gt_conf":    sum(gt_cs) / len(gt_cs) if gt_cs else None,
        "avg_gt_conf_correct":   sum(correct_cs)   / len(correct_cs)   if correct_cs   else None,
        "avg_gt_conf_incorrect": sum(incorrect_cs) / len(incorrect_cs) if incorrect_cs else None,
        "avg_pred_conf":  sum(e["confidence"] for e in entries) / n,
        "median_gt_rank": sorted(e.get("gt_rank", 999) for e in entries)[n // 2],
    }


def per_site_table(entries: list[dict]) -> list[dict]:
    """Per-site accuracy and confidence stats."""
    sites: dict = defaultdict(lambda: {"n": 0, "top1": 0, "top3": 0, "top5": 0,
                                        "gt_conf_sum": 0.0, "rank_sum": 0})
    for e in entries:
        gt = e.get("ground_truth", "?")
        sites[gt]["n"]           += 1
        sites[gt]["gt_conf_sum"] += e.get("gt_confidence", 0.0)
        sites[gt]["rank_sum"]    += e.get("gt_rank", 999)
        if e.get("gt_rank") == 1:
            sites[gt]["top1"] += 1
        if e.get("in_top3"):
            sites[gt]["top3"] += 1
        if e.get("in_top5"):
            sites[gt]["top5"] += 1

    rows = []
    for site, d in sorted(sites.items()):
        n = d["n"]
        rows.append({
            "site":          site,
            "n":             n,
            "top1_acc":      d["top1"] / n,
            "top3_acc":      d["top3"] / n,
            "top5_acc":      d["top5"] / n,
            "avg_gt_conf":   d["gt_conf_sum"] / n,
            "avg_gt_rank":   d["rank_sum"] / n,
        })
    return sorted(rows, key=lambda r: -r["top1_acc"])


def defense_comparison(all_entries: list[dict]) -> tuple[dict, dict]:
    """Split by defense_active and compute accuracy for each half."""
    off = [e for e in all_entries if not e.get("defense_active")]
    on  = [e for e in all_entries if e.get("defense_active")]
    return accuracy_block(off), accuracy_block(on)


def pct(num, den) -> str:
    return f"{num/den:.1%} ({num}/{den})" if den > 0 else "—"


def print_report(entries: list[dict], csv_path=None):
    total_lines = len(entries)
    if total_lines == 0:
        print("[!] No matching entries in log.")
        return

    print("=" * 60)
    print("WF-Guard Inference Log Analysis")
    print("=" * 60)
    print(f"Total entries (after filters): {total_lines}")

    # ── Overall accuracy ─────────────────────────────────────────────────────
    stats = accuracy_block(entries)
    print()
    print("── ACCURACY " + "─" * 48)
    print(f"  Top-1 : {pct(stats['top1'], stats['n'])}")
    print(f"  Top-3 : {pct(stats['top3'], stats['n'])}")
    print(f"  Top-5 : {pct(stats['top5'], stats['n'])}")
    print(f"  Median GT rank       : {stats['median_gt_rank']}")

    # ── GT Confidence ────────────────────────────────────────────────────────
    print()
    print("── GT CONFIDENCE " + "─" * 43)
    if stats["avg_gt_conf"] is not None:
        print(f"  Avg GT confidence (all)          : {stats['avg_gt_conf']:.3f}")
        if stats["avg_gt_conf_correct"] is not None:
            print(f"  Avg GT confidence (when correct) : {stats['avg_gt_conf_correct']:.3f}")
        if stats["avg_gt_conf_incorrect"] is not None:
            print(f"  Avg GT confidence (when wrong)   : {stats['avg_gt_conf_incorrect']:.3f}")
    print(f"  Avg prediction confidence        : {stats['avg_pred_conf']:.3f}")

    # ── Rank distribution ────────────────────────────────────────────────────
    from collections import Counter
    rank_counts = Counter(e.get("gt_rank", 999) for e in entries)
    print()
    print("── GT RANK DISTRIBUTION " + "─" * 36)
    for rank in sorted(rank_counts):
        label = f"Rank {rank}" if rank < 50 else "Rank 50+"
        bar   = "█" * int(rank_counts[rank] / stats["n"] * 40)
        print(f"  {label:10s}  {pct(rank_counts[rank], stats['n']):20s}  {bar}")

    # ── Defense comparison ────────────────────────────────────────────────────
    off_s, on_s = defense_comparison(entries)
    if off_s and on_s:
        print()
        print("── DEFENSE IMPACT " + "─" * 42)
        print(f"  Defense OFF  Top-1: {pct(off_s['top1'], off_s['n'])}  "
              f"Top-3: {pct(off_s['top3'], off_s['n'])}  "
              f"Avg GT conf: {off_s['avg_gt_conf']:.3f}")
        print(f"  Defense ON   Top-1: {pct(on_s['top1'],  on_s['n'])}   "
              f"Top-3: {pct(on_s['top3'],  on_s['n'])}  "
              f"Avg GT conf: {on_s['avg_gt_conf']:.3f}")

    # ── Per-site breakdown ────────────────────────────────────────────────────
    rows = per_site_table(entries)
    print()
    print("── PER-SITE BREAKDOWN " + "─" * 38)
    hdr = f"  {'Site':<20}  {'N':>4}  {'Top-1':>8}  {'Top-3':>8}  {'Top-5':>8}  {'Avg GT Conf':>12}  {'Avg Rank':>9}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in rows:
        print(
            f"  {r['site']:<20}  {r['n']:>4}  "
            f"{r['top1_acc']:>7.1%}  {r['top3_acc']:>7.1%}  {r['top5_acc']:>7.1%}  "
            f"{r['avg_gt_conf']:>11.3f}  {r['avg_gt_rank']:>8.1f}"
        )

    # ── CSV export ───────────────────────────────────────────────────────────
    if csv_path:
        if HAS_PANDAS:
            pd.DataFrame(rows).to_csv(csv_path, index=False, float_format="%.4f")
            print(f"\n[*] Per-site table saved → {csv_path}")
        else:
            import csv
            with open(csv_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=rows[0].keys())
                w.writeheader()
                w.writerows(rows)
            print(f"\n[*] Per-site table saved → {csv_path}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="WF-Guard inference log analyzer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log", default=DEFAULT_LOG, metavar="PATH",
        help=f"Path to inference_log.jsonl (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--source", choices=["fake", "real"], default=None,
        help="Filter to a specific data source.",
    )
    parser.add_argument(
        "--defense", choices=["on", "off"], default=None,
        help="Filter to defense-on or defense-off entries.",
    )
    parser.add_argument(
        "--csv", default=None, metavar="PATH",
        help="Write per-site breakdown to a CSV file.",
    )
    args = parser.parse_args()

    entries = load_log(args.log, source_filter=args.source, defense_filter=args.defense)
    print_report(entries, csv_path=args.csv)


if __name__ == "__main__":
    main()
