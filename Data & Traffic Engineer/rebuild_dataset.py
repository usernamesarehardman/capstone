"""
WF-Guard: Rebuild full dataset from raw PCAPs.

Runs: parse_pcaps.py (PCAP -> parsed sessions) -> build_dataset.py (features, split).
Use this to reproduce the dataset from PCAPs only.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

# Import from local modules so we can call their logic without re-executing scripts
from parse_pcaps import run_parsing
from build_dataset import main as build_main


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild WF-Guard dataset from raw PCAPs (parse -> features -> split).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--pcap-root", default="data", help="Root containing defense_off/ and defense_on/ PCAPs")
    parser.add_argument("--output-dir", default="dataset", help="Output directory for feature matrices and manifests")
    parser.add_argument("--parsed-dir", default=None, help="Directory for parsed sessions (default: <output-dir>/parsed)")
    parser.add_argument("--bpf-filter", default="", help="BPF filter for parse step")
    parser.add_argument("--use-tshark", action="store_true", help="Use tshark instead of PyShark for parsing")
    parser.add_argument("--format", choices=("csv", "parquet"), default="csv", help="Parsed session format")
    parser.add_argument("--no-balance", action="store_true", help="Skip balancing in build_dataset")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for split")
    args = parser.parse_args()

    parsed_dir = args.parsed_dir or os.path.join(args.output_dir, "parsed")
    # So that build_dataset finds manifest and parsed files in the same tree
    dataset_output = args.output_dir

    print("Step 1: Parsing PCAPs ->", parsed_dir)
    run_parsing(
        root=args.pcap_root,
        output_dir=parsed_dir,
        bpf_filter=args.bpf_filter,
        use_tshark=args.use_tshark,
        format=args.format,
    )

    manifest_path = os.path.join(parsed_dir, "manifest.csv")
    if not os.path.isfile(manifest_path):
        print("No manifest produced; no PCAPs found or all failed.", file=sys.stderr)
        return 1

    print("Step 2: Building dataset (features, balance, split) ->", dataset_output)
    # Patch sys.argv so build_dataset sees our args
    prev_argv = sys.argv
    sys.argv = [
        "build_dataset.py",
        "--parsed-dir", parsed_dir,
        "--output-dir", dataset_output,
        "--format", args.format,
        "--seed", str(args.seed),
    ]
    if args.no_balance:
        sys.argv.append("--no-balance")
    try:
        code = build_main()
    finally:
        sys.argv = prev_argv

    if code != 0:
        return code
    print("Done. Feature files and overhead stats in", dataset_output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
