"""
WF-Guard: Traffic capture script for Tor visits.

Captures packets on a given interface for a fixed duration (or until idle).
Writes PCAPs to: {defense_on|defense_off}/{site_id}/visit_{visit_id}.pcap.

Usage:
  Single visit (manual): start capture, load URL in Tor Browser, stop after timeout.
  Batch: use --site-id, --visit-id, --defense-on/off and script starts/stops capture.

Requires: tshark on PATH. Optional: run with --list-interfaces to pick interface.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time


def list_interfaces() -> list[str]:
    """Return list of capture interface names from tshark -D."""
    try:
        out = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        lines = [l.strip() for l in out.stdout.strip().splitlines() if l.strip()]
        return lines
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print("tshark -D failed:", e, file=sys.stderr)
        return []


def capture_visit(
    output_path: str,
    interface: str,
    duration_sec: float | None = 60.0,
    packet_count_limit: int | None = None,
) -> float:
    """
    Run tshark capture and write PCAP to output_path.
    Returns actual duration in seconds.
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    start = time.perf_counter()

    # -i interface, -w file, -a duration:N or -c N
    cmd = ["tshark", "-i", interface, "-w", output_path, "-q"]
    if duration_sec is not None and duration_sec > 0:
        cmd.extend(["-a", f"duration:{duration_sec}"])
    if packet_count_limit is not None and packet_count_limit > 0:
        cmd.extend(["-c", str(packet_count_limit)])

    try:
        subprocess.run(cmd, check=True, timeout=(duration_sec or 300) + 10)
    except subprocess.CalledProcessError as e:
        print("tshark capture failed:", e, file=sys.stderr)
        raise
    except FileNotFoundError:
        print("tshark not found. Install Wireshark/tshark and ensure it is on PATH.", file=sys.stderr)
        raise

    elapsed = time.perf_counter() - start
    return elapsed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture Tor traffic per visit and save as PCAP.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--root",
        default="data",
        help="Root directory for defense_off/ and defense_on/ PCAPs",
    )
    parser.add_argument(
        "--interface",
        "-i",
        default="0",
        help="Capture interface (name or index). Use --list-interfaces to list.",
    )
    parser.add_argument(
        "--site-id",
        default="site_01",
        help="Site identifier (e.g. site_01)",
    )
    parser.add_argument(
        "--visit-id",
        default="visit_001",
        help="Visit identifier (e.g. visit_001)",
    )
    parser.add_argument(
        "--defense-on",
        action="store_true",
        help="Save under defense_on/; otherwise defense_off/",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="Capture duration in seconds (0 = until interrupted)",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Stop after this many packets (optional)",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List tshark capture interfaces and exit",
    ),
    args = parser.parse_args()

    if args.list_interfaces:
        for line in list_interfaces():
            print(line)
        return 0

    defense_dir = "defense_on" if args.defense_on else "defense_off"
    out_dir = os.path.join(args.root, defense_dir, args.site_id)
    out_file = os.path.join(out_dir, f"{args.visit_id}.pcap")

    duration_sec = args.duration if args.duration > 0 else None
    print(f"Capturing on interface {args.interface} for {duration_sec or 'until Ctrl+C'} seconds -> {out_file}")
    elapsed = capture_visit(out_file, args.interface, duration_sec, args.max_packets)
    print(f"Capture finished in {elapsed:.1f}s -> {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
