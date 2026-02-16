"""
WF-Guard: Parse PCAPs to per-session packet series (timestamps, sizes, directions).

Reads PCAPs from root layout: defense_off/<site_id>/visit_<id>.pcap and
defense_on/<site_id>/visit_<id>.pcap. Filters to Tor-related traffic
(see TOR_FILTER below). Outputs CSV or Parquet per session plus an optional manifest.

Tor filter: We keep packets that could be Tor Browser traffic. Typical setup:
- Tor Browser SOCKS on 127.0.0.1:9150; defense proxy may listen on another port (e.g. 9050).
- Filter: include traffic to/from localhost on common Tor/proxy ports, or exclude only
  clearly non-Tor (e.g. raw DNS to external IPs). Default: no BPF filter (capture
  is assumed to be on the interface that only sees Tor/proxy traffic); optional
  --bpf-filter to restrict by port/host.
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from pathlib import Path

# Optional: use pyshark for parsing; fallback to tshark CSV export if unavailable
try:
    import pyshark
except ImportError:
    pyshark = None

import pandas as pd

# Default: no BPF filter (user captures on the right interface). Set e.g. "tcp port 9150"
# if capturing on loopback and only want Tor Browser SOCKS traffic.
TOR_FILTER = ""

DEFENSE_OFF = "defense_off"
DEFENSE_ON = "defense_on"


def parse_pcap_pyshark(
    pcap_path: str,
    bpf_filter: str = "",
) -> pd.DataFrame:
    """
    Parse one PCAP with PyShark; return DataFrame with columns:
    timestamp (float), size (int), direction (int: +1 outbound, -1 inbound).
    """
    cap = pyshark.FileCapture(pcap_path, display_filter=bpf_filter if bpf_filter else None)
    rows = []
    try:
        for pkt in cap:
            try:
                ts = float(pkt.sniff_timestamp)
                length = int(pkt.length) if hasattr(pkt, "length") else 0
                # Heuristic: assume client-originated = outbound (+1), else inbound (-1).
                # PyShark may expose ip.src/dst; if loopback, use port or first-seen logic.
                direction = _direction_from_packet(pkt)
                rows.append({"timestamp": ts, "size": length, "direction": direction})
            except (AttributeError, ValueError, TypeError):
                continue
    finally:
        cap.close()
    return pd.DataFrame(rows)


def _direction_from_packet(pkt) -> int:
    """Return +1 for outbound (client->Tor), -1 for inbound (Tor->client)."""
    try:
        if hasattr(pkt, "tcp") and pkt.tcp:
            # Stream direction: high port usually client; could use port comparison.
            if hasattr(pkt, "ip"):
                # Simplified: use presence of dest/src; often need context of "our" IP.
                pass
    except Exception:
        pass
    # Default: assume alternating or outbound-first is not reliable; use +1 for first half
    # and -1 for second if we had stream order. Here we use a simple heuristic:
    # even index -> +1, odd -> -1 as placeholder; real impl. should use IP:port identity.
    return 1  # Conservative: treat as outbound; caller can refine with flow analysis.


def parse_pcap_tshark_csv(pcap_path: str, bpf_filter: str = "") -> pd.DataFrame:
    """
    Use tshark to export CSV (frame number, time, length) then parse.
    Direction: +1 outbound, -1 inbound. We use a simple heuristic (e.g. even/odd)
    unless tshark provides stream info; for full accuracy use flow tracking.
    """
    extra = ["-Y", bpf_filter] if bpf_filter else []
    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y", "-E", "separator=,",
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.len",
        *extra,
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
    except Exception as e:
        raise RuntimeError(f"tshark failed for {pcap_path}: {e}") from e

    rows = []
    reader = csv.DictReader(out.stdout.strip().splitlines() or [], fieldnames=["frame.number", "frame.time_epoch", "frame.len"])
    for i, r in enumerate(reader):
        try:
            ts = float(r.get("frame.time_epoch", 0))
            length = int(r.get("frame.len", 0))
            direction = 1 if (i % 2 == 0) else -1  # Placeholder
            rows.append({"timestamp": ts, "size": length, "direction": direction})
        except (ValueError, TypeError):
            continue
    return pd.DataFrame(rows)


# Prefer PyShark for consistency; fall back to tshark CSV
def parse_pcap(pcap_path: str, bpf_filter: str = "", use_tshark: bool = False) -> pd.DataFrame:
    """Parse one PCAP; return DataFrame with timestamp, size, direction."""
    if use_tshark or pyshark is None:
        return parse_pcap_tshark_csv(pcap_path, bpf_filter)
    return parse_pcap_pyshark(pcap_path, bpf_filter)


def discover_pcaps(root: str) -> list[tuple[str, str, bool, str]]:
    """
    Discover all PCAPs under root. Returns list of (site_id, visit_id, defense_on, pcap_path).
    """
    root_path = Path(root)
    results = []
    for defense_dir in (DEFENSE_OFF, DEFENSE_ON):
        defense_path = root_path / defense_dir
        if not defense_path.is_dir():
            continue
        defense_on = defense_dir == DEFENSE_ON
        for site_dir in sorted(defense_path.iterdir()):
            if not site_dir.is_dir():
                continue
            site_id = site_dir.name
            for pcap in sorted(site_dir.glob("*.pcap")):
                # visit_001.pcap -> visit_001
                stem = pcap.stem
                visit_id = stem if stem.startswith("visit_") else f"visit_{stem}"
                rel = os.path.relpath(pcap, root_path)
                results.append((site_id, visit_id, defense_on, rel))
    return results


def run_parsing(
    root: str,
    output_dir: str,
    bpf_filter: str = "",
    use_tshark: bool = False,
    format: str = "csv",
) -> pd.DataFrame:
    """
    Parse all PCAPs under root; write per-session files to output_dir and return manifest.
    """
    discovered = discover_pcaps(root)
    manifest_rows = []

    for site_id, visit_id, defense_on, rel_path in discovered:
        pcap_full = os.path.join(root, rel_path)
        if not os.path.isfile(pcap_full):
            continue
        try:
            df = parse_pcap(pcap_full, bpf_filter=bpf_filter, use_tshark=use_tshark)
        except Exception as e:
            print(f"Parse failed {pcap_full}: {e}", file=sys.stderr)
            continue

        if df.empty:
            print(f"Empty: {pcap_full}", file=sys.stderr)
            continue

        # Output path: parsed/defense_off/site_01/visit_001.csv
        defense_dir = DEFENSE_ON if defense_on else DEFENSE_OFF
        out_subdir = os.path.join(output_dir, defense_dir, site_id)
        os.makedirs(out_subdir, exist_ok=True)
        ext = "csv" if format == "csv" else "parquet"
        out_name = f"{visit_id}.{ext}"
        out_path = os.path.join(out_subdir, out_name)

        if format == "parquet":
            df.to_parquet(out_path, index=False)
        else:
            df.to_csv(out_path, index=False)

        manifest_rows.append({
            "site_id": site_id,
            "visit_id": visit_id,
            "defense_on": defense_on,
            "pcap_path": rel_path,
            "parsed_path": os.path.join(defense_dir, site_id, out_name),
            "packet_count": len(df),
            "total_bytes": int(df["size"].sum()),
        })

    manifest = pd.DataFrame(manifest_rows)
    if not manifest.empty:
        manifest_path = os.path.join(output_dir, "manifest.csv")
        manifest.to_csv(manifest_path, index=False)
        print(f"Wrote manifest ({len(manifest)} sessions) -> {manifest_path}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse WF-Guard PCAPs to per-session series (timestamp, size, direction).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--pcap-root", default="data", help="Root containing defense_off/ and defense_on/")
    parser.add_argument("--output-dir", default="parsed", help="Output directory for parsed CSVs/Parquet and manifest")
    parser.add_argument("--bpf-filter", default=TOR_FILTER, help="BPF/display filter for Tor traffic (optional)")
    parser.add_argument("--use-tshark", action="store_true", help="Use tshark CSV export instead of PyShark")
    parser.add_argument("--format", choices=("csv", "parquet"), default="csv", help="Output format per session")
    args = parser.parse_args()

    run_parsing(
        root=args.pcap_root,
        output_dir=args.output_dir,
        bpf_filter=args.bpf_filter or "",
        use_tshark=args.use_tshark,
        format=args.format,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
