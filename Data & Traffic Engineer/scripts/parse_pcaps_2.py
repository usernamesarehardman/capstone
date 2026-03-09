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

Direction heuristic (see _direction_from_ip):
  Priority 1 — IP comparison: if --client-ip is provided and is not a loopback address,
    src == client_ip → outbound (+1), dst == client_ip → inbound (-1).
  Priority 2 — Port-based: if dst_port is in the known Tor/proxy port set → outbound (+1);
    if src_port is in that set → inbound (-1). This handles loopback captures where
    both src and dst are 127.0.0.1.
  Priority 3 — Low-port heuristic: the lower-numbered port is assumed to be the server
    (Tor relay or proxy); packets directed toward it are outbound.
  Fallback — +1 (conservative; treats unknown as outbound).
"""

from __future__ import annotations

import argparse
import csv
import os
import socket
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

# Known Tor / proxy ports. Tor Browser SOCKS: 9150. Tor daemon SOCKS: 9050.
# Tor OR port: 9001. Tor dir port: 9030. Add the defense proxy port here if different.
TOR_PORTS: set[int] = {9001, 9030, 9050, 9150}

DEFENSE_OFF = "defense_off"
DEFENSE_ON = "defense_on"

LOOPBACK_ADDRS = {"127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}


# ---------------------------------------------------------------------------
# Direction helpers
# ---------------------------------------------------------------------------

def _infer_client_ip() -> str:
    """
    Best-effort: return the primary non-loopback local IP.
    Used as a default when --client-ip is not provided.
    Returns empty string on failure (caller falls back to port heuristic).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip if ip not in LOOPBACK_ADDRS else ""
    except Exception:
        return ""


def _direction_from_ip(
    src_ip: str,
    dst_ip: str,
    src_port: str,
    dst_port: str,
    client_ip: str,
    tor_ports: set[int],
) -> int:
    """
    Determine packet direction: +1 outbound (client→Tor), -1 inbound (Tor→client).

    Priority:
      1. IP comparison — requires client_ip to be set and non-loopback.
      2. Port-based — dst_port in tor_ports → outbound; src_port in tor_ports → inbound.
         Handles loopback captures where IP comparison is useless.
      3. Low-port heuristic — the lower port is assumed to be the Tor/proxy server side.
      4. Default +1 (conservative).
    """
    # 1. IP-based (only useful for non-loopback interfaces)
    if client_ip and client_ip not in LOOPBACK_ADDRS:
        if src_ip == client_ip:
            return 1   # we sent this
        if dst_ip == client_ip:
            return -1  # we received this

    # 2. Port-based (primary method for loopback / unknown client IP)
    try:
        dp = int(dst_port) if dst_port else -1
        sp = int(src_port) if src_port else -1
        if dp in tor_ports:
            return 1   # browser/client → Tor or proxy
        if sp in tor_ports:
            return -1  # Tor or proxy → browser/client
        # 3. Low-port heuristic: lower port ≈ server side
        if dp > 0 and sp > 0:
            if dp < sp:
                return 1   # sending toward the lower (server) port → outbound
            if sp < dp:
                return -1  # server-side src port → inbound
    except (TypeError, ValueError):
        pass

    # 4. Conservative default
    return 1


# ---------------------------------------------------------------------------
# PyShark parser
# ---------------------------------------------------------------------------

def parse_pcap_pyshark(
    pcap_path: str,
    bpf_filter: str = "",
    client_ip: str = "",
    tor_ports: set[int] | None = None,
) -> pd.DataFrame:
    """
    Parse one PCAP with PyShark; return DataFrame with columns:
    timestamp (float), size (int), direction (int: +1 outbound, -1 inbound).
    """
    if tor_ports is None:
        tor_ports = TOR_PORTS

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=bpf_filter if bpf_filter else None,
    )
    rows = []
    try:
        for pkt in cap:
            try:
                ts = float(pkt.sniff_timestamp)
                length = int(pkt.length) if hasattr(pkt, "length") else 0

                src_ip = dst_ip = ""
                src_port = dst_port = ""

                if hasattr(pkt, "ip"):
                    src_ip = str(pkt.ip.src)
                    dst_ip = str(pkt.ip.dst)
                elif hasattr(pkt, "ipv6"):
                    src_ip = str(pkt.ipv6.src)
                    dst_ip = str(pkt.ipv6.dst)

                if hasattr(pkt, "tcp"):
                    src_port = str(pkt.tcp.srcport)
                    dst_port = str(pkt.tcp.dstport)
                elif hasattr(pkt, "udp"):
                    src_port = str(pkt.udp.srcport)
                    dst_port = str(pkt.udp.dstport)

                direction = _direction_from_ip(
                    src_ip, dst_ip, src_port, dst_port, client_ip, tor_ports
                )
                rows.append({"timestamp": ts, "size": length, "direction": direction})
            except (AttributeError, ValueError, TypeError):
                continue
    finally:
        cap.close()
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# tshark CSV parser
# ---------------------------------------------------------------------------

def parse_pcap_tshark_csv(
    pcap_path: str,
    bpf_filter: str = "",
    client_ip: str = "",
    tor_ports: set[int] | None = None,
) -> pd.DataFrame:
    """
    Use tshark to export fields (time, length, IP, ports) then determine direction.
    Falls back to _direction_from_ip with the same priority chain as the PyShark path.
    """
    if tor_ports is None:
        tor_ports = TOR_PORTS

    extra = ["-Y", bpf_filter] if bpf_filter else []
    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        *extra,
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=120
        )
    except Exception as e:
        raise RuntimeError(f"tshark failed for {pcap_path}: {e}") from e

    lines = out.stdout.strip().splitlines()
    if not lines:
        return pd.DataFrame()

    reader = csv.DictReader(lines)
    rows = []
    for r in reader:
        try:
            ts = float(r.get("frame.time_epoch", 0) or 0)
            length = int(r.get("frame.len", 0) or 0)

            src_ip = (r.get("ip.src") or "").strip('"')
            dst_ip = (r.get("ip.dst") or "").strip('"')
            # Prefer TCP ports; fall back to UDP
            src_port = (r.get("tcp.srcport") or r.get("udp.srcport") or "").strip('"')
            dst_port = (r.get("tcp.dstport") or r.get("udp.dstport") or "").strip('"')

            direction = _direction_from_ip(
                src_ip, dst_ip, src_port, dst_port, client_ip, tor_ports
            )
            rows.append({"timestamp": ts, "size": length, "direction": direction})
        except (ValueError, TypeError):
            continue
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def parse_pcap(
    pcap_path: str,
    bpf_filter: str = "",
    use_tshark: bool = False,
    client_ip: str = "",
    tor_ports: set[int] | None = None,
) -> pd.DataFrame:
    """Parse one PCAP; return DataFrame with timestamp, size, direction."""
    if tor_ports is None:
        tor_ports = TOR_PORTS
    if use_tshark or pyshark is None:
        return parse_pcap_tshark_csv(
            pcap_path, bpf_filter, client_ip=client_ip, tor_ports=tor_ports
        )
    return parse_pcap_pyshark(
        pcap_path, bpf_filter, client_ip=client_ip, tor_ports=tor_ports
    )


# ---------------------------------------------------------------------------
# PCAP discovery
# ---------------------------------------------------------------------------

def discover_pcaps(root: str) -> list[tuple[str, str, bool, str]]:
    """
    Discover all PCAPs under root.
    Returns list of (site_id, visit_id, defense_on, rel_pcap_path).
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
                stem = pcap.stem
                visit_id = stem if stem.startswith("visit_") else f"visit_{stem}"
                rel = os.path.relpath(pcap, root_path)
                results.append((site_id, visit_id, defense_on, rel))
    return results


# ---------------------------------------------------------------------------
# Full parsing run
# ---------------------------------------------------------------------------

def run_parsing(
    root: str,
    output_dir: str,
    bpf_filter: str = "",
    use_tshark: bool = False,
    format: str = "csv",
    client_ip: str = "",
    tor_ports: set[int] | None = None,
) -> pd.DataFrame:
    """
    Parse all PCAPs under root; write per-session files to output_dir and return manifest.
    """
    if tor_ports is None:
        tor_ports = TOR_PORTS

    # Auto-detect client IP if not provided
    if not client_ip:
        client_ip = _infer_client_ip()
        if client_ip:
            print(f"Auto-detected client IP: {client_ip}")
        else:
            print(
                "Could not detect client IP; falling back to port-based direction heuristic. "
                "Pass --client-ip <IP> to override."
            )

    discovered = discover_pcaps(root)
    manifest_rows = []

    for site_id, visit_id, defense_on, rel_path in discovered:
        pcap_full = os.path.join(root, rel_path)
        if not os.path.isfile(pcap_full):
            continue
        try:
            df = parse_pcap(
                pcap_full,
                bpf_filter=bpf_filter,
                use_tshark=use_tshark,
                client_ip=client_ip,
                tor_ports=tor_ports,
            )
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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse WF-Guard PCAPs to per-session series (timestamp, size, direction).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--pcap-root", default="data",
        help="Root containing defense_off/ and defense_on/",
    )
    parser.add_argument(
        "--output-dir", default="parsed",
        help="Output directory for parsed CSVs/Parquet and manifest",
    )
    parser.add_argument(
        "--bpf-filter", default=TOR_FILTER,
        help="BPF/display filter for Tor traffic (optional)",
    )
    parser.add_argument(
        "--use-tshark", action="store_true",
        help="Use tshark CSV export instead of PyShark",
    )
    parser.add_argument(
        "--format", choices=("csv", "parquet"), default="csv",
        help="Output format per session",
    )
    parser.add_argument(
        "--client-ip", default="",
        help=(
            "IP address of the capture machine (e.g. 192.168.1.10). "
            "Used for IP-based direction detection. Auto-detected if omitted; "
            "falls back to port-based heuristic on loopback."
        ),
    )
    parser.add_argument(
        "--tor-ports", default="",
        help=(
            "Comma-separated list of Tor/proxy ports for port-based direction detection. "
            f"Defaults to {sorted(TOR_PORTS)}."
        ),
    )
    args = parser.parse_args()

    tor_ports = TOR_PORTS
    if args.tor_ports:
        try:
            tor_ports = {int(p.strip()) for p in args.tor_ports.split(",") if p.strip()}
        except ValueError:
            print("--tor-ports must be comma-separated integers.", file=sys.stderr)
            return 1

    run_parsing(
        root=args.pcap_root,
        output_dir=args.output_dir,
        bpf_filter=args.bpf_filter or "",
        use_tshark=args.use_tshark,
        format=args.format,
        client_ip=args.client_ip,
        tor_ports=tor_ports,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())