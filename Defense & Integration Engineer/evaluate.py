"""
evaluate.py
===========
Phase 5 evaluation script for WF-Guard defense proxy.

Measures and compares two key metrics with defense ON vs OFF:
  - Bandwidth overhead  : Total Bytes ON / Total Bytes OFF
  - Latency overhead    : Average page load time ON vs OFF

Usage:
    # Tor must be running first
    python evaluate.py

Output is printed to the terminal and saved to evaluation_results.txt.

Requirements:
    pip install requests[socks] PySocks fake-useragent
"""

import time
import statistics
from dataclasses import dataclass, field

from defense_proxy import (
    new_session,
    fetch,
    start_cover_traffic,
    stop_cover_traffic,
    _defense_enabled,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# URLs to benchmark — mix of lightweight and heavier pages
TEST_URLS = [
    "https://www.wikipedia.org",
    "https://httpbin.org/get",
    "https://www.python.org",
    "https://httpbin.org/headers",
    "https://www.example.com",
]

RUNS_PER_URL = 3   # How many times each URL is fetched per state
COVER_INTERVAL = (1.0, 3.0)   # Cover traffic interval during ON phase


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

@dataclass
class RequestResult:
    url:         str
    success:     bool
    latency_s:   float   # Time from request start to first byte received
    bytes_rx:    int     # Response content length in bytes


@dataclass
class PhaseResults:
    state:    str   # "ON" or "OFF"
    results:  list[RequestResult] = field(default_factory=list)

    def successful(self):
        return [r for r in self.results if r.success]

    def total_bytes(self) -> int:
        return sum(r.bytes_rx for r in self.successful())

    def avg_latency(self) -> float:
        latencies = [r.latency_s for r in self.successful()]
        return statistics.mean(latencies) if latencies else 0.0

    def success_rate(self) -> float:
        if not self.results:
            return 0.0
        return len(self.successful()) / len(self.results) * 100


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def run_phase(state: str, urls: list[str], runs: int) -> PhaseResults:
    """
    Fetch each URL `runs` times and record latency + bytes received.
    Defense state (ON/OFF) must already be set before calling this.
    """
    phase = PhaseResults(state=state)
    session = new_session()

    print(f"\n  Running {len(urls)} URLs × {runs} runs with defense {state}...")

    for url in urls:
        for run in range(1, runs + 1):
            start = time.perf_counter()
            resp = fetch(url, session=session, delay=(0.5, 1.5), retries=2)
            elapsed = time.perf_counter() - start

            if resp and resp.ok:
                bytes_rx = len(resp.content)
                phase.results.append(RequestResult(url, True, elapsed, bytes_rx))
                print(f"    [{state}] {url} — {elapsed:.2f}s, {bytes_rx} bytes (run {run}/{runs})")
            else:
                phase.results.append(RequestResult(url, False, elapsed, 0))
                print(f"    [{state}] {url} — FAILED (run {run}/{runs})")

    return phase


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(on: PhaseResults, off: PhaseResults) -> str:
    """Print comparison table and return the report as a string."""

    bw_on  = on.total_bytes()
    bw_off = off.total_bytes()
    bw_overhead = (bw_on / bw_off) if bw_off > 0 else float("inf")

    lat_on  = on.avg_latency()
    lat_off = off.avg_latency()
    lat_overhead = (lat_on / lat_off) if lat_off > 0 else float("inf")

    lines = [
        "",
        "=" * 55,
        "  WF-Guard — Phase 5 Evaluation Results",
        "=" * 55,
        "",
        f"  {'Metric':<30} {'ON':>8}  {'OFF':>8}  {'Overhead':>10}",
        f"  {'-'*30} {'-'*8}  {'-'*8}  {'-'*10}",
        f"  {'Total bytes received':<30} {bw_on:>8}  {bw_off:>8}  {bw_overhead:>9.2f}x",
        f"  {'Avg latency (s)':<30} {lat_on:>8.2f}  {lat_off:>8.2f}  {lat_overhead:>9.2f}x",
        f"  {'Success rate (%)':<30} {on.success_rate():>7.1f}%  {off.success_rate():>7.1f}%  {'—':>10}",
        f"  {'Requests made':<30} {len(on.results):>8}  {len(off.results):>8}  {'—':>10}",
        "",
        "  Bandwidth overhead formula:",
        f"    Total Bytes ON / Total Bytes OFF = {bw_on} / {bw_off} = {bw_overhead:.4f}x",
        "",
        "  Interpretation:",
    ]

    if bw_overhead > 1.0:
        lines.append(f"    Defense adds {(bw_overhead - 1) * 100:.1f}% extra bandwidth (cover traffic).")
    else:
        lines.append("    Bandwidth overhead not measurable — cover traffic may not have fired.")

    if lat_overhead > 1.0:
        lines.append(f"    Defense adds {(lat_overhead - 1) * 100:.1f}% latency (timing jitter).")
    else:
        lines.append("    No measurable latency overhead detected.")

    lines += ["", "=" * 55, ""]

    report = "\n".join(lines)
    print(report)
    return report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("  WF-Guard — Phase 5 Evaluation")
    print("=" * 55)
    print(f"\n  Test URLs   : {len(TEST_URLS)}")
    print(f"  Runs per URL: {RUNS_PER_URL}")
    print(f"  Total reqs  : {len(TEST_URLS) * RUNS_PER_URL} per state\n")

    # --- Phase 1: Defense ON ---
    print("[1/2] Defense ON phase")
    _defense_enabled.set()
    start_cover_traffic(interval=COVER_INTERVAL)
    on_results = run_phase("ON", TEST_URLS, RUNS_PER_URL)
    stop_cover_traffic()
    time.sleep(1)   # Let cover thread wind down

    # --- Phase 2: Defense OFF ---
    print("\n[2/2] Defense OFF phase")
    _defense_enabled.clear()
    off_results = run_phase("OFF", TEST_URLS, RUNS_PER_URL)

    # Restore default state
    _defense_enabled.set()

    # --- Report ---
    report = print_report(on_results, off_results)

    # Save to file
    output_file = "evaluation_results.txt"
    with open(output_file, "w") as f:
        f.write(report)
    print(f"  Results saved to {output_file}\n")
