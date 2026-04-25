"""
collect_fresh.py
================
Fresh training-data collector for WF-Guard.

Replaces the original collect.py + pcap-to-CSV pipeline. Captures scapy
packets directly during headless Firefox page loads and writes signed traces
to a CSV that evaluate_models.py can consume without modification.

The script is restartable: it checks how many traces already exist per site
and only collects what is missing.

Usage:
    python collect_fresh.py                          # 15 demo sites, 20 traces each
    python collect_fresh.py --traces 50              # more traces per site
    python collect_fresh.py --all                    # all 40 training sites
    python collect_fresh.py --sites wikipedia,imdb   # explicit site list
    python collect_fresh.py --output /tmp/fresh.csv  # custom output path
    python collect_fresh.py --iface ens33            # different network interface

Options:
    --traces N      Traces to collect per site (default: 20).
    --all           Include all 40 original training sites instead of the
                    15 high-recall demo sites.
    --sites S       Comma-separated site names (overrides --all/demo set).
    --output PATH   Output CSV path (default: collect/dataset.csv).
    --iface IFACE   Network interface to sniff on (default: eth0).

Output files (default location: this directory):
    dataset.csv      — append-friendly training CSV
    collection.log   — timestamped progress log

To retrain the model after collection:
    cd ..
    python evaluate_models.py --dataset collect/dataset.csv
"""

import argparse
import csv
import os
import random
import sys
import time

# Reach extract_features in the parent scripts/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from extract_features import packets_to_trace

# ── Configuration ─────────────────────────────────────────────────────────────
TOR_SOCKS_HOST    = "127.0.0.1"
TOR_SOCKS_PORT    = 9050
TOR_CONTROL_PORT  = 9051
GECKODRIVER_PATH  = "/usr/local/bin/geckodriver"
FIREFOX_BINARY    = "/usr/bin/firefox-esr"
PAGE_LOAD_TIMEOUT = 15     # seconds before giving up on a page load
CAPTURE_DURATION  = 10     # seconds post-load to keep sniffing (matches collect.py)
MIN_DELAY         = 2.0    # seconds between traces
MAX_DELAY         = 4.0
DEFAULT_TRACES    = 20     # traces per site; original dataset used 100
SNIFF_IFACE       = "eth0"
SNIFF_FILTER      = "tcp"

HERE       = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.path.join(HERE, "dataset.csv")
LOG_FILE   = os.path.join(HERE, "collection.log")

# Sites with >=65% recall on the original test set — used unless --all is passed
DEMO_SITES = {
    "wikipedia", "theguardian", "ubuntu", "amazon", "duckduckgo",
    "airbnb", "debian", "kernel", "tripadvisor", "upenn",
    "etsy", "homedepot", "wordpress", "bing", "imdb",
}

SITE_URLS = {
    "airbnb":         "https://www.airbnb.com",
    "aliexpress":     "https://www.aliexpress.com",
    "amazon":         "https://www.amazon.com",
    "apache":         "https://www.apache.org",
    "bbc":            "https://www.bbc.com",
    "bing":           "https://www.bing.com",
    "booking":        "https://www.booking.com",
    "cdc":            "https://www.cdc.gov",
    "craigslist":     "https://www.craigslist.org",
    "debian":         "https://www.debian.org",
    "dropbox":        "https://www.dropbox.com",
    "duckduckgo":     "https://duckduckgo.com",
    "eff":            "https://www.eff.org",
    "etsy":           "https://www.etsy.com",
    "expedia":        "https://www.expedia.com",
    "foxnews":        "https://www.foxnews.com",
    "github":         "https://www.github.com",
    "homedepot":      "https://www.homedepot.com",
    "hulu":           "https://www.hulu.com",
    "imdb":           "https://www.imdb.com",
    "instagram":      "https://www.instagram.com",
    "jhu":            "https://www.jhu.edu",
    "kernel":         "https://www.kernel.org",
    "linkedin":       "https://www.linkedin.com",
    "loc":            "https://www.loc.gov",
    "nih":            "https://www.nih.gov",
    "quora":          "https://www.quora.com",
    "spotify":        "https://www.spotify.com",
    "stanford":       "https://www.stanford.edu",
    "theguardian":    "https://www.theguardian.com",
    "tripadvisor":    "https://www.tripadvisor.com",
    "tumblr":         "https://www.tumblr.com",
    "twitch":         "https://www.twitch.tv",
    "ubuntu":         "https://www.ubuntu.com",
    "upenn":          "https://www.upenn.edu",
    "washingtonpost": "https://www.washingtonpost.com",
    "weather":        "https://weather.com",
    "wikipedia":      "https://www.wikipedia.org",
    "wordpress":      "https://www.wordpress.com",
    "youtube":        "https://www.youtube.com",
}


# ── Logging ───────────────────────────────────────────────────────────────────
def log(msg: str):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ── Tor / browser helpers ─────────────────────────────────────────────────────
def renew_tor_circuit():
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=TOR_CONTROL_PORT) as ctl:
            ctl.authenticate()
            ctl.signal(Signal.NEWNYM)
            time.sleep(3)
    except Exception as e:
        log(f"  [~] circuit renewal skipped: {e}")


def setup_browser():
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service

    opts = Options()
    opts.add_argument("-headless")
    opts.page_load_strategy = "eager"
    opts.set_preference("network.proxy.type", 1)
    opts.set_preference("network.proxy.socks", TOR_SOCKS_HOST)
    opts.set_preference("network.proxy.socks_port", TOR_SOCKS_PORT)
    opts.set_preference("network.proxy.socks_remote_dns", True)
    opts.set_preference("network.proxy.no_proxies_on", "localhost, 127.0.0.1")
    opts.set_preference("browser.cache.disk.enable", False)
    opts.set_preference("browser.cache.memory.enable", False)
    opts.set_preference("network.http.use-cache", False)
    opts.binary_location = FIREFOX_BINARY
    driver = webdriver.Firefox(service=Service(GECKODRIVER_PATH), options=opts)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return driver


# ── Capture ───────────────────────────────────────────────────────────────────
def collect_trace(url: str):
    """
    Load url through Tor while sniffing eth0 for CAPTURE_DURATION seconds
    after the page load completes. Returns a signed numpy trace or None.

    Uses count-based capture (same as the dashboard's RealDataSource) because
    WSL2's L2 socket implementation does not reliably support count=None/
    indefinite capture — it can crash with a NoneType timestamp comparison error.
    A count of 3000 with a generous timeout captures a full page load comfortably.
    """
    from scapy.all import AsyncSniffer

    sniffer = AsyncSniffer(
        iface=SNIFF_IFACE,
        filter=SNIFF_FILTER,
        count=3000,
        timeout=PAGE_LOAD_TIMEOUT + CAPTURE_DURATION + 5,
    )
    driver = None
    try:
        sniffer.start()
        driver = setup_browser()
        try:
            driver.get(url)
        except Exception:
            pass  # page load timeout is non-fatal — capture whatever arrived
        time.sleep(CAPTURE_DURATION)
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass  # sniffer may have already stopped (WSL2 socket error or count reached)
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    packets = list(sniffer.results or [])
    if not packets:
        return None
    trace = packets_to_trace(packets)
    return trace if len(trace) > 0 else None


# ── Resumability ──────────────────────────────────────────────────────────────
def load_existing_counts(output_csv: str) -> dict:
    """Return {label: count} for traces already written to output_csv."""
    counts: dict = {}
    if not os.path.exists(output_csv):
        return counts
    with open(output_csv, newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for row in reader:
            if row:
                counts[row[0]] = counts.get(row[0], 0) + 1
    return counts


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global SNIFF_IFACE  # allow --iface to override the module-level default

    parser = argparse.ArgumentParser(
        description="WF-Guard fresh training-data collector.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--traces", type=int, default=DEFAULT_TRACES, metavar="N",
        help=f"Traces to collect per site (default: {DEFAULT_TRACES}).",
    )
    parser.add_argument(
        "--all", action="store_true", dest="collect_all",
        help="Collect all 40 original training sites (default: 15 high-recall demo sites).",
    )
    parser.add_argument(
        "--sites", metavar="SITE,...", default=None,
        help="Comma-separated site names to collect (overrides --all/demo set).",
    )
    parser.add_argument(
        "--output", metavar="PATH", default=OUTPUT_CSV,
        help=f"Output CSV path (default: {OUTPUT_CSV}).",
    )
    parser.add_argument(
        "--iface", metavar="IFACE", default=SNIFF_IFACE,
        help=f"Network interface to sniff on (default: {SNIFF_IFACE}).",
    )
    args = parser.parse_args()

    SNIFF_IFACE = args.iface
    output_csv  = args.output

    if args.sites:
        explicit     = {s.strip() for s in args.sites.split(",")}
        target_sites = {k: v for k, v in SITE_URLS.items() if k in explicit}
    elif args.collect_all:
        target_sites = SITE_URLS
    else:
        target_sites = {k: v for k, v in SITE_URLS.items() if k in DEMO_SITES}

    sites = sorted(target_sites.items())

    log(f"{'='*55}")
    log(f"WF-Guard fresh collection — {len(sites)} sites × {args.traces} traces")
    log(f"Output: {output_csv}")
    log(f"{'='*55}")

    write_header = not os.path.exists(output_csv)
    existing     = load_existing_counts(output_csv)

    with open(output_csv, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["label"] + [f"pkt_{i}" for i in range(1500)])

        for name, url in sites:
            have = existing.get(name, 0)
            need = args.traces - have
            if need <= 0:
                log(f"[{name}] {have}/{args.traces} already collected, skipping")
                continue

            log(f"[{name}] need {need} more traces (have {have}/{args.traces})")

            collected    = 0
            attempts     = 0
            max_attempts = need * 2

            while collected < need and attempts < max_attempts:
                attempts += 1
                renew_tor_circuit()
                trace = collect_trace(url)

                if trace is not None:
                    writer.writerow([name] + trace.tolist())
                    f.flush()
                    collected += 1
                    log(f"  [{collected}/{need}] {name}: {len(trace)} packets")
                else:
                    log(f"  [attempt {attempts}] {name}: capture failed, retrying")

                time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

            if collected < need:
                log(f"  [!] {name}: only collected {collected}/{need} after {attempts} attempts")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Collection stopped.")
        sys.exit(0)
