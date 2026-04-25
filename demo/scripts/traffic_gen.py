"""
traffic_gen.py
==============
Demo traffic generator for WF-Guard.

Drives headless Firefox through Tor to generate real website traffic for the
dashboard's real-mode classifier. Run in a separate terminal while the
dashboard is open.

Usage:
    python traffic_gen.py                        # all 40 sites, browser mode
    python traffic_gen.py --demo                 # 15 high-recall sites only
    python traffic_gen.py --simple               # requests.get() only (testing)
    python traffic_gen.py --demo --once          # one full rotation then exit
    python traffic_gen.py --sites wikipedia,imdb # explicit site list

Options:
    --demo          Restrict rotation to the 15 sites with >=65%% test recall.
                    Recommended for live demos.
    --simple        Use requests.get() instead of headless Firefox. Fetches
                    HTML only — model will misclassify. Testing use only.
    --once          Complete one full rotation through the site list then exit.
                    Useful for scripted evaluation runs.
    --sites S       Comma-separated list of site names to visit (overrides
                    --demo). Names must match label_map.json entries.

Requirements (browser mode):
    sudo apt install firefox-esr        (via ppa:mozillateam/ppa)
    geckodriver in /usr/local/bin/
    pip install selenium stem
"""

import argparse
import json
import os
import random
import sys
import time

# --- Configuration ---
TOR_SOCKS_HOST   = "127.0.0.1"
TOR_SOCKS_PORT   = 9050
TOR_CONTROL_PORT = 9051
GECKODRIVER_PATH = "/usr/local/bin/geckodriver"
FIREFOX_BINARY   = "/usr/bin/firefox-esr"   # update if `which firefox-esr` returns a different path
PAGE_LOAD_TIMEOUT = 15   # seconds before giving up on a page load
SETTLE_TIME       = 8    # seconds to let sub-resources finish after eager load
MIN_DELAY         = 2.0  # seconds between sites
MAX_DELAY         = 5.0

# Shared file dashboard reads to get ground truth for accuracy tracking
GROUND_TRUTH_FILE = "/tmp/wfguard_gt.txt"

# Sites with >=65% recall on the test set -- use --demo to restrict rotation to these
DEMO_SITES = {
    "wikipedia", "theguardian", "ubuntu", "amazon", "duckduckgo",
    "airbnb", "debian", "kernel", "tripadvisor", "upenn",
    "etsy", "homedepot", "wordpress", "bing", "imdb",
}

# Label name -> URL mapping for all 40 training classes
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


def load_sites(demo_only: bool = False):
    """Load site list from label_map.json in label-index order.
    Pass demo_only=True to restrict to high-recall sites for cleaner demos."""
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "label_map.json")) as f:
        lmap = json.load(f)
    sites = []
    for i in range(len(lmap)):
        name = lmap[str(i)]
        if demo_only and name not in DEMO_SITES:
            continue
        url = SITE_URLS.get(name)
        if url:
            sites.append((name, url))
        else:
            print(f"[!] No URL mapping for label '{name}' -- skipping")
    return sites


def write_ground_truth(name: str):
    """Write current site label to shared file so dashboard can track accuracy."""
    try:
        with open(GROUND_TRUTH_FILE, "w") as f:
            f.write(name)
    except OSError:
        pass


def renew_tor_circuit():
    """Ask Tor to build a new circuit between sites.
    Requires ControlPort 9051 in /etc/tor/torrc -- non-fatal if missing."""
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            time.sleep(3)
    except Exception as e:
        print(f"[~] Circuit renewal skipped: {e}")


def setup_browser():
    """Configure headless Firefox to route through Tor.
    Mirrors collect.py exactly -- same proxy settings, same cache disable."""
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service

    options = Options()
    options.add_argument("-headless")
    options.page_load_strategy = "eager"  # DOM ready + deferred scripts, not all resources

    # Route all traffic through local Tor SOCKS5
    options.set_preference("network.proxy.type", 1)
    options.set_preference("network.proxy.socks", TOR_SOCKS_HOST)
    options.set_preference("network.proxy.socks_port", TOR_SOCKS_PORT)
    options.set_preference("network.proxy.socks_remote_dns", True)

    # Prevent Tor from intercepting geckodriver's internal WebDriver connection
    options.set_preference("network.proxy.no_proxies_on", "localhost, 127.0.0.1")

    # Disable cache -- matches training capture conditions
    options.set_preference("browser.cache.disk.enable", False)
    options.set_preference("browser.cache.memory.enable", False)
    options.set_preference("network.http.use-cache", False)

    options.binary_location = FIREFOX_BINARY
    service = Service(GECKODRIVER_PATH)
    driver  = webdriver.Firefox(service=service, options=options)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return driver


def run_browser(sites, demo_only: bool = False, once: bool = False):
    """Continuous browser-based traffic generation.
    Each iteration: renew circuit -> launch Firefox -> load page ->
    settle (let sub-resources finish) -> quit -> sleep -> next site.
    This matches the traffic shape the model was trained on."""
    mode = "demo" if demo_only else "full"
    print(f"[*] WF-Guard traffic generator -- browser mode ({mode})")
    print(f"[*] {len(sites)} sites in rotation{'  [one pass]' if once else ''}")
    print(f"[*] Routing through Tor at {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    print("[*] Press Ctrl+C to stop.\n")

    rotation = list(sites)
    random.shuffle(rotation)
    idx = 0

    while True:
        name, url = rotation[idx % len(rotation)]
        idx += 1

        renew_tor_circuit()

        driver = None
        try:
            driver = setup_browser()
            write_ground_truth(name)
            t0 = time.time()
            driver.get(url)
            time.sleep(SETTLE_TIME)  # wait for parallel sub-resource loads
            elapsed = time.time() - t0
            print(f"[+] {name:<20} {url}  ({elapsed:.1f}s)")
        except Exception as e:
            print(f"[!] {name}: {e}")
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

        # Reshuffle after each full pass; exit if --once was set
        if idx % len(rotation) == 0:
            if once:
                print("[*] One full rotation complete. Exiting.")
                return
            random.shuffle(rotation)


def run_simple(sites):
    """Bare requests.get() fallback. For connection testing only.
    The model will not classify correctly in real mode with this traffic."""
    import requests

    proxy = {
        "http":  f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
        "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
    }

    print("[*] WF-Guard traffic generator -- simple mode (HTML only, not for demos)")
    print(f"[*] {len(sites)} sites in rotation")
    print(f"[*] Routing through Tor at {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
    print("[*] Press Ctrl+C to stop.\n")

    session = requests.Session()
    session.proxies.update(proxy)

    while True:
        name, url = random.choice(sites)
        try:
            r  = session.get(url, timeout=20)
            kb = len(r.content) / 1024
            print(f"[+] {r.status_code}  {name:<20} {url}  {kb:.1f} KB")
        except Exception as e:
            print(f"[!] {name}: {e}")
        time.sleep(random.uniform(3.0, 7.0))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WF-Guard traffic generator — drives headless Firefox through Tor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Restrict rotation to the 15 high-recall demo sites (>=65%% test recall).",
    )
    parser.add_argument(
        "--simple", action="store_true",
        help="Use requests.get() instead of headless Firefox. Testing only — model will misclassify.",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Complete one full rotation through the site list then exit.",
    )
    parser.add_argument(
        "--sites", metavar="SITE,...", default=None,
        help="Comma-separated site names to visit (overrides --demo). Must match label_map.json.",
    )
    args = parser.parse_args()

    if args.sites:
        explicit = {s.strip() for s in args.sites.split(",")}
        sites = load_sites(demo_only=False)
        sites = [(n, u) for n, u in sites if n in explicit]
        if not sites:
            print(f"[!] No matching sites found for: {args.sites}")
            sys.exit(1)
    else:
        sites = load_sites(demo_only=args.demo)
        if not sites:
            print("[!] No sites loaded. Check label_map.json.")
            sys.exit(1)

    try:
        if args.simple:
            run_simple(sites)
        else:
            run_browser(sites, demo_only=args.demo, once=args.once)
    except KeyboardInterrupt:
        print("\n[*] Traffic generator stopped.")
        sys.exit(0)
