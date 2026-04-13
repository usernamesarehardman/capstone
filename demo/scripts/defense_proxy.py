"""
defense_proxy.py
================
SOCKS5 proxy client designed for use with Tor.
Provides anti-fingerprinting via randomized headers, request timing,
cover traffic injection, and live defense toggling via kill switch.

Requirements:
    pip install -r requirements.txt

Tor must be running:
    sudo systemctl start tor      # Linux / WSL

Kill switch: press D + Enter to toggle defense ON/OFF at runtime.
"""

import time
import random
import logging
import threading
import requests

# Optional: integrate dataset_manager for data-driven timing
try:
    from dataset_manager import DatasetManager, get_proxy_delay as _get_proxy_delay
    _dataset_manager_available = True
except ImportError:
    _dataset_manager_available = False

_dm = None   # DatasetManager instance — set by init_dataset_manager()

# Optional: install fake-useragent for a broader UA pool
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

try:
    from fake_useragent import UserAgent
    _ua = UserAgent()
    def random_user_agent():
        return _ua.random
except ImportError:
    def random_user_agent():
        return random.choice(_UA_POOL)


# ---------------------------------------------------------------------------
# Dataset Manager Integration
# ---------------------------------------------------------------------------

def init_dataset_manager(directory: str = "data") -> bool:
    """
    Load pcap files from `directory` and train a traffic profile.
    Returns True if data was found and loaded, False to fall back to random delays.
    Call once at startup before making requests.
    """
    global _dm
    if not _dataset_manager_available:
        log.warning("dataset_manager not available — using random delay fallback.")
        return False
    try:
        dm = DatasetManager().load_directory(directory)
        if not dm.flows:
            log.warning("No pcap files found in '%s' — using random delay fallback.", directory)
            return False
        dm.train_models()
        _dm = dm
        log.info("DatasetManager ready — fetch() will use learned traffic profile.")
        return True
    except Exception as e:
        log.warning("DatasetManager init failed (%s) — using random delay fallback.", e)
        return False


def _sample_delay(fallback: tuple) -> float:
    """Return a delay for fetch() — learned profile when available, else random."""
    if _dm is not None:
        return _get_proxy_delay(_dm)
    return random.uniform(*fallback)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TOR_SOCKS5_PROXY = "socks5h://127.0.0.1:9050"   # Tor daemon on Linux/WSL
TOR_CONTROL_PORT = 9051

DEFAULT_PROXIES = {
    "http":  TOR_SOCKS5_PROXY,
    "https": TOR_SOCKS5_PROXY,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("defense_proxy")


# ---------------------------------------------------------------------------
# Defense state — controlled exclusively by the dashboard UI toggle
# ---------------------------------------------------------------------------

_defense_enabled = threading.Event()
_defense_enabled.set()   # Defense ON by default

def is_defense_enabled() -> bool:
    return _defense_enabled.is_set()


# ---------------------------------------------------------------------------
# Header Randomization
# ---------------------------------------------------------------------------

_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en-US,en;q=0.9,es;q=0.7",
    "en-CA,en;q=0.9,fr;q=0.5",
    "en-AU,en;q=0.8",
]

_ACCEPT_ENCODING = [
    "gzip, deflate, br",
    "gzip, deflate",
    "br, gzip",
]

def build_headers(extra: dict = None) -> dict:
    """Build a randomized but realistic browser header set."""
    headers = {
        "User-Agent":      random_user_agent(),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
        "Accept-Encoding": random.choice(_ACCEPT_ENCODING),
        "Connection":      "keep-alive",
        "DNT":             random.choice(["1", "0"]),
        "Upgrade-Insecure-Requests": "1",
    }
    if extra:
        headers.update(extra)
    return headers


# ---------------------------------------------------------------------------
# Session Factory
# ---------------------------------------------------------------------------

def new_session(extra_headers: dict = None) -> requests.Session:
    """Create a requests.Session pre-configured for Tor SOCKS5."""
    session = requests.Session()
    session.proxies.update(DEFAULT_PROXIES)
    session.headers.update(build_headers(extra_headers))
    return session


# ---------------------------------------------------------------------------
# Identity / Circuit Control
# ---------------------------------------------------------------------------

def request_new_identity(password: str = "") -> bool:
    """
    Signal Tor to build a new circuit (new exit IP).
    Requires ControlPort 9051 in /etc/tor/torrc.
    """
    try:
        import socket
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=5) as s:
            s.sendall(f'AUTHENTICATE "{password}"\r\n'.encode())
            resp = s.recv(1024).decode()
            if not resp.startswith("250"):
                log.warning("Tor auth failed: %s", resp.strip())
                return False
            s.sendall(b"SIGNAL NEWNYM\r\n")
            resp = s.recv(1024).decode()
            if resp.startswith("250"):
                log.info("New Tor identity requested successfully.")
                time.sleep(random.uniform(1.0, 3.0))
                return True
            log.warning("NEWNYM failed: %s", resp.strip())
            return False
    except Exception as e:
        log.error("Could not reach Tor control port: %s", e)
        return False


# ---------------------------------------------------------------------------
# High-level Request Helper
# ---------------------------------------------------------------------------

def fetch(
    url: str,
    method: str = "GET",
    session: requests.Session = None,
    delay: tuple = (0.5, 2.5),
    retries: int = 3,
    **kwargs,
) -> requests.Response | None:
    """
    Make an HTTP request through Tor with randomized headers,
    jittered timing, and automatic retry.
    Defense state (on/off) controls whether randomization is applied.
    """
    sess = session or new_session()
    kwargs.setdefault("timeout", 30)

    if is_defense_enabled():
        sess.headers.update(build_headers())
    else:
        sess.headers.update({"User-Agent": _UA_POOL[0]})

    for attempt in range(1, retries + 1):
        sleep_for = _sample_delay(delay) if is_defense_enabled() else 0
        log.debug(
            "Sleeping %.2fs before request (attempt %d/%d) [defense=%s, profile=%s]",
            sleep_for, attempt, retries,
            "ON" if is_defense_enabled() else "OFF",
            "learned" if _dm is not None else "fallback",
        )
        time.sleep(sleep_for)

        try:
            resp = sess.request(method, url, **kwargs)
            log.info("%s %s → %d", method.upper(), url, resp.status_code)
            return resp
        except requests.exceptions.ConnectionError as e:
            log.warning("Connection error on attempt %d: %s", attempt, e)
        except requests.exceptions.Timeout:
            log.warning("Timeout on attempt %d for %s", attempt, url)
        except requests.exceptions.RequestException as e:
            log.error("Request failed: %s", e)
            break

    log.error("All %d attempts failed for %s", retries, url)
    return None


# ---------------------------------------------------------------------------
# Cover Traffic
# ---------------------------------------------------------------------------

_COVER_URLS = [
    "https://www.wikipedia.org",
    "https://www.reddit.com",
    "https://www.github.com",
    "https://www.bbc.com",
    "https://www.reuters.com",
    "https://www.archive.org",
    "https://www.python.org",
    "https://www.stackoverflow.com",
]

_cover_stop = threading.Event()

def _cover_traffic_worker(interval: tuple):
    """Background thread: HEAD requests through Tor to inject cover traffic."""
    session = new_session()
    log.info("Cover traffic worker started.")
    while not _cover_stop.is_set():
        if not is_defense_enabled():
            time.sleep(0.5)
            continue
        url = random.choice(_COVER_URLS)
        try:
            session.request("HEAD", url, timeout=10, proxies=DEFAULT_PROXIES)
            log.debug("Cover traffic → HEAD %s", url)
        except Exception:
            pass
        sleep_for = _sample_delay(interval)
        _cover_stop.wait(timeout=sleep_for)
    log.info("Cover traffic worker stopped.")

def start_cover_traffic(interval: tuple = (1.0, 5.0)) -> threading.Thread:
    """Start sending cover traffic in a background daemon thread."""
    _cover_stop.clear()
    t = threading.Thread(
        target=_cover_traffic_worker,
        args=(interval,),
        daemon=True,
        name="cover-traffic",
    )
    t.start()
    log.info("Cover traffic started (interval fallback: %.1f–%.1fs).", *interval)
    return t

def stop_cover_traffic():
    """Signal the cover traffic thread to stop cleanly."""
    _cover_stop.set()
    log.info("Cover traffic stop requested.")


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def check_tor_ip() -> str | None:
    """Fetch current exit IP through Tor to confirm routing."""
    resp = fetch("https://api.ipify.org?format=json", delay=(0, 0), retries=1)
    if resp and resp.ok:
        ip = resp.json().get("ip")
        log.info("Current Tor exit IP: %s", ip)
        return ip
    log.error("Could not determine Tor exit IP.")
    return None


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("  WF-Guard Defense Proxy — Tor Connectivity Check")
    print("  Defense state is controlled by the dashboard UI.")
    print("=" * 55)

    if init_dataset_manager("data"):
        print("[+] Traffic profile loaded — using learned delays.")
    else:
        print("[~] No pcap data found — using random delay fallback.")

    start_cover_traffic()
    print("[+] Cover traffic active.")

    exit_ip = check_tor_ip()
    if not exit_ip:
        print("\n[!] Could not connect through Tor.")
        print("    Start Tor:  sudo service tor start   (or: tor &)")
        raise SystemExit(1)

    print(f"\n[+] Routing through Tor exit node: {exit_ip}")

    session = new_session()
    print(f"[+] Session User-Agent: {session.headers['User-Agent'][:60]}...")

    resp = fetch("https://httpbin.org/headers", session=session)
    if resp:
        print("\n[+] Headers seen by server:")
        for k, v in resp.json().get("headers", {}).items():
            print(f"    {k}: {v}")

    print("\n[~] Requesting new Tor identity...")
    if request_new_identity():
        new_ip = check_tor_ip()
        print(f"[+] New exit IP: {new_ip}")
    else:
        print("[!] Identity rotation failed — check /etc/tor/torrc for ControlPort 9051.")
