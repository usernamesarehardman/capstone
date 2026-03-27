"""
tor_proxy.py
============
SOCKS5 proxy client designed for use with Tor.
Provides anti-fingerprinting via randomized headers, request timing,
and easy session management.

Requirements:
    pip install requests[socks] PySocks fake-useragent

Tor must be running locally (default: 127.0.0.1:9050)
  - macOS:    brew install tor && tor
  - Linux:    sudo apt install tor && sudo systemctl start tor
  - Windows:  Download Tor Expert Bundle from torproject.org
"""

import time
import random
import logging
import threading
import requests

# Optional: integrate dataset_manager for data-driven timing
# pip install scapy pandas numpy scikit-learn joblib
try:
    from dataset_manager import DatasetManager, get_proxy_delay as _get_proxy_delay
    _dataset_manager_available = True
except ImportError:
    _dataset_manager_available = False

_dm = None   # DatasetManager instance — set by init_dataset_manager()

# Optional: install fake-useragent for broader UA pool
# pip install fake-useragent
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
    Returns True if data was found and loaded, False if falling back to
    random delays (no pcaps available yet).

    Call this once at startup before making requests.
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
    """
    Return a delay (seconds) for use in fetch().
    Uses learned profile when available, otherwise random uniform fallback.
    """
    if _dm is not None:
        return _get_proxy_delay(_dm)
    return random.uniform(*fallback)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TOR_SOCKS5_PROXY = "socks5h://127.0.0.1:9050"   # 'h' = resolve DNS over Tor too
TOR_CONTROL_PORT = 9051                           # Used to request new identity

DEFAULT_PROXIES = {
    "http":  TOR_SOCKS5_PROXY,
    "https": TOR_SOCKS5_PROXY,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("tor_proxy")


# ---------------------------------------------------------------------------
# Kill Switch — toggle defense on/off with 'D' keypress (no Enter needed)
# ---------------------------------------------------------------------------

_defense_enabled = threading.Event()
_defense_enabled.set()   # Defense ON by default

def is_defense_enabled() -> bool:
    return _defense_enabled.is_set()

def _kill_switch_listener():
    """
    Background daemon thread: press 'D' to toggle the defense on/off.
    Uses msvcrt on Windows for single-keypress detection (no Enter needed).
    Falls back to stdin readline on other platforms.
    """
    try:
        import msvcrt
        print("[*] Kill switch active — press 'D' to toggle defense ON/OFF.")
        while True:
            if msvcrt.kbhit():
                key = msvcrt.getch().decode(errors="ignore").upper()
                if key == "D":
                    if _defense_enabled.is_set():
                        _defense_enabled.clear()
                        print("\n[DEFENSE OFF] Anti-fingerprinting disabled.")
                        log.info("Defense DISABLED via kill switch.")
                    else:
                        _defense_enabled.set()
                        print("\n[DEFENSE ON]  Anti-fingerprinting enabled.")
                        log.info("Defense ENABLED via kill switch.")
            time.sleep(0.05)   # Poll at 20 Hz — low CPU, responsive
    except (ImportError, UnicodeDecodeError):
        # Non-Windows fallback: type 'D' + Enter
        print("[*] Kill switch active — type 'D' + Enter to toggle defense ON/OFF.")
        while True:
            try:
                line = input().strip().upper()
                if line == "D":
                    if _defense_enabled.is_set():
                        _defense_enabled.clear()
                        print("[DEFENSE OFF] Anti-fingerprinting disabled.")
                        log.info("Defense DISABLED via kill switch.")
                    else:
                        _defense_enabled.set()
                        print("[DEFENSE ON]  Anti-fingerprinting enabled.")
                        log.info("Defense ENABLED via kill switch.")
            except EOFError:
                break

def start_kill_switch():
    """Spawn the kill switch listener as a background daemon thread."""
    t = threading.Thread(target=_kill_switch_listener, daemon=True, name="kill-switch")
    t.start()
    return t


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
    """
    Build a randomized but realistic browser header set.
    Pass `extra` to merge/override specific headers.
    """
    headers = {
        "User-Agent":      random_user_agent(),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
        "Accept-Encoding": random.choice(_ACCEPT_ENCODING),
        "Connection":      "keep-alive",
        "DNT":             random.choice(["1", "0"]),   # Do-Not-Track noise
        "Upgrade-Insecure-Requests": "1",
    }
    if extra:
        headers.update(extra)
    return headers


# ---------------------------------------------------------------------------
# Session Factory
# ---------------------------------------------------------------------------

def new_session(extra_headers: dict = None) -> requests.Session:
    """
    Create a requests.Session pre-configured for Tor SOCKS5
    with randomized fingerprint headers.
    """
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
    Requires the Tor control port to be open.

    Setup: add these lines to /etc/tor/torrc (or tor config):
        ControlPort 9051
        CookieAuthentication 1
        # OR: HashedControlPassword <hash of your password>

    Returns True on success.
    """
    try:
        import socket
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=5) as s:
            auth_cmd = f'AUTHENTICATE "{password}"\r\n'.encode()
            s.sendall(auth_cmd)
            resp = s.recv(1024).decode()
            if not resp.startswith("250"):
                log.warning("Tor auth failed: %s", resp.strip())
                return False
            s.sendall(b"SIGNAL NEWNYM\r\n")
            resp = s.recv(1024).decode()
            if resp.startswith("250"):
                log.info("New Tor identity requested successfully.")
                # Tor recommends waiting before using new circuit
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
    Make an HTTP request through Tor with:
      - Randomized headers per call
      - Jittered request timing (pass delay=(min, max) seconds)
      - Automatic retry on failure

    Args:
        url:     Target URL
        method:  HTTP method (GET, POST, etc.)
        session: Reuse an existing session, or None to create a fresh one
        delay:   (min, max) seconds to sleep before request — mimics human pacing
        retries: Number of attempts before giving up
        **kwargs: Passed directly to requests (json=, data=, params=, timeout=, etc.)

    Returns:
        requests.Response on success, None after all retries exhausted.
    """
    sess = session or new_session()
    kwargs.setdefault("timeout", 30)

    # Refresh headers each call — only randomize when defense is active
    if is_defense_enabled():
        sess.headers.update(build_headers())
    else:
        sess.headers.update({"User-Agent": _UA_POOL[0]})  # Fixed UA when defense is off

    for attempt in range(1, retries + 1):
        # Timing jitter only when defense is active
        # Uses learned traffic profile if pcap data is loaded, else random fallback
        sleep_for = _sample_delay(delay) if is_defense_enabled() else 0
        log.debug("Sleeping %.2fs before request (attempt %d/%d) [defense=%s, profile=%s]",
                  sleep_for, attempt, retries,
                  "ON" if is_defense_enabled() else "OFF",
                  "learned" if _dm is not None else "fallback")
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
            break   # Non-retryable

    log.error("All %d attempts failed for %s", retries, url)
    return None


# ---------------------------------------------------------------------------
# Utility: Verify Tor is working
# ---------------------------------------------------------------------------

def check_tor_ip() -> str | None:
    """
    Fetch your current exit IP through Tor.
    Useful for confirming the proxy is active.
    """
    resp = fetch("https://api.ipify.org?format=json", delay=(0, 0), retries=1)
    if resp and resp.ok:
        ip = resp.json().get("ip")
        log.info("Current Tor exit IP: %s", ip)
        return ip
    log.error("Could not determine Tor exit IP.")
    return None


# ---------------------------------------------------------------------------
# Example Usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("  Tor SOCKS5 Proxy — Capstone Project")
    print("=" * 55)

    # Start kill switch in background
    start_kill_switch()

    # Load traffic profile from pcap data (falls back to random delay if none found)
    if init_dataset_manager("data"):
        print("[+] Traffic profile loaded — using learned delays.")
    else:
        print("[~] No pcap data found — using random delay fallback.")

    # 1. Confirm we're routing through Tor
    exit_ip = check_tor_ip()
    if not exit_ip:
        print("\n[!] Could not connect through Tor.")
        print("    Make sure Tor is running: tor  (or systemctl start tor)")
        raise SystemExit(1)

    print(f"\n[+] Routing through Tor exit node: {exit_ip}")

    # 2. Create a persistent session (same circuit)
    session = new_session()
    print(f"[+] Session User-Agent: {session.headers['User-Agent'][:60]}...")

    # 3. Make a sample request
    resp = fetch("https://httpbin.org/headers", session=session)
    if resp:
        print("\n[+] Headers seen by server:")
        for k, v in resp.json().get("headers", {}).items():
            print(f"    {k}: {v}")

    # 4. Rotate to a new Tor circuit
    print("\n[~] Requesting new Tor identity...")
    rotated = request_new_identity(password="")   # Set your control password here
    if rotated:
        new_ip = check_tor_ip()
        print(f"[+] New exit IP: {new_ip}")
    else:
        print("[!] Identity rotation failed — check Tor control port config.")