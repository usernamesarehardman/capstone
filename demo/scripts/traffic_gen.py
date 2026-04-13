"""
traffic_gen.py
==============
Demo traffic generator for WF-Guard.

Loops through a list of sites via Tor SOCKS5, generating realistic
browsing traffic on the loopback interface for the dashboard sniffer.

Run in a separate terminal while the dashboard is open:
    python traffic_gen.py

Requires Tor running on 127.0.0.1:9050.
No flags needed — just start it and leave it running.
"""

import time
import random
import sys
import requests

PROXY = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

# Sites that match the model's training set
SITES = [
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.reddit.com",
    "https://www.bbc.com",
    "https://duckduckgo.com",
    "https://www.python.org",
    "https://www.amazon.com",
    "https://www.theguardian.com",
    "https://www.youtube.com",
    "https://www.instagram.com",
]

# Seconds between requests — mimics real browsing pacing
MIN_DELAY = 3.0
MAX_DELAY = 7.0

def run():
    session = requests.Session()
    session.proxies.update(PROXY)

    print("[*] WF-Guard traffic generator started.")
    print(f"[*] Routing through Tor at 127.0.0.1:9050")
    print(f"[*] {len(SITES)} sites in rotation — delay {MIN_DELAY}–{MAX_DELAY}s")
    print("[*] Press Ctrl+C to stop.\n")

    while True:
        url = random.choice(SITES)
        try:
            r = session.get(url, timeout=20)
            kb = len(r.content) / 1024
            print(f"[+] {r.status_code}  {url:<40}  {kb:6.1f} KB")
        except requests.exceptions.ConnectionError:
            print(f"[!] Connection failed — is Tor running?  ({url})")
            time.sleep(5)
            continue
        except Exception as e:
            print(f"[!] {url} — {e}")

        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\n[*] Traffic generator stopped.")
        sys.exit(0)
