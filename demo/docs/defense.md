# defense_proxy.py — Setup and Demo Guide (WSL/Linux)

---

## Prerequisites

**Python** — fresh WSL Ubuntu does not have a `python` binary:

```bash
sudo apt install python3 python3-venv python-is-python3
```

**Tor** — install first, then start with whichever method works on your WSL:

```bash
sudo apt install tor

# Option 1 — SysV init (most WSL installs)
sudo service tor start

# Option 2 — run directly (always works, bypasses service management entirely)
tor &
```

Verify Tor is routing before proceeding:

```bash
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
# Should return a Tor exit IP, not your real IP
```

**Python dependencies** (from `demo/` with venv active):

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Enable Tor Identity Rotation (optional but recommended for demo)

Add to `/etc/tor/torrc`:

```text
ControlPort 9051
CookieAuthentication 1
```

```bash
sudo service tor restart
```

---

## Running the Proxy

```bash
cd demo/scripts
python defense_proxy.py
```

Expected startup output:

```text
=======================================================
  WF-Guard Defense Proxy
=======================================================
[*] Kill switch active — type 'D' + Enter to toggle defense ON/OFF.
[~] No pcap data found — using random delay fallback.
[+] Cover traffic active.
[+] Routing through Tor exit node: <exit IP>
[+] Session User-Agent: Mozilla/5.0 ...
```

If you see `Could not connect through Tor`:

```bash
sudo service tor start
sudo service tor status
```

---

## Kill Switch

Type `D` + Enter in the proxy terminal to toggle defense on/off:

| State | Behavior |
| --- | --- |
| Defense ON (default) | Randomized headers, jittered timing, cover traffic active |
| Defense OFF | Fixed User-Agent, no delay, cover traffic paused |

```text
[DEFENSE OFF] Anti-fingerprinting disabled.
[DEFENSE ON]  Anti-fingerprinting enabled.
```

---

## Cover Traffic

When defense is ON, a background thread sends randomized HEAD requests to 8
public sites through Tor to inject dummy traffic and obscure real request
patterns. Cover traffic pauses automatically when defense is toggled OFF.

---

## Verifying Tor Routing

The proxy prints your exit IP at startup. To verify manually:

```python
from defense_proxy import check_tor_ip
check_tor_ip()
```

The returned IP must differ from your real IP. If they match, Tor is not routing.

---

## Phase 5 Evaluation (Bandwidth / Latency)

```bash
cd demo/scripts
python evaluate.py
```

Runs 5 URLs × 3 times with defense ON, then OFF. Outputs:

- Total bytes ON vs OFF (bandwidth overhead)
- Average latency ON vs OFF
- Success rate
- Saves `evaluation_results.txt`

Bandwidth overhead formula (from rubric):

```text
Overhead = Total Bytes ON / Total Bytes OFF
```

---

## Troubleshooting

**`Failed to start tor.service: Unit tor.service not found`**

Two possible causes:

1. Tor is not installed — install it first:
   ```bash
   sudo apt install tor
   sudo service tor start
   ```

2. Tor is installed but service management is broken on this WSL instance —
   bypass it entirely by running Tor directly:
   ```bash
   tor &
   ```
   Tor will start in the background and listen on `127.0.0.1:9050`.
   Verify with: `curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org`

**`python: command not found`**

```bash
sudo apt install python-is-python3
```

Or activate the venv — `python` is always available inside `.venv/bin/`.

**`dataset_manager` import warning**

Expected if no pcap files are in `scripts/data/`. The proxy falls back to
random delays — all features work normally.

**Identity rotation failing**

Confirm `ControlPort 9051` is in `/etc/tor/torrc` and Tor was restarted
with `sudo service tor restart`.

**Scapy permission errors**

```bash
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)
```
