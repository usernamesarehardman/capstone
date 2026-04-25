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

## Defense Control

Defense state is controlled exclusively by the **dashboard sidebar toggle**
("Enable WF-Guard"). There is no separate kill-switch process to run.

The toggle sets/clears `_defense_enabled` — a `threading.Event` defined in
`defense_proxy.py` and imported by `dashboard.py`. Both the dashboard and
`defense_proxy.py` share this object, so the toggle is the single source
of truth for all defense behavior.

| State | Behavior |
| --- | --- |
| **Defense ON** | Randomized headers, jittered request timing, cover traffic active |
| **Defense OFF** | Fixed User-Agent, no delay, cover traffic paused |

---

## Cover Traffic

When defense is ON and the dashboard is running, a background thread sends
randomized HEAD requests to public sites through Tor to inject dummy traffic
and obscure real browsing patterns.

Cover traffic is started when the dashboard **▶ Start** button is pressed
and stopped when **⏹ Stop** is pressed, regardless of the defense toggle.
The toggle only controls whether cover requests are actually sent (the
thread idles when defense is OFF).

---

## Running defense_proxy.py Standalone

`defense_proxy.py` can also run independently for testing or evaluation:

```bash
cd demo/scripts
python defense_proxy.py
```

Standalone mode performs a Tor connectivity check, sends one test request,
and attempts identity rotation. Useful for verifying Tor is working before
running the full demo.

Expected output:

```text
=======================================================
  WF-Guard Defense Proxy — Tor Connectivity Check
  Defense state is controlled by the dashboard UI.
=======================================================
[~] No pcap data found — using random delay fallback.
[+] Cover traffic active.
[+] Routing through Tor exit node: <exit IP>
[+] Session User-Agent: Mozilla/5.0 ...
```

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

This must be re-run after any pip upgrade that modifies the Python binary.
