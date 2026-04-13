# defense_proxy.py — Setup and Demo Guide (WSL/Linux)

---

## Prerequisites

Tor

```bash
sudo apt install tor
sudo systemctl start tor
sudo systemctl status tor   # confirm it's running
```

**Python dependencies** (from demo/ with venv active):

```bash
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
sudo systemctl restart tor
```

---

## Running the Proxy

```bash
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

If you see `Could not connect through Tor` — run `sudo systemctl start tor` and retry.

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
public sites through Tor. This injects dummy traffic to obscure the real
request pattern. Cover traffic pauses automatically when defense is toggled OFF.

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

**`Could not connect through Tor`**

```bash
sudo systemctl start tor
sudo systemctl status tor
```

**`dataset_manager` import warning**
Expected if no pcap files are in `data/`. The proxy falls back to random
delays — all features work normally.

**Identity rotation failing**
Confirm `ControlPort 9051` is in `/etc/tor/torrc` and Tor was restarted.

Scapy permission errors

```bash
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)
```
