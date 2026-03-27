# REPRODUCE.md — WF-Guard Defense Proxy

Step-by-step instructions to reproduce the live demo for the Week 15 capstone presentation.

---

## 1. Prerequisites

**Tor**

- macOS: `brew install tor && tor`
- Linux: `sudo apt install tor && sudo systemctl start tor`
- Windows: Download the Tor Expert Bundle from [torproject.org](https://www.torproject.org/download/tor/) and run `tor.exe`

Confirm Tor is running before launching the proxy. The default SOCKS5 port is `9050`.

**Python**

Python 3.10 or higher is required (uses `match`-free type union syntax `X | Y`).

**Dependencies**

```bash
pip install requests[socks] PySocks fake-useragent
```

Optional — only needed if you have pcap files to load:

```bash
pip install scapy pandas numpy scikit-learn joblib
```

---

## 2. Setup

**Clone the repository**

```bash
git clone <repo-url>
cd capstone/Defense\ \&\ Integration\ Engineer
```

**Add pcap files (optional)**

Drop any `.pcap` or `.pcapng` traffic captures into the `data/` folder. If none are present the proxy falls back to randomized delays automatically — the demo works either way.

**Enable Tor identity rotation (optional)**

Add the following to your `torrc` file to enable circuit rotation via the kill switch:

- Linux/macOS: `/etc/tor/torrc`
- Windows: `Tor Browser\Browser\TorBrowser\Data\Tor\torrc`

```
ControlPort 9051
CookieAuthentication 1
```

Then restart Tor.

---

## 3. Running the Proxy

```bash
python defense_proxy.py
```

Expected startup output:

```
=======================================================
  Tor SOCKS5 Proxy — Capstone Project
=======================================================
[*] Kill switch active — press 'D' to toggle defense ON/OFF.
[~] No pcap data found — using random delay fallback.
    (or)
[+] Traffic profile loaded — using learned delays.
[+] Cover traffic active — dummy requests running in background.
[+] Routing through Tor exit node: <exit IP>
[+] Session User-Agent: Mozilla/5.0 ...
```

If you see `Could not connect through Tor` — Tor is not running. Start it and retry.

---

## 4. Using the Kill Switch

Press `D` at any time while the proxy is running to toggle the defense on or off.

| State | Behavior |
|---|---|
| Defense ON (default) | Randomized headers, jittered timing, cover traffic active |
| Defense OFF | Fixed User-Agent, no delay, cover traffic paused |

Watch the terminal output to confirm the toggle:

```
[DEFENSE OFF] Anti-fingerprinting disabled.
[DEFENSE ON]  Anti-fingerprinting enabled.
```

---

## 5. Verifying Tor Routing

The proxy confirms your exit IP at startup. To verify manually, make a request through the proxy and check the reported IP:

```python
from defense_proxy import check_tor_ip
check_tor_ip()
```

The returned IP should differ from your real IP. If they match, Tor is not routing correctly.

---

## 6. ON vs OFF Comparison (Phase 5 Evaluation)

To demonstrate the difference between defense states:

1. Launch the proxy and note the startup exit IP.
2. Let it run with defense **ON** for 30–60 seconds — observe cover traffic in the logs.
3. Press `D` to switch defense **OFF** — cover traffic and timing jitter stop immediately.
4. Press `D` again to re-enable — cover traffic resumes.

For formal bandwidth overhead measurement:

```
Overhead = Total Bytes With Defense ON / Total Bytes Without Defense ON
```

Capture traffic with Wireshark on the loopback interface (`127.0.0.1`) during both states and compare total byte counts over the same time window.

---

## 7. Troubleshooting

**Tor not connecting**
- Confirm the Tor process is running before starting the proxy.
- Default SOCKS5 port is `9050` — check `torrc` if it has been changed.

**Missing dependencies**
```bash
pip install requests[socks] PySocks fake-useragent
```

**`dataset_manager` import warning at startup**
- This is expected if `scapy`/`sklearn` are not installed.
- The proxy falls back to random delays — all other features work normally.

**Identity rotation not working**
- Confirm `ControlPort 9051` is in `torrc` and Tor has been restarted.
- If you set a `HashedControlPassword`, pass it to `request_new_identity(password="yourpassword")`.

**Kill switch not responding on Linux/macOS**
- The terminal must have focus for keypress detection.
- If single-key detection fails, the fallback activates: type `D` + Enter.
