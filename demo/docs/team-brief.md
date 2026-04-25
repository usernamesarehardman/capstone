# WF-Guard Demo — Team Status Brief

**Date:** 2026-04-23  
**Author:** William Freeman

---

## Current Status

| Component | Status | Notes |
| --- | --- | --- |
| Dashboard UI | Working | Sidebar-controlled; no file edits needed to run |
| Fake mode | **Fully working** | Correct defense contrast — use for presentation |
| Real mode (capture) | Partially working | Captures traffic correctly on eth0 |
| Real mode (classification) | Broken | See root cause below |
| Defense toggle | Working | Sidebar toggle; thread-safe via `_defense_enabled` event |
| evaluate.py | Working | Runs defense ON/OFF bandwidth/latency benchmark |
| evaluate_models.py | Working | Dataset paths updated; CSV included in demo/scripts/ |

---

## Root Cause — Real Mode Classification Failure

Real mode consistently predicts "expedia" or "hulu" regardless of what site
is actually being visited. This is a **training/inference mismatch**, not a
code bug.

**How training data was collected** (`archive/Data & Traffic Engineer/collect.py`):

```
headless Firefox → SOCKS5 → Tor → eth0 → tcpdump captures TCP packets
```

Each trace is a Firefox browser loading a complete web page — HTML, CSS,
JavaScript, images, fonts — hundreds of sub-resources all loaded in parallel.
Traffic was captured on `eth0` (real network adapter, ~1500 byte MTU).

**How the current traffic generator works** (`scripts/traffic_gen.py`):

```
requests.get(url) → SOCKS5 → Tor → eth0 → sniffer captures TCP packets
```

`requests.get()` fetches only the HTML document. No sub-resources are loaded.
This produces a simple request→response pattern fundamentally different from
what the model was trained on.

**At the Tor circuit level (eth0)**, the difference is stark:

- Firefox page load: dozens of outgoing bursts followed by large incoming data
  bursts as each sub-resource loads; complex timing, high packet volume
- `requests.get()`: one outgoing burst, one incoming data burst, done

The model has never seen the `requests.get()` pattern during training. It
defaults to whichever trained class is nearest in feature space — currently
"expedia."

---

## What Was Fixed

These changes are already committed to `demo/scripts/`:

1. **Capture interface** changed from `lo` (loopback) to `eth0` — matching
   the training data capture interface. Loopback has a 65,536-byte MTU vs.
   the 1,500-byte MTU used during training; the oversized packets put feature
   values completely out of distribution.

2. **Capture filter** changed from `tcp port 9050` (SOCKS5) to `tcp` — Tor
   circuit traffic on eth0 uses guard-node ports (443, 9001), not port 9050.

3. **Direction detection** for loopback traffic uses TCP port instead of IP
   address (IP-based detection fails when src == dst == 127.0.0.1).

4. **Fake mode defense toggle** fixed — the dashboard sidebar toggle now
   correctly affects the background worker thread via `_defense_enabled`
   (a `threading.Event`). The previous implementation read from Streamlit
   session state, which is not accessible from background threads.

5. **Fake mode site list** now loads from `label_map.json` on init — same
   40-site set as real mode. Previous implementation was hardcoded to 8
   different sites.

6. **Dataset paths** updated — `curated_raw_dataset.csv` copied into
   `demo/scripts/` so the demo is fully self-contained; no archive/ digging
   required.

7. **Documentation** updated — README, dashboard.md, defense.md, ml-guide.md
   all reflect the current architecture.

---

## What Still Needs Fixing

### Real-mode traffic generator (Data & Traffic Engineer)

`traffic_gen.py` needs to drive a real browser instead of using
`requests.get()`. The architecture already exists in `collect.py` — it just
needs to be adapted for continuous rotation instead of per-site collection.

**Required in WSL:**
```bash
sudo apt install firefox-esr
# geckodriver matching Firefox version from: github.com/mozilla/geckodriver/releases
sudo mv geckodriver /usr/local/bin/
pip install selenium
```

**Core change to `traffic_gen.py`:**

The `run_browser()` function stub is already written and documented in
`traffic_gen.py`. It sets up headless Firefox with the same proxy/cache
preferences as `collect.py` and loops through the sites in the model's label
set. It is currently not the default because geckodriver may not be installed.

Once geckodriver is installed:
```bash
python traffic_gen.py          # browser mode — correct
python traffic_gen.py --simple # old behavior — do not use for demos
```

---

## Demo Strategy

**Recommended path for any upcoming presentation:**

Use **Fake mode** for the primary demonstration. Fake mode fully demonstrates
the defense contrast:

- Defense OFF → 65–80% confidence on the predicted site, clear probability spike
- Defense ON → 2–4% uniform across all 40 sites, no site identifiable

This is the correct demo narrative regardless of real/fake mode. Once the
browser traffic generator is working, Real mode can replace Fake mode and
the same contrast will be visible with live Tor traffic.

**Terminal setup for Fake mode demo:**
```bash
# Terminal 1
cd demo/scripts && streamlit run dashboard.py
# → open http://localhost:8501 in browser
# → select Fake, press Start, demonstrate defense toggle
```

**Terminal setup for Real mode demo (once traffic_gen.py is fixed):**
```bash
# Terminal 1: Tor
sudo service tor start

# Terminal 2: traffic generator
cd demo/scripts && python traffic_gen.py

# Terminal 3: dashboard
cd demo/scripts && streamlit run dashboard.py
# → select Real, press Start
```

---

## Questions / Owners

| Issue | Suggested Owner |
| --- | --- |
| geckodriver install + `traffic_gen.py` browser mode | Data & Traffic Engineer |
| Verify real-mode classification accuracy once browser mode works | ML Engineer |
| Evaluate defense ON/OFF contrast in real mode | Defense & Integration Engineer |
| Verify `eth0` interface name on each team member's machine | Systems Engineer |
