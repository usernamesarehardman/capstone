# Tor Proxy + Dataset Manager — Setup Guide

---

## 1. Install Tor

**macOS**
```bash
brew install tor && tor
```

**Linux**
```bash
sudo apt install tor && sudo systemctl start tor
```

**Windows**
Download the Tor Expert Bundle from [torproject.org](https://www.torproject.org/download/tor/)

---

## 2. Install Python Dependencies

```bash
pip install requests[socks] PySocks fake-useragent scapy pandas numpy scikit-learn joblib
```

---

## 3. Set Up Your Project Folder

```
project/
├── data/               ← drop your .pcap / .pcapng files here
├── models/             ← auto-created when you train
├── tor_proxy.py
└── dataset_manager.py
```

---

## 4. Verify Tor Is Routing Correctly

```bash
python tor_proxy.py
```

You should see a Tor exit IP printed. If it matches your real IP, something is wrong — double-check Tor is running.

---

## 5. (Optional) Enable Tor Identity Rotation

Add the following to your `torrc` file:
- **Linux/macOS:** `/etc/tor/torrc`
- **Windows:** `Tor Browser\Browser\TorBrowser\Data\Tor\torrc`

```
ControlPort 9051
CookieAuthentication 1
```

Then restart Tor:
```bash
# Linux
sudo systemctl restart tor

# macOS
brew services restart tor
```

---

## 6. Load Your pcap Files and Train Models

Drop `.pcap` or `.pcapng` files into the `data/` folder, then run:

```bash
python dataset_manager.py
```

This will:
- Parse your traces into flows
- Extract timing and fingerprint features
- Train the anomaly detector (unsupervised, no labels needed)
- Save trained models to `models/`

---

## 7. Connect dataset_manager.py to tor_proxy.py

Add this to the top of `tor_proxy.py`:

```python
from dataset_manager import DatasetManager, get_proxy_delay
dm = DatasetManager().load_directory("data")
dm.train_models()
```

Then in the `fetch()` function, replace:
```python
sleep_for = random.uniform(*delay)
```
with:
```python
sleep_for = get_proxy_delay(dm)
```

---

## 8. Iterate as Your Data Grows

| When you... | Do this... |
|---|---|
| Add more pcap files | Re-run `python dataset_manager.py` to retrain |
| Start labeling flows | Set `flow.label` values — supervised classifier activates automatically |
| Add new User-Agent data | Extend `_UA_POOL` in `tor_proxy.py` or plug in `fake-useragent` |
| Add fingerprint profiles | Extend `TRAFFIC_LABELS` in `dataset_manager.py` |

---

## Quick Reference — Common Issues

**Tor not connecting**
- Make sure the Tor process is running before executing the script
- Default SOCKS5 port is `9050` — confirm it hasn't been changed in your `torrc`

**Scapy permission errors on pcap**
```bash
sudo python dataset_manager.py   # or run with elevated permissions
```

**No pcap files found**
- Files must be in the `data/` folder with `.pcap` or `.pcapng` extension
- The script will fall back to synthetic data for testing if none are found

**Identity rotation not working**
- Confirm `ControlPort 9051` is set in `torrc` and Tor has been restarted
- If you set a `HashedControlPassword`, pass it to `request_new_identity(password="yourpassword")`
