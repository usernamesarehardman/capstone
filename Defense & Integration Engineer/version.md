# defense_proxy.py — Version History

---

## v1.2.0 — 2026-03-27

- Added `init_dataset_manager(directory)`: loads pcap files, trains a `DatasetManager` traffic profile, and sets the module-level `_dm` instance. Returns `True` if data was found, `False` if falling back to random delays.
- Added `_sample_delay(fallback)`: single decision point for request timing — uses `get_proxy_delay(_dm)` when a profile is loaded, otherwise falls back to `random.uniform(*fallback)`.
- Added optional import block for `dataset_manager`: gracefully skips if `scapy`/`sklearn` are not installed, setting `_dataset_manager_available = False`.
- Added `_dm` module-level variable: holds the active `DatasetManager` instance (`None` until `init_dataset_manager()` is called).
- Changed `fetch()`: timing delay now routed through `_sample_delay(delay)` instead of `random.uniform(*delay)`.
- Changed `fetch()` debug log: now reports active delay mode (`learned` vs `fallback`).
- Changed `__main__` block: calls `init_dataset_manager("data")` at startup and prints which mode is active.

---

## v1.1.0 — 2026-03-27

- Added kill switch (`start_kill_switch`): spawns a background daemon thread listening for the `D` key to toggle defense on/off at runtime with no restart required.
  - Windows: single-keypress detection via `msvcrt` (no Enter needed).
  - Linux/macOS: falls back to `D` + Enter via stdin.
- Added `is_defense_enabled()`: thread-safe helper returning the current defense state via `threading.Event`.
- Added `_defense_enabled` event: `threading.Event` initialized to `set` (defense ON by default).
- Added `threading` import (stdlib).
- Changed `fetch()`: header randomization and timing jitter are now conditional on `is_defense_enabled()`.
  - Defense ON: randomized headers + jitter applied as before.
  - Defense OFF: fixed User-Agent (`_UA_POOL[0]`), no sleep delay.
- Changed `_UA_POOL`: moved to module-level so it is always available regardless of whether `fake-useragent` is installed.
- Changed `__main__` block: calls `start_kill_switch()` at startup.

---

## v1.0.0 — initial

- Tor SOCKS5 proxy via `socks5h://127.0.0.1:9050`
- Randomized browser headers (`build_headers`)
- Jittered request timing and retry logic (`fetch`)
- Tor circuit rotation via control port (`request_new_identity`)
- Exit IP verification (`check_tor_ip`)
