"""
Automates the traffic collection with Selenium and Geckodriver on Tor Browser.

NETWORK_INTERFACE - Change to appropriate name to your network adapter name
PCAP_SAVE_DIR - Directory path to the file you want the pcap files to be saved to
NUM_TRACES_PER_SITE - Designates the number of traces per website to run
CAPTURE_DURATION - The number of seconds per traffic time read per trace.
"""
import os
import time
import subprocess
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from stem import Signal
from stem.control import Controller

# --- CONFIGURATION ---
# IMPORTANT: Run `ip a` in terminal to verify your interface (e.g., eth0, ens33)
NETWORK_INTERFACE = "eth0" 
PCAP_SAVE_DIR = "data/closed_world/"
NUM_TRACES_PER_SITE = 100
CAPTURE_DURATION = 10 # Seconds to wait after initial connection

os.makedirs(PCAP_SAVE_DIR, exist_ok=True)

def renew_tor_circuit():
    """Forces Tor to build a brand new circuit for a clean trace."""
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            time.sleep(3) 
    except Exception as e:
        print(f"  [!] Tor Circuit warning: {e}")

def setup_browser():
    """Configures Firefox to run invisibly and route through Tor."""
    options = Options()
    options.add_argument('-headless')
    options.page_load_strategy = 'eager' # Speed optimization
    
    # Route through local Tor proxy
    options.set_preference('network.proxy.type', 1)
    options.set_preference('network.proxy.socks', '127.0.0.1')
    options.set_preference('network.proxy.socks_port', 9050)
    options.set_preference('network.proxy.socks_remote_dns', True)
    
    # CRITICAL: Prevent Tor from breaking Geckodriver's internal connection
    options.set_preference('network.proxy.no_proxies_on', 'localhost, 127.0.0.1')
    
    # Disable cache for clean captures
    options.set_preference("browser.cache.disk.enable", False)
    options.set_preference("browser.cache.memory.enable", False)
    options.set_preference("network.http.use-cache", False)
    
    service = Service("/usr/local/bin/geckodriver")
    driver = webdriver.Firefox(service=service, options=options)
    driver.set_page_load_timeout(15) 
    return driver

def main():
    if not os.path.exists("monitored.txt"):
        print("Error: monitored.txt not found. Create it with your target URLs.")
        return

    with open("monitored.txt", "r") as f:
        sites = [line.strip() for line in f if line.strip()]

    for site in sites:
        site_name = site.replace("https://www.", "").replace("https://", "").split(".")[0]
        print(f"\n=== Starting collection for {site_name} ===")
        
        for i in range(NUM_TRACES_PER_SITE):
            pcap_file = os.path.join(PCAP_SAVE_DIR, f"{site_name}_{i}.pcap")
            print(f"[{i+1}/{NUM_TRACES_PER_SITE}] Capturing {site}...")
            
            renew_tor_circuit()
            
            cmd =["sudo", "tcpdump", "-i", NETWORK_INTERFACE, "-w", pcap_file, "tcp", "-q"]
            capture_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1) 
            
            driver = setup_browser()
            try:
                driver.get(site)
                time.sleep(CAPTURE_DURATION)
            except Exception:
                pass # Silently proceed if page load times out or finishes early
            finally:
                driver.quit()
                capture_proc.terminate()
                capture_proc.wait()
                time.sleep(1) 

if __name__ == "__main__":
    main()