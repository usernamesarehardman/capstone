#!/bin/bash
set -e

echo "=== [1/5] Installing System Dependencies ==="
sudo apt-get update -y
sudo apt-get install -y python3-pip python3-venv tcpdump tor wget tar nano software-properties-common zip

echo "=== [2/5] Fixing tcpdump Passwordless Sudo ==="
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/tcpdump, /usr/sbin/tcpdump" | sudo tee /etc/sudoers.d/tcpdump > /dev/null
sudo chmod 0440 /etc/sudoers.d/tcpdump

echo "=== [3/5] Swapping Snap Firefox for Native Firefox ==="
sudo snap remove firefox || true
sudo add-apt-repository ppa:mozillateam/ppa -y
echo -e "Package: *\nPin: release o=LP-PPA-mozillateam\nPin-Priority: 1001" | sudo tee /etc/apt/preferences.d/mozilla-firefox > /dev/null
sudo apt-get update -y
sudo apt-get install --allow-downgrades -y firefox

echo "=== [4/5] Installing Geckodriver & Configuring Tor ==="
wget -q https://github.com/mozilla/geckodriver/releases/download/v0.34.0/geckodriver-v0.34.0-linux64.tar.gz -O /tmp/geckodriver.tar.gz
sudo tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin/
sudo chmod +x /usr/local/bin/geckodriver
rm /tmp/geckodriver.tar.gz

# Configure Tor Control Port
sudo sed -i '/ControlPort 9051/d' /etc/tor/torrc
sudo sed -i '/CookieAuthentication 1/d' /etc/tor/torrc
sudo sed -i '/CookieAuthFileGroupReadable 1/d' /etc/tor/torrc
echo -e "ControlPort 9051\nCookieAuthentication 1\nCookieAuthFileGroupReadable 1" | sudo tee -a /etc/tor/torrc > /dev/null
sudo systemctl restart tor
sudo usermod -aG debian-tor $USER
sleep 2
sudo chmod 644 /run/tor/control.authcookie || true

echo "=== [5/5] Creating Python Workspace ==="
mkdir -p ~/wf-guard/data/closed_world
cd ~/wf-guard
python3 -m venv venv
./venv/bin/pip install -q selenium stem scapy scikit-learn numpy

echo "✅ Environment Setup Complete! Please navigate to ~/wf-guard"