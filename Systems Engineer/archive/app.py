import streamlit as st
import pandas as pd
import numpy as np
import time
import random

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="WF-Guard: Real-Time Attack Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# --- CSS FOR CUSTOM STYLING ---
st.markdown("""
    <style>
    .metric-card {
        background-color: #1e2130;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #4e73df;
    }
    </style>
    """, unsafe_allow_html=True)  # <-- Changed this from unsafe_allow_path
    
# --- SIDEBAR CONTROLS ---
st.sidebar.title("🎮 System Controls")
st.sidebar.markdown("---")

# 1. Attack Controls
st.sidebar.subheader("Attack Settings")
attack_mode = st.sidebar.radio("Input Source", ["Live Sniffer (Inactive)", "Simulation Mode"])
run_system = st.sidebar.button("🚀 Start Attack System", use_container_width=True)

st.sidebar.markdown("---")

# 2. Defense Controls (Requirement #3)
st.sidebar.subheader("Tor-Integrated Defense")
defense_active = st.sidebar.toggle("Enable WF-Guard (Padding/Obfuscation)")
if defense_active:
    st.sidebar.success("DEFENSE: ON (Injecting Dummy Packets)")
else:
    st.sidebar.error("DEFENSE: OFF (Vulnerable)")

# --- MAIN DASHBOARD INTERFACE ---
st.title("🛡️ WF-Guard: Real-Time Website Fingerprinting")
st.write("Project Role: **Systems Engineer** | Status: **Functional Prototype**")

# Top Row: Big Metrics
m1, m2, m3, m4 = st.columns(4)

# Placeholder variables for metrics
current_site = "Scanning..."
confidence = 0.0
packets_count = 0
latency = "0ms"

with m1:
    site_placeholder = st.empty()
    site_placeholder.metric("Current Prediction", current_site)
with m2:
    conf_placeholder = st.empty()
    conf_placeholder.metric("Confidence Score", f"{confidence:.1%}")
with m3:
    packet_placeholder = st.empty()
    packet_placeholder.metric("Packets Processed", packets_count)
with m4:
    st.metric("Inference Latency", "42ms")

st.markdown("---")

# Middle Row: Visualizations
v1, v2 = st.columns([2, 1])

with v1:
    st.subheader("📈 Time-to-Decision Curve (Requirement #4)")
    chart_placeholder = st.empty()
    # Initial empty dataframe for the accuracy curve
    chart_data = pd.DataFrame(columns=["Time (s)", "Accuracy"])

with v2:
    st.subheader("🕵️ Classifier Probabilities")
    bar_placeholder = st.empty()

st.markdown("---")

# Bottom Row: System Logs
st.subheader("📟 Real-Time Logs")
log_placeholder = st.empty()
logs = ["System Initialized...", "Waiting for Tor traffic on port 9150..."]
log_placeholder.text("\n".join(logs))

# --- SIMULATION LOGIC ---
if run_system:
    # Simulated database of monitored sites
    monitored_sites = ["Google", "YouTube", "Facebook", "Amazon", "Wikipedia"]
    target_site = random.choice(monitored_sites)
    
    accuracy_trend = []
    
    for seconds in range(1, 11):
        # 1. Simulate Packet Arrival
        packets_count += random.randint(50, 200)
        
        # 2. Simulate Model Logic
        # Accuracy grows over time unless Defense is ON
        if defense_active:
            # If defense is on, prediction stays noisy/incorrect
            current_prediction = "Unknown / Noise"
            confidence = random.uniform(0.1, 0.3)
            logs.append(f"[{seconds}s] Defense detected: Pattern obfuscated.")
        else:
            # If defense is off, prediction becomes clear
            current_prediction = target_site
            confidence = min(0.1 * seconds + random.uniform(0, 0.1), 0.98)
            logs.append(f"[{seconds}s] Feature Burst Detected. Matching against {target_site}...")

        # 3. Update Metrics
        site_placeholder.metric("Current Prediction", current_prediction)
        conf_placeholder.metric("Confidence Score", f"{confidence:.1%}", delta=None)
        packet_placeholder.metric("Packets Processed", packets_count)
        
        # 4. Update Time-to-Decision Chart
        accuracy_trend.append(confidence)
        chart_placeholder.line_chart(accuracy_trend)
        
        # 5. Update Bar Chart
        mock_probs = pd.DataFrame({
            'Site': monitored_sites,
            'Probability': [random.random() for _ in monitored_sites]
        })
        bar_placeholder.bar_chart(mock_probs.set_index('Site'))
        
        # 6. Update Logs
        log_placeholder.text("\n".join(logs[-10:]))
        
        time.sleep(0.8) # Simulate real-time delay

    st.success(f"Analysis Complete. Final Result: {current_prediction}")