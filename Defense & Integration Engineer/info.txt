# 🛡️ WF-Guard: Defense & Integration Task List

This document tracks the progress of the defensive countermeasures and system integration for the Website Fingerprinting (WF) Capstone Project.

## 📋 Project Progress
- [ ] **Phase 1: Research & Setup** (Weeks 1-3)
- [ ] **Phase 2: Design & Selection** (Weeks 4-6)
- [ ] **Phase 3: Development & Integration** (Weeks 7-9)
- [ ] **Phase 4: Refinement & Toggling** (Weeks 10-12)
- [ ] **Phase 5: Evaluation & Live Demo** (Weeks 13-15)

---

## 🛠️ Detailed Task Breakdown

### Phase 1 & 2: Strategy & Environment
- [ ] **Setup Development Environment**: Install Tor Browser, Python, and PyShark.
- [ ] **Literature Review**: Research **CS-BuFLO** and **WTF-PAD** defense mechanisms.
- [ ] **Architecture Design**: Confirm SOCKS proxy logic for intercepting Tor traffic.
    - *Decision*: Will use a local Python proxy to inject dummy packets.

### Phase 3: Core Defense Development
- [ ] **Implement Base Proxy**: Create a Python script using `socket` or `pysocks` to tunnel traffic.
- [ ] **Packet Injection Logic**:
    - [ ] Create a "Dummy Packet" generator (constant 512-byte cells).
    - [ ] Implement a basic padding interval (e.g., send a packet every $t$ milliseconds).
- [ ] **Traffic Shaping**: Ensure the defense modifies packet timing and direction patterns.

### Phase 4: Integration & UX
- [ ] **Tor Browser Hook**: Configure Tor Browser network settings to route through the local proxy (`127.0.0.1:PORT`).
- [ ] **The "Kill Switch"**:
    - [ ] Implement a CLI toggle (e.g., Press `D` to Enable/Disable defense).
    - [ ] Ensure the toggle is responsive during a live browsing session.
- [ ] **Stability Check**: Verify that the defense doesn't cause "Connection Timed Out" errors in Tor.

### Phase 5: Testing & Evaluation
- [ ] **Effectiveness Test**: Compare attack accuracy with Defense **ON** vs. **OFF**.
- [ ] **Overhead Calculation**:
    - [ ] Measure **Bandwidth Cost**: $\frac{\text{Total Bytes With Defense}}{\text{Total Bytes Without Defense}}$
    - [ ] Measure **Latency**: Increase in Page Load Time (PLT).
- [ ] **Final Demo Prep**: Ensure the `REPRODUCE.md` clearly explains how to launch the proxy.

---

## 🚀 Deliverables for Week 15
* [ ] Functional `defense_proxy.py` script.
*