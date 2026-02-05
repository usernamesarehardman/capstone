# 📊 WF-Guard: Data & Traffic Engineering Task List

This document tracks the progress of the data collection, traffic capture, processing, and feature engineering pipeline for the Website Fingerprinting (WF) Capstone Project.

## 📋 Project Progress
- [ ] **Phase 1: Research & Setup** (Weeks 1-3)
- [ ] **Phase 2: Design & Dataset Planning** (Weeks 4-6)
- [ ] **Phase 3: Collection & Processing Pipeline** (Weeks 7-9)
- [ ] **Phase 4: Feature Engineering & Validation** (Weeks 10-12)
- [ ] **Phase 5: Evaluation & Live Demo** (Weeks 13-15)

---

## 🛠️ Detailed Task Breakdown

### Phase 1 & 2: Traffic Strategy & Environment
- [ ] **Setup Data Environment**: Install Python, Wireshark/tshark, and PyShark.
- [ ] **Interface Verification**: Confirm correct network interface for Tor traffic capture.
- [ ] **Capture Method Design**: Decide on PCAP-based vs parsed-flow dataset format.
- [ ] **Dataset Plan**:
    - *Decision*: Fixed number of monitored sites and samples per site.
- [ ] **Labeling Scheme**:
    - [ ] Define site IDs and visit IDs.
    - [ ] Define Defense ON vs OFF label flag.

### Phase 3: Core Collection Development
- [ ] **Traffic Capture Script**: Create a Python script to automate packet capture per visit.
- [ ] **Session Capture Logic**:
    - [ ] Start capture before page load.
    - [ ] Stop capture after fixed timeout or network idle.
- [ ] **Tor Session Control**:
    - [ ] Ensure new circuit or fresh session when required.
    - [ ] Standardize capture duration across runs.
- [ ] **Raw Data Storage**:
    - [ ] Save PCAP files using structured naming convention.
    - [ ] Separate folders for Defense ON and Defense OFF.
- [ ] **Parsing Pipeline**:
    - [ ] Extract timestamps, packet sizes, and directions.
    - [ ] Filter to Tor-related flows only.

### Phase 4: Feature Engineering & Dataset Prep
- [ ] **Feature Extraction**:
    - [ ] Build packet size sequences.
    - [ ] Encode packet direction (+ / −).
    - [ ] Compute inter-packet timing gaps.
- [ ] **Sequence Formatting**:
    - [ ] Pad or truncate to fixed-length vectors.
    - [ ] Normalize numeric features where needed.
- [ ] **Quality Checks**:
    - [ ] Detect incomplete or corrupted captures.
    - [ ] Remove outlier sessions.
- [ ] **Dataset Balance**:
    - [ ] Verify equal samples per class.
    - [ ] Verify equal Defense ON/OFF coverage.
- [ ] **Dataset Split**:
    - [ ] Create train/validation/test sets.
    - [ ] Ensure no visit leakage between splits.

### Phase 5: Testing & Evaluation Support
- [ ] **Feature Export**: Provide processed feature files for model training.
- [ ] **Overhead Metrics Support**:
    - [ ] Export packet counts per session.
    - [ ] Export total bytes per session.
- [ ] **Defense Comparison Sets**:
    - [ ] Produce matched ON vs OFF sample groups.
- [ ] **Reproducibility**:
    - [ ] Create dataset rebuild script from raw PCAPs.
    - [ ] Document steps in `DATA_PIPELINE.md`.

---

## 🚀 Deliverables for Week 15
* [ ] Functional traffic capture script.
* [ ] PCAP parsing and feature extraction pipeline.
* [ ] Clean labeled dataset (Defense ON/OFF).
* [ ] Reproduction documentation (`DATA_PIPELINE.md`).