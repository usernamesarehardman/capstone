# WF-Guard: Machine Learning Engineer Task List

This document tracks model training, evaluation, and integration handoff for the WF-Guard capstone.

## Project Progress
- [ ] Phase 1: Data Intake and Validation
- [ ] Phase 2: Baseline Modeling
- [ ] Phase 3: Defense ON/OFF Evaluation
- [ ] Phase 4: Error Analysis and Tuning
- [ ] Phase 5: Integration Handoff

## Detailed Tasks

### Phase 1: Data Intake and Validation
- [ ] Confirm dataset artifacts from Data & Traffic Engineer:
  - [ ] `X_train.npy`, `X_val.npy`, `X_test.npy`
  - [ ] `metadata_train.csv`, `metadata_val.csv`, `metadata_test.csv`
  - [ ] `overhead_per_session.csv`
- [ ] Verify shape assumptions (feature dimension and sample counts).
- [ ] Verify label mapping from metadata (`site_id` to integer class).

### Phase 2: Baseline Modeling
- [ ] Train first baseline classifier (Logistic Regression).
- [ ] Tune regularization (`C`) with validation split.
- [ ] Save trained model and label map for Systems Engineer integration.

### Phase 3: Defense ON/OFF Evaluation
- [ ] Report overall accuracy on validation and test.
- [ ] Report macro precision/recall/F1.
- [ ] Report confusion matrix.
- [ ] Report subgroup accuracy for defense ON and defense OFF.

### Phase 4: Error Analysis and Tuning
- [ ] Identify top-confused site pairs.
- [ ] Compare errors across defense states.
- [ ] Document likely causes and next feature/model experiments.

### Phase 5: Integration Handoff
- [ ] Export model artifact (`model.joblib`).
- [ ] Export metrics report (`metrics_summary.json`).
- [ ] Export class mapping (`label_map.json`).
- [ ] Provide inference notes to Systems Engineer.

## Quick Start
Run from this directory:

```bash
python -m pip install -r requirements.txt
python train_baseline.py --dataset-dir ..\Data\ \&\ Traffic\ Engineer\dataset --output-dir artifacts
```

If your shell has trouble with spaces in paths, wrap the path in quotes:

```bash
python train_baseline.py --dataset-dir "..\Data & Traffic Engineer\dataset" --output-dir artifacts
```
