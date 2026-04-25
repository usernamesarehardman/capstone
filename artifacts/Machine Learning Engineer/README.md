# Machine Learning Engineer Guide

This folder contains the training and evaluation workflow for WF-Guard.

## Inputs
Expected dataset files (produced by `Data & Traffic Engineer/build_dataset.py`):

- `X_train.npy`
- `X_val.npy`
- `X_test.npy`
- `metadata_train.csv`
- `metadata_val.csv`
- `metadata_test.csv`

The metadata files must include:

- `site_id` (target class)
- `defense_on` (`0/1` or `False/True`)

## Baseline Model
`train_baseline.py` trains a multiclass Logistic Regression baseline with a small validation search over `C`.

Outputs:

- `model.joblib`
- `label_map.json`
- `metrics_summary.json`
- `confusion_matrix.csv`

## Run
From this directory:

```bash
python -m pip install -r requirements.txt
python train_baseline.py --dataset-dir "..\Data & Traffic Engineer\dataset" --output-dir artifacts
```

## What to hand off
For integration and demo, share:

- `artifacts/model.joblib`
- `artifacts/label_map.json`
- `artifacts/metrics_summary.json`
- `artifacts/confusion_matrix.csv`

## Notes
- Feature vectors are currently fixed-length flattened vectors from packet size, direction, and inter-arrival time.
- This baseline is intentionally simple and fast; it gives you a defensible first benchmark before trying stronger models.
