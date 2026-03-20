import argparse
import csv
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    top_k_accuracy_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

def default_dataset_path():
    return os.path.join(os.getcwd(), "wf_dataset.csv")

def extract_wf_features(trace):
    """
    Advanced feature extraction. 
    Focuses on traffic 'shape' and 'burstiness' to defeat encryption padding.
    """
    non_zero = trace[trace != 0]
    if non_zero.size == 0:
        return [0] * 52 

    # 1. Directional Stats
    out_pkts = non_zero[non_zero > 0]
    in_pkts = non_zero[non_zero < 0]
    
    total_count = len(non_zero)
    out_count = len(out_pkts)
    in_count = len(in_pkts)
    
    out_ratio = out_count / total_count if total_count > 0 else 0
    size_ratio = np.sum(out_pkts) / abs(np.sum(in_pkts)) if in_count > 0 else 0

    # 2. Packet Size Binning (MTU Analysis)
    bins = [
        np.sum(np.abs(non_zero) < 100),   
        np.sum((np.abs(non_zero) >= 100) & (np.abs(non_zero) < 1000)), 
        np.sum(np.abs(non_zero) >= 1000)  
    ]

    # 3. Burst Analysis
    signs = np.sign(non_zero)
    bursts = []
    curr_len, curr_sign = 0, signs[0]
    for s in signs:
        if s == curr_sign:
            curr_len += 1
        else:
            bursts.append(curr_len * curr_sign)
            curr_sign, curr_len = s, 1
    bursts.append(curr_len * curr_sign)

    avg_out_b = np.mean([b for b in bursts if b > 0]) if any(b > 0 for b in bursts) else 0
    avg_in_b = np.mean([abs(b) for b in bursts if b < 0]) if any(b < 0 for b in bursts) else 0
    max_b = np.max(np.abs(bursts))

    # 4. Statistical Moments
    cumsum = np.cumsum(non_zero)
    stats = [np.mean(non_zero), np.std(non_zero), np.mean(cumsum), np.std(cumsum)]

    # 5. The 'Header' Fingerprint (First 40 packets)
    head = np.pad(non_zero[:40], (0, max(0, 40 - len(non_zero))), mode='constant')

    return [
        total_count, out_count, in_count, out_ratio, size_ratio,
        avg_out_b, avg_in_b, max_b, len(bursts)
    ] + bins + stats + head.tolist()

def load_dataset(csv_path):
    X, y = [], []
    with open(csv_path, "r", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if not row: continue
            label = row[0].strip()
            trace = np.array([float(v) if v else 0 for v in row[1:]], dtype=np.float64)
            X.append(extract_wf_features(trace))
            y.append(label)
    return np.array(X, dtype=np.float64), np.array(y)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=default_dataset_path())
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print(f"[*] Processing data from {args.dataset}...")
    X, y_raw = load_dataset(args.dataset)
    
    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )

    # Scale the features (important for statistical moments)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print(f"[*] Training Random Forest (1200 estimators)...")
    model = RandomForestClassifier(
        n_estimators=1200, 
        max_depth=None,
        class_weight='balanced_subsample',
        n_jobs=-1,
        random_state=args.seed
    )

    model.fit(X_train, y_train)
    
    # Run Predictions
    y_pred = model.predict(X_test)
    probs = model.predict_proba(X_test)
    
    t1 = accuracy_score(y_test, y_pred)
    t5 = top_k_accuracy_score(y_test, probs, k=5, labels=np.unique(y))

    print("\n" + "="*45)
    print(f"ULTRA RANDOM FOREST RESULTS")
    print("-" * 45)
    print(f"Top-1 Accuracy: {t1:.2%}")
    print(f"Top-5 Accuracy: {t5:.2%}")
    print("="*45)

    print("\n[✔] Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=encoder.classes_, zero_division=0))

    # Optional: Save only the CSV for the heatmap script
    cm_df = pd.DataFrame(confusion_matrix(y_test, y_pred), index=encoder.classes_, columns=encoder.classes_)
    cm_df.to_csv("confusion_matrix.csv")
    print("[+] Confusion matrix updated.")

if __name__ == "__main__":
    main()