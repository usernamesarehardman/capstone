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

def find_dataset(filename="curated_raw_dataset.csv"):
    """
    Search strategy to find the dataset in your local or parent folders.
    """
    # Check local folder first
    if os.path.exists(filename):
        return os.path.abspath(filename)
    
    # Check the Data & Traffic Engineer folder relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    target_path = os.path.join(repo_root, "Data & Traffic Engineer", "initial_dataset", filename)
    
    if os.path.exists(target_path):
        return target_path

    return filename

def extract_wf_features(trace):
    """Advanced feature extraction for Random Forest."""
    non_zero = trace[trace != 0]
    if non_zero.size == 0:
        return [0] * 52

    out_pkts = non_zero[non_zero > 0]
    in_pkts = non_zero[non_zero < 0]
    total_count = len(non_zero)
    out_count = len(out_pkts)
    in_count = len(in_pkts)
    
    out_ratio = out_count / total_count if total_count > 0 else 0
    size_ratio = np.sum(out_pkts) / abs(np.sum(in_pkts)) if in_count > 0 else 0

    bins = [
        np.sum(np.abs(non_zero) < 100),   
        np.sum((np.abs(non_zero) >= 100) & (np.abs(non_zero) < 1000)), 
        np.sum(np.abs(non_zero) >= 1000)  
    ]

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

    cumsum = np.cumsum(non_zero)
    stats = [np.mean(non_zero), np.std(non_zero), np.mean(cumsum), np.std(cumsum)]
    head = np.pad(non_zero[:40], (0, max(0, 40 - len(non_zero))), mode='constant')

    return [
        total_count, out_count, in_count, out_ratio, size_ratio,
        avg_out_b, avg_in_b, max_b, len(bursts)
    ] + bins + stats + head.tolist()

def load_dataset(csv_path):
    """
    Robust loader that scans for data even if column headers vary.
    """
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        return [], []

    X, y = [], []
    print(f"[*] Starting deep scan of {os.path.basename(csv_path)}...")
    
    with open(csv_path, "r", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None) # Consume the header
        
        row_count = 0
        for row in reader:
            # Skip empty or tiny rows
            if not row or len(row) < 5:
                continue
            
            # Label is ALWAYS column 0 (e.g., 'google', 'amazon')
            label = row[0].strip()
            
            try:
                # Convert the rest of the row to floats, treating empty cells as 0
                trace = np.array([float(v) if (v and v.strip()) else 0 for v in row[1:]], dtype=np.float64)
                
                # Verify row has at least some non-zero data
                if np.any(trace):
                    X.append(extract_wf_features(trace))
                    y.append(label)
                    row_count += 1
            except ValueError:
                # This catches rows where the data isn't a number (e.g. extra headers)
                continue

            if row_count % 100 == 0 and row_count > 0:
                print(f"    [+] Successfully processed {row_count} rows...")

    return np.array(X, dtype=np.float64), np.array(y)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="curated_raw_dataset.csv")
    args = parser.parse_args()

    # Resolve actual file path
    target_file = find_dataset(args.dataset)
    print(f"[*] Resolved Path: {target_file}")
    
    X, y_raw = load_dataset(target_file)
    
    if len(X) == 0:
        print("\n[!] ERROR: No samples loaded.")
        print("[?] Possible fix: Open the CSV and make sure the first column contains the site name.")
        return

    print(f"[*] Found {len(X)} samples across {len(np.unique(y_raw))} classes.")
    
    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print(f"[*] Training Random Forest on {len(X_train)} training samples...")
    model = RandomForestClassifier(n_estimators=1000, n_jobs=-1, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    probs = model.predict_proba(X_test)
    
    print("\n" + "="*45)
    print(f"FINAL EVALUATION RESULTS")
    print("-" * 45)
    print(f"Top-1 Accuracy: {accuracy_score(y_test, y_pred):.2%}")
    print(f"Top-5 Accuracy: {top_k_accuracy_score(y_test, probs, k=5, labels=np.unique(y)):.2%}")
    print("="*45)

    # Update CSV for heatmap
    cm_df = pd.DataFrame(confusion_matrix(y_test, y_pred), index=encoder.classes_, columns=encoder.classes_)
    cm_df.to_csv("confusion_matrix.csv")

if __name__ == "__main__":
    main()