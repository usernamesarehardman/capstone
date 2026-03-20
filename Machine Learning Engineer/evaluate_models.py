import argparse
import csv
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    top_k_accuracy_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import LinearSVC

def default_dataset_path():
    return os.path.join(os.getcwd(), "wf_dataset.csv")

# --- ADVANCED FEATURE ENGINEERING (THE UPGRADE) ---

def extract_wf_features(trace):
    """
    Professional-grade feature extraction focusing on 'Burst' patterns.
    This helps distinguish encrypted sites with similar total packet counts.
    """
    non_zero = trace[trace != 0]
    if non_zero.size == 0:
        return [0] * 45  # Consistent feature length

    # 1. Basic Stats
    total_pkts = len(non_zero)
    out_pkts = np.sum(non_zero > 0)
    in_pkts = np.sum(non_zero < 0)
    out_ratio = out_pkts / total_pkts if total_pkts > 0 else 0

    # 2. Burst Analysis (Crucial for fingerprinting)
    signs = np.sign(non_zero)
    bursts = []
    current_burst_len = 0
    current_sign = signs[0]
    
    for s in signs:
        if s == current_sign:
            current_burst_len += 1
        else:
            bursts.append(current_burst_len * current_sign)
            current_sign = s
            current_burst_len = 1
    bursts.append(current_burst_len * current_sign)

    out_bursts = [b for b in bursts if b > 0]
    in_bursts = [abs(b) for b in bursts if b < 0]

    avg_out_burst = np.mean(out_bursts) if out_bursts else 0
    avg_in_burst = np.mean(in_bursts) if in_bursts else 0
    max_burst = np.max(np.abs(bursts)) if bursts else 0

    # 3. Shape Analysis (Cumulative Sum)
    # This captures the "loading curve" of the website
    cumsum = np.cumsum(non_zero)
    cumsum_stats = [np.mean(cumsum), np.std(cumsum), np.max(cumsum), np.min(cumsum)]

    # 4. First 30 Packets (The 'Fingerprint' Header)
    head = np.pad(non_zero[:30], (0, max(0, 30 - len(non_zero))), mode='constant')

    # Combine all into a feature vector
    return [
        total_pkts, out_pkts, in_pkts, out_ratio,
        avg_out_burst, avg_in_burst, max_burst, len(bursts)
    ] + cumsum_stats + head.tolist()

def load_dataset(csv_path):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset file not found: {csv_path}")

    X, y = [], []
    with open(csv_path, "r", newline="") as f:
        reader = csv.reader(f)
        next(reader, None) # Skip header

        for row in reader:
            if not row: continue
            label = row[0].strip()
            # Handle possible scientific notation or empty strings
            trace = np.array([float(v) if v else 0 for v in row[1:]], dtype=np.float64)
            X.append(extract_wf_features(trace))
            y.append(label)

    return np.array(X, dtype=np.float64), np.array(y)

# --- MODEL SUITE ---

def make_models(seed):
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=800,      # Beefed up for your rig
            max_depth=40,          # Deeper trees to catch nuances
            min_samples_leaf=1,
            random_state=seed,
            n_jobs=-1,             # Use all those cores!
            class_weight='balanced' # Helps with sites that have fewer samples
        ),
        "xgboost": XGBClassifier(
            n_estimators=500,
            learning_rate=0.03,
            max_depth=8,
            random_state=seed,
            eval_metric='mlogloss',
            n_jobs=-1
        ),
        "linear_svm": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LinearSVC(dual=False, random_state=seed, max_iter=5000))
        ])
    }

def get_top5_accuracy(model, X_test, y_test, labels):
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_test)
    elif hasattr(model, "decision_function"):
        probs = model.decision_function(X_test)
    else:
        return accuracy_score(y_test, model.predict(X_test))
    
    k = min(5, len(labels))
    return top_k_accuracy_score(y_test, probs, k=k, labels=labels)

# --- MAIN ENGINE ---

def main():
    parser = argparse.ArgumentParser(description="Final Capstone Model Evaluator")
    parser.add_argument("--dataset", default=default_dataset_path(), help="Path to CSV")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print(f"[*] Processing existing data from {args.dataset}...")
    X, y_raw = load_dataset(args.dataset)
    
    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)
    class_names = encoder.classes_

    # Stratify is key here to ensure 20 samples/site are split fairly
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )

    models = make_models(args.seed)
    
    print("\n" + "="*55)
    print(f"{'Model':<15} | {'Top-1 Accuracy':<14} | {'Top-5 Accuracy':<14}")
    print("-" * 55)

    best_f1 = 0
    final_cm = None

    for name, model in models.items():
        print(f"[*] Training {name}...", end="\r")
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        
        t1 = accuracy_score(y_test, y_pred)
        t5 = get_top5_accuracy(model, X_test, y_test, np.unique(y))
        f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
        
        print(f"{name:<15} | {t1:.4%}{'':<4} | {t5:.4%}")
        
        # We'll save the confusion matrix for the best performing model
        if f1 > best_f1:
            best_f1 = f1
            final_cm = confusion_matrix(y_test, y_pred)
            best_report = classification_report(y_test, y_pred, target_names=class_names, zero_division=0)

    print("="*55)
    print("\n[+] Detailed Classification Report (Best Model):")
    print(best_report)

    # Save finalized Confusion Matrix
    cm_df = pd.DataFrame(final_cm, index=class_names, columns=class_names)
    cm_df.to_csv("confusion_matrix.csv")
    print("\n[✔] Evaluation complete. Run your visualization script to see the new heatmap!")

if __name__ == "__main__":
    main()