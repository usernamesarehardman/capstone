import argparse
import csv
import os

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    top_k_accuracy_score,
)
from sklearn.model_selection import (
    GridSearchCV,
    StratifiedKFold,
    cross_validate,
    train_test_split,
)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import LinearSVC


def default_dataset_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    return os.path.join(
        repo_root,
        "Data & Traffic Engineer",
        "initial_dataset",
        "wf_dataset.csv",
    )


def parse_trace_values(values):
    trace = []
    for v in values:
        if v == "":
            trace.append(0)
            continue
        trace.append(int(float(v)))
    return np.array(trace, dtype=np.int32)


def compute_burst_lengths(non_zero_trace):
    if non_zero_trace.size == 0:
        return []

    signs = np.sign(non_zero_trace)
    burst_lengths = []
    current = 1

    for i in range(1, len(signs)):
        if signs[i] == signs[i - 1]:
            current += 1
        else:
            burst_lengths.append(current)
            current = 1

    burst_lengths.append(current)
    return burst_lengths


def burst_histogram(bursts):
    if not bursts:
        return [0.0] * 8

    # Bucket boundaries are roughly Fibonacci-like to capture short/long bursts.
    bins = [1, 2, 3, 5, 8, 13, 21, 9999]
    hist = np.zeros(len(bins), dtype=np.float64)
    for b in bursts:
        for i, bound in enumerate(bins):
            if b <= bound:
                hist[i] += 1
                break

    hist /= max(1, len(bursts))
    return hist.tolist()


def extract_wf_features(trace, head_packets=30, window_size=20, window_count=15):
    non_zero = trace[trace != 0]
    outgoing = non_zero[non_zero > 0]
    incoming = non_zero[non_zero < 0]

    total_packets = int(non_zero.size)
    outgoing_packets = int(outgoing.size)
    incoming_packets = int(incoming.size)

    outgoing_bytes = int(np.sum(outgoing)) if outgoing_packets else 0
    incoming_bytes = int(-np.sum(incoming)) if incoming_packets else 0

    abs_non_zero = np.abs(non_zero)
    mean_abs_packet = float(np.mean(abs_non_zero)) if total_packets else 0.0
    std_abs_packet = float(np.std(abs_non_zero)) if total_packets else 0.0

    bursts = compute_burst_lengths(non_zero)
    avg_burst = float(np.mean(bursts)) if bursts else 0.0
    max_burst = int(np.max(bursts)) if bursts else 0

    if total_packets > 1:
        direction_changes = int(
            np.sum(np.sign(non_zero[1:]) != np.sign(non_zero[:-1]))
        )
    else:
        direction_changes = 0

    # Keep first packet magnitudes and first packet directions as sequence hints.
    head = trace[:head_packets]
    if head.size < head_packets:
        head = np.pad(head, (0, head_packets - head.size), mode="constant")

    head_abs = np.abs(head).astype(np.float64)
    # Clip and normalize packet size to reduce dominance of large outliers.
    head_abs = np.clip(head_abs, 0, 2000) / 2000.0
    head_dir = np.sign(head).astype(np.float64)

    # Direction-balance windows over first packets as low-cost temporal structure.
    window_features = []
    window_span = window_size * window_count
    head_for_windows = trace[:window_span]
    if head_for_windows.size < window_span:
        head_for_windows = np.pad(
            head_for_windows, (0, window_span - head_for_windows.size), mode="constant"
        )
    signs = np.sign(head_for_windows)
    for i in range(window_count):
        start = i * window_size
        end = start + window_size
        window = signs[start:end]
        window_features.append(float(np.sum(window)) / float(window_size))

    burst_hist = burst_histogram(bursts)

    return [
        total_packets,
        outgoing_packets,
        incoming_packets,
        outgoing_bytes,
        incoming_bytes,
        mean_abs_packet,
        std_abs_packet,
        avg_burst,
        max_burst,
        direction_changes,
    ] + head_abs.tolist() + head_dir.tolist() + window_features + burst_hist


def load_dataset(csv_path):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset file not found: {csv_path}")

    X, y = [], []
    with open(csv_path, "r", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)

        for row in reader:
            if not row:
                continue
            label = row[0].strip()
            if label == "":
                continue
            trace = parse_trace_values(row[1:])
            X.append(extract_wf_features(trace))
            y.append(label)

    if not X:
        raise ValueError("No usable rows found in dataset.")

    return np.array(X, dtype=np.float64), np.array(y)


def top5_accuracy_from_model(model, X_test, y_test, labels):
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_test)
        k = min(5, len(labels))
        return top_k_accuracy_score(y_test, probs, k=k, labels=labels)

    # Fallback for models without probability output.
    y_pred = model.predict(X_test)
    return accuracy_score(y_test, y_pred)


def make_models(random_state):
    return {
        "knn": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("clf", KNeighborsClassifier(n_neighbors=4, metric="manhattan")),
            ]
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=1,
            random_state=random_state,
            n_jobs=-1,
        ),
        "grad_boost": GradientBoostingClassifier(
            random_state=random_state,
            n_estimators=300,
            learning_rate=0.05,
            max_depth=3,
        ),
        "linear_svm": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("clf", LinearSVC(random_state=random_state)),
            ]
        ),
    }


def evaluate_with_holdout(model, X, y, class_names, test_size, random_state):
    labels = np.arange(len(class_names))
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    top1 = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    top5 = top5_accuracy_from_model(model, X_test, y_test, labels)
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    report = classification_report(
        y_test,
        y_pred,
        target_names=class_names,
        zero_division=0,
    )

    return {
        "top1": top1,
        "top5": top5,
        "macro_f1": macro_f1,
        "report": report,
        "confusion_matrix": cm,
    }


def run_model_comparison(models, X, y, cv_folds, random_state):
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    results = []

    for name, model in models.items():
        cv_result = cross_validate(
            model,
            X,
            y,
            cv=cv,
            scoring={"top1": "accuracy", "macro_f1": "f1_macro"},
            n_jobs=-1,
        )
        results.append(
            {
                "name": name,
                "top1_mean": float(np.mean(cv_result["test_top1"])),
                "top1_std": float(np.std(cv_result["test_top1"])),
                "macro_f1_mean": float(np.mean(cv_result["test_macro_f1"])),
                "macro_f1_std": float(np.std(cv_result["test_macro_f1"])),
            }
        )

    results.sort(key=lambda r: r["top1_mean"], reverse=True)
    return results


def tune_model(best_name, best_model, X, y, cv_folds, random_state):
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)

    if best_name == "knn":
        param_grid = {
            "clf__n_neighbors": [1, 3, 5, 7, 11],
            "clf__weights": ["uniform", "distance"],
            "clf__metric": ["manhattan", "euclidean"],
        }
    elif best_name == "random_forest":
        param_grid = {
            "n_estimators": [200, 400],
            "max_depth": [None, 20, 40],
            "min_samples_leaf": [1, 2, 4],
        }
    elif best_name == "grad_boost":
        param_grid = {
            "n_estimators": [200, 400],
            "learning_rate": [0.03, 0.05, 0.1],
            "max_depth": [2, 3],
        }
    else:
        param_grid = {
            "clf__C": [0.1, 1.0, 3.0, 10.0],
            "clf__loss": ["hinge", "squared_hinge"],
        }

    search = GridSearchCV(
        estimator=best_model,
        param_grid=param_grid,
        scoring="accuracy",
        cv=cv,
        n_jobs=-1,
        verbose=0,
    )
    search.fit(X, y)
    return search.best_estimator_, search.best_params_, float(search.best_score_)


def save_confusion_matrix(confusion, class_names, output_path):
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["label"] + list(class_names))
        for i, row in enumerate(confusion):
            writer.writerow([class_names[i]] + row.tolist())


def print_summary_table(results):
    print("\n=== Cross-Validation Model Comparison ===")
    print(
        "model".ljust(16),
        "top1_mean".rjust(10),
        "top1_std".rjust(10),
        "macro_f1".rjust(10),
        "f1_std".rjust(10),
    )
    for r in results:
        print(
            r["name"].ljust(16),
            f"{r['top1_mean']:.4f}".rjust(10),
            f"{r['top1_std']:.4f}".rjust(10),
            f"{r['macro_f1_mean']:.4f}".rjust(10),
            f"{r['macro_f1_std']:.4f}".rjust(10),
        )


def main():
    parser = argparse.ArgumentParser(
        description="Website fingerprinting benchmark, tuning, and reporting"
    )
    parser.add_argument(
        "--dataset",
        default=default_dataset_path(),
        help="Path to wf_dataset.csv",
    )
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--confusion-output",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "confusion_matrix.csv",
        ),
        help="Path to write confusion matrix CSV",
    )
    args = parser.parse_args()

    X, y_labels = load_dataset(args.dataset)

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_labels)
    class_names = encoder.classes_

    if len(np.unique(y)) < 2:
        raise ValueError("Need at least 2 classes to train a classifier.")

    models = make_models(args.seed)
    comparison = run_model_comparison(models, X, y, args.cv_folds, args.seed)
    print_summary_table(comparison)

    best_name = comparison[0]["name"]
    print(f"\nBest model by CV top-1: {best_name}")

    tuned_model, best_params, best_cv_score = tune_model(
        best_name,
        models[best_name],
        X,
        y,
        args.cv_folds,
        args.seed,
    )

    print("\n=== Hyperparameter Tuning ===")
    print(f"best_cv_top1: {best_cv_score:.4f}")
    print(f"best_params: {best_params}")

    holdout = evaluate_with_holdout(
        tuned_model,
        X,
        y,
        class_names,
        args.test_size,
        args.seed,
    )

    print("\n=== Holdout Evaluation ===")
    print(f"top1_accuracy: {holdout['top1']:.4f}")
    print(f"top5_accuracy: {holdout['top5']:.4f}")
    print(f"macro_f1: {holdout['macro_f1']:.4f}")

    print("\nPer-class report:")
    print(holdout["report"])

    save_confusion_matrix(
        holdout["confusion_matrix"],
        class_names,
        args.confusion_output,
    )
    print(f"Confusion matrix saved to: {args.confusion_output}")


if __name__ == "__main__":
    main()