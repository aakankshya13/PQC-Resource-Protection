"""Independent evaluation of the project's synthetic-data anomaly detector.

This script does NOT modify pqc_anomaly_detector.pkl or the main DTN experiment.
It trains fresh Random Forest models on a stratified train/test split and compares:
  1. All seven numeric input features
  2. The same features excluding traffic_rate (feature-ablation check)

Outputs:
  ml_evaluation_summary.csv
  ml_test_predictions.csv
  ml_confusion_matrix.csv
  ml_feature_importance.csv

Run from the project folder:
  python evaluate_ml_model.py

Important: these metrics evaluate a synthetic dataset only. They are not
real-world UAV or attacker-detection performance estimates.
"""

from pathlib import Path
import sys

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score

DATASET_FILE = Path("pqc_traffic_dataset.csv")
RANDOM_STATE = 42
TEST_SIZE = 0.20

FEATURES = [
    "traffic_rate",
    "message_size",
    "buffer_utilization",
    "pqc_processing_time",
    "resource_consumption",
    "message_priority",
    "network_available",
]

TARGET_CANDIDATES = ["label", "target", "class", "anomaly_label", "threat_label"]


def find_target_column(frame):
    for column in TARGET_CANDIDATES:
        if column in frame.columns:
            return column
    raise ValueError(
        "Could not identify the label column. Expected one of: "
        + ", ".join(TARGET_CANDIDATES)
        + f"\nDataset columns are: {list(frame.columns)}"
    )


def make_model():
    return RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        min_samples_leaf=1,
        n_jobs=-1,
    )


def safe_class_metric(y_true, y_pred, target_class, metric):
    labels = sorted(set(y_true) | set(y_pred))
    if target_class not in labels:
        return 0.0
    if metric == "precision":
        return precision_score(y_true, y_pred, labels=[target_class], average="macro", zero_division=0)
    if metric == "recall":
        return recall_score(y_true, y_pred, labels=[target_class], average="macro", zero_division=0)
    return f1_score(y_true, y_pred, labels=[target_class], average="macro", zero_division=0)


def evaluate_variant(name, x_train, x_test, y_train, y_test, class_names):
    model = make_model()
    model.fit(x_train, y_train)
    predicted = model.predict(x_test)

    normal_labels = [c for c in class_names if str(c).strip().upper() == "NORMAL"]
    resource_labels = [c for c in class_names if "RESOURCE_EXHAUSTION" in str(c).strip().upper()]

    normal_fpr = None
    if normal_labels:
        normal_mask = y_test.astype(str).str.strip().str.upper().eq("NORMAL")
        if normal_mask.any():
            normal_fpr = float((pd.Series(predicted, index=y_test.index)[normal_mask].astype(str).str.strip().str.upper() != "NORMAL").mean())

    resource_recall = None
    if resource_labels:
        resource_recall = safe_class_metric(
            y_test.astype(str).tolist(),
            pd.Series(predicted).astype(str).tolist(),
            str(resource_labels[0]),
            "recall",
        )

    row = {
        "Model Variant": name,
        "Test Samples": int(len(y_test)),
        "Accuracy": float(accuracy_score(y_test, predicted)),
        "Balanced Accuracy": float(balanced_accuracy_score(y_test, predicted)),
        "Macro F1": float(f1_score(y_test, predicted, average="macro", zero_division=0)),
        "Normal False Positive Rate": normal_fpr,
        "Resource Exhaustion Recall": resource_recall,
    }

    report = classification_report(
        y_test,
        predicted,
        labels=class_names,
        output_dict=True,
        zero_division=0,
    )

    return model, predicted, row, report


def main():
    if not DATASET_FILE.exists():
        print(f"ERROR: Dataset not found: {DATASET_FILE.resolve()}")
        print("Copy evaluate_ml_model.py into the project folder containing pqc_traffic_dataset.csv.")
        sys.exit(1)

    frame = pd.read_csv(DATASET_FILE)
    target = find_target_column(frame)
    missing = [column for column in FEATURES if column not in frame.columns]
    if missing:
        raise ValueError(
            "Dataset is missing required feature columns: " + ", ".join(missing)
            + f"\nAvailable columns: {list(frame.columns)}"
        )

    data = frame[FEATURES + [target]].copy()
    for column in FEATURES:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    data[target] = data[target].astype(str).str.strip()
    data = data.dropna(subset=FEATURES + [target])
    data = data[data[target] != ""]

    class_counts = data[target].value_counts().sort_index()
    if len(class_counts) < 2:
        raise ValueError("At least two target classes are required for evaluation.")
    if class_counts.min() < 2:
        raise ValueError("Each class needs at least two records for a stratified split.")

    print("=" * 72)
    print("INDEPENDENT ML MODEL EVALUATION")
    print("=" * 72)
    print("Dataset:", DATASET_FILE.resolve())
    print("Target column:", target)
    print("Usable records:", len(data))
    print("Features:", ", ".join(FEATURES))
    print("Class distribution:")
    print(class_counts.to_string())

    x = data[FEATURES]
    y = data[target]
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    class_names = sorted(y.unique().tolist())

    full_model, full_pred, full_row, full_report = evaluate_variant(
        "All 7 features", x_train, x_test, y_train, y_test, class_names
    )

    ablation_features = [feature for feature in FEATURES if feature != "traffic_rate"]
    _, ablation_pred, ablation_row, ablation_report = evaluate_variant(
        "Without traffic_rate",
        x_train[ablation_features],
        x_test[ablation_features],
        y_train,
        y_test,
        class_names,
    )

    summary = pd.DataFrame([full_row, ablation_row])
    summary.to_csv("ml_evaluation_summary.csv", index=False)

    predictions = pd.DataFrame({
        "actual_label": y_test.to_numpy(),
        "predicted_all_7_features": full_pred,
        "predicted_without_traffic_rate": ablation_pred,
    }, index=y_test.index).sort_index()
    predictions.to_csv("ml_test_predictions.csv", index_label="dataset_row")

    cm = confusion_matrix(y_test, full_pred, labels=class_names)
    cm_frame = pd.DataFrame(
        cm,
        index=[f"Actual: {label}" for label in class_names],
        columns=[f"Predicted: {label}" for label in class_names],
    )
    cm_frame.to_csv("ml_confusion_matrix.csv")

    importance = pd.DataFrame({
        "Feature": FEATURES,
        "Importance": full_model.feature_importances_,
    }).sort_values("Importance", ascending=False)
    importance.to_csv("ml_feature_importance.csv", index=False)

    # Cross-validation is run on the same synthetic dataset as an additional
    # stability check. It must not be described as external validation.
    min_class_count = int(class_counts.min())
    folds = min(5, min_class_count)
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=RANDOM_STATE)
    cv_model = make_model()
    cv_scores = cross_val_score(cv_model, x, y, cv=cv, scoring="f1_macro", n_jobs=1)

    print("\n--- HELD-OUT TEST RESULTS (80/20 stratified split) ---")
    print(summary.to_string(index=False, float_format=lambda value: f"{value:.4f}"))
    print("\nClassification report: all 7 features")
    print(classification_report(y_test, full_pred, labels=class_names, zero_division=0))
    print("Confusion matrix labels:", class_names)
    print(cm_frame.to_string())
    print("\nFeature importance:")
    print(importance.to_string(index=False, float_format=lambda value: f"{value:.4f}"))
    print(f"\n{folds}-fold stratified CV macro-F1: mean={cv_scores.mean():.4f}, std={cv_scores.std():.4f}")

    print("\nFiles saved:")
    print("- ml_evaluation_summary.csv")
    print("- ml_test_predictions.csv")
    print("- ml_confusion_matrix.csv")
    print("- ml_feature_importance.csv")
    print("\nLIMITATION: this is a held-out evaluation on a synthetic dataset. It does not establish real-world detection accuracy.")
    print("Review the 'Without traffic_rate' result: a large performance drop suggests the model relies heavily on that feature.")


if __name__ == "__main__":
    main()

