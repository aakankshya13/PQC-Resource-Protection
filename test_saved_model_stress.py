"""
Saved-model false-positive / false-negative stress test
For: PQC-Aware Resource Protection capstone

Run from the project folder:
    python test_saved_model_stress.py

This script loads the existing pqc_anomaly_detector.pkl model. It does NOT train a new model.
The scenarios are hand-designed synthetic stress cases, not real-world ground truth.
"""

from pathlib import Path
import sys
import joblib
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report

MODEL_PATH = Path("pqc_anomaly_detector.pkl")
OUTPUT_PATH = Path("saved_model_stress_test_results.csv")

FEATURES = [
    "traffic_rate",
    "message_size",
    "buffer_utilization",
    "pqc_processing_time",
    "resource_consumption",
    "message_priority",
    "network_available",
]

# Expected labels describe the scenario we intentionally constructed.
# They are for stress-test comparison only, not independently verified ground truth.
SCENARIOS = [
    # Normal traffic cases, including busy-but-legitimate and emergency traffic.
    {"case_id": "N01", "scenario": "Normal low traffic", "expected": "NORMAL",
     "traffic_rate": 2, "message_size": 180, "buffer_utilization": 20,
     "pqc_processing_time": 0.00030, "resource_consumption": 20,
     "message_priority": 3, "network_available": 1},
    {"case_id": "N02", "scenario": "Normal moderate traffic", "expected": "NORMAL",
     "traffic_rate": 8, "message_size": 400, "buffer_utilization": 45,
     "pqc_processing_time": 0.00035, "resource_consumption": 35,
     "message_priority": 3, "network_available": 1},
    {"case_id": "N03", "scenario": "Legitimate traffic during congestion", "expected": "NORMAL",
     "traffic_rate": 9, "message_size": 450, "buffer_utilization": 88,
     "pqc_processing_time": 0.00045, "resource_consumption": 55,
     "message_priority": 3, "network_available": 0},
    {"case_id": "N04", "scenario": "Emergency message during congestion", "expected": "NORMAL",
     "traffic_rate": 4, "message_size": 350, "buffer_utilization": 90,
     "pqc_processing_time": 0.00045, "resource_consumption": 55,
     "message_priority": 5, "network_available": 0},

    # Suspicious/flooding cases. Include lower-rate attacks to test missed detections.
    {"case_id": "S01", "scenario": "Moderate flooding", "expected": "SUSPICIOUS",
     "traffic_rate": 18, "message_size": 700, "buffer_utilization": 70,
     "pqc_processing_time": 0.00065, "resource_consumption": 65,
     "message_priority": 1, "network_available": 1},
    {"case_id": "S02", "scenario": "High-rate flooding", "expected": "SUSPICIOUS",
     "traffic_rate": 35, "message_size": 900, "buffer_utilization": 85,
     "pqc_processing_time": 0.00090, "resource_consumption": 80,
     "message_priority": 1, "network_available": 0},
    {"case_id": "S03", "scenario": "Low-rate flooding", "expected": "SUSPICIOUS",
     "traffic_rate": 6, "message_size": 700, "buffer_utilization": 55,
     "pqc_processing_time": 0.00045, "resource_consumption": 45,
     "message_priority": 1, "network_available": 1},
    {"case_id": "S04", "scenario": "Burst after contact returns", "expected": "SUSPICIOUS",
     "traffic_rate": 24, "message_size": 500, "buffer_utilization": 65,
     "pqc_processing_time": 0.00070, "resource_consumption": 70,
     "message_priority": 1, "network_available": 1},

    # Resource-exhaustion cases.
    {"case_id": "R01", "scenario": "High buffer and resource use", "expected": "RESOURCE_EXHAUSTION",
     "traffic_rate": 12, "message_size": 1200, "buffer_utilization": 96,
     "pqc_processing_time": 0.00120, "resource_consumption": 95,
     "message_priority": 1, "network_available": 0},
    {"case_id": "R02", "scenario": "Sustained resource exhaustion", "expected": "RESOURCE_EXHAUSTION",
     "traffic_rate": 28, "message_size": 1400, "buffer_utilization": 99,
     "pqc_processing_time": 0.00140, "resource_consumption": 98,
     "message_priority": 1, "network_available": 0},
    {"case_id": "R03", "scenario": "Large message under high load", "expected": "RESOURCE_EXHAUSTION",
     "traffic_rate": 16, "message_size": 1500, "buffer_utilization": 92,
     "pqc_processing_time": 0.00100, "resource_consumption": 90,
     "message_priority": 2, "network_available": 1},
    {"case_id": "R04", "scenario": "High resource use at moderate rate", "expected": "RESOURCE_EXHAUSTION",
     "traffic_rate": 8, "message_size": 1000, "buffer_utilization": 95,
     "pqc_processing_time": 0.00110, "resource_consumption": 92,
     "message_priority": 2, "network_available": 0},
]


def load_saved_model(path):
    if not path.exists():
        print(f"[ERROR] Model file not found: {path.resolve()}")
        print("Run this script from the folder containing pqc_anomaly_detector.pkl.")
        sys.exit(1)

    bundle = joblib.load(path)

    # The project model is expected to be saved as a dictionary with model + features.
    if isinstance(bundle, dict):
        model = bundle.get("model")
        saved_features = bundle.get("features", FEATURES)
        if model is None:
            print("[ERROR] The pickle is a dictionary but has no 'model' key.")
            print("Dictionary keys:", list(bundle.keys()))
            sys.exit(1)
        return model, list(saved_features)

    # Also allow a model object saved directly.
    return bundle, FEATURES


def main():
    print("=" * 76)
    print("SAVED MODEL: FALSE-POSITIVE / FALSE-NEGATIVE STRESS TEST")
    print("=" * 76)
    model, model_features = load_saved_model(MODEL_PATH)
    print(f"Loaded existing model: {MODEL_PATH.resolve()}")
    print("No training was performed.")
    print("Model features:", ", ".join(model_features))

    missing = [feature for feature in model_features if feature not in FEATURES]
    if missing:
        print("[ERROR] Script has no scenario values for required features:", missing)
        sys.exit(1)

    df = pd.DataFrame(SCENARIOS)
    X = df[model_features].copy()

    try:
        predictions = model.predict(X)
    except Exception as exc:
        print("\n[ERROR] The saved model rejected the feature input.")
        print("Details:", repr(exc))
        print("Check that the model was trained with these seven numeric features.")
        sys.exit(1)

    df["predicted"] = predictions
    if hasattr(model, "predict_proba"):
        try:
            probabilities = model.predict_proba(X)
            classes = list(model.classes_)
            df["confidence"] = [
                round(float(max(row)), 4) for row in probabilities
            ]
            for idx, class_name in enumerate(classes):
                safe_name = str(class_name).replace(" ", "_")
                df[f"prob_{safe_name}"] = [
                    round(float(row[idx]), 4) for row in probabilities
                ]
        except Exception:
            df["confidence"] = pd.NA
    else:
        df["confidence"] = pd.NA

    df["correct_for_designed_scenario"] = df["expected"] == df["predicted"]
    df["error_type"] = ""
    normal_mask = df["expected"] == "NORMAL"
    df.loc[normal_mask & (df["predicted"] != "NORMAL"), "error_type"] = "FALSE_POSITIVE"
    df.loc[(~normal_mask) & (df["predicted"] == "NORMAL"), "error_type"] = "FALSE_NEGATIVE"
    df.loc[(~normal_mask) & (df["predicted"] != "NORMAL") &
           (df["predicted"] != df["expected"]), "error_type"] = "CLASS_CONFUSION"

    display_cols = [
        "case_id", "scenario", "expected", "predicted", "confidence",
        "correct_for_designed_scenario", "error_type"
    ]
    print("\n--- PER-SCENARIO RESULTS ---")
    print(df[display_cols].to_string(index=False))

    labels = ["NORMAL", "SUSPICIOUS", "RESOURCE_EXHAUSTION"]
    print("\n--- CONFUSION MATRIX (DESIGNED SCENARIO LABELS) ---")
    print("Label order:", labels)
    print(pd.DataFrame(
        confusion_matrix(df["expected"], df["predicted"], labels=labels),
        index=[f"Actual {x}" for x in labels],
        columns=[f"Predicted {x}" for x in labels],
    ).to_string())

    print("\n--- CLASSIFICATION REPORT (DESIGNED SCENARIO LABELS) ---")
    print(classification_report(
        df["expected"], df["predicted"], labels=labels,
        zero_division=0, digits=3
    ))

    fp = int((normal_mask & (df["predicted"] != "NORMAL")).sum())
    normal_total = int(normal_mask.sum())
    attack_mask = ~normal_mask
    fn = int((attack_mask & (df["predicted"] == "NORMAL")).sum())
    attack_total = int(attack_mask.sum())
    print("--- KEY COUNTS ---")
    print(f"Normal scenarios falsely flagged: {fp}/{normal_total}")
    print(f"Normal false-positive rate on these designed cases: {fp / normal_total:.1%}")
    print(f"Attack/resource scenarios predicted NORMAL: {fn}/{attack_total}")
    print(f"False-negative rate on these designed cases: {fn / attack_total:.1%}")
    print("NOTE: These rates describe only these 12 hand-designed synthetic scenarios.")
    print("They are not population estimates and are not a substitute for held-out testing.")

    df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved per-scenario results to: {OUTPUT_PATH.resolve()}")


if __name__ == "__main__":
    main()
