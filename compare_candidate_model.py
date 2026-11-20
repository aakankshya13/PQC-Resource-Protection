"""
Controlled candidate-model experiment for the PQC-aware resource-protection capstone.

Run from the project folder:
    python compare_candidate_model.py

What this script does:
- Loads the existing dataset and saved model.
- Leaves pqc_anomaly_detector.pkl and all V6 files unchanged.
- Creates a SEPARATE candidate model by augmenting the training data with
  explicitly synthetic low-rate flooding and moderate-rate resource-exhaustion examples.
- Compares baseline and candidate predictions on the 12 existing hand-designed scenarios.
- Writes a comparison CSV. It does NOT save/replace a model.

Important:
The added samples are rule-designed synthetic examples, not real traffic.
The 12 scenarios are a small stress test, not an independent population test.
A candidate improvement here is exploratory and must not be reported as real-world accuracy.
"""

from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

DATA_PATH = Path("pqc_traffic_dataset.csv")
MODEL_PATH = Path("pqc_anomaly_detector.pkl")
OUTPUT_PATH = Path("candidate_model_comparison.csv")

FEATURES = [
    "traffic_rate",
    "message_size",
    "buffer_utilization",
    "pqc_processing_time",
    "resource_consumption",
    "message_priority",
    "network_available",
]
LABELS = ["NORMAL", "SUSPICIOUS", "RESOURCE_EXHAUSTION"]

# Same 12 scenarios used by test_saved_model_stress.py.
SCENARIOS = [
    {"case_id":"N01","scenario":"Normal low traffic","expected":"NORMAL","traffic_rate":2,"message_size":180,"buffer_utilization":20,"pqc_processing_time":0.00030,"resource_consumption":20,"message_priority":3,"network_available":1},
    {"case_id":"N02","scenario":"Normal moderate traffic","expected":"NORMAL","traffic_rate":8,"message_size":400,"buffer_utilization":45,"pqc_processing_time":0.00035,"resource_consumption":35,"message_priority":3,"network_available":1},
    {"case_id":"N03","scenario":"Legitimate traffic during congestion","expected":"NORMAL","traffic_rate":9,"message_size":450,"buffer_utilization":88,"pqc_processing_time":0.00045,"resource_consumption":55,"message_priority":3,"network_available":0},
    {"case_id":"N04","scenario":"Emergency message during congestion","expected":"NORMAL","traffic_rate":4,"message_size":350,"buffer_utilization":90,"pqc_processing_time":0.00045,"resource_consumption":55,"message_priority":5,"network_available":0},
    {"case_id":"S01","scenario":"Moderate flooding","expected":"SUSPICIOUS","traffic_rate":18,"message_size":700,"buffer_utilization":70,"pqc_processing_time":0.00065,"resource_consumption":65,"message_priority":1,"network_available":1},
    {"case_id":"S02","scenario":"High-rate flooding","expected":"SUSPICIOUS","traffic_rate":35,"message_size":900,"buffer_utilization":85,"pqc_processing_time":0.00090,"resource_consumption":80,"message_priority":1,"network_available":0},
    {"case_id":"S03","scenario":"Low-rate flooding","expected":"SUSPICIOUS","traffic_rate":6,"message_size":700,"buffer_utilization":55,"pqc_processing_time":0.00045,"resource_consumption":45,"message_priority":1,"network_available":1},
    {"case_id":"S04","scenario":"Burst after contact returns","expected":"SUSPICIOUS","traffic_rate":24,"message_size":500,"buffer_utilization":65,"pqc_processing_time":0.00070,"resource_consumption":70,"message_priority":1,"network_available":1},
    {"case_id":"R01","scenario":"High buffer and resource use","expected":"RESOURCE_EXHAUSTION","traffic_rate":12,"message_size":1200,"buffer_utilization":96,"pqc_processing_time":0.00120,"resource_consumption":95,"message_priority":1,"network_available":0},
    {"case_id":"R02","scenario":"Sustained resource exhaustion","expected":"RESOURCE_EXHAUSTION","traffic_rate":28,"message_size":1400,"buffer_utilization":99,"pqc_processing_time":0.00140,"resource_consumption":98,"message_priority":1,"network_available":0},
    {"case_id":"R03","scenario":"Large message under high load","expected":"RESOURCE_EXHAUSTION","traffic_rate":16,"message_size":1500,"buffer_utilization":92,"pqc_processing_time":0.00100,"resource_consumption":90,"message_priority":2,"network_available":1},
    {"case_id":"R04","scenario":"High resource use at moderate rate","expected":"RESOURCE_EXHAUSTION","traffic_rate":8,"message_size":1000,"buffer_utilization":95,"pqc_processing_time":0.00110,"resource_consumption":92,"message_priority":2,"network_available":0},
]


def load_bundle(path):
    if not path.exists():
        raise FileNotFoundError(f"Missing model: {path.resolve()}")
    bundle = joblib.load(path)
    if isinstance(bundle, dict):
        model = bundle.get("model")
        features = bundle.get("features", FEATURES)
        if model is None:
            raise ValueError("Model bundle has no 'model' key.")
        return model, list(features)
    return bundle, FEATURES


def make_supplemental_samples(seed=20261015, count_per_pattern=250):
    """Generate explicit, reproducible synthetic coverage examples."""
    rng = np.random.default_rng(seed)
    rows = []

    # Low-rate flooding: low-to-moderate rate but attacker-like priority and
    # moderately elevated size/resource features. Avoid exact copies of S03.
    for _ in range(count_per_pattern):
        rows.append({
            "traffic_rate": float(rng.uniform(3.0, 10.0)),
            "message_size": int(rng.integers(520, 901)),
            "buffer_utilization": float(rng.uniform(40.0, 72.0)),
            "pqc_processing_time": float(rng.uniform(0.00030, 0.00070)),
            "resource_consumption": float(rng.uniform(35.0, 68.0)),
            "message_priority": int(rng.choice([1, 1, 1, 2])),
            "network_available": int(rng.integers(0, 2)),
            "traffic_type": "Flooding",
            "label": "SUSPICIOUS",
        })

    # Resource exhaustion at moderate rates: high buffer/resource use even
    # when rate is not extreme. Vary values so the training rows aren't copies.
    for _ in range(count_per_pattern):
        rows.append({
            "traffic_rate": float(rng.uniform(5.0, 15.0)),
            "message_size": int(rng.integers(800, 1301)),
            "buffer_utilization": float(rng.uniform(90.0, 99.5)),
            "pqc_processing_time": float(rng.uniform(0.00075, 0.00150)),
            "resource_consumption": float(rng.uniform(84.0, 99.5)),
            "message_priority": int(rng.choice([1, 2])),
            "network_available": int(rng.integers(0, 2)),
            "traffic_type": "Flooding",
            "label": "RESOURCE_EXHAUSTION",
        })

    return pd.DataFrame(rows)


def main():
    print("=" * 78)
    print("BASELINE VS CANDIDATE MODEL: TARGETED SYNTHETIC COVERAGE EXPERIMENT")
    print("=" * 78)

    for path in (DATA_PATH, MODEL_PATH):
        if not path.exists():
            print(f"[ERROR] Required file not found: {path.resolve()}")
            sys.exit(1)

    baseline, model_features = load_bundle(MODEL_PATH)
    data = pd.read_csv(DATA_PATH)

    required = set(FEATURES + ["label"])
    missing = required - set(data.columns)
    if missing:
        print("[ERROR] Dataset missing columns:", sorted(missing))
        sys.exit(1)
    if list(model_features) != FEATURES:
        print("[ERROR] Saved model feature list differs from expected features:")
        print(model_features)
        sys.exit(1)

    # Keep only the seven model inputs plus target. Any traffic_type column is
    # deliberately excluded because the saved model expects seven numeric inputs.
    base_X = data[FEATURES].copy()
    base_y = data["label"].astype(str).copy()

    supplemental = make_supplemental_samples()
    augmented = pd.concat(
        [data[FEATURES + ["label"]].copy(), supplemental[FEATURES + ["label"]]],
        ignore_index=True,
    )
    candidate = clone(baseline)
    candidate.fit(augmented[FEATURES], augmented["label"].astype(str))

    test_df = pd.DataFrame(SCENARIOS)
    X_test = test_df[FEATURES].copy()
    y_true = test_df["expected"].astype(str)

    test_df["baseline_prediction"] = baseline.predict(X_test)
    test_df["candidate_prediction"] = candidate.predict(X_test)
    test_df["baseline_correct"] = test_df["baseline_prediction"] == y_true
    test_df["candidate_correct"] = test_df["candidate_prediction"] == y_true
    test_df["candidate_changed_prediction"] = (
        test_df["baseline_prediction"] != test_df["candidate_prediction"]
    )

    for prefix, model in (("baseline", baseline), ("candidate", candidate)):
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_test)
            classes = list(model.classes_)
            test_df[f"{prefix}_confidence"] = probabilities.max(axis=1).round(4)
            for idx, class_name in enumerate(classes):
                test_df[f"{prefix}_prob_{class_name}"] = probabilities[:, idx].round(4)

    test_df.to_csv(OUTPUT_PATH, index=False)

    normal = y_true.eq("NORMAL")
    abnormal = ~normal
    print(f"Original training records: {len(data)}")
    print(f"Supplemental synthetic records: {len(supplemental)}")
    print("Supplemental classes:", supplemental["label"].value_counts().to_dict())
    print("\n--- PER-SCENARIO COMPARISON ---")
    cols = [
        "case_id", "scenario", "expected", "baseline_prediction",
        "candidate_prediction", "baseline_correct", "candidate_correct",
        "candidate_changed_prediction",
    ]
    print(test_df[cols].to_string(index=False))

    print("\n--- SUMMARY (12 HAND-DESIGNED SCENARIOS ONLY) ---")
    print(f"Baseline correct: {int(test_df['baseline_correct'].sum())}/12 ({accuracy_score(y_true, test_df['baseline_prediction']):.1%})")
    print(f"Candidate correct: {int(test_df['candidate_correct'].sum())}/12 ({accuracy_score(y_true, test_df['candidate_prediction']):.1%})")
    print(f"Baseline normal false positives: {int((normal & test_df['baseline_prediction'].ne('NORMAL')).sum())}/4")
    print(f"Candidate normal false positives: {int((normal & test_df['candidate_prediction'].ne('NORMAL')).sum())}/4")
    print(f"Baseline abnormal cases predicted NORMAL: {int((abnormal & test_df['baseline_prediction'].eq('NORMAL')).sum())}/8")
    print(f"Candidate abnormal cases predicted NORMAL: {int((abnormal & test_df['candidate_prediction'].eq('NORMAL')).sum())}/8")

    print("\n--- BASELINE CLASSIFICATION REPORT ---")
    print(classification_report(y_true, test_df["baseline_prediction"], labels=LABELS, zero_division=0, digits=3))
    print("--- CANDIDATE CLASSIFICATION REPORT ---")
    print(classification_report(y_true, test_df["candidate_prediction"], labels=LABELS, zero_division=0, digits=3))

    print(f"\nSaved comparison to: {OUTPUT_PATH.resolve()}")
    print("The saved baseline model, dataset, and V6 files were not modified.")
    print("CAUTION: Candidate training used synthetic coverage examples. These results are exploratory only.")
    print("Do not claim real-world accuracy or independent validation from these 12 designed cases.")


if __name__ == "__main__":
    main()
