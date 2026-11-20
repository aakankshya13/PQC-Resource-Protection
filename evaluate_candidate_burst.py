"""
Independent burst-after-contact stress evaluation for the PQC capstone.

Run:
    python evaluate_candidate_burst.py

Reads:
    pqc_traffic_dataset.csv
    pqc_anomaly_detector.pkl

Does not modify the saved model, dataset, or V6 files.
It trains a temporary candidate model in memory with supplemental synthetic examples,
then compares baseline and candidate on a fresh deterministic set of scenarios.
"""

from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import accuracy_score, classification_report

DATA_PATH = Path("pqc_traffic_dataset.csv")
MODEL_PATH = Path("pqc_anomaly_detector.pkl")
OUTPUT_PATH = Path("candidate_burst_evaluation.csv")

FEATURES = [
    "traffic_rate", "message_size", "buffer_utilization",
    "pqc_processing_time", "resource_consumption",
    "message_priority", "network_available",
]
LABELS = ["NORMAL", "SUSPICIOUS", "RESOURCE_EXHAUSTION"]


def load_bundle(path):
    bundle = joblib.load(path)
    if isinstance(bundle, dict):
        model = bundle.get("model")
        features = list(bundle.get("features", FEATURES))
        if model is None:
            raise ValueError("Saved bundle has no 'model' key.")
        return model, features
    return bundle, FEATURES


def build_supplemental_training(seed=81273, n=300):
    """Synthetic training coverage; deliberately not the evaluation cases."""
    rng = np.random.default_rng(seed)
    rows = []

    # Low-rate flooding coverage, broad enough not to copy the S03 stress row.
    for _ in range(n):
        rows.append({
            "traffic_rate": rng.uniform(3, 10),
            "message_size": rng.integers(520, 901),
            "buffer_utilization": rng.uniform(40, 72),
            "pqc_processing_time": rng.uniform(0.00030, 0.00070),
            "resource_consumption": rng.uniform(35, 68),
            "message_priority": rng.choice([1, 1, 1, 2]),
            "network_available": rng.integers(0, 2),
            "label": "SUSPICIOUS",
        })

    # Resource exhaustion even when the traffic rate is not extreme.
    for _ in range(n):
        rows.append({
            "traffic_rate": rng.uniform(5, 15),
            "message_size": rng.integers(800, 1301),
            "buffer_utilization": rng.uniform(90, 99.5),
            "pqc_processing_time": rng.uniform(0.00075, 0.00150),
            "resource_consumption": rng.uniform(84, 99.5),
            "message_priority": rng.choice([1, 2]),
            "network_available": rng.integers(0, 2),
            "label": "RESOURCE_EXHAUSTION",
        })

    # Burst after contact returns: elevated rate/queue/resource signals, with
    # variation and without copying the S04 hand-designed scenario.
    for _ in range(n):
        rows.append({
            "traffic_rate": rng.uniform(18, 32),
            "message_size": rng.integers(400, 850),
            "buffer_utilization": rng.uniform(58, 82),
            "pqc_processing_time": rng.uniform(0.00055, 0.00095),
            "resource_consumption": rng.uniform(60, 82),
            "message_priority": rng.choice([1, 1, 1, 2]),
            "network_available": 1,
            "label": "SUSPICIOUS",
        })

    return pd.DataFrame(rows)


def build_fresh_scenarios(seed=9917, n_each=40):
    """New varied evaluation rows, distinct from the fixed 12 scenarios."""
    rng = np.random.default_rng(seed)
    rows = []

    # Normal and emergency traffic: includes busy conditions to check false alarms.
    for i in range(n_each):
        emergency = i % 2 == 0
        rows.append({
            "case_id": f"N{i+1:03d}",
            "scenario": "Emergency/normal traffic under varying load",
            "expected": "NORMAL",
            "traffic_rate": rng.uniform(1.5, 10),
            "message_size": rng.integers(100, 600),
            "buffer_utilization": rng.uniform(15, 91),
            "pqc_processing_time": rng.uniform(0.00020, 0.00055),
            "resource_consumption": rng.uniform(15, 58),
            "message_priority": 5 if emergency else 3,
            "network_available": int(rng.integers(0, 2)),
        })

    # Burst-after-contact suspicious cases.
    for i in range(n_each):
        rows.append({
            "case_id": f"B{i+1:03d}",
            "scenario": "Burst after contact returns",
            "expected": "SUSPICIOUS",
            "traffic_rate": rng.uniform(18, 32),
            "message_size": rng.integers(400, 850),
            "buffer_utilization": rng.uniform(58, 82),
            "pqc_processing_time": rng.uniform(0.00055, 0.00095),
            "resource_consumption": rng.uniform(60, 82),
            "message_priority": int(rng.choice([1, 2])),
            "network_available": 1,
        })

    # Low-rate flooding cases.
    for i in range(n_each):
        rows.append({
            "case_id": f"L{i+1:03d}",
            "scenario": "Low-rate flooding",
            "expected": "SUSPICIOUS",
            "traffic_rate": rng.uniform(3, 10),
            "message_size": rng.integers(520, 901),
            "buffer_utilization": rng.uniform(40, 72),
            "pqc_processing_time": rng.uniform(0.00030, 0.00070),
            "resource_consumption": rng.uniform(35, 68),
            "message_priority": int(rng.choice([1, 2])),
            "network_available": int(rng.integers(0, 2)),
        })

    # Resource exhaustion with moderate rates.
    for i in range(n_each):
        rows.append({
            "case_id": f"R{i+1:03d}",
            "scenario": "Resource exhaustion at moderate traffic rate",
            "expected": "RESOURCE_EXHAUSTION",
            "traffic_rate": rng.uniform(5, 15),
            "message_size": rng.integers(800, 1301),
            "buffer_utilization": rng.uniform(90, 99.5),
            "pqc_processing_time": rng.uniform(0.00075, 0.00150),
            "resource_consumption": rng.uniform(84, 99.5),
            "message_priority": int(rng.choice([1, 2])),
            "network_available": int(rng.integers(0, 2)),
        })

    return pd.DataFrame(rows)


def main():
    print("=" * 78)
    print("FRESH SYNTHETIC STRESS EVALUATION: BASELINE VS CANDIDATE")
    print("=" * 78)

    for p in (DATA_PATH, MODEL_PATH):
        if not p.exists():
            print(f"[ERROR] Missing required file: {p.resolve()}")
            sys.exit(1)

    baseline, model_features = load_bundle(MODEL_PATH)
    if model_features != FEATURES:
        print("[ERROR] Saved model feature list differs from this script's expected features.")
        print("Saved:", model_features)
        sys.exit(1)

    original = pd.read_csv(DATA_PATH)
    required = set(FEATURES + ["label"])
    missing = required - set(original.columns)
    if missing:
        print("[ERROR] Dataset is missing columns:", sorted(missing))
        sys.exit(1)

    supplemental = build_supplemental_training()
    train = pd.concat(
        [original[FEATURES + ["label"]], supplemental[FEATURES + ["label"]]],
        ignore_index=True,
    )
    candidate = clone(baseline)
    candidate.fit(train[FEATURES], train["label"].astype(str))

    test = build_fresh_scenarios()
    X = test[FEATURES]
    y = test["expected"].astype(str)
    test["baseline_prediction"] = baseline.predict(X)
    test["candidate_prediction"] = candidate.predict(X)

    test["baseline_correct"] = test["baseline_prediction"] == y
    test["candidate_correct"] = test["candidate_prediction"] == y
    test.to_csv(OUTPUT_PATH, index=False)

    print(f"Original dataset records: {len(original)}")
    print(f"Supplemental training records: {len(supplemental)}")
    print(f"Fresh evaluation scenarios: {len(test)}")
    print("\n--- PERFORMANCE BY SCENARIO GROUP ---")
    for group, mask in [
        ("NORMAL / EMERGENCY", test["expected"].eq("NORMAL")),
        ("BURST AFTER CONTACT", test["scenario"].eq("Burst after contact returns")),
        ("LOW-RATE FLOODING", test["scenario"].eq("Low-rate flooding")),
        ("RESOURCE EXHAUSTION", test["scenario"].eq("Resource exhaustion at moderate traffic rate")),
    ]:
        part = test.loc[mask]
        b_acc = accuracy_score(part["expected"], part["baseline_prediction"])
        c_acc = accuracy_score(part["expected"], part["candidate_prediction"])
        print(f"{group}: baseline={b_acc:.1%} ({int(part['baseline_correct'].sum())}/{len(part)}), "
              f"candidate={c_acc:.1%} ({int(part['candidate_correct'].sum())}/{len(part)})")

    normal = test["expected"].eq("NORMAL")
    print("\n--- SUMMARY ---")
    print(f"Baseline overall accuracy: {accuracy_score(y, test['baseline_prediction']):.1%}")
    print(f"Candidate overall accuracy: {accuracy_score(y, test['candidate_prediction']):.1%}")
    print(f"Baseline normal false positives: {(normal & test['baseline_prediction'].ne('NORMAL')).sum()}/{normal.sum()}")
    print(f"Candidate normal false positives: {(normal & test['candidate_prediction'].ne('NORMAL')).sum()}/{normal.sum()}")
    print("\n--- BASELINE REPORT ---")
    print(classification_report(y, test["baseline_prediction"], labels=LABELS, zero_division=0, digits=3))
    print("--- CANDIDATE REPORT ---")
    print(classification_report(y, test["candidate_prediction"], labels=LABELS, zero_division=0, digits=3))

    print(f"\nSaved per-scenario results to: {OUTPUT_PATH.resolve()}")
    print("Existing model, dataset, and V6 files were not modified.")
    print("All additional examples and evaluation labels are synthetic by construction.")
    print("These results measure consistency on this synthetic generator, not real-world accuracy.")


if __name__ == "__main__":
    main()
