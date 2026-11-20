"""Project integrity check; does not require liboqs or run the cryptographic experiment."""
from pathlib import Path
import sys
import py_compile

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parent
REQUIRED = [
    "ml_pqc_secure_dtn_experiment_v2.py",
    "pqc_traffic_dataset.csv",
    "pqc_anomaly_detector.pkl",
    "pqc_manager.py",
    "secure_message.py",
    "secure_dtn_delivery_test.py",
]
FEATURES = [
    "traffic_rate",
    "message_size",
    "buffer_utilization",
    "pqc_processing_time",
    "resource_consumption",
    "message_priority",
    "network_available",
]


def main():
    errors = []
    print("=" * 68)
    print("PQC PROJECT HEALTH CHECK")
    print("=" * 68)

    for filename in REQUIRED:
        if (ROOT / filename).is_file():
            print(f"[OK] Required file: {filename}")
        else:
            errors.append(f"Missing required file: {filename}")
            print(f"[FAIL] Required file: {filename}")

    py_files = sorted(ROOT.glob("*.py"))
    for path in py_files:
        try:
            source = path.read_text(encoding="utf-8")
            compile(source, str(path), "exec")
        except Exception as exc:
            errors.append(f"Syntax error in {path.name}: {exc}")
            print(f"[FAIL] Python syntax: {path.name}: {exc}")
    if py_files:
        print(f"[OK] Python syntax: {len(py_files)} top-level files checked")

    dataset_path = ROOT / "pqc_traffic_dataset.csv"
    if dataset_path.exists():
        try:
            df = pd.read_csv(dataset_path)
            missing = [c for c in FEATURES + ["label"] if c not in df.columns]
            if missing:
                errors.append("Dataset missing columns: " + ", ".join(missing))
                print("[FAIL] Dataset columns missing:", ", ".join(missing))
            else:
                null_count = int(df[FEATURES + ["label"]].isna().sum().sum())
                print(f"[OK] Dataset rows: {len(df)}")
                print("[INFO] Dataset labels:")
                print(df["label"].value_counts().to_string())
                if null_count:
                    errors.append(f"Dataset has {null_count} missing required values")
                    print(f"[FAIL] Dataset missing values: {null_count}")
                else:
                    print("[OK] No missing values in required feature/label columns")
        except Exception as exc:
            errors.append(f"Dataset could not be read: {exc}")
            print(f"[FAIL] Dataset read: {exc}")

    model_path = ROOT / "pqc_anomaly_detector.pkl"
    if model_path.exists():
        try:
            saved = joblib.load(model_path)
            model = saved.get("model") if isinstance(saved, dict) else saved
            model_features = list(saved.get("features", [])) if isinstance(saved, dict) else list(getattr(model, "feature_names_in_", []))
            if model is None:
                raise ValueError("model object is missing")
            if model_features and set(FEATURES) - set(model_features):
                raise ValueError("saved model is missing one or more required features")
            if "traffic_type" in model_features or "label" in model_features:
                raise ValueError("ground-truth traffic_type/label must not be model input")
            print("[OK] Saved model loads")
            print("[OK] Model feature list:", ", ".join(model_features or FEATURES))
            print("[INFO] Model classes:", ", ".join(map(str, getattr(model, "classes_", []))))
        except Exception as exc:
            errors.append(f"Saved model check failed: {exc}")
            print(f"[FAIL] Saved model: {exc}")

    print("-" * 68)
    if errors:
        print(f"CHECK FAILED: {len(errors)} issue(s)")
        for item in errors:
            print(" -", item)
        return 1
    print("STATIC CHECK PASSED. This does not test liboqs runtime or end-to-end behavior.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
