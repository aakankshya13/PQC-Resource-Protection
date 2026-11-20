import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_FILE = "pqc_traffic_dataset.csv"
MODEL_FILE = "pqc_anomaly_detector.pkl"


# ============================================================
# LOAD DATASET
# ============================================================

data = pd.read_csv(
    DATASET_FILE
)


print()
print("========================================")
print("       ML ANOMALY DETECTION")
print("========================================")

print()

print(
    "Dataset records:",
    len(data)
)

print(
    "Dataset columns:",
    len(data.columns)
)

print()


# ============================================================
# SELECT ML FEATURES
# ============================================================
#
# traffic_type is intentionally NOT used.
#
# The model should learn from measurable traffic
# and resource characteristics.
#
# ============================================================

feature_columns = [
    "traffic_rate",
    "message_size",
    "buffer_utilization",
    "pqc_processing_time",
    "resource_consumption",
    "message_priority",
    "network_available"
]


X = data[
    feature_columns
]

y = data[
    "label"
]


print("ML features:")

for feature in feature_columns:

    print(
        "-",
        feature
    )

print()

print(
    "Excluded from ML:",
    "traffic_type"
)

print()


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print(
    "Training records:",
    len(X_train)
)

print(
    "Testing records:",
    len(X_test)
)

print()


# ============================================================
# RANDOM FOREST MODEL
# ============================================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)


# ============================================================
# TRAIN MODEL
# ============================================================

print(
    "Training Random Forest..."
)

print()

model.fit(
    X_train,
    y_train
)


# ============================================================
# PREDICTIONS
# ============================================================

y_pred = model.predict(
    X_test
)


# ============================================================
# ACCURACY
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)


print("========================================")
print("          MODEL PERFORMANCE")
print("========================================")

print()

print(
    "Accuracy:",
    f"{accuracy * 100:.2f}%"
)

print()


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print(
    "Classification Report:"
)

print()

print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

labels = [
    "NORMAL",
    "RESOURCE_EXHAUSTION",
    "SUSPICIOUS"
]


matrix = confusion_matrix(
    y_test,
    y_pred,
    labels=labels
)


print(
    "Confusion Matrix:"
)

print()

print(
    "Labels:",
    labels
)

print()

print(
    matrix
)

print()


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

feature_importance = pd.DataFrame(
    {
        "feature": feature_columns,
        "importance": model.feature_importances_
    }
)


feature_importance = (
    feature_importance
    .sort_values(
        by="importance",
        ascending=False
    )
)


print(
    "Feature Importance:"
)

print()

for _, row in feature_importance.iterrows():

    print(
        f"{row['feature']}: "
        f"{row['importance']:.4f}"
    )

print()


# ============================================================
# SAVE MODEL
# ============================================================

model_data = {
    "model": model,
    "features": feature_columns
}


joblib.dump(
    model_data,
    MODEL_FILE
)


print(
    "Model saved to:",
    MODEL_FILE
)

print()

print("========================================")
print("       ML TRAINING COMPLETE")
print("========================================")