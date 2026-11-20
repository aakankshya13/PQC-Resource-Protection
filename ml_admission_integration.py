
import joblib
import pandas as pd

from message import Message
from pqc_manager import PQCManager
from secure_message import SecureMessage
from admission_controller import AdmissionController


RELAY_CAPACITY = 5000
MODEL_FILE = "pqc_anomaly_detector.pkl"

SCENARIOS = [
    {
        "name": "Normal Traffic",
        "message_id": "MSG001",
        "message_type": "Normal",
        "priority": 3,
        "payload_size": 300,
        "traffic_rate": 5,
        "buffer_utilization": 30,
        "resource_consumption": 25,
        "network_available": 1,
    },
    {
        "name": "Suspicious Flooding",
        "message_id": "MSG002",
        "message_type": "Flooding",
        "priority": 1,
        "payload_size": 1000,
        "traffic_rate": 45,
        "buffer_utilization": 75,
        "resource_consumption": 70,
        "network_available": 1,
    },
    {
        "name": "Severe Resource Exhaustion",
        "message_id": "MSG003",
        "message_type": "Flooding",
        "priority": 1,
        "payload_size": 1300,
        "traffic_rate": 80,
        "buffer_utilization": 95,
        "resource_consumption": 90,
        "network_available": 1,
    },
    {
        "name": "Critical Emergency",
        "message_id": "MSG004",
        "message_type": "Emergency",
        "priority": 5,
        "payload_size": 250,
        "traffic_rate": 3,
        "buffer_utilization": 70,
        "resource_consumption": 35,
        "network_available": 0,
    },
]


def load_trained_model(filename):
    """Load the trained estimator from the saved model file."""
    loaded_data = joblib.load(filename)

    if hasattr(loaded_data, "predict"):
        return loaded_data

    if isinstance(loaded_data, dict):
        preferred_keys = [
            "model",
            "classifier",
            "best_model",
            "trained_model",
            "pipeline",
            "random_forest",
            "rf_model",
            "anomaly_detector",
        ]

        for key in preferred_keys:
            candidate = loaded_data.get(key)
            if hasattr(candidate, "predict"):
                print("Found trained model under key:", key)
                return candidate

        for key, candidate in loaded_data.items():
            if hasattr(candidate, "predict"):
                print("Found trained model under key:", key)
                return candidate

        raise TypeError(
            "No trained model with a predict() method was found. "
            f"Available dictionary keys: {list(loaded_data.keys())}"
        )

    raise TypeError(
        f"Unexpected saved object type: {type(loaded_data).__name__}"
    )


def main():
    print("=" * 50)
    print("      ML + PQC ADMISSION INTEGRATION")
    print("=" * 50)

    model = load_trained_model(MODEL_FILE)
    print("ML model loaded:", type(model).__name__)

    pqc_manager = PQCManager()
    admission_controller = AdmissionController(RELAY_CAPACITY)

    actual_buffer_used = 0
    results = []

    print("Relay capacity:", RELAY_CAPACITY, "bytes")
    print("ML model file:", MODEL_FILE)
    print("Resource conditions: scenario-simulated")
    print()

    for scenario in SCENARIOS:
        print("-" * 50)
        print("Scenario:", scenario["name"])

        payload = b"X" * scenario["payload_size"]

        message = Message(
            scenario["message_id"],
            "UAV1",
            scenario["message_type"],
            scenario["priority"],
            scenario["payload_size"],
        )

        secure_message = SecureMessage(
            message,
            pqc_manager,
            application_payload=payload,
        )

        bundle_size = secure_message.bundle_size()

        # Use named columns to match the model's training features.
        features = pd.DataFrame([{
            "traffic_rate": scenario["traffic_rate"],
            "message_size": scenario["payload_size"],
            "buffer_utilization": scenario["buffer_utilization"],
            "pqc_processing_time": secure_message.pqc_processing_time,
            "resource_consumption": scenario["resource_consumption"],
            "message_priority": scenario["priority"],
            "network_available": scenario["network_available"],
        }])

        # If the saved model uses feature names, validate their order.
        if hasattr(model, "feature_names_in_"):
            expected_features = list(model.feature_names_in_)

            if set(expected_features) != set(features.columns):
                raise ValueError(
                    "Feature columns do not match the trained model.\n"
                    f"Expected: {expected_features}\n"
                    f"Provided: {list(features.columns)}"
                )

            features = features[expected_features]

        prediction = str(model.predict(features)[0])

        confidence = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(features)[0]
            confidence = float(max(probabilities)) * 100

        rule_decision = admission_controller.evaluate(
            scenario["priority"],
            bundle_size,
            actual_buffer_used,
        )

        # Combine ML detection, priority, and rule-based admission.
        if scenario["priority"] >= 5:
            decision = "ACCEPT"

        elif prediction == "RESOURCE_EXHAUSTION":
            decision = "DROP"

        elif prediction == "SUSPICIOUS":
            if rule_decision == "ACCEPT":
                decision = "THROTTLE"
            else:
                decision = rule_decision

        else:
            decision = rule_decision

        # Enforce relay buffer capacity.
        if decision == "ACCEPT":
            if actual_buffer_used + bundle_size > RELAY_CAPACITY:
                decision = (
                    "DELAY"
                    if scenario["priority"] >= 5
                    else "DROP"
                )

        if decision == "ACCEPT":
            actual_buffer_used += bundle_size

        utilization = actual_buffer_used / RELAY_CAPACITY * 100

        print("Application payload:", len(payload), "bytes")
        print("Encrypted bundle:", bundle_size, "bytes")
        print(
            "Scenario buffer utilization:",
            scenario["buffer_utilization"],
            "%",
        )
        print(
            "Actual relay buffer:",
            actual_buffer_used,
            "/",
            RELAY_CAPACITY,
            "bytes",
        )
        print("Actual buffer utilization:", f"{utilization:.2f}%")
        print(
            "PQC processing time:",
            f"{secure_message.pqc_processing_time:.6f}",
            "seconds",
        )
        print("ML prediction:", prediction)

        if confidence is not None:
            print("ML confidence:", f"{confidence:.2f}%")

        print("Rule-based decision:", rule_decision)
        print("Final decision:", decision)

        results.append({
            "scenario": scenario["name"],
            "prediction": prediction,
            "decision": decision,
            "bundle_size": bundle_size,
        })

    print()
    print("=" * 50)
    print("             INTEGRATION SUMMARY")
    print("=" * 50)

    for decision_name in ["ACCEPT", "THROTTLE", "DROP", "DELAY"]:
        count = sum(
            1
            for result in results
            if result["decision"] == decision_name
        )
        print(f"{decision_name.title()}: {count}")

    print(
        "Final buffer usage:",
        actual_buffer_used,
        "/",
        RELAY_CAPACITY,
        "bytes",
    )
    print(
        "Final buffer utilization:",
        f"{actual_buffer_used / RELAY_CAPACITY * 100:.2f}%",
    )

    print()
    print("Scenario predictions and decisions:")

    for result in results:
        print(
            f'{result["scenario"]}: '
            f'{result["prediction"]} -> {result["decision"]}'
        )

    print()
    print("Integration test completed.")


if __name__ == "__main__":
    main()
