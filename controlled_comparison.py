
import joblib
import pandas as pd

from message import Message
from pqc_manager import PQCManager
from secure_message import SecureMessage
from admission_controller import AdmissionController


# ============================================================
# CONFIGURATION
# ============================================================

RELAY_CAPACITY = 5000
MODEL_FILE = "pqc_anomaly_detector.pkl"
RESULT_FILE = "controlled_comparison_results.csv"

ATTACKER_NAME = "AttackerUAV"
EMERGENCY_SOURCE = "EmergencyUAV"


# ============================================================
# LOAD ML MODEL
# ============================================================

saved_model = joblib.load(MODEL_FILE)

if isinstance(saved_model, dict):
    ml_model = saved_model.get("model")

    if ml_model is None or not hasattr(ml_model, "predict"):
        ml_model = next(
            (
                value
                for value in saved_model.values()
                if hasattr(value, "predict")
            ),
            None,
        )

    if ml_model is None:
        raise TypeError("No trained model was found in the model file.")

    ml_features = saved_model.get("features")
else:
    ml_model = saved_model
    ml_features = None

if ml_features is None:
    ml_features = getattr(ml_model, "feature_names_in_", None)

if ml_features is None:
    ml_features = [
        "traffic_rate",
        "message_size",
        "buffer_utilization",
        "pqc_processing_time",
        "resource_consumption",
        "message_priority",
        "network_available",
    ]

ml_features = list(ml_features)

print("Loaded ML model:", type(ml_model).__name__)
print("ML features:", ml_features)


# ============================================================
# FIXED ATTACK TRAFFIC
# These are simulated traffic characteristics.
# ============================================================

attack_traffic = [
    {
        "traffic_rate": 15,
        "message_size": 500,
        "resource_consumption": 50,
        "pqc_processing_time": 0.00050,
    },
    {
        "traffic_rate": 20,
        "message_size": 600,
        "resource_consumption": 55,
        "pqc_processing_time": 0.00055,
    },
    {
        "traffic_rate": 25,
        "message_size": 700,
        "resource_consumption": 60,
        "pqc_processing_time": 0.00060,
    },
    {
        "traffic_rate": 30,
        "message_size": 800,
        "resource_consumption": 70,
        "pqc_processing_time": 0.00070,
    },
    {
        "traffic_rate": 35,
        "message_size": 900,
        "resource_consumption": 75,
        "pqc_processing_time": 0.00075,
    },
    {
        "traffic_rate": 45,
        "message_size": 1000,
        "resource_consumption": 70,
        "pqc_processing_time": 0.00090,
    },
    {
        "traffic_rate": 55,
        "message_size": 1100,
        "resource_consumption": 80,
        "pqc_processing_time": 0.00100,
    },
    {
        "traffic_rate": 65,
        "message_size": 1200,
        "resource_consumption": 88,
        "pqc_processing_time": 0.00110,
    },
    {
        "traffic_rate": 75,
        "message_size": 1300,
        "resource_consumption": 90,
        "pqc_processing_time": 0.00120,
    },
    {
        "traffic_rate": 80,
        "message_size": 1400,
        "resource_consumption": 95,
        "pqc_processing_time": 0.00130,
    },
]


# ============================================================
# FIXED EMERGENCY TRAFFIC
# ============================================================

emergency_traffic = [
    {"message_size": 250, "priority": 5},
    {"message_size": 300, "priority": 5},
    {"message_size": 350, "priority": 5},
]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def create_secure_message(
    message_id,
    source,
    message_type,
    priority,
    payload_size,
    pqc,
):
    """Encrypt a real payload of the requested size."""

    message = Message(
        message_id,
        source,
        message_type,
        priority,
        payload_size,
    )

    # Important: encrypt the actual requested payload size.
    payload = b"X" * payload_size

    secure_message = SecureMessage(
        message,
        pqc,
        application_payload=payload,
    )

    bundle_size = secure_message.bundle_size()

    return message, secure_message, bundle_size


def fits_in_buffer(current_buffer, bundle_size):
    return current_buffer + bundle_size <= RELAY_CAPACITY


def update_peak_buffer(current_buffer, peak_buffer):
    return max(current_buffer, peak_buffer)


def record_decision(decision, counters):
    """Track outcomes without treating throttling as dropping."""

    if decision == "ACCEPT":
        counters["admitted"] += 1
    elif decision == "THROTTLE":
        counters["throttled"] += 1
    elif decision == "DROP":
        counters["dropped"] += 1
    elif decision == "DELAY":
        counters["delayed"] += 1
    else:
        counters["rejected"] += 1


def new_attack_counters():
    return {
        "admitted": 0,
        "throttled": 0,
        "dropped": 0,
        "delayed": 0,
        "rejected": 0,
    }


def new_emergency_counters():
    return {
        "admitted": 0,
        "delayed": 0,
        "dropped": 0,
        "rejected": 0,
    }


def summarize_results(
    approach,
    attack_counters,
    emergency_counters,
    current_buffer,
    peak_buffer,
    total_pqc_time,
):
    """Build a consistent results row for the CSV."""

    attack_not_admitted = (
        attack_counters["throttled"]
        + attack_counters["dropped"]
        + attack_counters["delayed"]
        + attack_counters["rejected"]
    )

    emergency_not_admitted = (
        emergency_counters["delayed"]
        + emergency_counters["dropped"]
        + emergency_counters["rejected"]
    )

    return {
        "Approach": approach,
        "Attack Attempted": len(attack_traffic),
        "Attack Admitted": attack_counters["admitted"],
        "Attack Throttled": attack_counters["throttled"],
        "Attack Dropped": attack_counters["dropped"],
        "Attack Delayed": attack_counters["delayed"],
        "Attack Rejected": attack_counters["rejected"],
        "Attack Not Admitted": attack_not_admitted,
        "Emergency Attempted": len(emergency_traffic),
        "Emergency Admitted to Relay": emergency_counters["admitted"],
        "Emergency Delayed": emergency_counters["delayed"],
        "Emergency Dropped": emergency_counters["dropped"],
        "Emergency Rejected": emergency_counters["rejected"],
        "Emergency Not Admitted": emergency_not_admitted,
        "Peak Buffer Utilization (%)": (
            peak_buffer / RELAY_CAPACITY
        ) * 100,
        "Final Buffer Utilization (%)": (
            current_buffer / RELAY_CAPACITY
        ) * 100,
        "Total PQC Processing Time (s)": total_pqc_time,
    }


# ============================================================
# ML PREDICTION
# ============================================================

def predict_threat(
    traffic_rate,
    message_size,
    buffer_utilization,
    pqc_processing_time,
    resource_consumption,
    message_priority,
    network_available,
):
    row = {
        "traffic_rate": traffic_rate,
        "message_size": message_size,
        "buffer_utilization": buffer_utilization,
        "pqc_processing_time": pqc_processing_time,
        "resource_consumption": resource_consumption,
        "message_priority": message_priority,
        "network_available": network_available,
        "traffic_type_Flooding": 1,
        "traffic_type_Normal": 0,
        "traffic_type_Emergency": 0,
    }

    dataframe = pd.DataFrame([row])
    dataframe = dataframe.reindex(columns=ml_features, fill_value=0)

    prediction = str(ml_model.predict(dataframe)[0])

    confidence = None
    if hasattr(ml_model, "predict_proba"):
        probabilities = ml_model.predict_proba(dataframe)[0]
        confidence = float(max(probabilities)) * 100

    return prediction, confidence


# ============================================================
# 1. NO-PROTECTION BASELINE
# ============================================================

def run_no_protection():
    pqc = PQCManager()

    current_buffer = 0
    peak_buffer = 0
    total_pqc_time = 0.0

    attack_counters = new_attack_counters()
    emergency_counters = new_emergency_counters()

    print()
    print("=" * 50)
    print("1. NO PROTECTION")
    print("=" * 50)

    # Flooding messages are processed first.
    for i, attack in enumerate(attack_traffic, start=1):
        _, secure_message, bundle_size = create_secure_message(
            f"ATTACK-{i:03d}",
            ATTACKER_NAME,
            "Flooding",
            1,
            attack["message_size"],
            pqc,
        )

        # Count cryptographic work for every attempted message.
        total_pqc_time += secure_message.pqc_processing_time

        if fits_in_buffer(current_buffer, bundle_size):
            current_buffer += bundle_size
            peak_buffer = update_peak_buffer(
                current_buffer, peak_buffer
            )
            decision = "ACCEPT"
        else:
            decision = "REJECT"

        record_decision(decision, attack_counters)

        print(
            f"ATTACK-{i:03d} | Payload: {attack['message_size']} bytes "
            f"| Bundle: {bundle_size} bytes | {decision}"
        )

    # Emergency messages follow the attack workload.
    for i, emergency in enumerate(emergency_traffic, start=1):
        _, secure_message, bundle_size = create_secure_message(
            f"EMERGENCY-{i:03d}",
            EMERGENCY_SOURCE,
            "Emergency",
            emergency["priority"],
            emergency["message_size"],
            pqc,
        )

        total_pqc_time += secure_message.pqc_processing_time

        if fits_in_buffer(current_buffer, bundle_size):
            current_buffer += bundle_size
            peak_buffer = update_peak_buffer(
                current_buffer, peak_buffer
            )
            decision = "ACCEPT"
        else:
            decision = "REJECT"

        record_decision(decision, emergency_counters)

        print(
            f"EMERGENCY-{i:03d} | Payload: "
            f"{emergency['message_size']} bytes "
            f"| Bundle: {bundle_size} bytes | {decision}"
        )

    return summarize_results(
        "No Protection",
        attack_counters,
        emergency_counters,
        current_buffer,
        peak_buffer,
        total_pqc_time,
    )


# ============================================================
# 2. RULE-BASED PROTECTION
# ============================================================

def run_rule_based():
    pqc = PQCManager()
    controller = AdmissionController(RELAY_CAPACITY)

    current_buffer = 0
    peak_buffer = 0
    total_pqc_time = 0.0

    attack_counters = new_attack_counters()
    emergency_counters = new_emergency_counters()

    print()
    print("=" * 50)
    print("2. RULE-BASED PROTECTION")
    print("=" * 50)

    for i, attack in enumerate(attack_traffic, start=1):
        _, secure_message, bundle_size = create_secure_message(
            f"ATTACK-{i:03d}",
            ATTACKER_NAME,
            "Flooding",
            1,
            attack["message_size"],
            pqc,
        )

        total_pqc_time += secure_message.pqc_processing_time

        decision = controller.evaluate(
            message_priority=1,
            message_size=bundle_size,
            current_buffer_usage=current_buffer,
        )

        if decision == "ACCEPT":
            if fits_in_buffer(current_buffer, bundle_size):
                current_buffer += bundle_size
                peak_buffer = update_peak_buffer(
                    current_buffer, peak_buffer
                )
            else:
                decision = "DROP"

        record_decision(decision, attack_counters)

        print(
            f"ATTACK-{i:03d} | Payload: {attack['message_size']} bytes "
            f"| Bundle: {bundle_size} bytes | {decision}"
        )

    for i, emergency in enumerate(emergency_traffic, start=1):
        _, secure_message, bundle_size = create_secure_message(
            f"EMERGENCY-{i:03d}",
            EMERGENCY_SOURCE,
            "Emergency",
            emergency["priority"],
            emergency["message_size"],
            pqc,
        )

        total_pqc_time += secure_message.pqc_processing_time

        decision = controller.evaluate(
            message_priority=emergency["priority"],
            message_size=bundle_size,
            current_buffer_usage=current_buffer,
        )

        if decision == "ACCEPT":
            if fits_in_buffer(current_buffer, bundle_size):
                current_buffer += bundle_size
                peak_buffer = update_peak_buffer(
                    current_buffer, peak_buffer
                )
            else:
                decision = "DELAY"

        record_decision(decision, emergency_counters)

        print(
            f"EMERGENCY-{i:03d} | Payload: "
            f"{emergency['message_size']} bytes "
            f"| Bundle: {bundle_size} bytes | {decision}"
        )

    return summarize_results(
        "Rule-Based",
        attack_counters,
        emergency_counters,
        current_buffer,
        peak_buffer,
        total_pqc_time,
    )


# ============================================================
# 3. ML + PQC-AWARE PROTECTION
# ============================================================

def run_ml_pqc_aware():
    pqc = PQCManager()
    controller = AdmissionController(RELAY_CAPACITY)

    current_buffer = 0
    peak_buffer = 0
    total_pqc_time = 0.0

    attack_counters = new_attack_counters()
    emergency_counters = new_emergency_counters()

    print()
    print("=" * 50)
    print("3. ML + PQC-AWARE PROTECTION")
    print("=" * 50)

    # Process attack traffic.
    for i, attack in enumerate(attack_traffic, start=1):
        _, secure_message, bundle_size = create_secure_message(
            f"ATTACK-{i:03d}",
            ATTACKER_NAME,
            "Flooding",
            1,
            attack["message_size"],
            pqc,
        )

        total_pqc_time += secure_message.pqc_processing_time

        buffer_utilization = (
            current_buffer / RELAY_CAPACITY
        ) * 100

        # These are predefined scenario features for the ML model.
        prediction, confidence = predict_threat(
            traffic_rate=attack["traffic_rate"],
            message_size=attack["message_size"],
            buffer_utilization=buffer_utilization,
            pqc_processing_time=attack["pqc_processing_time"],
            resource_consumption=attack["resource_consumption"],
            message_priority=1,
            network_available=1,
        )

        rule_decision = controller.evaluate(
            message_priority=1,
            message_size=bundle_size,
            current_buffer_usage=current_buffer,
        )

        if prediction == "RESOURCE_EXHAUSTION":
            final_decision = "DROP"

        elif prediction == "SUSPICIOUS":
            if rule_decision == "ACCEPT":
                final_decision = "THROTTLE"
            else:
                final_decision = rule_decision

        else:
            final_decision = rule_decision

        if final_decision == "ACCEPT":
            if fits_in_buffer(current_buffer, bundle_size):
                current_buffer += bundle_size
                peak_buffer = update_peak_buffer(
                    current_buffer, peak_buffer
                )
            else:
                final_decision = "DROP"

        record_decision(final_decision, attack_counters)

        confidence_text = (
            f"{confidence:.1f}%"
            if confidence is not None
            else "N/A"
        )

        print(
            f"ATTACK-{i:03d} | ML: {prediction} ({confidence_text}) "
            f"| Rule: {rule_decision} | Final: {final_decision}"
        )

    # Process emergency traffic.
    for i, emergency in enumerate(emergency_traffic, start=1):
        _, secure_message, bundle_size = create_secure_message(
            f"EMERGENCY-{i:03d}",
            EMERGENCY_SOURCE,
            "Emergency",
            emergency["priority"],
            emergency["message_size"],
            pqc,
        )

        total_pqc_time += secure_message.pqc_processing_time

        buffer_utilization = (
            current_buffer / RELAY_CAPACITY
        ) * 100

        prediction, confidence = predict_threat(
            traffic_rate=3,
            message_size=emergency["message_size"],
            buffer_utilization=buffer_utilization,
            pqc_processing_time=0.00035,
            resource_consumption=35,
            message_priority=emergency["priority"],
            network_available=0,
        )

        rule_decision = controller.evaluate(
            message_priority=emergency["priority"],
            message_size=bundle_size,
            current_buffer_usage=current_buffer,
        )

        # Critical emergency traffic receives preferential admission.
        if emergency["priority"] >= 5:
            final_decision = "ACCEPT"
        elif prediction == "RESOURCE_EXHAUSTION":
            final_decision = "DROP"
        else:
            final_decision = rule_decision

        # An emergency can only be admitted if space is available.
        if final_decision == "ACCEPT":
            if fits_in_buffer(current_buffer, bundle_size):
                current_buffer += bundle_size
                peak_buffer = update_peak_buffer(
                    current_buffer, peak_buffer
                )
            else:
                final_decision = "DELAY"

        record_decision(final_decision, emergency_counters)

        confidence_text = (
            f"{confidence:.1f}%"
            if confidence is not None
            else "N/A"
        )

        print(
            f"EMERGENCY-{i:03d} | ML: {prediction} "
            f"({confidence_text}) | Final: {final_decision}"
        )

    return summarize_results(
        "ML + PQC-Aware",
        attack_counters,
        emergency_counters,
        current_buffer,
        peak_buffer,
        total_pqc_time,
    )


# ============================================================
# PRINT SUMMARY
# ============================================================

def print_summary(results):
    print()
    print("=" * 65)
    print("CONTROLLED COMPARISON SUMMARY")
    print("=" * 65)

    for result in results:
        print()
        print("Approach:", result["Approach"])
        print(
            "Attack admitted:",
            result["Attack Admitted"],
            "/",
            result["Attack Attempted"],
        )
        print("Attack throttled:", result["Attack Throttled"])
        print("Attack dropped:", result["Attack Dropped"])
        print("Attack delayed:", result["Attack Delayed"])
        print("Attack rejected:", result["Attack Rejected"])
        print("Attack not admitted:", result["Attack Not Admitted"])

        print(
            "Emergency admitted to relay:",
            result["Emergency Admitted to Relay"],
            "/",
            result["Emergency Attempted"],
        )
        print("Emergency delayed:", result["Emergency Delayed"])
        print("Emergency dropped:", result["Emergency Dropped"])
        print("Emergency rejected:", result["Emergency Rejected"])

        print(
            "Peak buffer utilization:",
            f'{result["Peak Buffer Utilization (%)"]:.2f}%',
        )
        print(
            "Final buffer utilization:",
            f'{result["Final Buffer Utilization (%)"]:.2f}%',
        )
        print(
            "Total PQC processing time:",
            f'{result["Total PQC Processing Time (s)"]:.6f}',
            "seconds",
        )
        print("-" * 65)


# ============================================================
# MAIN EXPERIMENT
# ============================================================

def main():
    print()
    print("=" * 65)
    print("CONTROLLED COMPARISON EXPERIMENT")
    print("=" * 65)
    print("Relay capacity:", RELAY_CAPACITY, "bytes")
    print("Attack messages:", len(attack_traffic))
    print("Emergency messages:", len(emergency_traffic))
    print("Same predefined traffic workload for all approaches.")
    print("Emergency metric means admitted to relay, not destination delivery.")
    print("PQC timing includes every attempted message.")
    print()

    results = [
        run_no_protection(),
        run_rule_based(),
        run_ml_pqc_aware(),
    ]

    print_summary(results)

    results_dataframe = pd.DataFrame(results)
    results_dataframe.to_csv(RESULT_FILE, index=False)

    print()
    print("Results saved to:", RESULT_FILE)
    print("Controlled comparison experiment completed.")


if __name__ == "__main__":
    main()
