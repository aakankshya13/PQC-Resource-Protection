import random
import pandas as pd
import joblib

from message import Message
from pqc_manager import PQCManager
from secure_message import SecureMessage
from resource_monitor import ResourceMonitor
from admission_controller import AdmissionController


# ==================================================
# FINAL COMPARISON EXPERIMENT
# ==================================================

MODEL_FILE = "pqc_anomaly_detector.pkl"

RELAY_CAPACITY = 5000

NUMBER_OF_ATTACK_MESSAGES = 10

NUMBER_OF_EMERGENCY_MESSAGES = 3


print("========================================")
print("       FINAL COMPARISON EXPERIMENT")
print("========================================")
print()


# --------------------------------------------------
# 1. LOAD ML MODEL
# --------------------------------------------------

saved_model = joblib.load(
    MODEL_FILE
)

model = saved_model["model"]

features = saved_model["features"]

print("Random Forest model loaded.")
print()


# --------------------------------------------------
# 2. CREATE PQC COMPONENT
# --------------------------------------------------

pqc = PQCManager()

controller = AdmissionController(
    relay_capacity=RELAY_CAPACITY
)


# --------------------------------------------------
# 3. CREATE ML FEATURE FUNCTION
# --------------------------------------------------

def create_ml_features(
    traffic_rate,
    message_size,
    buffer_utilization,
    pqc_processing_time,
    resource_consumption,
    message_priority,
    network_available,
    traffic_type
):

    return pd.DataFrame(
        [
            {
                "traffic_rate": traffic_rate,

                "message_size": message_size,

                "buffer_utilization":
                    buffer_utilization,

                "pqc_processing_time":
                    pqc_processing_time,

                "resource_consumption":
                    resource_consumption,

                "message_priority":
                    message_priority,

                "network_available":
                    network_available,

                "traffic_type_Emergency":
                    1 if traffic_type == "Emergency" else 0,

                "traffic_type_Flooding":
                    1 if traffic_type == "Flooding" else 0,

                "traffic_type_Normal":
                    1 if traffic_type == "Normal" else 0
            }
        ]
    )


# --------------------------------------------------
# 4. ML PREDICTION FUNCTION
# --------------------------------------------------

def predict_threat(
    traffic_rate,
    message_size,
    buffer_utilization,
    pqc_processing_time,
    resource_consumption,
    message_priority,
    network_available,
    traffic_type
):

    ml_data = create_ml_features(
        traffic_rate,
        message_size,
        buffer_utilization,
        pqc_processing_time,
        resource_consumption,
        message_priority,
        network_available,
        traffic_type
    )

    prediction = model.predict(
        ml_data[features]
    )[0]

    return prediction


# ==================================================
# EXPERIMENT 1
# NO PROTECTION
# ==================================================

print("========================================")
print("       EXPERIMENT 1: NO PROTECTION")
print("========================================")
print()

monitor_no_protection = ResourceMonitor(
    relay_capacity=RELAY_CAPACITY
)

accepted_no_protection = 0

emergency_delivered_no_protection = 0

attack_messages = []


# --------------------------------------------------
# Generate attack traffic
# --------------------------------------------------

for i in range(
    1,
    NUMBER_OF_ATTACK_MESSAGES + 1
):

    message = Message(
        f"ATTACK-{i:03d}",
        "AttackerUAV",
        "Flooding",
        1,
        100
    )

    secure_message = SecureMessage(
        message,
        pqc
    )

    bundle_size = (
        len(secure_message.encapsulated_key)
        +
        len(secure_message.nonce)
        +
        len(secure_message.ciphertext)
    )

    attack_messages.append(
        (
            message,
            secure_message,
            bundle_size
        )
    )


# --------------------------------------------------
# Accept all attack traffic
# --------------------------------------------------

for message, secure_message, bundle_size in attack_messages:

    accepted_no_protection += 1

    monitor_no_protection.record_message(
        bundle_size
    )

    monitor_no_protection.record_pqc_processing(
        secure_message.pqc_processing_time
    )

    monitor_no_protection.update_buffer(
        monitor_no_protection.buffer_used
        + bundle_size
    )


# --------------------------------------------------
# Emergency messages
# --------------------------------------------------

for i in range(
    1,
    NUMBER_OF_EMERGENCY_MESSAGES + 1
):

    message = Message(
        f"EMERGENCY-{i:03d}",
        "UAV1",
        "Emergency",
        5,
        100
    )

    secure_message = SecureMessage(
        message,
        pqc
    )

    bundle_size = (
        len(secure_message.encapsulated_key)
        +
        len(secure_message.nonce)
        +
        len(secure_message.ciphertext)
    )

    current_buffer = (
        monitor_no_protection.buffer_used
    )

    # No protection means the emergency message
    # competes with the already overloaded buffer.

    if (
        current_buffer + bundle_size
        <= RELAY_CAPACITY
    ):

        emergency_delivered_no_protection += 1

        monitor_no_protection.update_buffer(
            current_buffer + bundle_size
        )

        monitor_no_protection.record_message(
            bundle_size
        )

        monitor_no_protection.record_pqc_processing(
            secure_message.pqc_processing_time
        )


print(
    "Attack messages accepted:",
    accepted_no_protection
)

print(
    "Final buffer utilization:",
    f"{monitor_no_protection.get_buffer_utilization():.2f}%"
)

print(
    "Emergency messages delivered:",
    emergency_delivered_no_protection,
    "/",
    NUMBER_OF_EMERGENCY_MESSAGES
)

print()


# ==================================================
# EXPERIMENT 2
# RULE-BASED PROTECTION
# ==================================================

print("========================================")
print("       EXPERIMENT 2: RULE-BASED")
print("========================================")
print()

monitor_rule = ResourceMonitor(
    relay_capacity=RELAY_CAPACITY
)

accepted_rule = 0
throttled_rule = 0
dropped_rule = 0
emergency_delivered_rule = 0


# --------------------------------------------------
# Attack traffic
# --------------------------------------------------

for message, secure_message, bundle_size in attack_messages:

    current_buffer = (
        monitor_rule.buffer_used
    )

    decision = controller.evaluate(
        message_priority=message.priority,
        message_size=bundle_size,
        current_buffer_usage=current_buffer
    )

    if decision == "ACCEPT":

        accepted_rule += 1

        monitor_rule.update_buffer(
            current_buffer + bundle_size
        )

        monitor_rule.record_message(
            bundle_size
        )

        monitor_rule.record_pqc_processing(
            secure_message.pqc_processing_time
        )

    elif decision == "THROTTLE":

        throttled_rule += 1

    elif decision == "DROP":

        dropped_rule += 1


# --------------------------------------------------
# Emergency traffic
# --------------------------------------------------

for i in range(
    1,
    NUMBER_OF_EMERGENCY_MESSAGES + 1
):

    message = Message(
        f"EMERGENCY-{i:03d}",
        "UAV1",
        "Emergency",
        5,
        100
    )

    secure_message = SecureMessage(
        message,
        pqc
    )

    bundle_size = (
        len(secure_message.encapsulated_key)
        +
        len(secure_message.nonce)
        +
        len(secure_message.ciphertext)
    )

    current_buffer = (
        monitor_rule.buffer_used
    )

    decision = controller.evaluate(
        message_priority=message.priority,
        message_size=bundle_size,
        current_buffer_usage=current_buffer
    )

    if (
        decision == "ACCEPT"
        and current_buffer + bundle_size
        <= RELAY_CAPACITY
    ):

        emergency_delivered_rule += 1

        monitor_rule.update_buffer(
            current_buffer + bundle_size
        )

        monitor_rule.record_message(
            bundle_size
        )

        monitor_rule.record_pqc_processing(
            secure_message.pqc_processing_time
        )


print(
    "Attack messages accepted:",
    accepted_rule
)

print(
    "Attack messages throttled:",
    throttled_rule
)

print(
    "Attack messages dropped:",
    dropped_rule
)

print(
    "Final buffer utilization:",
    f"{monitor_rule.get_buffer_utilization():.2f}%"
)

print(
    "Emergency messages delivered:",
    emergency_delivered_rule,
    "/",
    NUMBER_OF_EMERGENCY_MESSAGES
)

print()


# ==================================================
# EXPERIMENT 3
# ML + PQC-AWARE PROTECTION
# ==================================================

print("========================================")
print("    EXPERIMENT 3: ML + PQC-AWARE")
print("========================================")
print()

monitor_ml = ResourceMonitor(
    relay_capacity=RELAY_CAPACITY
)

accepted_ml = 0
throttled_ml = 0
dropped_ml = 0
emergency_delivered_ml = 0


# --------------------------------------------------
# Attack traffic
# --------------------------------------------------

for message, secure_message, bundle_size in attack_messages:

    current_buffer = (
        monitor_ml.buffer_used
    )

    buffer_utilization = (
        monitor_ml.get_buffer_utilization()
    )

    prediction = predict_threat(

        traffic_rate=random.randint(
            15,
            100
        ),

        message_size=bundle_size,

        buffer_utilization=buffer_utilization,

        pqc_processing_time=(
            secure_message.pqc_processing_time
        ),

        resource_consumption=random.uniform(
            60,
            100
        ),

        message_priority=message.priority,

        network_available=1,

        traffic_type="Flooding"
    )


    # First use the normal admission controller.

    admission_decision = controller.evaluate(
        message_priority=message.priority,
        message_size=bundle_size,
        current_buffer_usage=current_buffer
    )


    # Then add ML threat information.

    if prediction == "RESOURCE_EXHAUSTION":

        if message.priority < 5:

            final_decision = "DROP"

        else:

            final_decision = "ACCEPT"

    elif prediction == "SUSPICIOUS":

        if (
            message.priority < 5
            and admission_decision == "ACCEPT"
        ):

            final_decision = "THROTTLE"

        else:

            final_decision = admission_decision

    else:

        final_decision = admission_decision


    if final_decision == "ACCEPT":

        accepted_ml += 1

        monitor_ml.update_buffer(
            current_buffer + bundle_size
        )

        monitor_ml.record_message(
            bundle_size
        )

        monitor_ml.record_pqc_processing(
            secure_message.pqc_processing_time
        )

    elif final_decision == "THROTTLE":

        throttled_ml += 1

    elif final_decision == "DROP":

        dropped_ml += 1


# --------------------------------------------------
# Emergency traffic
# --------------------------------------------------

for i in range(
    1,
    NUMBER_OF_EMERGENCY_MESSAGES + 1
):

    message = Message(
        f"EMERGENCY-{i:03d}",
        "UAV1",
        "Emergency",
        5,
        100
    )

    secure_message = SecureMessage(
        message,
        pqc
    )

    bundle_size = (
        len(secure_message.encapsulated_key)
        +
        len(secure_message.nonce)
        +
        len(secure_message.ciphertext)
    )

    current_buffer = (
        monitor_ml.buffer_used
    )

    buffer_utilization = (
        monitor_ml.get_buffer_utilization()
    )

    prediction = predict_threat(

        traffic_rate=3,

        message_size=bundle_size,

        buffer_utilization=buffer_utilization,

        pqc_processing_time=(
            secure_message.pqc_processing_time
        ),

        resource_consumption=35,

        message_priority=5,

        network_available=0,

        traffic_type="Emergency"
    )


    admission_decision = controller.evaluate(
        message_priority=5,
        message_size=bundle_size,
        current_buffer_usage=current_buffer
    )


    # Critical traffic receives priority.

    if message.priority >= 5:

        final_decision = "ACCEPT"

    elif prediction == "RESOURCE_EXHAUSTION":

        final_decision = "DROP"

    else:

        final_decision = admission_decision


    if (
        final_decision == "ACCEPT"
        and current_buffer + bundle_size
        <= RELAY_CAPACITY
    ):

        emergency_delivered_ml += 1

        monitor_ml.update_buffer(
            current_buffer + bundle_size
        )

        monitor_ml.record_message(
            bundle_size
        )

        monitor_ml.record_pqc_processing(
            secure_message.pqc_processing_time
        )


print(
    "Attack messages accepted:",
    accepted_ml
)

print(
    "Attack messages throttled:",
    throttled_ml
)

print(
    "Attack messages dropped:",
    dropped_ml
)

print(
    "Final buffer utilization:",
    f"{monitor_ml.get_buffer_utilization():.2f}%"
)

print(
    "Emergency messages delivered:",
    emergency_delivered_ml,
    "/",
    NUMBER_OF_EMERGENCY_MESSAGES
)

print()


# ==================================================
# FINAL COMPARISON
# ==================================================

print("========================================")
print("       FINAL COMPARISON")
print("========================================")
print()

comparison = pd.DataFrame(
    [
        {
            "Approach": "No Protection",
            "Attack Accepted": accepted_no_protection,
            "Attack Throttled": 0,
            "Attack Dropped": 0,
            "Final Buffer %":
                monitor_no_protection.get_buffer_utilization(),
            "Emergency Delivered":
                emergency_delivered_no_protection
        },

        {
            "Approach": "Rule-Based",
            "Attack Accepted": accepted_rule,
            "Attack Throttled": throttled_rule,
            "Attack Dropped": dropped_rule,
            "Final Buffer %":
                monitor_rule.get_buffer_utilization(),
            "Emergency Delivered":
                emergency_delivered_rule
        },

        {
            "Approach": "ML + PQC-Aware",
            "Attack Accepted": accepted_ml,
            "Attack Throttled": throttled_ml,
            "Attack Dropped": dropped_ml,
            "Final Buffer %":
                monitor_ml.get_buffer_utilization(),
            "Emergency Delivered":
                emergency_delivered_ml
        }
    ]
)


print(
    comparison.to_string(
        index=False
    )
)

print()


# --------------------------------------------------
# SAVE RESULTS
# --------------------------------------------------

comparison.to_csv(
    "comparison_results.csv",
    index=False
)


print(
    "Results saved to:",
    "comparison_results.csv"
)

print()

print("========================================")
print("       COMPARISON COMPLETED")
print("========================================")
