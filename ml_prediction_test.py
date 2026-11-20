import pandas as pd
import joblib


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_FILE = "pqc_anomaly_detector.pkl"


# ============================================================
# LOAD MODEL
# ============================================================

saved_model = joblib.load(
    MODEL_FILE
)

model = saved_model["model"]
features = saved_model["features"]


# ============================================================
# PREDICTION FUNCTION
# ============================================================

def predict_traffic(
    traffic_rate,
    message_size,
    buffer_utilization,
    pqc_processing_time,
    resource_consumption,
    message_priority,
    network_available
):

    data = pd.DataFrame(
        [
            {
                "traffic_rate": traffic_rate,
                "message_size": message_size,
                "buffer_utilization": buffer_utilization,
                "pqc_processing_time": pqc_processing_time,
                "resource_consumption": resource_consumption,
                "message_priority": message_priority,
                "network_available": network_available
            }
        ]
    )

    # Make sure the columns are exactly the
    # same as the features used during training.

    data = data.reindex(
        columns=features
    )

    prediction = model.predict(
        data
    )[0]

    probabilities = model.predict_proba(
        data
    )[0]

    confidence = max(
        probabilities
    ) * 100

    return prediction, confidence


# ============================================================
# TEST SCENARIOS
# ============================================================

test_cases = [

    {
        "name": "Normal Traffic",

        "traffic_rate": 5,

        "message_size": 300,

        "buffer_utilization": 30,

        "pqc_processing_time": 0.000300,

        "resource_consumption": 25,

        "message_priority": 3,

        "network_available": 1
    },


    {
        "name": "Suspicious Flooding",

        "traffic_rate": 45,

        "message_size": 1000,

        "buffer_utilization": 75,

        "pqc_processing_time": 0.000900,

        "resource_consumption": 70,

        "message_priority": 1,

        "network_available": 1
    },


    {
        "name": "Severe Resource Exhaustion",

        "traffic_rate": 80,

        "message_size": 1300,

        "buffer_utilization": 95,

        "pqc_processing_time": 0.001200,

        "resource_consumption": 90,

        "message_priority": 1,

        "network_available": 1
    },


    {
        "name": "Critical Emergency",

        "traffic_rate": 3,

        "message_size": 250,

        "buffer_utilization": 70,

        "pqc_processing_time": 0.000350,

        "resource_consumption": 35,

        "message_priority": 5,

        "network_available": 0
    }

]


# ============================================================
# RUN TESTS
# ============================================================

print()
print("========================================")
print("       ML PREDICTION TEST")
print("========================================")
print()


for test in test_cases:

    prediction, confidence = predict_traffic(

        traffic_rate=test["traffic_rate"],

        message_size=test["message_size"],

        buffer_utilization=test[
            "buffer_utilization"
        ],

        pqc_processing_time=test[
            "pqc_processing_time"
        ],

        resource_consumption=test[
            "resource_consumption"
        ],

        message_priority=test[
            "message_priority"
        ],

        network_available=test[
            "network_available"
        ]
    )


    print("----------------------------------------")

    print(
        "Scenario:",
        test["name"]
    )

    print(
        "Traffic rate:",
        test["traffic_rate"]
    )

    print(
        "Message size:",
        test["message_size"],
        "bytes"
    )

    print(
        "Buffer utilization:",
        test["buffer_utilization"],
        "%"
    )

    print(
        "PQC processing time:",
        test["pqc_processing_time"],
        "seconds"
    )

    print(
        "Resource consumption:",
        test["resource_consumption"],
        "%"
    )

    print(
        "Message priority:",
        test["message_priority"]
    )

    print(
        "Network available:",
        test["network_available"]
    )

    print()

    print(
        "Predicted class:",
        prediction
    )

    print(
        "Confidence:",
        f"{confidence:.2f}%"
    )


print()
print("----------------------------------------")
print("ML prediction testing completed.")
print("----------------------------------------")