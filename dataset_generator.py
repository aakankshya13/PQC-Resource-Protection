import random
import pandas as pd


# ============================================================
# SYNTHETIC DATASET GENERATOR
# PQC-AWARE RESOURCE PROTECTION PROJECT
# ============================================================

OUTPUT_FILE = "pqc_traffic_dataset.csv"

NUMBER_OF_RECORDS = 1000

random.seed(42)


# ============================================================
# DATA GENERATION
# ============================================================

dataset = []


for _ in range(NUMBER_OF_RECORDS):

    # --------------------------------------------------------
    # Select traffic scenario
    # --------------------------------------------------------

    traffic_type = random.choices(
        [
            "Normal",
            "Emergency",
            "Flooding"
        ],
        weights=[
            60,
            20,
            20
        ],
        k=1
    )[0]


    # ========================================================
    # NORMAL TRAFFIC
    # ========================================================

    if traffic_type == "Normal":

        traffic_rate = random.uniform(
            1,
            10
        )

        message_size = random.randint(
            50,
            500
        )

        buffer_utilization = random.uniform(
            10,
            60
        )

        pqc_processing_time = random.uniform(
            0.00020,
            0.00050
        )

        resource_consumption = random.uniform(
            10,
            40
        )

        message_priority = random.choice(
            [
                2,
                3,
                4
            ]
        )

        network_available = random.choice(
            [
                0,
                1
            ]
        )


    # ========================================================
    # EMERGENCY TRAFFIC
    # ========================================================

    elif traffic_type == "Emergency":

        traffic_rate = random.uniform(
            1,
            5
        )

        message_size = random.randint(
            100,
            500
        )

        buffer_utilization = random.uniform(
            30,
            90
        )

        pqc_processing_time = random.uniform(
            0.00020,
            0.00060
        )

        resource_consumption = random.uniform(
            20,
            60
        )

        message_priority = 5

        network_available = random.choice(
            [
                0,
                1
            ]
        )


    # ========================================================
    # FLOODING TRAFFIC
    # ========================================================

    else:

        traffic_rate = random.uniform(
            15,
            100
        )

        message_size = random.randint(
            500,
            1500
        )

        buffer_utilization = random.uniform(
            60,
            100
        )

        pqc_processing_time = random.uniform(
            0.00040,
            0.00150
        )

        resource_consumption = random.uniform(
            50,
            100
        )

        message_priority = 1

        network_available = random.choice(
            [
                0,
                1
            ]
        )


    # ========================================================
    # BEHAVIOR-BASED LABEL GENERATION
    # ========================================================
    #
    # IMPORTANT:
    #
    # The label is NOT directly assigned from traffic_type.
    #
    # The ML model should learn from:
    #
    # - Traffic rate
    # - Message size
    # - Buffer utilization
    # - PQC processing time
    # - Resource consumption
    # - Message priority
    #
    # ========================================================


    severe_conditions = 0


    if buffer_utilization >= 85:
        severe_conditions += 1

    if resource_consumption >= 85:
        severe_conditions += 1

    if traffic_rate >= 60:
        severe_conditions += 1


    suspicious_conditions = 0


    if buffer_utilization >= 70:
        suspicious_conditions += 1

    if resource_consumption >= 65:
        suspicious_conditions += 1

    if traffic_rate >= 30:
        suspicious_conditions += 1

    if message_size >= 900:
        suspicious_conditions += 1

    if pqc_processing_time >= 0.00090:
        suspicious_conditions += 1


    # --------------------------------------------------------
    # Determine final label
    # --------------------------------------------------------

    if severe_conditions >= 2:

        label = "RESOURCE_EXHAUSTION"

    elif suspicious_conditions >= 2:

        label = "SUSPICIOUS"

    else:

        label = "NORMAL"


    # ========================================================
    # STORE RECORD
    # ========================================================

    dataset.append(
        {
            "traffic_rate": round(
                traffic_rate,
                3
            ),

            "message_size": message_size,

            "buffer_utilization": round(
                buffer_utilization,
                3
            ),

            "pqc_processing_time": round(
                pqc_processing_time,
                6
            ),

            "resource_consumption": round(
                resource_consumption,
                3
            ),

            "message_priority": message_priority,

            "network_available": network_available,

            "traffic_type": traffic_type,

            "label": label
        }
    )


# ============================================================
# CREATE DATAFRAME
# ============================================================

dataframe = pd.DataFrame(
    dataset
)


# ============================================================
# SAVE DATASET
# ============================================================

dataframe.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# DISPLAY DATASET SUMMARY
# ============================================================

print()
print("========================================")
print("       PQC TRAFFIC DATASET")
print("========================================")

print()

print(
    "Dataset records:",
    len(dataframe)
)

print(
    "Dataset columns:",
    len(dataframe.columns)
)

print()

print("Label distribution:")

print(
    dataframe["label"].value_counts()
)

print()

print("Traffic type distribution:")

print(
    dataframe["traffic_type"].value_counts()
)

print()

print("Missing values:")

print(
    dataframe.isnull().sum()
)

print()

print(
    "Dataset saved to:",
    OUTPUT_FILE
)

print()

print("========================================")
print("       DATASET GENERATION COMPLETE")
print("========================================")