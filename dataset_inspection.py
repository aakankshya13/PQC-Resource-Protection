import pandas as pd


# ==================================================
# DATASET INSPECTION
# ==================================================

FILE_NAME = "pqc_traffic_dataset.csv"


print("========================================")
print("       DATASET INSPECTION")
print("========================================")
print()


# --------------------------------------------------
# 1. LOAD DATASET
# --------------------------------------------------

data = pd.read_csv(FILE_NAME)

print("Dataset loaded successfully.")
print()


# --------------------------------------------------
# 2. BASIC INFORMATION
# --------------------------------------------------

print("========== DATASET INFORMATION ==========")

print(
    "Number of records:",
    len(data)
)

print(
    "Number of columns:",
    len(data.columns)
)

print()

print("Columns:")

for column in data.columns:
    print("-", column)

print()


# --------------------------------------------------
# 3. FIRST FIVE RECORDS
# --------------------------------------------------

print("========== FIRST FIVE RECORDS ==========")

print(
    data.head().to_string(index=False)
)

print()


# --------------------------------------------------
# 4. CHECK MISSING VALUES
# --------------------------------------------------

print("========== MISSING VALUES ==========")

missing_values = data.isnull().sum()

print(missing_values)

print()


# --------------------------------------------------
# 5. LABEL DISTRIBUTION
# --------------------------------------------------

print("========== LABEL DISTRIBUTION ==========")

label_counts = data["label"].value_counts()

print(label_counts)

print()


# --------------------------------------------------
# 6. TRAFFIC TYPE DISTRIBUTION
# --------------------------------------------------

print("========== TRAFFIC TYPE DISTRIBUTION ==========")

traffic_counts = data["traffic_type"].value_counts()

print(traffic_counts)

print()


# --------------------------------------------------
# 7. BASIC STATISTICS
# --------------------------------------------------

print("========== NUMERICAL STATISTICS ==========")

print(
    data.describe().to_string()
)

print()


# --------------------------------------------------
# 8. LABEL PERCENTAGES
# --------------------------------------------------

print("========== LABEL PERCENTAGES ==========")

label_percentages = (
    data["label"]
    .value_counts(normalize=True)
    * 100
)

for label, percentage in label_percentages.items():

    print(
        f"{label}: "
        f"{percentage:.2f}%"
    )

print()


# --------------------------------------------------
# 9. FINAL CHECK
# --------------------------------------------------

print("========================================")
print("       DATASET CHECK")
print("========================================")

if data.isnull().sum().sum() == 0:

    print(
        "PASS: No missing values found."
    )

else:

    print(
        "WARNING: Missing values found."
    )


if len(data) == 1000:

    print(
        "PASS: Dataset contains 1000 records."
    )

else:

    print(
        "WARNING: Dataset does not contain "
        "1000 records."
    )


print()
print("========================================")
print("       INSPECTION COMPLETED")
print("========================================")