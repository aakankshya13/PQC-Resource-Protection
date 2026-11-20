
import os
import re
import sys

import pandas as pd
import matplotlib.pyplot as plt


CSV_FILE = "controlled_comparison_results.csv"
OUTPUT_DIR = "comparison_graphs"

APPROACHES = [
    "No Protection",
    "Rule-Based",
    "ML + PQC-Aware",
]


def normalize_name(name):
    """Normalize column names for flexible matching."""
    return re.sub(r"[^a-z0-9]+", "", str(name).lower())


def find_column(df, candidates, keywords=()):
    """Find a column using common names and fallback keywords."""
    normalized = {
        normalize_name(column): column
        for column in df.columns
    }

    for candidate in candidates:
        key = normalize_name(candidate)
        if key in normalized:
            return normalized[key]

    for column in df.columns:
        key = normalize_name(column)
        if keywords and all(word in key for word in keywords):
            return column

    return None


def to_numeric(series):
    """Convert numbers, percentages, and seconds to numeric values."""
    cleaned = (
        series.astype(str)
        .str.replace(",", "", regex=False)
        .str.replace("%", "", regex=False)
        .str.replace("seconds", "", regex=False)
        .str.replace("second", "", regex=False)
        .str.replace("secs", "", regex=False)
        .str.replace("sec", "", regex=False)
        .str.strip()
    )
    return pd.to_numeric(cleaned, errors="coerce")


def main():
    print("=" * 65)
    print("VALIDATING CONTROLLED COMPARISON RESULTS")
    print("=" * 65)

    if not os.path.exists(CSV_FILE):
        print(f"ERROR: Cannot find {CSV_FILE}")
        print("Make sure this script is in your project folder.")
        sys.exit(1)

    try:
        df = pd.read_csv(CSV_FILE)
    except Exception as error:
        print(f"ERROR reading CSV: {error}")
        sys.exit(1)

    if df.empty:
        print("ERROR: The CSV file contains no data rows.")
        sys.exit(1)

    print(f"\nFile: {os.path.abspath(CSV_FILE)}")
    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")
    print("\nColumn names:")
    for column in df.columns:
        print(f"  - {column}")

    print("\nFirst five rows:")
    print(df.head().to_string(index=False))

    print("\nMissing values per column:")
    print(df.isnull().sum().to_string())

    # Identify the summary columns written by the experiment.
    approach_col = find_column(
        df,
        ["Approach", "Protection Approach", "Method"],
        ("approach",),
    )

    attack_col = find_column(
        df,
        ["Attack Admitted", "Attack Messages Admitted"],
        ("attack", "admitted"),
    )

    emergency_col = find_column(
        df,
        [
            "Emergency Admitted to Relay",
            "Emergency Admitted",
            "Emergency Messages Admitted",
        ],
        ("emergency", "admitted"),
    )

    buffer_col = find_column(
        df,
        ["Peak Buffer Utilization", "Peak Buffer Usage"],
        ("peak", "buffer"),
    )

    pqc_col = find_column(
        df,
        ["Total PQC Processing Time", "PQC Processing Time"],
        ("pqc", "processing", "time"),
    )

    required = {
        "Approach": approach_col,
        "Attack admitted": attack_col,
        "Emergency admitted to relay": emergency_col,
        "Peak buffer utilization": buffer_col,
        "Total PQC processing time": pqc_col,
    }

    missing = [
        name for name, column in required.items()
        if column is None
    ]

    if missing:
        print("\nThe CSV columns do not match the expected summary format.")
        print("Metrics not found:", ", ".join(missing))
        print(
            "\nNo graphs were generated, to avoid plotting "
            "incorrect metrics."
        )
        print(
            "\nShare the column names and first five rows printed "
            "above so the script can be matched to your CSV format."
        )
        sys.exit(2)

    summary = df[
        [
            approach_col,
            attack_col,
            emergency_col,
            buffer_col,
            pqc_col,
        ]
    ].copy()

    summary.columns = [
        "Approach",
        "Attack Admitted",
        "Emergency Admitted to Relay",
        "Peak Buffer Utilization",
        "Total PQC Processing Time",
    ]

    # Match the three expected approaches.
    summary["Approach"] = summary["Approach"].astype(str).str.strip()

    def standardize_approach(value):
        key = normalize_name(value)

        if key in ("noprotection", "withoutprotection"):
            return "No Protection"
        if key in ("rulebased", "rulebasedprotection"):
            return "Rule-Based"
        if key in (
            "mlpq caware".replace(" ", ""),
            "mlpqcaware",
            "mlpqcawareprotection",
        ):
            return "ML + PQC-Aware"

        return value

    summary["Approach"] = summary["Approach"].apply(
        standardize_approach
    )

    numeric_columns = [
        "Attack Admitted",
        "Emergency Admitted to Relay",
        "Peak Buffer Utilization",
        "Total PQC Processing Time",
    ]

    for column in numeric_columns:
        summary[column] = to_numeric(summary[column])

    summary = summary.dropna(subset=numeric_columns)

    # Keep the latest summary row if an approach appears more than once.
    summary = summary.drop_duplicates(
        subset=["Approach"], keep="last"
    )

    order = {name: i for i, name in enumerate(APPROACHES)}
    summary["_order"] = summary["Approach"].map(order)
    summary = (
        summary.dropna(subset=["_order"])
        .sort_values("_order")
        .drop(columns="_order")
    )

    if len(summary) != 3:
        print("\nERROR: Expected one summary row for each approach.")
        print("Approaches found:", summary["Approach"].tolist())
        print("\nValidated summary:")
        print(summary.to_string(index=False))
        print(
            "\nNo graphs generated. Check the CSV format and "
            "approach names."
        )
        sys.exit(2)

    # Convert a 0-1 buffer ratio to a percentage if necessary.
    if summary["Peak Buffer Utilization"].max() <= 1:
        summary["Peak Buffer Utilization"] *= 100

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("\nValidated comparison summary:")
    print(summary.to_string(index=False))

    graphs = [
        (
            "attack_messages_admitted.png",
            "Attack Messages Admitted",
            "Number of attack messages",
            "Attack Admitted",
        ),
        (
            "emergency_messages_admitted.png",
            "Emergency Messages Admitted to Relay",
            "Number of emergency messages",
            "Emergency Admitted to Relay",
        ),
        (
            "peak_buffer_utilization.png",
            "Peak Relay Buffer Utilization",
            "Buffer utilization (%)",
            "Peak Buffer Utilization",
        ),
        (
            "total_pqc_processing_time.png",
            "Total PQC Processing Time",
            "Processing time (seconds)",
            "Total PQC Processing Time",
        ),
    ]

    for filename, title, ylabel, metric in graphs:
        fig, ax = plt.subplots(figsize=(9, 5))

        bars = ax.bar(
            summary["Approach"],
            summary[metric],
        )

        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.set_xlabel("Protection approach")
        ax.grid(axis="y", linestyle="--", alpha=0.4)
        ax.set_axisbelow(True)

        if metric == "Peak Buffer Utilization":
            ax.set_ylim(0, 100)

        ax.bar_label(bars, fmt="%.3f" if metric ==
                     "Total PQC Processing Time" else "%.2f")

        plt.xticks(rotation=10)
        plt.tight_layout()

        output_path = os.path.join(OUTPUT_DIR, filename)
        fig.savefig(output_path, dpi=200, bbox_inches="tight")
        plt.close(fig)

        print(f"Graph saved: {output_path}")

    print("\n" + "=" * 65)
    print("VALIDATION AND GRAPH GENERATION COMPLETED")
    print(f"Graphs folder: {os.path.abspath(OUTPUT_DIR)}")
    print("=" * 65)


if __name__ == "__main__":
    main()
