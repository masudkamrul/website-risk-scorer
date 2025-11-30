import csv
import os
from datetime import datetime


def log_entry(
    url,
    features,
    score,
    risk_class,
    threat_category,
    auto_label,
    csv_path,
):
    """
    Append a single scan entry into fraudshield_dataset_v3.csv

    Columns:
    - timestamp
    - url
    - f0..fN (features)
    - risk_score
    - risk_class
    - threat_category
    - auto_label
    - verified_label  (for manual review later)
    """

    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    timestamp = datetime.utcnow().isoformat()
    rounded_score = round(float(score), 2)

    feature_count = len(features)
    feature_headers = [f"f{i}" for i in range(feature_count)]

    header = (
        ["timestamp", "url"]
        + feature_headers
        + ["risk_score", "risk_class", "threat_category", "auto_label", "verified_label"]
    )

    row = (
        [timestamp, url]
        + list(features)
        + [rounded_score, risk_class, threat_category, auto_label, ""]
    )

    file_exists = os.path.exists(csv_path)

    try:
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(header)
            writer.writerow(row)

        print("➡ CSV update OK:", csv_path)

    except Exception as e:
        print("❌ CSV Write Error:", e)
