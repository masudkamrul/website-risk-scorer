import csv

FRAUD_FILE = "data/fraudshield_dataset_v8.csv"
SAFE_FILE = "data/safe_dataset_v8.csv"
OUTPUT_FILE = "data/training_dataset_v8.csv"

def read_csv(filepath):
    with open(filepath, "r") as f:
        return list(csv.DictReader(f))

def main():
    fraud_data = read_csv(FRAUD_FILE)
    safe_data = read_csv(SAFE_FILE)

    combined = fraud_data + safe_data

    # Shuffle for better mixing (optional, can remove)
    import random
    random.shuffle(combined)

    fieldnames = list(combined[0].keys())

    with open(OUTPUT_FILE, "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(combined)

    print("\n📌 Final training dataset ready!")
    print(f"Total rows: {len(combined)}")
    print(f"Saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
