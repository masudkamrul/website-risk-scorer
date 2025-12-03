import pandas as pd
import os

V3_PATH = "data/fraudshield_dataset_v3.csv"
V4_PATH = "data/fraudshield_dataset_v4.csv"
V5_PATH = "data/fraudshield_dataset_v5.csv"

print("📌 Loading V3 and V4 datasets...")

if not os.path.exists(V3_PATH):
    raise FileNotFoundError(f"Missing file: {V3_PATH}")

if not os.path.exists(V4_PATH):
    raise FileNotFoundError(f"Missing file: {V4_PATH}")

df_v3 = pd.read_csv(V3_PATH)
df_v4 = pd.read_csv(V4_PATH)

print("V3 rows:", len(df_v3))
print("V4 rows:", len(df_v4))

# We expect columns:
# timestamp,url,f0,...,f23,risk_score,risk_class,threat_category,auto_label,verified_label

# Make sure we only keep common columns (in case V4 has slightly fewer)
common_cols = [c for c in df_v3.columns if c in df_v4.columns]
df_v3 = df_v3[common_cols].copy()
df_v4 = df_v4[common_cols].copy()

print("Common columns used:", common_cols)

# Label definition:
#  - Safe (0): risk_class == "Safe"
#  - Fraud (1): everything else (Suspicious / High Risk / Blacklisted Threat etc.)

def label_row(row):
    rc = str(row.get("risk_class", "")).strip()
    if rc == "Safe":
        return 0
    return 1

df_v3["label"] = df_v3.apply(label_row, axis=1)
df_v4["label"] = df_v4.apply(label_row, axis=1)  # should all be 0 for your v4 bulk safe data

print("\n📊 Class distribution in V3:")
print(df_v3["label"].value_counts())

print("\n📊 Class distribution in V4:")
print(df_v4["label"].value_counts())

# Keep ONLY fraud rows from V3 (label == 1)
df_v3_fraud = df_v3[df_v3["label"] == 1].copy()
print("\n✅ Fraud rows from V3:", len(df_v3_fraud))

# Optionally cap fraud count (e.g., at 1000) so data isn't too skewed
MAX_FRAUD = 1000
if len(df_v3_fraud) > MAX_FRAUD:
    df_v3_fraud = df_v3_fraud.sample(MAX_FRAUD, random_state=42)
    print(f"✂️ Capped fraud rows to {MAX_FRAUD}")

# V4 is your "clean US safe" dataset → keep all
df_v4_safe = df_v4[df_v4["label"] == 0].copy()
print("✅ Safe rows from V4:", len(df_v4_safe))

# Combine into V5
df_v5 = pd.concat([df_v4_safe, df_v3_fraud], ignore_index=True)

print("\n📌 Final V5 shape:", df_v5.shape)
print(df_v5["label"].value_counts())

# Save output
df_v5.to_csv(V5_PATH, index=False)
print(f"\n💾 Saved merged dataset → {V5_PATH}")
