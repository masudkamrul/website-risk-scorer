import pandas as pd
import time
import tldextract
import os

# Paths
V3_DATA = "data/fraudshield_dataset_v3.csv"  # includes fraud data
SAFE_LIST = "data/safe_urls_us_v6.txt"
OUT_PATH = "data/fraudshield_dataset_v6.csv"

print("📌 Loading base fraud dataset...")
df_fraud = pd.read_csv(V3_DATA)

# Keep only verified fraud rows
df_fraud = df_fraud[df_fraud['verified_label'] == 'Fraud']
df_fraud = df_fraud.head(1000)  # Keep balance limit

print(f"Fraud rows kept: {len(df_fraud)}")

# Load safe URLs
if not os.path.exists(SAFE_LIST):
    print(f"❌ ERROR: Missing {SAFE_LIST}")
    exit()

with open(SAFE_LIST, "r", encoding="utf-8") as f:
    safe_urls = [u.strip() for u in f if u.strip()]

print(f"Safe URLs found: {len(safe_urls)}")

# Build safe dataset
rows = []
for url in safe_urls:
    rows.append([
        time.time(),     # timestamp
        url,             # url
        *([0]*24),       # placeholder feature fields
        1.0,             # risk_score placeholder (very low == safe)
        "Safe",
        "Trusted Safe Website",
        "Safe — Manual",
        "Safe"
    ])

df_safe = pd.DataFrame(rows, columns=df_fraud.columns)

print(f"Safe rows generated: {len(df_safe)}")

# Merge fraud + safe
df_combined = pd.concat([df_fraud, df_safe], ignore_index=True)

# Shuffle so training is randomized
df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"📌 Final V6 dataset size: {len(df_combined)} rows")

df_combined.to_csv(OUT_PATH, index=False)
print(f"💾 Saved → {OUT_PATH}")
