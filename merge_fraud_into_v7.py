import pandas as pd
import os
import time

SAFE_FILE = "data/fraudshield_dataset_v6.csv"
FRAUD_FILE = "data/fraudshield_dataset_v3.csv"
OUT_FILE = "data/fraudshield_dataset_v7.csv"

print("📌 Loading safe dataset V6...")
df_safe = pd.read_csv(SAFE_FILE)

print("📌 Loading fraud dataset V3...")
df_fraud = pd.read_csv(FRAUD_FILE)

print("🔍 Filtering fraud rows...")
df_fraud = df_fraud[df_fraud["verified_label"] != "Safe"]

print(f"Safe rows:  {len(df_safe)}")
print(f"Fraud rows: {len(df_fraud)}")

print("📌 Aligning columns...")
common_cols = list(set(df_safe.columns).intersection(set(df_fraud.columns)))
df_safe = df_safe[common_cols]
df_fraud = df_fraud[common_cols]

print("📌 Merging datasets...")
df_merged = pd.concat([df_safe, df_fraud], ignore_index=True)

print("🧹 Removing duplicates by domain...")
df_merged["domain"] = df_merged["url"].str.extract(r"https?://([^/]+)/?")
df_merged.drop_duplicates(subset="domain", inplace=True)

df_merged.drop(columns=["domain"], inplace=True)

print(f"📊 Final V7 count: {len(df_merged)} rows")

print(f"💾 Saving → {OUT_FILE}")
df_merged.to_csv(OUT_FILE, index=False)

print("🎯 Merge completed successfully!")
