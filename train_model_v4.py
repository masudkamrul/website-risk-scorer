import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump
import os

DATA_PATH = "data/fraudshield_dataset_v4.csv"
MODEL_OUT = "fraudshield_model_v4.joblib"

print("📌 Loading dataset...")
df = pd.read_csv(DATA_PATH)

print(f"Total entries: {len(df)}")

# Target label -----------------------------
df["label"] = df["risk_class"].apply(lambda x: 1 if x != "Safe" else 0)

# Feature engineering ----------------------
# Use these 6 key features only (stable + reliable)
df["uses_https"] = df["f18"]
df["mixed_ratio"] = df["f19"] / (df["f20"].replace(0, 1))  # avoid division zero
df["has_hsts_meta"] = df["f22"]
df["has_csp_meta"] = df["f23"]
df["domain_age_days"] = df["f0"]
df["blacklist_flag"] = df["f7"]

features = [
    "domain_age_days",
    "blacklist_flag",
    "uses_https",
    "mixed_ratio",
    "has_hsts_meta",
    "has_csp_meta"
]

X = df[features].fillna(0)
y = df["label"]

print("📌 Feature matrix shape:", X.shape)

# Balanced split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

# Train model --------------------------------
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=18,
    class_weight="balanced",
    random_state=42
)

print("🤖 Training model V4...")
model.fit(X_train, y_train)

# Evaluate -----------------------------------
y_pred = model.predict(X_test)

print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred))

print("\n🔍 Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model ---------------------------------
print(f"\n💾 Saving model → {MODEL_OUT}")
dump({
    "model": model,
    "features": features
}, MODEL_OUT)

print("🎯 Model V4 training completed successfully!")

