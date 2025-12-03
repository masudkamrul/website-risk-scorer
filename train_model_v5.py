import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump

DATA_PATH = "data/fraudshield_dataset_v5.csv"
MODEL_OUT = "fraudshield_model_v5.joblib"

print("📌 Loading V5 dataset...")
df = pd.read_csv(DATA_PATH)

print("Total entries:", len(df))

# If label not present (just in case), create it from risk_class
if "label" not in df.columns:
    df["label"] = df["risk_class"].apply(lambda x: 1 if str(x).strip() != "Safe" else 0)

print("\n📊 Label distribution (0=Safe, 1=Fraud):")
print(df["label"].value_counts())

# Feature engineering (reuse the same signal group)
# f0  = domain_age_days (from earlier logs)
# f7  = blacklist_flag or Safe Browsing hit (1 = blacklisted)
# f18 = uses_https
# f19 = mixed content count
# f20 = total resources
# f22 = has_hsts_meta or HSTS-like flag
# f23 = has_csp_meta or CSP-like flag

df["domain_age_days"] = df["f0"].fillna(0)
df["blacklist_flag"] = df["f7"].fillna(0)
df["uses_https"] = df["f18"].fillna(0)

# Avoid division by zero for mixed_ratio
total_resources = df["f20"].replace(0, 1)
df["mixed_ratio"] = df["f19"].fillna(0) / total_resources

df["has_hsts_meta"] = df["f22"].fillna(0)
df["has_csp_meta"] = df["f23"].fillna(0)

features = [
    "domain_age_days",
    "blacklist_flag",
    "uses_https",
    "mixed_ratio",
    "has_hsts_meta",
    "has_csp_meta",
]

X = df[features].astype(float)
y = df["label"].astype(int)

print("\n📌 Feature matrix shape:", X.shape)

# Train / test split with stratification
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=18,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("\n🤖 Training model V5...")
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)

print("\n📊 Classification Report (0=Safe, 1=Fraud):")
print(classification_report(y_test, y_pred, digits=4))

print("\n🔍 Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model + feature list
print(f"\n💾 Saving model → {MODEL_OUT}")
dump({
    "model": model,
    "features": features
}, MODEL_OUT)

print("🎯 Model V5 training completed successfully!")
