import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump

DATA_PATH = "data/fraudshield_dataset_v7.csv"

print("📌 Loading V7 dataset...")
df = pd.read_csv(DATA_PATH)

df["label"] = df["verified_label"].apply(lambda x: 0 if x == "Safe" else 1)

X = df[["f0", "f18", "f21", "f22", "f23"]].fillna(0)
y = df["label"]

print("\n📊 Label distribution:")
print(y.value_counts())

print(f"\n📌 Feature matrix shape: {X.shape}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

print("\n🤖 Training RandomForest Model V7...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    class_weight="balanced_subsample",
    random_state=42,
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred))

print("\n🔍 Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

dump({"model": model}, "fraudshield_model_v7.joblib")
print("\n💾 Model saved → fraudshield_model_v7.joblib")
print("🎯 V7 training completed successfully!")
