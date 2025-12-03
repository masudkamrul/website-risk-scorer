import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)
from joblib import dump

DATA_FILE = "data/training_dataset_v8.csv"
MODEL_FILE = "fraudshield_model_v8.joblib"

def main():
    print("\n📚 Loading V8 training dataset...")
    df = pd.read_csv(DATA_FILE)

    print(df.head())

    # Separate features and label
    X = df[["domain_age_days", "blacklist_flag"]]
    y = df["label"]

    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n🤖 Training RandomForest V8 model...")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=10,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    # Save model
    dump(model, MODEL_FILE)
    print(f"\n💾 Model saved as: {MODEL_FILE}")

    # Predictions
    y_pred = model.predict(X_test)

    # Evaluation
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    cr = classification_report(y_test, y_pred)

    print("\n📊 Model V8 Evaluation Results:")
    print(f"Accuracy: {acc:.4f}")
    print("\nConfusion Matrix:")
    print(cm)
    print("\nClassification Report:")
    print(cr)


if __name__ == "__main__":
    main()
