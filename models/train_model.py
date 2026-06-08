# models/train_model.py
# ─────────────────────────────────────────────────────────────────
# Train the RandomForest attack classifier used by
# the Threat Intelligence Agent.
#
# Run:  python models/train_model.py
# ─────────────────────────────────────────────────────────────────

import os
import sys
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import (
    DATASET_RAW_PATH, MODEL_PATH, RANDOM_STATE, ATTACK_LABELS
)
from utils.data_preprocessing import generate_synthetic_dataset
from utils.helper_functions import log_event


def train_and_save():
    # ── 1. Load / generate dataset ──────────────────────────────
    if not os.path.exists(DATASET_RAW_PATH):
        log_event("train_model: dataset missing – generating …", "WARNING")
        generate_synthetic_dataset(save=True)

    df = pd.read_csv(DATASET_RAW_PATH)
    log_event(f"train_model: loaded {len(df)} rows for training.", "INFO")

    # ── 2. Preprocess ────────────────────────────────────────────
    df = df.dropna()

    le_proto = LabelEncoder()
    df["protocol_type_enc"] = le_proto.fit_transform(df["protocol_type"].astype(str).str.upper())

    le_label = LabelEncoder()
    le_label.fit(sorted(ATTACK_LABELS))
    df["label_enc"] = le_label.transform(df["label"])

    feature_cols = ["protocol_type_enc", "packet_size", "connection_duration",
                    "login_attempts", "port_number"]

    X = df[feature_cols].values.astype(float)
    y = df["label_enc"].values

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # ── 3. Split ─────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    log_event(f"train_model: train={len(X_train)}, test={len(X_test)}", "INFO")

    # ── 4. Train RandomForest ────────────────────────────────────
    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)
    log_event("train_model: RandomForestClassifier trained.", "INFO")

    # ── 5. Evaluate ──────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    target_names = le_label.classes_

    print("\n" + "="*60)
    print("  MODEL EVALUATION REPORT")
    print("="*60)
    print(classification_report(y_test, y_pred, target_names=target_names))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(pd.DataFrame(cm, index=target_names, columns=target_names))
    print("="*60 + "\n")

    acc = (y_pred == y_test).mean()
    log_event(f"train_model: test accuracy = {acc:.4f}", "INFO")

    # ── 6. Save model ────────────────────────────────────────────
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    log_event(f"train_model: model saved → {MODEL_PATH}", "INFO")
    print(f"✅  Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    train_and_save()
