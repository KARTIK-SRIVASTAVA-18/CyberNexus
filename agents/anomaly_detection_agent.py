# agents/anomaly_detection_agent.py
# ─────────────────────────────────────────────────────────────────
# ANOMALY DETECTION AGENT
# Responsibilities:
#   • Encode and normalise raw traffic features
#   • Train / load an Isolation Forest model
#   • Score every traffic record
#   • Flag suspicious records and pass them to the Threat Intelligence Agent
# ─────────────────────────────────────────────────────────────────

import os
import sys
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import ANOMALY_MODEL_PATH, ANOMALY_CONTAMINATION, RANDOM_STATE
from utils.helper_functions import log_event

NUMERIC_FEATURES   = ["packet_size", "connection_duration", "login_attempts", "port_number"]
CATEGORIC_FEATURES = ["protocol_type"]
ALL_FEATURES       = CATEGORIC_FEATURES + NUMERIC_FEATURES


class AnomalyDetectionAgent:
    """
    Agent 2 – Anomaly Detector (Isolation Forest)

    Input : raw pd.DataFrame from MonitoringAgent
    Output: pd.DataFrame with only the anomalous rows + anomaly_score column
    """

    def __init__(self, contamination: float = ANOMALY_CONTAMINATION):
        self.contamination = contamination
        self.model: IsolationForest | None = None
        self.le    = LabelEncoder()
        self.scaler = StandardScaler()
        log_event("AnomalyDetectionAgent initialised.", "INFO")

    # ------------------------------------------------------------------
    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        1. Pre-process features.
        2. Train (or load) Isolation Forest.
        3. Predict anomalies.
        4. Return only suspicious rows.
        """
        log_event("AnomalyDetectionAgent: processing traffic features …", "INFO")

        X, df_clean = self._prepare(df)

        self.model = self._load_or_train(X)

        scores   = self.model.decision_function(X)   # more negative → more anomalous
        preds    = self.model.predict(X)              # -1 = anomaly, +1 = normal

        df_clean = df_clean.copy()
        df_clean["anomaly_score"] = scores
        df_clean["is_anomaly"]    = (preds == -1).astype(int)

        suspicious = df_clean[df_clean["is_anomaly"] == 1].reset_index(drop=True)

        n_anom = len(suspicious)
        log_event(f"AnomalyDetectionAgent: flagged {n_anom} / {len(df_clean)} records as anomalous.", "INFO")
        return suspicious

    # ------------------------------------------------------------------
    def _prepare(self, df: pd.DataFrame):
        """Encode categoricals, normalise numerics, return (X_array, df_clean)."""
        df_clean = df.copy()

        # Encode protocol_type
        df_clean["protocol_type_enc"] = self.le.fit_transform(
            df_clean["protocol_type"].astype(str)
        )

        feature_cols = ["protocol_type_enc"] + NUMERIC_FEATURES
        # Ensure all numeric cols exist; fill missing with 0
        for col in NUMERIC_FEATURES:
            if col not in df_clean.columns:
                df_clean[col] = 0.0

        X_raw = df_clean[feature_cols].values.astype(float)
        X     = self.scaler.fit_transform(X_raw)
        return X, df_clean

    def _load_or_train(self, X: np.ndarray) -> IsolationForest:
        """Load saved model if it exists, otherwise train a new one."""
        if os.path.exists(ANOMALY_MODEL_PATH):
            log_event(f"AnomalyDetectionAgent: loading model from {ANOMALY_MODEL_PATH}", "INFO")
            with open(ANOMALY_MODEL_PATH, "rb") as f:
                return pickle.load(f)

        log_event("AnomalyDetectionAgent: training Isolation Forest …", "INFO")
        model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        model.fit(X)

        os.makedirs(os.path.dirname(ANOMALY_MODEL_PATH), exist_ok=True)
        with open(ANOMALY_MODEL_PATH, "wb") as f:
            pickle.dump(model, f)
        log_event(f"AnomalyDetectionAgent: model saved → {ANOMALY_MODEL_PATH}", "INFO")
        return model
