# agents/threat_intelligence_agent.py
# ─────────────────────────────────────────────────────────────────
# THREAT INTELLIGENCE AGENT
# Responsibilities:
#   • Load the pre-trained RandomForest classifier
#   • Classify each suspicious record into an attack type
#   • Attach predicted label + confidence score
# ─────────────────────────────────────────────────────────────────

import os
import sys
import pickle

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import MODEL_PATH, ATTACK_LABELS
from utils.helper_functions import log_event

NUMERIC_FEATURES = ["packet_size", "connection_duration", "login_attempts", "port_number"]


class ThreatIntelligenceAgent:
    """
    Agent 3 – Attack Classifier (Random Forest)

    Input : pd.DataFrame of anomalous records (from AnomalyDetectionAgent)
    Output: same DataFrame with 'attack_type' and 'confidence' columns added
    """

    def __init__(self):
        self.model      = None
        self.le_proto   = LabelEncoder().fit(["ICMP", "TCP", "UDP"])
        self.le_label   = LabelEncoder().fit(sorted(ATTACK_LABELS))
        self.scaler     = StandardScaler()
        self._scaler_fitted = False
        log_event("ThreatIntelligenceAgent initialised.", "INFO")

    # ------------------------------------------------------------------
    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        """Classify every row and return enriched DataFrame."""
        if df.empty:
            log_event("ThreatIntelligenceAgent: no suspicious records to classify.", "INFO")
            df["attack_type"] = []
            df["confidence"]  = []
            return df

        log_event(f"ThreatIntelligenceAgent: classifying {len(df)} suspicious records …", "INFO")

        self.model = self._load_model()
        X          = self._prepare(df)

        probs        = self.model.predict_proba(X)
        label_indices = probs.argmax(axis=1)
        confidences  = probs.max(axis=1)

        # Map numeric index → attack label string
        attack_types = self.le_label.inverse_transform(label_indices)

        df = df.copy()
        df["attack_type"] = attack_types
        df["confidence"]  = np.round(confidences * 100, 1)

        # Summary log
        counts = pd.Series(attack_types).value_counts().to_dict()
        log_event(f"ThreatIntelligenceAgent: classification results → {counts}", "INFO")
        return df

    # ------------------------------------------------------------------
    def _prepare(self, df: pd.DataFrame) -> np.ndarray:
        """Build feature matrix matching the training schema."""
        tmp = df.copy()

        # Encode protocol_type safely (handle unseen values)
        proto = tmp["protocol_type"].astype(str).str.upper()
        proto = proto.apply(lambda p: p if p in self.le_proto.classes_ else "TCP")
        tmp["protocol_type_enc"] = self.le_proto.transform(proto)

        for col in NUMERIC_FEATURES:
            if col not in tmp.columns:
                tmp[col] = 0.0

        feature_cols = ["protocol_type_enc"] + NUMERIC_FEATURES
        X = tmp[feature_cols].values.astype(float)

        if not self._scaler_fitted:
            self.scaler.fit(X)
            self._scaler_fitted = True
        return self.scaler.transform(X)

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Trained model not found at {MODEL_PATH}. "
                "Run 'python models/train_model.py' first."
            )
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        log_event(f"ThreatIntelligenceAgent: model loaded from {MODEL_PATH}", "INFO")
        return model
