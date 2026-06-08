# agents/monitoring_agent.py
# ─────────────────────────────────────────────────────────────────
# MONITORING AGENT
# Responsibilities:
#   • Load raw network traffic dataset (or generate synthetic data)
#   • Validate and extract relevant features
#   • Pass structured DataFrame to the Anomaly Detection Agent
# ─────────────────────────────────────────────────────────────────

import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import DATASET_RAW_PATH, N_SAMPLES
from utils.data_preprocessing import generate_synthetic_dataset
from utils.helper_functions import log_event

# Features this agent is responsible for delivering downstream
REQUIRED_FEATURES = [
    "source_ip",
    "destination_ip",
    "protocol_type",
    "packet_size",
    "connection_duration",
    "login_attempts",
    "port_number",
    "label",          # ground-truth label (used for evaluation)
]


class MonitoringAgent:
    """
    Agent 1 – Network Traffic Monitor

    Input : raw CSV path or synthetic generation flag
    Output: pd.DataFrame with REQUIRED_FEATURES columns
    """

    def __init__(self, raw_path: str = DATASET_RAW_PATH, n_samples: int = N_SAMPLES):
        self.raw_path = raw_path
        self.n_samples = n_samples
        log_event("MonitoringAgent initialised.", "INFO")

    # ------------------------------------------------------------------
    def run(self) -> pd.DataFrame:
        """Main entry point. Returns a clean feature DataFrame."""
        log_event("MonitoringAgent: starting traffic collection …", "INFO")

        df = self._load_or_generate()
        df = self._validate(df)
        df = self._extract_features(df)

        log_event(f"MonitoringAgent: collected {len(df)} traffic records.", "INFO")
        return df

    # ------------------------------------------------------------------
    def _load_or_generate(self) -> pd.DataFrame:
        """Load dataset from disk; generate synthetic data if absent."""
        if os.path.exists(self.raw_path):
            log_event(f"MonitoringAgent: loading existing dataset from {self.raw_path}", "INFO")
            return pd.read_csv(self.raw_path)
        else:
            log_event("MonitoringAgent: dataset not found – generating synthetic traffic …", "WARNING")
            return generate_synthetic_dataset(n_samples=self.n_samples, save=True)

    def _validate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Drop rows with missing required fields; clip obviously invalid values."""
        before = len(df)
        df = df.dropna(subset=[c for c in REQUIRED_FEATURES if c in df.columns])
        dropped = before - len(df)
        if dropped:
            log_event(f"MonitoringAgent: dropped {dropped} incomplete rows.", "WARNING")

        # Sanity-clip numeric columns
        if "packet_size" in df.columns:
            df["packet_size"] = df["packet_size"].clip(lower=20)
        if "port_number" in df.columns:
            df["port_number"] = df["port_number"].clip(lower=1, upper=65535)
        if "login_attempts" in df.columns:
            df["login_attempts"] = df["login_attempts"].clip(lower=0)
        if "connection_duration" in df.columns:
            df["connection_duration"] = df["connection_duration"].clip(lower=0)

        return df

    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Keep only the required feature columns (+ label if present)."""
        cols = [c for c in REQUIRED_FEATURES if c in df.columns]
        return df[cols].reset_index(drop=True)
