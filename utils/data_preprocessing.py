# utils/data_preprocessing.py
# Handles dataset generation, loading, cleaning, encoding, and normalization.

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import DATASET_RAW_PATH, DATASET_PROCESSED_PATH, N_SAMPLES, RANDOM_STATE, ATTACK_LABELS


def generate_synthetic_dataset(n_samples: int = N_SAMPLES, save: bool = True) -> pd.DataFrame:
    """
    Generate a realistic synthetic network traffic dataset.

    Features:
        source_ip          - source IPv4 address (string)
        destination_ip     - destination IPv4 address (string)
        protocol_type      - TCP / UDP / ICMP
        packet_size        - bytes per packet (int)
        connection_duration - seconds (float)
        login_attempts     - int
        port_number        - int
        label              - attack class
    """
    np.random.seed(RANDOM_STATE)

    # --- weights per class so data is realistic ---
    label_weights = [0.55, 0.15, 0.12, 0.12, 0.06]   # normal is majority
    labels = np.random.choice(ATTACK_LABELS, size=n_samples, p=label_weights)

    records = []
    for label in labels:
        rec = _generate_record(label)
        rec["label"] = label
        records.append(rec)

    df = pd.DataFrame(records)
    os.makedirs(os.path.dirname(DATASET_RAW_PATH), exist_ok=True)
    if save:
        df.to_csv(DATASET_RAW_PATH, index=False)
        print(f"[DataGen] Saved {len(df)} records → {DATASET_RAW_PATH}")
    return df


def _generate_record(label: str) -> dict:
    """Return one traffic record with feature values tuned per attack type."""
    protocols = ["TCP", "UDP", "ICMP"]

    if label == "normal":
        return dict(
            source_ip=_rand_ip(),
            destination_ip=_rand_ip(),
            protocol_type=np.random.choice(protocols, p=[0.6, 0.35, 0.05]),
            packet_size=int(np.random.normal(512, 150)),
            connection_duration=round(abs(np.random.normal(2.5, 1.5)), 2),
            login_attempts=int(np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1])),
            port_number=int(np.random.choice([80, 443, 22, 8080, 3306], p=[0.4, 0.3, 0.1, 0.1, 0.1])),
        )
    elif label == "DDoS":
        return dict(
            source_ip=_rand_ip(),
            destination_ip="192.168.1.1",         # single victim
            protocol_type=np.random.choice(protocols, p=[0.2, 0.7, 0.1]),
            packet_size=int(np.random.normal(64, 10)),   # tiny flooding packets
            connection_duration=round(abs(np.random.normal(0.1, 0.05)), 3),
            login_attempts=0,
            port_number=80,
        )
    elif label == "brute_force":
        return dict(
            source_ip=_rand_ip(),
            destination_ip=_rand_ip(),
            protocol_type="TCP",
            packet_size=int(np.random.normal(256, 50)),
            connection_duration=round(abs(np.random.normal(0.5, 0.2)), 2),
            login_attempts=int(np.random.randint(10, 100)),   # many attempts
            port_number=int(np.random.choice([22, 3389, 21])),
        )
    elif label == "port_scan":
        return dict(
            source_ip=_rand_ip(),
            destination_ip=_rand_ip(),
            protocol_type=np.random.choice(["TCP", "UDP"]),
            packet_size=int(np.random.normal(40, 10)),
            connection_duration=round(abs(np.random.normal(0.02, 0.01)), 4),
            login_attempts=0,
            port_number=int(np.random.randint(1, 65535)),   # scanning random ports
        )
    else:  # malware
        return dict(
            source_ip=_rand_ip(),
            destination_ip=_rand_ip(),
            protocol_type=np.random.choice(["TCP", "UDP"], p=[0.7, 0.3]),
            packet_size=int(np.random.normal(1400, 200)),   # large payloads
            connection_duration=round(abs(np.random.normal(15, 8)), 2),
            login_attempts=int(np.random.choice([0, 1])),
            port_number=int(np.random.choice([4444, 6666, 1234, 9999])),  # known C2 ports
        )


def _rand_ip() -> str:
    return ".".join(str(np.random.randint(1, 255)) for _ in range(4))


# ---------------------------------------------------------------------------

def load_and_preprocess(raw_path: str = DATASET_RAW_PATH) -> pd.DataFrame:
    """Load raw CSV, clean, encode categoricals, normalize numerics."""
    df = pd.read_csv(raw_path)
    print(f"[Preprocess] Loaded {len(df)} rows, {df.shape[1]} columns")

    # 1. Drop missing
    df.dropna(inplace=True)

    # 2. Clip obviously wrong values
    df["packet_size"] = df["packet_size"].clip(lower=20)
    df["connection_duration"] = df["connection_duration"].clip(lower=0)
    df["login_attempts"] = df["login_attempts"].clip(lower=0)
    df["port_number"] = df["port_number"].clip(lower=1, upper=65535)

    # 3. Encode protocol_type
    le = LabelEncoder()
    df["protocol_type_enc"] = le.fit_transform(df["protocol_type"])

    # 4. Encode label
    df["label_enc"] = le.fit_transform(df["label"])

    # 5. Normalize numeric features
    numeric_cols = ["packet_size", "connection_duration", "login_attempts", "port_number"]
    scaler = StandardScaler()
    df[numeric_cols] = scaler.fit_transform(df[numeric_cols])

    os.makedirs(os.path.dirname(DATASET_PROCESSED_PATH), exist_ok=True)
    df.to_csv(DATASET_PROCESSED_PATH, index=False)
    print(f"[Preprocess] Saved processed data → {DATASET_PROCESSED_PATH}")
    return df


def get_feature_matrix(df: pd.DataFrame):
    """Return X (features) and y (labels) ready for sklearn."""
    feature_cols = ["protocol_type_enc", "packet_size", "connection_duration",
                    "login_attempts", "port_number"]
    X = df[feature_cols].values
    y = df["label_enc"].values
    return X, y


def train_test(df: pd.DataFrame, test_size: float = 0.2):
    X, y = get_feature_matrix(df)
    return train_test_split(X, y, test_size=test_size, random_state=RANDOM_STATE, stratify=y)
