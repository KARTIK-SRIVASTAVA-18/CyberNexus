# config/config.py
# Central configuration for the Multi-Agent Cybersecurity Threat Detection System

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Paths
DATASET_RAW_PATH      = os.path.join(BASE_DIR, "dataset", "raw_data", "network_traffic.csv")
DATASET_PROCESSED_PATH = os.path.join(BASE_DIR, "dataset", "processed_data", "processed_traffic.csv")
MODEL_PATH            = os.path.join(BASE_DIR, "models", "saved_model.pkl")
ANOMALY_MODEL_PATH    = os.path.join(BASE_DIR, "models", "anomaly_model.pkl")
LOG_PATH              = os.path.join(BASE_DIR, "logs", "system_logs.txt")
REPORT_PATH           = os.path.join(BASE_DIR, "logs", "threat_report.json")

# Simulation
N_SAMPLES = 5000          # number of synthetic traffic records to generate
RANDOM_STATE = 42

# Anomaly detection
ANOMALY_CONTAMINATION = 0.15   # expected fraction of anomalies

# Response thresholds
BLOCK_DURATION_MINUTES = 20    # how long to block a malicious IP

# Attack labels
ATTACK_LABELS = ["normal", "DDoS", "brute_force", "port_scan", "malware"]

# Severity mapping
SEVERITY = {
    "normal":      "INFO",
    "DDoS":        "CRITICAL",
    "brute_force": "HIGH",
    "port_scan":   "MEDIUM",
    "malware":     "CRITICAL",
}
