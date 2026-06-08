# main.py
# ─────────────────────────────────────────────────────────────────
# MAIN CONTROLLER
# Orchestrates all five agents in the correct pipeline order:
#
#   MonitoringAgent
#       ↓
#   AnomalyDetectionAgent
#       ↓
#   ThreatIntelligenceAgent
#       ↓
#   ResponseAgent
#       ↓
#   ReportingAgent
# ─────────────────────────────────────────────────────────────────

import os
import sys
import argparse

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.config import MODEL_PATH
from agents.monitoring_agent          import MonitoringAgent
from agents.anomaly_detection_agent   import AnomalyDetectionAgent
from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.response_agent            import ResponseAgent
from agents.reporting_agent           import ReportingAgent
from utils.helper_functions           import log_event


def run_pipeline(n_samples: int = 5000, retrain: bool = False):
    print("\n" + "█"*62)
    print("  🛡️   CYBERNEXUS: MULTI-AGENT THREAT DETECTION SYSTEM")
    print("█"*62 + "\n")

    # ── 0. Train model if needed ─────────────────────────────────
    if retrain or not os.path.exists(MODEL_PATH):
        log_event("main: (re)training classifier …", "INFO")
        from models.train_model import train_and_save
        train_and_save()

    # ── 1. Monitoring Agent ──────────────────────────────────────
    log_event("main: ── STAGE 1 – Monitoring Agent ──", "INFO")
    monitor = MonitoringAgent(n_samples=n_samples)
    traffic_df = monitor.run()

    # ── 2. Anomaly Detection Agent ───────────────────────────────
    log_event("main: ── STAGE 2 – Anomaly Detection Agent ──", "INFO")
    anomaly_agent = AnomalyDetectionAgent()
    suspicious_df = anomaly_agent.run(traffic_df)

    if suspicious_df.empty:
        print("✅  No anomalies detected in the current traffic window.")
        return

    # ── 3. Threat Intelligence Agent ─────────────────────────────
    log_event("main: ── STAGE 3 – Threat Intelligence Agent ──", "INFO")
    threat_agent = ThreatIntelligenceAgent()
    classified_df = threat_agent.run(suspicious_df)

    # Filter out records classified as normal (false positives from anomaly step)
    threats_df = classified_df[classified_df["attack_type"] != "normal"].reset_index(drop=True)
    log_event(f"main: {len(threats_df)} genuine threats identified.", "INFO")

    if threats_df.empty:
        print("✅  All flagged records reclassified as normal traffic.")
        return

    # ── 4. Response Agent ─────────────────────────────────────────
    log_event("main: ── STAGE 4 – Response Agent ──", "INFO")
    response_agent = ResponseAgent()
    responded_df = response_agent.run(threats_df)
    log_event(f"main: {response_agent.blocked_count} unique IPs blocked.", "INFO")

    # ── 5. Reporting Agent ────────────────────────────────────────
    log_event("main: ── STAGE 5 – Reporting Agent ──", "INFO")
    reporting_agent = ReportingAgent()
    reporting_agent.run(responded_df)

    print("\n✅  Pipeline complete. Launch dashboard with:")
    print("    streamlit run dashboard/dashboard.py\n")


# ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cybersecurity Threat Detection Pipeline")
    parser.add_argument("--samples", type=int, default=5000,
                        help="Number of traffic records to simulate (default 5000)")
    parser.add_argument("--retrain", action="store_true",
                        help="Force retrain the classifier even if a saved model exists")
    args = parser.parse_args()

    run_pipeline(n_samples=args.samples, retrain=args.retrain)
