# agents/reporting_agent.py
# ─────────────────────────────────────────────────────────────────
# REPORTING AGENT
# Responsibilities:
#   • Compile a structured threat report for every detected incident
#   • Write human-readable logs to logs/system_logs.txt
#   • Persist machine-readable JSON to logs/threat_report.json
#   • Print a formatted summary to the console
# ─────────────────────────────────────────────────────────────────

import os
import sys
from datetime import datetime

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.helper_functions import log_event, save_report, timestamp


class ReportingAgent:
    """
    Agent 5 – Security Reporter

    Input : pd.DataFrame with attack_type, source_ip, severity, response_action
    Output: None (side effects: log file + JSON report)
    """

    def __init__(self):
        log_event("ReportingAgent initialised.", "INFO")

    # ------------------------------------------------------------------
    def run(self, df: pd.DataFrame) -> None:
        if df.empty:
            log_event("ReportingAgent: no incidents to report.", "INFO")
            return

        log_event(f"ReportingAgent: generating reports for {len(df)} incidents …", "INFO")

        for _, row in df.iterrows():
            report = self._build_report(row)
            save_report(report)
            self._print_report(report)

        self._print_summary(df)

    # ------------------------------------------------------------------
    def _build_report(self, row: pd.Series) -> dict:
        return {
            "timestamp":       timestamp(),
            "attack_type":     row.get("attack_type", "unknown"),
            "source_ip":       row.get("source_ip", "unknown"),
            "destination_ip":  row.get("destination_ip", "unknown"),
            "protocol":        row.get("protocol_type", "unknown"),
            "port":            int(row.get("port_number", 0)),
            "login_attempts":  int(row.get("login_attempts", 0)),
            "anomaly_score":   round(float(row.get("anomaly_score", 0.0)), 4),
            "confidence_pct":  float(row.get("confidence", 0.0)),
            "severity":        row.get("severity", "UNKNOWN"),
            "response_action": row.get("response_action", "none"),
        }

    def _print_report(self, r: dict) -> None:
        border = "─" * 60
        print(f"\n{'═'*60}")
        print(f"  🚨  THREAT DETECTED")
        print(border)
        print(f"  Attack Type   : {r['attack_type']}")
        print(f"  Source IP     : {r['source_ip']}")
        print(f"  Destination IP: {r['destination_ip']}")
        print(f"  Protocol      : {r['protocol']}  Port: {r['port']}")
        print(f"  Severity      : {r['severity']}")
        print(f"  Confidence    : {r['confidence_pct']}%")
        print(f"  Timestamp     : {r['timestamp']}")
        print(border)
        print(f"  Action Taken  : {r['response_action']}")
        print(f"{'═'*60}")

    def _print_summary(self, df: pd.DataFrame) -> None:
        total   = len(df)
        counts  = df["attack_type"].value_counts().to_dict()
        sevs    = df["severity"].value_counts().to_dict()

        print(f"\n{'━'*60}")
        print(f"  📊  INCIDENT SUMMARY  ({timestamp()})")
        print(f"{'━'*60}")
        print(f"  Total incidents : {total}")
        print(f"  By attack type  :")
        for atype, cnt in counts.items():
            print(f"      {atype:<20} {cnt:>5}")
        print(f"  By severity     :")
        for sev, cnt in sevs.items():
            print(f"      {sev:<20} {cnt:>5}")
        print(f"{'━'*60}\n")
        log_event(f"ReportingAgent: summary – {counts}", "INFO")
