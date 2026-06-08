# agents/response_agent.py
# ─────────────────────────────────────────────────────────────────
# RESPONSE AGENT
# Responsibilities:
#   • Evaluate each classified threat
#   • Execute the appropriate automated response:
#       - Block IP (simulated firewall rule)
#       - Generate alert
#       - Log security incident
#   • Return enriched DataFrame with 'response_action' column
# ─────────────────────────────────────────────────────────────────

import os
import sys
from typing import Dict, Set

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import BLOCK_DURATION_MINUTES
from utils.helper_functions import log_event, get_severity

# In-memory "firewall" – tracks currently blocked IPs
_BLOCKED_IPS: Set[str] = set()


class ResponseAgent:
    """
    Agent 4 – Automated Response

    Input : pd.DataFrame with 'attack_type' and 'source_ip' columns
    Output: same DataFrame with 'response_action' and 'severity' columns added
    """

    def __init__(self):
        self.blocked_ips: Set[str] = _BLOCKED_IPS
        log_event("ResponseAgent initialised.", "INFO")

    # ------------------------------------------------------------------
    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            log_event("ResponseAgent: no threats to respond to.", "INFO")
            df["response_action"] = []
            df["severity"]        = []
            return df

        log_event(f"ResponseAgent: evaluating {len(df)} threats …", "INFO")

        actions   = []
        severities = []

        for _, row in df.iterrows():
            attack_type = row.get("attack_type", "normal")
            source_ip   = row.get("source_ip", "unknown")
            severity    = get_severity(attack_type)

            action = self._decide_action(attack_type, source_ip)
            actions.append(action)
            severities.append(severity)

        df = df.copy()
        df["response_action"] = actions
        df["severity"]        = severities
        return df

    # ------------------------------------------------------------------
    def _decide_action(self, attack_type: str, source_ip: str) -> str:
        """Return the response action string and execute it (simulated)."""
        if attack_type == "normal":
            return "No action required"

        elif attack_type == "DDoS":
            self._block_ip(source_ip)
            msg = f"IP {source_ip} blocked for {BLOCK_DURATION_MINUTES} min | Rate-limiting applied | Admin alerted"
            log_event(f"[RESPONSE] DDoS: {msg}", "CRITICAL")
            return msg

        elif attack_type == "brute_force":
            self._block_ip(source_ip)
            msg = f"IP {source_ip} blocked | Account lockout enforced | MFA prompt triggered"
            log_event(f"[RESPONSE] Brute-force: {msg}", "HIGH")
            return msg

        elif attack_type == "port_scan":
            msg = f"IP {source_ip} flagged for monitoring | Port-scan alert raised"
            log_event(f"[RESPONSE] Port-scan: {msg}", "MEDIUM")
            return msg

        elif attack_type == "malware":
            self._block_ip(source_ip)
            msg = f"IP {source_ip} blocked | Connection terminated | Endpoint quarantine initiated"
            log_event(f"[RESPONSE] Malware: {msg}", "CRITICAL")
            return msg

        else:
            msg = f"Unknown threat from {source_ip} – logged for review"
            log_event(f"[RESPONSE] Unknown: {msg}", "WARNING")
            return msg

    def _block_ip(self, ip: str) -> None:
        """Simulate adding a firewall block rule."""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            log_event(f"[FIREWALL] Simulated block rule added for {ip}", "INFO")

    @property
    def blocked_count(self) -> int:
        return len(self.blocked_ips)
