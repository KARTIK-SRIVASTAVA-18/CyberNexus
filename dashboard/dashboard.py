# dashboard/dashboard.py
# ──────────────────────────────────────────────────────────────
# CyberNexus — Multi-Agent Threat Intelligence Dashboard
# Run: streamlit run dashboard/dashboard.py
# ──────────────────────────────────────────────────────────────

import os, sys, time, datetime, json, random, hashlib, base64
from collections import deque

# ── Timezone: force Indian Standard Time (UTC+5:30) ─────────
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import REPORT_PATH, LOG_PATH
from utils.helper_functions import load_reports

# ── Page Config ──────────────────────────────────────────────
st.set_page_config(
    page_title="CyberNexus — Threat Intelligence",
    page_icon="C",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Design System (CSS) ─────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Base ────────────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background-color: #0b1120;
    color: #d1d5db;
}
.main { background-color: #0b1120; }

/* ── Typography ──────────────────────────────────────────── */
h1 { font-family: 'Inter', sans-serif; font-weight: 700; color: #e2e8f0; font-size: 1.75rem !important; letter-spacing: -0.02em; }
h2 { font-family: 'Inter', sans-serif; font-weight: 600; color: #e2e8f0; font-size: 1.3rem !important; }
h3 { font-family: 'Inter', sans-serif; font-weight: 600; color: #94a3b8; font-size: 0.95rem !important; text-transform: uppercase; letter-spacing: 0.08em; }

/* ── Sidebar ─────────────────────────────────────────────── */
section[data-testid="stSidebar"] { background-color: #0f172a; border-right: 1px solid #1e293b; }
section[data-testid="stSidebar"] h2 { color: #e2e8f0; }

/* ── KPI Metric Cards ────────────────────────────────────── */
[data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 1.8rem !important;
    font-weight: 600 !important;
    color: #e2e8f0 !important;
}
[data-testid="stMetricLabel"] { color: #64748b !important; font-size: 0.8rem !important; text-transform: uppercase; letter-spacing: 0.05em; }
[data-testid="stMetricDelta"] { color: #34d399 !important; }
[data-testid="metric-container"] {
    background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 16px;
}

/* ── Multiselect Tags ────────────────────────────────────── */
span[data-baseweb="tag"] {
    background-color: #1e293b !important;
    border: 1px solid #334155 !important;
    color: #94a3b8 !important;
    border-radius: 6px !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.8rem !important;
}
span[data-baseweb="tag"] svg { fill: #ef4444 !important; }

/* ── Section Dividers ────────────────────────────────────── */
hr { border-color: #1e293b !important; opacity: 0.5 !important; }

/* ── Top Command Bar ─────────────────────────────────────── */
.cn-cmd-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(90deg, #111827 0%, #0f172a 50%, #111827 100%);
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 12px 24px;
    margin-bottom: 16px;
    flex-wrap: wrap;
    gap: 10px;
}
.cn-cmd-left {
    display: flex;
    align-items: center;
    gap: 14px;
}
.cn-cmd-logo {
    width: 36px; height: 36px;
    background: linear-gradient(135deg, #3b82f6, #8b5cf6);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700; font-size: 0.95rem; color: white;
}
.cn-cmd-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #e2e8f0;
    font-family: 'Inter', sans-serif;
}
.cn-cmd-tagline {
    font-size: 0.7rem;
    color: #64748b;
}
.cn-cmd-stats {
    display: flex;
    align-items: center;
    gap: 28px;
    flex-wrap: wrap;
}
.cn-cmd-stat {
    text-align: center;
}
.cn-cmd-stat-label {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #475569;
    margin-bottom: 2px;
}
.cn-cmd-stat-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    font-weight: 600;
    color: #e2e8f0;
}
.cn-cmd-stat-value .val-green { color: #4ade80; }
.cn-cmd-stat-value .val-red   { color: #f87171; }
.cn-cmd-stat-value .val-amber { color: #fbbf24; }
.cn-cmd-stat-value .val-blue  { color: #60a5fa; }

/* ── Custom Components ───────────────────────────────────── */
.cn-header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 4px;
}
.cn-logo {
    width: 38px; height: 38px;
    background: linear-gradient(135deg, #3b82f6, #8b5cf6);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700; font-size: 1.1rem; color: white;
}
.cn-subtitle { font-size: 0.8rem; color: #64748b; font-family: 'Inter', sans-serif; }

.cn-section-label {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #475569;
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid #1e293b;
}

/* ── Pipeline Visualization ──────────────────────────────── */
.cn-pipeline {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 20px;
}
.cn-pipe-step {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 10px 0;
    position: relative;
}
.cn-pipe-step:not(:last-child) { border-left: 2px solid #1e293b; margin-left: 14px; padding-left: 24px; }
.cn-pipe-step:last-child { margin-left: 14px; padding-left: 24px; border-left: 2px solid transparent; }
.cn-pipe-dot {
    width: 12px; height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 9px;
    top: 14px;
    z-index: 1;
}
.cn-pipe-dot.active { background: #4ade80; box-shadow: 0 0 8px rgba(74,222,128,0.5); }
.cn-pipe-dot.idle   { background: #334155; }
.cn-pipe-agent {
    font-weight: 600;
    font-size: 0.88rem;
    color: #e2e8f0;
}
.cn-pipe-action {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: #4ade80;
    margin-top: 2px;
}
.cn-pipe-action.idle-text { color: #475569; }

/* ── Agent Status Table ──────────────────────────────────── */
.cn-agent-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
}
.cn-agent-table th {
    text-align: left;
    padding: 8px 12px;
    color: #475569;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-bottom: 1px solid #1e293b;
    font-weight: 600;
}
.cn-agent-table td {
    padding: 10px 12px;
    color: #d1d5db;
    border-bottom: 1px solid #111827;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
}
.cn-agent-table tr:hover td { background: #1e293b; }
.agent-online { color: #4ade80; font-weight: 600; }
.agent-idle   { color: #64748b; }
.progress-bar {
    width: 60px;
    height: 6px;
    background: #1e293b;
    border-radius: 3px;
    overflow: hidden;
    display: inline-block;
    vertical-align: middle;
    margin-right: 6px;
}
.progress-fill {
    height: 100%;
    border-radius: 3px;
}

/* ── Alert Feed ──────────────────────────────────────────── */
.cn-alert {
    background: #111827;
    border: 1px solid #1e293b;
    border-left: 3px solid #ef4444;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 5px 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #d1d5db;
    transition: background 0.2s;
}
.cn-alert:hover { background: #1e293b; }
.cn-alert.sev-HIGH   { border-left-color: #f59e0b; }
.cn-alert.sev-MEDIUM { border-left-color: #eab308; }
.cn-alert.sev-INFO   { border-left-color: #3b82f6; }

/* ── Response Cards ──────────────────────────────────────── */
.cn-resp-card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px;
    margin: 6px 0;
    font-family: 'Inter', sans-serif;
    transition: border-color 0.2s, transform 0.2s;
}
.cn-resp-card:hover { border-color: #334155; transform: translateY(-1px); }
.cn-resp-card .card-tag {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    margin-bottom: 8px;
}
.cn-resp-card .tag-critical { background: rgba(239,68,68,0.15); color: #f87171; }
.cn-resp-card .tag-high     { background: rgba(245,158,11,0.15); color: #fbbf24; }
.cn-resp-card .tag-medium   { background: rgba(234,179,8,0.15);  color: #facc15; }
.cn-resp-card .card-title   { font-size: 0.95rem; font-weight: 600; color: #e2e8f0; margin-bottom: 10px; }
.cn-resp-card .card-action  { color: #34d399; font-size: 0.8rem; margin: 3px 0; font-family: 'JetBrains Mono', monospace; }
.cn-resp-card .card-meta    { color: #64748b; font-size: 0.75rem; margin-top: 8px; }

/* ── Welcome Card ────────────────────────────────────────── */
.cn-welcome {
    background: linear-gradient(135deg, #111827 0%, #1e1b4b 100%);
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 40px 32px;
    text-align: center;
    max-width: 750px;
    margin: 40px auto;
}
.cn-welcome h2 { color: #e2e8f0 !important; font-size: 1.5rem !important; margin-bottom: 16px; text-transform: none !important; letter-spacing: normal !important; }
.cn-welcome p { color: #94a3b8; font-size: 1rem; line-height: 1.7; text-align: left; }
.cn-welcome .highlight { color: #818cf8; font-weight: 600; }
.cn-welcome .step-list { text-align: left; margin: 16px 0; padding-left: 0; }
.cn-welcome .step-item {
    display: flex; align-items: flex-start; gap: 12px;
    padding: 8px 0;
    color: #94a3b8;
    font-size: 0.92rem;
}
.cn-welcome .step-num {
    min-width: 26px; height: 26px;
    background: linear-gradient(135deg, #3b82f6, #8b5cf6);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.75rem; font-weight: 700; color: white;
    flex-shrink: 0;
}
.cn-welcome .step-text b { color: #e2e8f0; }

/* ── KPI Card Row ────────────────────────────────────────── */
.cn-kpi-row { display: flex; gap: 14px; flex-wrap: wrap; }
.cn-kpi-card {
    flex: 1;
    min-width: 140px;
    background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 16px;
    display: flex;
    align-items: center;
    gap: 14px;
}
.cn-kpi-icon {
    width: 44px; height: 44px;
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.2rem;
    flex-shrink: 0;
}
.cn-kpi-icon.kpi-red    { background: rgba(239,68,68,0.15); color: #f87171; }
.cn-kpi-icon.kpi-green  { background: rgba(74,222,128,0.15); color: #4ade80; }
.cn-kpi-icon.kpi-amber  { background: rgba(251,191,36,0.15); color: #fbbf24; }
.cn-kpi-icon.kpi-blue   { background: rgba(96,165,250,0.15); color: #60a5fa; }
.cn-kpi-icon.kpi-purple { background: rgba(139,92,246,0.15); color: #a78bfa; }
.cn-kpi-label {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748b;
    margin-bottom: 2px;
}
.cn-kpi-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.6rem;
    font-weight: 600;
    color: #e2e8f0;
    line-height: 1.1;
}
.cn-kpi-delta {
    font-size: 0.72rem;
    color: #4ade80;
    margin-top: 2px;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Sidebar Agent Dots ──────────────────────────────────── */
.cn-agent-row {
    display: flex; align-items: center; gap: 8px;
    padding: 6px 0;
    font-size: 0.82rem;
    color: #94a3b8;
}
.cn-agent-dot {
    width: 7px; height: 7px; border-radius: 50%;
    flex-shrink: 0;
}
.cn-agent-dot.active { background: #4ade80; box-shadow: 0 0 6px rgba(74,222,128,0.5); }
.cn-agent-dot.idle   { background: #475569; }
.cn-agent-name { font-weight: 500; color: #cbd5e1; }

/* ── Data Table ──────────────────────────────────────────── */
.stDataFrame { background: #111827 !important; border-radius: 8px; }

/* ── Threat Timeline ─────────────────────────────────────── */
.cn-timeline {
    position: relative;
    padding-left: 20px;
}
.cn-timeline::before {
    content: '';
    position: absolute;
    left: 6px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: #1e293b;
}
.cn-tl-item {
    position: relative;
    padding: 8px 0 8px 16px;
    font-size: 0.82rem;
}
.cn-tl-item::before {
    content: '';
    position: absolute;
    left: -17px;
    top: 14px;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    border: 2px solid;
}
.cn-tl-item.tl-critical::before { border-color: #ef4444; background: rgba(239,68,68,0.3); }
.cn-tl-item.tl-high::before     { border-color: #f59e0b; background: rgba(245,158,11,0.3); }
.cn-tl-item.tl-medium::before   { border-color: #eab308; background: rgba(234,179,8,0.3); }
.cn-tl-item.tl-info::before     { border-color: #3b82f6; background: rgba(59,130,246,0.3); }
.cn-tl-time {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #475569;
}
.cn-tl-title {
    font-weight: 600;
    color: #e2e8f0;
    font-size: 0.85rem;
}
.cn-tl-desc {
    color: #64748b;
    font-size: 0.78rem;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Footer ──────────────────────────────────────────────── */
.cn-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 0 8px;
    color: #334155;
    font-size: 0.75rem;
    font-family: 'Inter', sans-serif;
    border-top: 1px solid #1e293b;
    margin-top: 30px;
}
.cn-footer-status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 600;
}
.cn-footer-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    display: inline-block;
}
.cn-footer-dot.operational { background: #4ade80; box-shadow: 0 0 6px rgba(74,222,128,0.4); }
.cn-footer-dot.standby     { background: #475569; }
</style>
""", unsafe_allow_html=True)

# ── Geo Helper: derive country from IP hash ──────────────────
COUNTRY_DATA = [
    ("United States", "USA", 37.0902, -95.7129),
    ("China",         "CHN", 35.8617, 104.1954),
    ("Russia",        "RUS", 61.5240, 105.3188),
    ("Germany",       "DEU", 51.1657, 10.4515),
    ("Brazil",        "BRA", -14.2350, -51.9253),
    ("India",         "IND", 20.5937, 78.9629),
    ("Netherlands",   "NLD", 52.1326, 5.2913),
    ("South Korea",   "KOR", 35.9078, 127.7669),
    ("Iran",          "IRN", 32.4279, 53.6880),
    ("Vietnam",       "VNM", 14.0583, 108.2772),
    ("Romania",       "ROU", 45.9432, 24.9668),
    ("Indonesia",     "IDN", -0.7893, 113.9213),
]

def ip_to_country(ip):
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    return COUNTRY_DATA[h % len(COUNTRY_DATA)]

# ── Session State Init ───────────────────────────────────────
if "app_initialized" not in st.session_state:
    st.session_state.app_initialized = True
    if os.path.exists(REPORT_PATH):
        try: os.remove(REPORT_PATH)
        except Exception: pass
    if os.path.exists(LOG_PATH):
        try: os.remove(LOG_PATH)
        except Exception: pass

if "spike_history" not in st.session_state:
    st.session_state.spike_history = deque(maxlen=60)
    st.session_state.prev_total = 0

if "auto_inject" not in st.session_state:
    st.session_state.auto_inject = False

if "last_pipeline_info" not in st.session_state:
    st.session_state.last_pipeline_info = None

# ── Helper ───────────────────────────────────────────────────
def load_data():
    reports = load_reports()
    if not reports: return pd.DataFrame()
    df = pd.DataFrame(reports)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

# ── SIDEBAR ──────────────────────────────────────────────────
with st.sidebar:
    # Load sidebar logo
    _logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
    _logo_b64_sidebar = ""
    if os.path.exists(_logo_path):
        with open(_logo_path, "rb") as _img_f:
            _logo_b64_sidebar = base64.b64encode(_img_f.read()).decode()
    _logo_sidebar = f"<img src='data:image/png;base64,{_logo_b64_sidebar}' style='width:80px;height:80px;border-radius:16px;margin-bottom:10px;'>" if _logo_b64_sidebar else ""

    st.markdown(f"""
    <div style='text-align:center;padding:8px 0 4px;'>
        {_logo_sidebar}
        <div style='font-size:1.4rem;font-weight:700;color:#e2e8f0;font-family:Inter,sans-serif;'>CyberNexus</div>
        <div class='cn-subtitle'>Threat Intelligence Platform</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")

    st.markdown("<div class='cn-section-label'>Controls</div>", unsafe_allow_html=True)
    refresh_rate = st.slider("Refresh interval", 2, 15, 3, help="How often the dashboard polls for new data (seconds)")
    if st.button("Refresh now"): st.rerun()
    st.markdown("---")

    st.markdown("<div class='cn-section-label'>Real-Time Interception</div>", unsafe_allow_html=True)
    st.caption("Generates unclassified network packets and feeds them through the 5-agent ML pipeline for live analysis.")
    btn_label = "Disable interception" if st.session_state.auto_inject else "Enable interception"
    if st.button(btn_label, type="primary" if not st.session_state.auto_inject else "secondary"):
        st.session_state.auto_inject = not st.session_state.auto_inject
        st.rerun()
    st.markdown("---")

    st.markdown("<div class='cn-section-label'>Agent Pipeline</div>", unsafe_allow_html=True)
    agents_sidebar = [
        ("Monitoring Agent", "Packet capture"),
        ("Anomaly Detection", "Isolation Forest"),
        ("Threat Intelligence", "Random Forest"),
        ("Response Engine", "Firewall rules"),
        ("Reporting Agent", "Log generation"),
    ]
    dot_class = "active" if st.session_state.auto_inject else "idle"
    for name, desc in agents_sidebar:
        st.markdown(f"""
        <div class='cn-agent-row'>
            <div class='cn-agent-dot {dot_class}'></div>
            <span class='cn-agent-name'>{name}</span>
            <span style='margin-left:auto;font-size:0.72rem;color:#475569'>{desc}</span>
        </div>""", unsafe_allow_html=True)
    st.markdown("---")

    st.markdown("<div class='cn-section-label'>Filters</div>", unsafe_allow_html=True)
    severity_filter = st.multiselect("Severity", ["CRITICAL","HIGH","MEDIUM","INFO"], default=["CRITICAL","HIGH","MEDIUM","INFO"])
    attack_filter   = st.multiselect("Attack type", ["DDoS","brute_force","port_scan","malware"], default=["DDoS","brute_force","port_scan","malware"])
    st.markdown("---")

    if st.button("Reset dashboard"):
        try:
            if os.path.exists(REPORT_PATH): os.remove(REPORT_PATH)
            st.session_state.spike_history = deque(maxlen=60)
            st.session_state.prev_total = 0
            st.session_state.last_pipeline_info = None
            st.rerun()
        except Exception as e:
            st.error(f"Error: {e}")

# ── INTERCEPTION ENGINE ──────────────────────────────────────
pipeline_info = None
if st.session_state.auto_inject:
    from utils.data_preprocessing import generate_synthetic_dataset
    from agents.anomaly_detection_agent import AnomalyDetectionAgent
    from agents.threat_intelligence_agent import ThreatIntelligenceAgent
    from agents.response_agent import ResponseAgent
    from agents.reporting_agent import ReportingAgent

    t0 = time.time()
    n_packets = random.randint(20, 60)
    traffic_df = generate_synthetic_dataset(n_samples=n_packets, save=False)
    t1 = time.time()

    pipeline_info = {
        "packets_scanned": n_packets,
        "suspicious_found": 0,
        "threats_classified": 0,
        "actions_taken": 0,
        "sample_ip": "—",
        "sample_attack": "—",
        "sample_score": "—",
        "times": {
            "Monitoring": round((t1 - t0) * 1000, 1),
            "Detection": 0,
            "Intelligence": 0,
            "Response": 0,
            "Reporting": 0,
        },
        "counts": {
            "Monitoring": n_packets,
            "Detection": 0,
            "Intelligence": 0,
            "Response": 0,
            "Reporting": 0,
        },
        "tasks": {
            "Monitoring": f"Scanned {n_packets} packets",
            "Detection": "Standby",
            "Intelligence": "Standby",
            "Response": "Standby",
            "Reporting": "Standby",
        }
    }

    anomaly_agent = AnomalyDetectionAgent()
    t_start = time.time()
    suspicious_df = anomaly_agent.run(traffic_df)
    pipeline_info["times"]["Detection"] = round((time.time() - t_start) * 1000, 1)
    pipeline_info["counts"]["Detection"] = len(traffic_df)

    if not suspicious_df.empty:
        pipeline_info["suspicious_found"] = len(suspicious_df)
        pipeline_info["tasks"]["Detection"] = f"Flagged {len(suspicious_df)} anomalies"

        threat_agent = ThreatIntelligenceAgent()
        t_start = time.time()
        classified_df = threat_agent.run(suspicious_df)
        pipeline_info["times"]["Intelligence"] = round((time.time() - t_start) * 1000, 1)
        pipeline_info["counts"]["Intelligence"] = len(suspicious_df)

        threats_df = classified_df[classified_df["attack_type"] != "normal"].reset_index(drop=True)

        if not threats_df.empty:
            pipeline_info["threats_classified"] = len(threats_df)
            pipeline_info["tasks"]["Intelligence"] = f"Classified {len(threats_df)} threats"
            pipeline_info["sample_ip"] = threats_df.iloc[0].get("source_ip", "—")
            pipeline_info["sample_attack"] = threats_df.iloc[0].get("attack_type", "—")
            conf = threats_df.iloc[0].get("confidence_pct", threats_df.iloc[0].get("confidence", 0))
            pipeline_info["sample_score"] = f"{conf:.0f}%" if isinstance(conf, (int, float)) else str(conf)

            response_agent = ResponseAgent()
            t_start = time.time()
            responded_df = response_agent.run(threats_df)
            pipeline_info["times"]["Response"] = round((time.time() - t_start) * 1000, 1)
            pipeline_info["counts"]["Response"] = len(threats_df)
            pipeline_info["actions_taken"] = len(responded_df)
            pipeline_info["tasks"]["Response"] = f"Deployed {len(responded_df)} countermeasures"

            reporting_agent = ReportingAgent()
            t_start = time.time()
            reporting_agent.run(responded_df)
            pipeline_info["times"]["Reporting"] = round((time.time() - t_start) * 1000, 1)
            pipeline_info["counts"]["Reporting"] = len(responded_df)
            pipeline_info["tasks"]["Reporting"] = f"Logged {len(responded_df)} incidents"
        else:
            pipeline_info["tasks"]["Intelligence"] = "No confirmed threats"
    else:
        pipeline_info["tasks"]["Detection"] = "Traffic normal"

    st.session_state.last_pipeline_info = pipeline_info

# ── LOAD DATA ────────────────────────────────────────────────
df_all = load_data()

# ── WELCOME SCREEN (empty state) ────────────────────────────
if df_all.empty:
    # Load logo
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
    logo_b64 = ""
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as img_f:
            logo_b64 = base64.b64encode(img_f.read()).decode()
    logo_html = f"<img src='data:image/png;base64,{logo_b64}' style='width:64px;height:64px;border-radius:14px;margin-bottom:12px;'>" if logo_b64 else ""

    st.markdown(f"""
    <div class='cn-welcome'>
        {logo_html}
        <h2>Welcome to CyberNexus</h2>
        <p style='text-align:center;'>
            The system is standing by. No threats have been intercepted yet.
        </p>
        <br>
        <p>
            <b style='color:#e2e8f0;font-size:1.05rem;'>How to get started</b><br>
            Open the <span class='highlight'>sidebar</span> on the left and click
            <span class='highlight'>Enable interception</span>. Here is what will happen:
        </p>
        <div class='step-list'>
            <div class='step-item'>
                <div class='step-num'>1</div>
                <div class='step-text'><b>Packet Generation</b> — The system creates realistic network traffic that mimics real-world internet activity (web browsing, file transfers, server requests).</div>
            </div>
            <div class='step-item'>
                <div class='step-num'>2</div>
                <div class='step-text'><b>Anomaly Detection</b> — An Isolation Forest model scans every packet and flags anything that looks unusual or suspicious compared to normal traffic patterns.</div>
            </div>
            <div class='step-item'>
                <div class='step-num'>3</div>
                <div class='step-text'><b>Threat Classification</b> — A Random Forest classifier identifies the type of attack: DDoS, Brute Force, Port Scan, or Malware.</div>
            </div>
            <div class='step-item'>
                <div class='step-num'>4</div>
                <div class='step-text'><b>Automated Response</b> — The system blocks malicious IPs, triggers lockouts, quarantines endpoints, and alerts administrators.</div>
            </div>
            <div class='step-item'>
                <div class='step-num'>5</div>
                <div class='step-text'><b>Live Reporting</b> — All results are logged and instantly displayed on this dashboard with charts, maps, and a live alert feed.</div>
            </div>
        </div>
        <br>
        <p style='text-align:center;font-size:0.85rem;color:#64748b;'>
            All processing happens locally using machine learning — no external APIs, no cloud dependencies.
        </p>
    </div>
    """, unsafe_allow_html=True)
    if st.session_state.auto_inject:
        time.sleep(refresh_rate)
        st.rerun()
    st.stop()

# ── FILTER ───────────────────────────────────────────────────
df = df_all.copy()
if "severity"    in df.columns: df = df[df["severity"].isin(severity_filter)]
if "attack_type" in df.columns: df = df[df["attack_type"].isin(attack_filter + ["normal"])]

current_total = len(df_all)
new_this_tick = max(0, current_total - st.session_state.prev_total)
st.session_state.spike_history.append({
    "time": datetime.datetime.now(IST).strftime("%H:%M:%S"),
    "new": new_this_tick,
    "total": current_total,
})
st.session_state.prev_total = current_total

# Compute threat level
critical_count_all = len(df[df["severity"]=="CRITICAL"]) if "severity" in df.columns else 0
high_count_all     = len(df[df["severity"]=="HIGH"])     if "severity" in df.columns else 0
if critical_count_all > 5:
    threat_level, tl_color = "CRITICAL", "val-red"
elif critical_count_all > 0 or high_count_all > 3:
    threat_level, tl_color = "HIGH", "val-amber"
elif high_count_all > 0:
    threat_level, tl_color = "MEDIUM", "val-amber"
else:
    threat_level, tl_color = "LOW", "val-green"

# ═══════════════════════════════════════════════════════════════
# ██  TOP COMMAND BAR  ██
# ═══════════════════════════════════════════════════════════════
sys_status = "ACTIVE" if st.session_state.auto_inject else "STANDBY"
sys_color  = "val-green" if st.session_state.auto_inject else "val-blue"
now_str    = datetime.datetime.now(IST).strftime("%H:%M:%S")

# Load logo for header
logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
logo_b64_header = ""
if os.path.exists(logo_path):
    with open(logo_path, "rb") as img_f:
        logo_b64_header = base64.b64encode(img_f.read()).decode()
logo_img = f"<img src='data:image/png;base64,{logo_b64_header}' style='width:36px;height:36px;border-radius:8px;'>" if logo_b64_header else "<div class='cn-cmd-logo'>CN</div>"

st.markdown(f"""
<div class='cn-cmd-bar'>
    <div class='cn-cmd-left'>
        {logo_img}
        <div>
            <div class='cn-cmd-title'>Multi-Agent Cyber Defense System</div>
            <div class='cn-cmd-tagline'>Intelligent. Autonomous. Adaptive.</div>
        </div>
    </div>
    <div class='cn-cmd-stats'>
        <div class='cn-cmd-stat'>
            <div class='cn-cmd-stat-label'>Status</div>
            <div class='cn-cmd-stat-value'><span class='{sys_color}'>{sys_status}</span></div>
        </div>
        <div class='cn-cmd-stat'>
            <div class='cn-cmd-stat-label'>Threat Level</div>
            <div class='cn-cmd-stat-value'><span class='{tl_color}'>{threat_level}</span></div>
        </div>
        <div class='cn-cmd-stat'>
            <div class='cn-cmd-stat-label'>Active Agents</div>
            <div class='cn-cmd-stat-value'><span class='val-green'>5 / 5</span></div>
        </div>
        <div class='cn-cmd-stat'>
            <div class='cn-cmd-stat-label'>Last Scan</div>
            <div class='cn-cmd-stat-value'>{now_str}</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── KPI ROW (Custom Cards with Icons) ────────────────────────
total_incidents = len(df)
critical_count  = len(df[df["severity"]=="CRITICAL"])   if "severity"    in df.columns else 0
high_count      = len(df[df["severity"]=="HIGH"])        if "severity"    in df.columns else 0
unique_ips      = df["source_ip"].nunique()              if "source_ip"   in df.columns else 0
ddos_count      = len(df[df["attack_type"]=="DDoS"])     if "attack_type" in df.columns else 0
malware_count   = len(df[df["attack_type"]=="malware"])  if "attack_type" in df.columns else 0

delta_html = f"<div class='cn-kpi-delta'>+{new_this_tick} new</div>" if new_this_tick else ""

st.markdown(f"""
<div class='cn-kpi-row'>
    <div class='cn-kpi-card'>
        <div class='cn-kpi-icon kpi-red'>&#9888;</div>
        <div>
            <div class='cn-kpi-label'>Threats Detected</div>
            <div class='cn-kpi-value'>{total_incidents}</div>
            {delta_html}
        </div>
    </div>
    <div class='cn-kpi-card'>
        <div class='cn-kpi-icon kpi-green'>&#9881;</div>
        <div>
            <div class='cn-kpi-label'>Agents Running</div>
            <div class='cn-kpi-value'>5 / 5</div>
            <div class='cn-kpi-delta' style='color:#4ade80;'>All operational</div>
        </div>
    </div>
    <div class='cn-kpi-card'>
        <div class='cn-kpi-icon kpi-amber'>&#9650;</div>
        <div>
            <div class='cn-kpi-label'>Critical Alerts</div>
            <div class='cn-kpi-value'>{critical_count}</div>
        </div>
    </div>
    <div class='cn-kpi-card'>
        <div class='cn-kpi-icon kpi-blue'>&#9741;</div>
        <div>
            <div class='cn-kpi-label'>Unique IPs</div>
            <div class='cn-kpi-value'>{unique_ips}</div>
        </div>
    </div>
    <div class='cn-kpi-card'>
        <div class='cn-kpi-icon kpi-purple'>&#9878;</div>
        <div>
            <div class='cn-kpi-label'>Systems Protected</div>
            <div class='cn-kpi-value'>{ddos_count + malware_count + critical_count}</div>
            <div class='cn-kpi-delta' style='color:#a78bfa;'>Active defense</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)
st.markdown("---")

# ── THREAT SPIKE CHART ───────────────────────────────────────
st.markdown("### Threat activity")
hist  = list(st.session_state.spike_history)
times = [h["time"] for h in hist]
news  = [h["new"]  for h in hist]

fig_spike = go.Figure()
fig_spike.add_trace(go.Scatter(
    x=times, y=news, mode="lines+markers",
    name="New threats",
    line=dict(color="#6366f1", width=2.5, shape="spline"),
    marker=dict(size=4, color="#6366f1"),
    fill="tozeroy", fillcolor="rgba(99,102,241,0.08)",
))
if news:
    avg = sum(news) / max(len(news), 1)
    sx = [times[i] for i in range(len(news)) if news[i] > max(avg * 1.8, 2)]
    sy = [news[i]  for i in range(len(news)) if news[i] > max(avg * 1.8, 2)]
    if sx:
        fig_spike.add_trace(go.Scatter(
            x=sx, y=sy, mode="markers", name="Spike",
            marker=dict(color="#ef4444", size=10, symbol="diamond", line=dict(color="#0b1120", width=2)),
        ))
fig_spike.update_layout(
    paper_bgcolor="#0b1120", plot_bgcolor="#0b1120",
    font=dict(color="#94a3b8", family="Inter"),
    xaxis=dict(gridcolor="#1e293b", showgrid=True, title="", zeroline=False),
    yaxis=dict(gridcolor="#1e293b", showgrid=True, title="", rangemode="tozero", zeroline=False),
    legend=dict(font=dict(color="#94a3b8"), orientation="h", y=1.1),
    margin=dict(t=10, b=30, l=50, r=20), height=380, hovermode="x unified",
)
st.plotly_chart(fig_spike, use_container_width=True)
st.markdown("---")

# ═══════════════════════════════════════════════════════════════
# ██  AGENT COLLABORATION PIPELINE + THREAT INTELLIGENCE MAP ██
# ═══════════════════════════════════════════════════════════════
col_pipe, col_map = st.columns([2, 3])

with col_pipe:
    st.markdown("### Agent Collaboration")
    pinfo = st.session_state.last_pipeline_info
    is_active = st.session_state.auto_inject
    dot = "active" if is_active else "idle"
    act_cls = "cn-pipe-action" if is_active else "cn-pipe-action idle-text"

    if pinfo and is_active:
        steps = [
            ("Monitoring Agent",       f"Scanned {pinfo['packets_scanned']} packets"),
            ("Anomaly Detection Agent", f"Found {pinfo['suspicious_found']} suspicious flows"),
            ("Threat Intelligence",     f"Classified — {pinfo['sample_attack']} (score: {pinfo['sample_score']})"),
            ("Response Agent",          f"Blocking {pinfo['sample_ip']}"),
            ("Reporting Agent",         f"Generated {pinfo['actions_taken']} incident reports"),
        ]
    else:
        steps = [
            ("Monitoring Agent",        "Awaiting activation..."),
            ("Anomaly Detection Agent", "Awaiting activation..."),
            ("Threat Intelligence",     "Awaiting activation..."),
            ("Response Agent",          "Awaiting activation..."),
            ("Reporting Agent",         "Awaiting activation..."),
        ]

    pipeline_html = "<div class='cn-pipeline'>"
    for agent_name, action_text in steps:
        pipeline_html += f"""
        <div class='cn-pipe-step'>
            <div class='cn-pipe-dot {dot}'></div>
            <div>
                <div class='cn-pipe-agent'>{agent_name}</div>
                <div class='{act_cls}'>{action_text}</div>
            </div>
        </div>"""
    pipeline_html += "</div>"
    st.markdown(pipeline_html, unsafe_allow_html=True)

with col_map:
    st.markdown("### Threat Intelligence — Attack Sources")
    if "source_ip" in df.columns:
        threat_ips = df[df["attack_type"] != "normal"]["source_ip"].value_counts().head(30)
        geo_rows = []
        for ip, count in threat_ips.items():
            name, code, lat, lon = ip_to_country(ip)
            geo_rows.append({"country": name, "code": code, "lat": lat, "lon": lon, "attacks": count})

        if geo_rows:
            geo_df = pd.DataFrame(geo_rows).groupby(["country", "code", "lat", "lon"], as_index=False)["attacks"].sum()
            geo_df = geo_df.sort_values("attacks", ascending=False)

            fig_map = go.Figure()
            fig_map.add_trace(go.Scattergeo(
                lat=geo_df["lat"], lon=geo_df["lon"],
                text=geo_df.apply(lambda r: f"{r['country']}: {r['attacks']} attacks", axis=1),
                marker=dict(
                    size=geo_df["attacks"] * 1.5 + 6,
                    color=geo_df["attacks"],
                    colorscale=[[0, "#1e293b"], [0.5, "#6366f1"], [1, "#ef4444"]],
                    sizemode="area",
                    sizemin=5,
                    line=dict(width=0.5, color="#0b1120"),
                ),
                hoverinfo="text",
            ))
            fig_map.update_geos(
                bgcolor="#0b1120",
                landcolor="#1e293b",
                oceancolor="#0b1120",
                showocean=True,
                coastlinecolor="#334155",
                countrycolor="#334155",
                showframe=False,
                projection_type="natural earth",
            )
            fig_map.update_layout(
                paper_bgcolor="#0b1120",
                margin=dict(t=0, b=0, l=0, r=0),
                height=320,
                showlegend=False,
            )
            st.plotly_chart(fig_map, use_container_width=True)

            # Top countries list
            top_countries = geo_df.head(5)
            country_html = "<div style='display:flex;gap:16px;flex-wrap:wrap;margin-top:4px;'>"
            for _, row in top_countries.iterrows():
                country_html += f"""<div style='font-size:0.8rem;'>
                    <span style='color:#e2e8f0;font-weight:600;'>{row['country']}</span>
                    <span style='color:#6366f1;font-family:JetBrains Mono,monospace;margin-left:6px;'>{int(row['attacks'])}</span>
                </div>"""
            country_html += "</div>"
            st.markdown(country_html, unsafe_allow_html=True)

st.markdown("---")

# ── AGENT STATUS TABLE ───────────────────────────────────────
st.markdown("### Agent Status")
pinfo = st.session_state.last_pipeline_info
status_lbl = "Online" if st.session_state.auto_inject else "Idle"
status_cls = "agent-online" if st.session_state.auto_inject else "agent-idle"
now_time   = datetime.datetime.now(IST).strftime("%H:%M:%S")

table_html = """
<div style='background:#111827;border:1px solid #1e293b;border-radius:8px;padding:4px;overflow-x:auto;'>
<table class='cn-agent-table'>
    <thead><tr>
        <th>Agent</th><th>Status</th><th>Proc. Time (ms)</th><th>Records Processed</th><th>Current Task</th><th>Last Action</th>
    </tr></thead>
    <tbody>
"""
agents_list = ["Monitoring", "Detection", "Intelligence", "Response", "Reporting"]
for name in agents_list:
    if pinfo and st.session_state.auto_inject:
        t_ms = pinfo["times"].get(name, 0)
        cnt = pinfo["counts"].get(name, 0)
        curr_task = pinfo["tasks"].get(name, "Standby")
    else:
        t_ms = 0
        cnt = 0
        curr_task = "Idle"

    t_color = "#4ade80" if t_ms < 50 else ("#fbbf24" if t_ms < 200 else "#ef4444")
    
    table_html += f"""<tr>
        <td style='color:#e2e8f0;font-weight:500;font-family:Inter,sans-serif;'>{name}</td>
        <td><span class='{status_cls}'>{status_lbl}</span></td>
        <td style='color:{t_color};font-family:JetBrains Mono,monospace;'>{t_ms}</td>
        <td style='font-family:JetBrains Mono,monospace;'>{cnt}</td>
        <td style='font-family:Inter,sans-serif;font-size:0.78rem;'>{curr_task}</td>
        <td>{now_time}</td>
    </tr>"""
table_html += "</tbody></table></div>"
st.markdown(table_html, unsafe_allow_html=True)
st.markdown("---")


# ── CHARTS ROW 1: Pie + Timeline ─────────────────────────────
col_a, col_b = st.columns([2, 3])
with col_a:
    st.markdown("### Attack breakdown")
    if "attack_type" in df.columns:
        ac = df[df["attack_type"] != "normal"]["attack_type"].value_counts().reset_index()
        ac.columns = ["Attack Type", "Count"]
        fig_pie = px.pie(ac, names="Attack Type", values="Count",
            color_discrete_sequence=["#ef4444", "#f59e0b", "#eab308", "#3b82f6", "#8b5cf6"], hole=0.5)
        fig_pie.update_traces(textinfo="label+percent", textfont_color="#e2e8f0", textfont_size=11)
        fig_pie.update_layout(
            paper_bgcolor="#0b1120", plot_bgcolor="#0b1120", font_color="#94a3b8",
            legend=dict(font=dict(color="#94a3b8", size=11)), margin=dict(t=10, b=10, l=10, r=10),
        )
        st.plotly_chart(fig_pie, use_container_width=True)

with col_b:
    st.markdown("### Threat timeline")
    if "timestamp" in df.columns and "attack_type" in df.columns:
        df_time = df[df["attack_type"] != "normal"].copy()
        df_time["minute"] = df_time["timestamp"].dt.floor("10min")
        timeline = df_time.groupby(["minute", "attack_type"]).size().reset_index(name="count")
        fig_line = px.area(timeline, x="minute", y="count", color="attack_type",
            color_discrete_map={"DDoS": "#ef4444", "brute_force": "#f59e0b", "port_scan": "#eab308", "malware": "#3b82f6"})
        fig_line.update_traces(line=dict(width=1.5))
        fig_line.update_layout(
            paper_bgcolor="#0b1120", plot_bgcolor="#0b1120", font_color="#94a3b8",
            xaxis=dict(gridcolor="#1e293b", title=""), yaxis=dict(gridcolor="#1e293b", title=""),
            legend=dict(font=dict(color="#94a3b8"), orientation="h", y=1.12), margin=dict(t=10, b=20), height=300,
        )
        st.plotly_chart(fig_line, use_container_width=True)
st.markdown("---")

# ── CHARTS ROW 2: Severity + Top IPs ─────────────────────────
col_c, col_d = st.columns(2)
with col_c:
    st.markdown("### Severity levels")
    if "severity" in df.columns:
        sev = df["severity"].value_counts().reset_index()
        sev.columns = ["Severity", "Count"]
        color_map = {"CRITICAL": "#ef4444", "HIGH": "#f59e0b", "MEDIUM": "#eab308", "INFO": "#3b82f6"}
        fig_sev = px.bar(sev, x="Severity", y="Count", color="Severity", color_discrete_map=color_map, text="Count")
        fig_sev.update_traces(textposition="outside", textfont_color="#94a3b8", marker_line_width=0)
        fig_sev.update_layout(
            paper_bgcolor="#0b1120", plot_bgcolor="#0b1120", font_color="#94a3b8", showlegend=False,
            xaxis=dict(gridcolor="#1e293b", title=""), yaxis=dict(gridcolor="#1e293b", title=""),
            margin=dict(t=30, b=20), bargap=0.35,
        )
        st.plotly_chart(fig_sev, use_container_width=True)

with col_d:
    st.markdown("### Top source IPs")
    if "source_ip" in df.columns:
        top_ips = df[df["attack_type"] != "normal"]["source_ip"].value_counts().head(8).reset_index()
        top_ips.columns = ["IP", "Count"]
        fig_ips = px.bar(top_ips, x="Count", y="IP", orientation="h",
            color="Count", color_continuous_scale=["#1e293b", "#6366f1", "#ef4444"], text="Count")
        fig_ips.update_traces(textposition="outside", textfont_color="#94a3b8")
        fig_ips.update_layout(
            paper_bgcolor="#0b1120", plot_bgcolor="#0b1120", font_color="#94a3b8",
            showlegend=False, coloraxis_showscale=False,
            xaxis=dict(gridcolor="#1e293b", title=""), yaxis=dict(gridcolor="#1e293b", autorange="reversed", title=""),
            margin=dict(t=10, b=20, l=130),
        )
        st.plotly_chart(fig_ips, use_container_width=True)
st.markdown("---")

# ── PROTOCOL BREAKDOWN ───────────────────────────────────────
if "protocol" in df.columns:
    st.markdown("### Protocol distribution")
    proto = df["protocol"].value_counts().reset_index()
    proto.columns = ["Protocol", "Count"]
    fig_proto = px.bar(proto, x="Protocol", y="Count", color="Protocol",
        color_discrete_sequence=["#6366f1", "#34d399", "#f59e0b"], text="Count")
    fig_proto.update_traces(textposition="outside", textfont_color="#94a3b8", marker_line_width=0)
    fig_proto.update_layout(
        paper_bgcolor="#0b1120", plot_bgcolor="#0b1120", font_color="#94a3b8", showlegend=False,
        xaxis=dict(gridcolor="#1e293b", title=""), yaxis=dict(gridcolor="#1e293b", title=""),
        margin=dict(t=30, b=20), bargap=0.4,
    )
    st.plotly_chart(fig_proto, use_container_width=True)
    st.markdown("---")

# ═══════════════════════════════════════════════════════════════
# ██  THREAT TIMELINE  ██
# ═══════════════════════════════════════════════════════════════
st.markdown("### Threat Timeline")
if not df.empty and "attack_type" in df.columns:
    recent_events = df[df["attack_type"] != "normal"].sort_values("timestamp", ascending=False).head(8)
    tl_html = "<div class='cn-timeline'>"
    for _, row in recent_events.iterrows():
        sev = row.get("severity", "INFO")
        tl_class = f"tl-{sev.lower()}" if sev.lower() in ["critical","high","medium"] else "tl-info"
        atype = str(row.get("attack_type", "")).replace("_", " ").title()
        src_ip = row.get("source_ip", "?")
        ts = str(row.get("timestamp", ""))[:19]
        action = str(row.get("response_action", ""))[:50]
        tl_html += f"""
        <div class='cn-tl-item {tl_class}'>
            <div class='cn-tl-time'>{ts}</div>
            <div class='cn-tl-title'>{atype}</div>
            <div class='cn-tl-desc'>{src_ip} — {action}</div>
        </div>"""
    tl_html += "</div>"
    st.markdown(tl_html, unsafe_allow_html=True)

st.markdown("---")

# ── COUNTER-ATTACK RESPONSES ────────────────────────────────
st.markdown("### Automated responses")
if not df.empty and "response_action" in df.columns and "attack_type" in df.columns:
    threats_df = df[df["attack_type"] != "normal"]

    r1, r2, r3, r4, r5 = st.columns(5)
    blocked_ips = threats_df["source_ip"].nunique() if "source_ip" in threats_df.columns else 0
    r1.metric("IPs blocked", blocked_ips)
    r2.metric("DDoS mitigated", len(threats_df[threats_df["attack_type"] == "DDoS"]))
    r3.metric("Brute force stopped", len(threats_df[threats_df["attack_type"] == "brute_force"]))
    r4.metric("Port scans flagged", len(threats_df[threats_df["attack_type"] == "port_scan"]))
    r5.metric("Malware quarantined", len(threats_df[threats_df["attack_type"] == "malware"]))

    st.markdown("<br>", unsafe_allow_html=True)

    action_map = {
        "DDoS":        ("critical", "CRITICAL", ["IP blocked for 20 min", "Rate-limiting applied", "Admin alerted", "Inbound traffic filtered"]),
        "brute_force": ("high",     "HIGH",     ["Source IP blocked", "Account lockout enforced", "MFA prompt triggered", "Login attempts logged"]),
        "port_scan":   ("medium",   "MEDIUM",   ["IP flagged for monitoring", "Port-scan alert raised", "Traffic pattern logged", "Watchlist entry created"]),
        "malware":     ("critical", "CRITICAL", ["Source IP blocked", "Connection terminated", "Endpoint quarantined", "C2 port blacklisted"]),
    }

    col1, col2 = st.columns(2)
    for i, (attack, (css, sev, actions)) in enumerate(action_map.items()):
        count = len(threats_df[threats_df["attack_type"] == attack])
        action_html = "".join(f"<div class='card-action'>&#10003; {a}</div>" for a in actions)
        html = f"""<div class='cn-resp-card'>
            <span class='card-tag tag-{css}'>{sev}</span>
            <div class='card-title'>{attack.upper().replace("_", " ")}</div>
            {action_html}
            <div class='card-meta'>{count} incident{"s" if count != 1 else ""} intercepted</div>
        </div>"""
        if i % 2 == 0: col1.markdown(html, unsafe_allow_html=True)
        else:          col2.markdown(html, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_rc1, col_rc2 = st.columns(2)
    with col_rc1:
        st.markdown("### Response actions by type")
        rc = threats_df["attack_type"].value_counts().reset_index()
        rc.columns = ["Attack Type", "Count"]
        fig_resp = px.bar(rc, x="Attack Type", y="Count", color="Attack Type",
            color_discrete_map={"DDoS": "#ef4444", "brute_force": "#f59e0b", "port_scan": "#eab308", "malware": "#3b82f6"},
            text="Count")
        fig_resp.update_traces(textposition="outside", textfont_color="#94a3b8", marker_line_width=0)
        fig_resp.update_layout(
            paper_bgcolor="#0b1120", plot_bgcolor="#0b1120", font_color="#94a3b8", showlegend=False,
            xaxis=dict(gridcolor="#1e293b", title=""), yaxis=dict(gridcolor="#1e293b", title=""),
            margin=dict(t=30, b=20),
        )
        st.plotly_chart(fig_resp, use_container_width=True)

    with col_rc2:
        st.markdown("### Severity breakdown")
        if "severity" in threats_df.columns:
            sr = threats_df["severity"].value_counts().reset_index()
            sr.columns = ["Severity", "Count"]
            fig_sr = px.pie(sr, names="Severity", values="Count", color="Severity",
                color_discrete_map={"CRITICAL": "#ef4444", "HIGH": "#f59e0b", "MEDIUM": "#eab308", "INFO": "#3b82f6"},
                hole=0.45)
            fig_sr.update_traces(textinfo="label+percent", textfont_color="#e2e8f0", textfont_size=11)
            fig_sr.update_layout(
                paper_bgcolor="#0b1120", plot_bgcolor="#0b1120", font_color="#94a3b8",
                legend=dict(font=dict(color="#94a3b8")), margin=dict(t=10, b=10),
            )
            st.plotly_chart(fig_sr, use_container_width=True)

    st.markdown("### Most targeted destinations")
    if "destination_ip" in threats_df.columns:
        ti = threats_df["destination_ip"].value_counts().head(8).reset_index()
        ti.columns = ["Destination IP", "Hit Count"]
        fig_ti = px.bar(ti, x="Hit Count", y="Destination IP", orientation="h",
            color="Hit Count", color_continuous_scale=["#1e293b", "#eab308", "#ef4444"], text="Hit Count")
        fig_ti.update_traces(textposition="outside", textfont_color="#94a3b8")
        fig_ti.update_layout(
            paper_bgcolor="#0b1120", plot_bgcolor="#0b1120", font_color="#94a3b8",
            showlegend=False, coloraxis_showscale=False,
            xaxis=dict(gridcolor="#1e293b", title=""), yaxis=dict(gridcolor="#1e293b", autorange="reversed", title=""),
            margin=dict(t=10, b=20, l=130),
        )
        st.plotly_chart(fig_ti, use_container_width=True)
st.markdown("---")

# ── LIVE ALERT FEED ──────────────────────────────────────────
st.markdown("### Alert feed")
if not df.empty and "attack_type" in df.columns:
    recent_alerts = df[df["attack_type"] != "normal"].sort_values("timestamp", ascending=False).head(10)
    for _, row in recent_alerts.iterrows():
        sev    = row.get("severity", "INFO")
        atype  = row.get("attack_type", "unknown")
        src    = row.get("source_ip", "?")
        dst    = row.get("destination_ip", "?")
        ts     = str(row.get("timestamp", ""))[:19]
        action = str(row.get("response_action", ""))[:80]
        sev_class = f"sev-{sev}" if sev in ["HIGH", "MEDIUM", "INFO"] else ""
        st.markdown(f"""<div class='cn-alert {sev_class}'>
            <b>{ts}</b> &nbsp;|&nbsp;
            <b style='color:#818cf8'>{atype.upper().replace("_"," ")}</b> &nbsp;|&nbsp;
            <span style='color:#94a3b8'>{src}</span> &rarr; <span style='color:#94a3b8'>{dst}</span> &nbsp;|&nbsp;
            <span style='color:#34d399'>{action}</span>
        </div>""", unsafe_allow_html=True)
st.markdown("---")

# ── INCIDENT TABLE ───────────────────────────────────────────
st.markdown("### Recent incidents")
display_cols = ["timestamp", "attack_type", "source_ip", "destination_ip", "severity", "confidence_pct", "response_action"]
display_cols = [c for c in display_cols if c in df.columns]
recent = df[df["attack_type"] != "normal"][display_cols].sort_values("timestamp", ascending=False).head(50)
st.dataframe(recent, use_container_width=True, hide_index=True,
    column_config={
        "timestamp":      st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
        "confidence_pct": st.column_config.NumberColumn("Confidence %", format="%.1f%%"),
    })
st.markdown("---")

# ── RAW LOGS ─────────────────────────────────────────────────
with st.expander("System logs"):
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()
        st.code("".join(lines[-100:]), language="text")
    else:
        st.caption("No log file generated yet.")

# ── FOOTER ───────────────────────────────────────────────────
footer_dot = "operational" if st.session_state.auto_inject else "standby"
footer_txt = "OPERATIONAL" if st.session_state.auto_inject else "STANDBY"
st.markdown(f"""
<div class='cn-footer'>
    <div class='cn-footer-status'>
        <span>SYSTEM STATUS</span>
        <span class='cn-footer-dot {footer_dot}'></span>
        <span style='color:#e2e8f0;'>{footer_txt}</span>
    </div>
    <div>CyberNexus &mdash; Multi-Agent Cyber Defense System</div>
    <div>v1.0.0</div>
</div>
""", unsafe_allow_html=True)

# ── AUTO-REFRESH (only when interception is active) ──────────
if st.session_state.auto_inject:
    time.sleep(refresh_rate)
    st.rerun()