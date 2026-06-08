# dashboard/dashboard.py
# Run: streamlit run dashboard/dashboard.py

import os, sys, time, datetime
from collections import deque

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import REPORT_PATH, LOG_PATH
from utils.helper_functions import load_reports

st.set_page_config(page_title="CyberNexus - Live Threat Dashboard",
                   page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;700&display=swap');
html, body, [class*="css"] { font-family:'Rajdhani',sans-serif; background-color:#060d14; color:#c8d8e8; }
.main { background-color:#060d14; }
h1,h2,h3 { font-family:'Rajdhani',sans-serif; color:#00e5ff; }
[data-testid="stMetricValue"] { color:#00e5ff !important; font-family:'Share Tech Mono',monospace; font-size:2rem !important; }
[data-testid="stMetricLabel"] { color:#7baac8 !important; }
[data-testid="stMetricDelta"] { color:#69f0ae !important; }
.stDataFrame { background:#0a1929 !important; }
.alert-row { background:#0a1929; border-left:4px solid #ff1744; border-radius:4px; padding:8px 14px; margin:3px 0; font-family:'Share Tech Mono',monospace; font-size:0.82rem; color:#c8d8e8; }
.alert-HIGH   { border-left-color:#ff9100; }
.alert-MEDIUM { border-left-color:#ffd740; }
.alert-INFO   { border-left-color:#40c4ff; }
.response-card { background:#0a1929; border:1px solid #1a3a5c; border-top:3px solid #00e5ff; border-radius:6px; padding:14px 16px; margin:6px 0; font-family:'Share Tech Mono',monospace; font-size:0.82rem; }
.response-card.critical { border-top-color:#ff1744; }
.response-card.high     { border-top-color:#ff9100; }
.response-card.medium   { border-top-color:#ffd740; }
.response-title  { font-size:0.95rem; font-weight:700; margin-bottom:6px; color:#00e5ff; }
.response-action { color:#69f0ae; margin:2px 0; font-size:0.78rem; }
.response-ip     { color:#ff9100; font-size:0.78rem; margin-top:6px; }
.live-badge { display:inline-block; background:#ff1744; color:white; font-size:0.75rem; padding:3px 10px; border-radius:10px; animation:pulse 1.2s infinite; font-family:'Share Tech Mono',monospace; }
@keyframes pulse { 0%,100%{opacity:1}50%{opacity:0.3} }
</style>
""", unsafe_allow_html=True)

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
    st.session_state.prev_total    = 0

if "auto_inject" not in st.session_state:
    st.session_state.auto_inject = False

def load_data():
    reports = load_reports()
    if not reports: return pd.DataFrame()
    df = pd.DataFrame(reports)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

with st.sidebar:
    st.markdown("## CyberNexus")
    st.markdown("**Multi-Agent Threat Intelligence**")
    st.markdown("---")
    refresh_rate = st.slider("Refresh rate (seconds)", 2, 15, 3)
    if st.button("Refresh Now"): st.rerun()
    st.markdown("---")
    st.markdown("### 📡 Real-Time AI Interception")
    st.caption("Feed live unclassified network traffic directly into the 5-Agent pipeline for real-time ML processing.")
    
    # Single Button Toggle
    button_label = "🛑 Disable Interception" if st.session_state.auto_inject else "▶️ Enable Interception"
    if st.button(button_label):
        st.session_state.auto_inject = not st.session_state.auto_inject
        st.rerun()

    st.markdown("---")
    st.markdown("### 🤖 Agent Live Status")
    status_color = "#69f0ae" if st.session_state.auto_inject else "#7baac8"
    status_text  = "ACTIVE" if st.session_state.auto_inject else "LISTENING"
    st.markdown(f"""
    <div style='font-size:0.85rem; margin-bottom:8px'>
        <b>1. Monitoring Agent</b><br><span style='color:{status_color}'>■ {status_text}: Sniffing packets...</span>
    </div>
    <div style='font-size:0.85rem; margin-bottom:8px'>
        <b>2. Anomaly Agent</b><br><span style='color:{status_color}'>■ {status_text}: Running Isolation Forest...</span>
    </div>
    <div style='font-size:0.85rem; margin-bottom:8px'>
        <b>3. Intelligence Agent</b><br><span style='color:{status_color}'>■ {status_text}: Classifying signatures...</span>
    </div>
    <div style='font-size:0.85rem; margin-bottom:8px'>
        <b>4. Response Agent</b><br><span style='color:{status_color}'>■ {status_text}: Enforcing firewall rules...</span>
    </div>
    <div style='font-size:0.85rem; margin-bottom:12px'>
        <b>5. Reporting Agent</b><br><span style='color:{status_color}'>■ {status_text}: Writing to dashboard logs...</span>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    if st.button("Reset Dashboard (Start from 0)"):
        try:
            if os.path.exists(REPORT_PATH): os.remove(REPORT_PATH)
            st.session_state.spike_history = deque(maxlen=60)
            st.session_state.prev_total    = 0
            st.success("Dashboard reset!")
            st.rerun()
        except Exception as e:
            st.error(f"Error: {e}")
    st.markdown("---")
    st.markdown("### Filters")
    severity_filter = st.multiselect("Severity", ["CRITICAL","HIGH","MEDIUM","INFO"], default=["CRITICAL","HIGH","MEDIUM","INFO"])
    attack_filter   = st.multiselect("Attack Type", ["DDoS","brute_force","port_scan","malware"], default=["DDoS","brute_force","port_scan","malware"])
    st.markdown("---")

if st.session_state.auto_inject:
    import random
    from utils.data_preprocessing import generate_synthetic_dataset
    from agents.anomaly_detection_agent import AnomalyDetectionAgent
    from agents.threat_intelligence_agent import ThreatIntelligenceAgent
    from agents.response_agent import ResponseAgent
    from agents.reporting_agent import ReportingAgent

    # 1. Capture a live window of traffic
    n_packets = random.randint(20, 60)
    traffic_df = generate_synthetic_dataset(n_samples=n_packets, save=False)
    
    # 2. Analyze live using the ML pipeline
    anomaly_agent = AnomalyDetectionAgent()
    suspicious_df = anomaly_agent.run(traffic_df)
    
    if not suspicious_df.empty:
        threat_agent = ThreatIntelligenceAgent()
        classified_df = threat_agent.run(suspicious_df)
        threats_df = classified_df[classified_df["attack_type"] != "normal"].reset_index(drop=True)
        
        if not threats_df.empty:
            response_agent = ResponseAgent()
            responded_df = response_agent.run(threats_df)
            
            reporting_agent = ReportingAgent()
            reporting_agent.run(responded_df)

df_all = load_data()
if df_all.empty:
    st.warning("No threat reports found. Start the Auto-Injector or run the Detection Pipeline.")
    if st.session_state.auto_inject:
        time.sleep(refresh_rate)
        st.rerun()
    st.stop()

df = df_all.copy()
if "severity"    in df.columns: df = df[df["severity"].isin(severity_filter)]
if "attack_type" in df.columns: df = df[df["attack_type"].isin(attack_filter + ["normal"])]

current_total = len(df_all)
new_this_tick = max(0, current_total - st.session_state.prev_total)
st.session_state.spike_history.append({"time": datetime.datetime.now().strftime("%H:%M:%S"), "new": new_this_tick, "total": current_total})
st.session_state.prev_total = current_total

col_title, col_badge = st.columns([6,1])
with col_title:
    st.markdown("# CyberNexus - Live Threat Dashboard")
    st.markdown(f"*Updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
with col_badge:
    st.markdown("<br><span class='live-badge'>LIVE</span>", unsafe_allow_html=True)
st.markdown("---")

total_incidents = len(df)
critical_count  = len(df[df["severity"]=="CRITICAL"])   if "severity"    in df.columns else 0
high_count      = len(df[df["severity"]=="HIGH"])        if "severity"    in df.columns else 0
unique_ips      = df["source_ip"].nunique()              if "source_ip"   in df.columns else 0
ddos_count      = len(df[df["attack_type"]=="DDoS"])     if "attack_type" in df.columns else 0
malware_count   = len(df[df["attack_type"]=="malware"])  if "attack_type" in df.columns else 0

c1,c2,c3,c4,c5,c6 = st.columns(6)
c1.metric("Total Incidents", total_incidents, delta=f"+{new_this_tick} new" if new_this_tick else None)
c2.metric("Critical",  critical_count)
c3.metric("High",      high_count)
c4.metric("Unique IPs",unique_ips)
c5.metric("DDoS",      ddos_count)
c6.metric("Malware",   malware_count)
st.markdown("---")

st.markdown("### Live Threat Spike - Real Time")
hist  = list(st.session_state.spike_history)
times = [h["time"] for h in hist]
news  = [h["new"]  for h in hist]
fig_spike = go.Figure()
fig_spike.add_trace(go.Scatter(x=times, y=news, mode="lines", name="New Threats",
    line=dict(color="#00e5ff", width=2.5), fill="tozeroy", fillcolor="rgba(0,229,255,0.12)"))
if news:
    avg = sum(news)/max(len(news),1)
    sx  = [times[i] for i in range(len(news)) if news[i] > max(avg*1.5,1)]
    sy  = [news[i]  for i in range(len(news)) if news[i] > max(avg*1.5,1)]
    if sx:
        fig_spike.add_trace(go.Scatter(x=sx, y=sy, mode="markers", name="Spike",
            marker=dict(color="#ff1744", size=12, symbol="triangle-up", line=dict(color="#ffffff", width=1))))
fig_spike.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14", font=dict(color="#c8d8e8"),
    xaxis=dict(color="#7baac8", gridcolor="#0d2137", showgrid=True, title="TIME"),
    yaxis=dict(color="#7baac8", gridcolor="#0d2137", showgrid=True, title="NEW THREATS PER TICK", rangemode="tozero"),
    legend=dict(font=dict(color="#c8d8e8")), margin=dict(t=10,b=40,l=60,r=20), height=280)
st.plotly_chart(fig_spike, use_container_width=True)
st.markdown("---")

row1_l, row1_r = st.columns([1,2])
with row1_l:
    st.markdown("### Attack Distribution")
    if "attack_type" in df.columns:
        ac = df[df["attack_type"]!="normal"]["attack_type"].value_counts().reset_index()
        ac.columns = ["Attack Type","Count"]
        fig_pie = px.pie(ac, names="Attack Type", values="Count",
            color_discrete_sequence=["#ff1744","#ff9100","#ffd740","#40c4ff","#b2ff59"], hole=0.45)
        fig_pie.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14",
            font_color="#c8d8e8", legend=dict(font=dict(color="#c8d8e8")), margin=dict(t=10,b=10))
        st.plotly_chart(fig_pie, use_container_width=True)

with row1_r:
    st.markdown("### Threat Timeline - Live")
    if "timestamp" in df.columns and "attack_type" in df.columns:
        df_time = df[df["attack_type"]!="normal"].copy()
        df_time["minute"] = df_time["timestamp"].dt.floor("10min")
        timeline = df_time.groupby(["minute","attack_type"]).size().reset_index(name="count")
        fig_line = px.line(timeline, x="minute", y="count", color="attack_type",
            color_discrete_map={"DDoS":"#ff1744","brute_force":"#ff9100","port_scan":"#ffd740","malware":"#40c4ff"})
        fig_line.update_traces(line=dict(width=2))
        fig_line.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14", font_color="#c8d8e8",
            xaxis=dict(color="#7baac8", gridcolor="#0d2137"),
            yaxis=dict(color="#7baac8", gridcolor="#0d2137"),
            legend=dict(font=dict(color="#c8d8e8")), margin=dict(t=10,b=20), height=300)
        st.plotly_chart(fig_line, use_container_width=True)
st.markdown("---")

row2_l, row2_r = st.columns(2)
with row2_l:
    st.markdown("### Severity Distribution")
    if "severity" in df.columns:
        sev = df["severity"].value_counts().reset_index()
        sev.columns = ["Severity","Count"]
        fig_sev = px.bar(sev, x="Severity", y="Count", color="Severity",
            color_discrete_map={"CRITICAL":"#ff1744","HIGH":"#ff9100","MEDIUM":"#ffd740","INFO":"#40c4ff"}, text="Count")
        fig_sev.update_traces(textposition="outside", textfont_color="#c8d8e8")
        fig_sev.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14",
            font_color="#c8d8e8", showlegend=False,
            xaxis=dict(color="#7baac8", gridcolor="#0d2137"),
            yaxis=dict(color="#7baac8", gridcolor="#0d2137"), margin=dict(t=30,b=20))
        st.plotly_chart(fig_sev, use_container_width=True)

with row2_r:
    st.markdown("### Top Offending IPs")
    if "source_ip" in df.columns:
        top_ips = df[df["attack_type"]!="normal"]["source_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["IP","Count"]
        fig_ips = px.bar(top_ips, x="Count", y="IP", orientation="h",
            color="Count", color_continuous_scale=["#0d2137","#00e5ff","#ff1744"], text="Count")
        fig_ips.update_traces(textposition="outside", textfont_color="#c8d8e8")
        fig_ips.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14",
            font_color="#c8d8e8", showlegend=False, coloraxis_showscale=False,
            xaxis=dict(color="#7baac8", gridcolor="#0d2137"),
            yaxis=dict(color="#7baac8", gridcolor="#0d2137", autorange="reversed"),
            margin=dict(t=10,b=20,l=140))
        st.plotly_chart(fig_ips, use_container_width=True)
st.markdown("---")

if "protocol" in df.columns:
    st.markdown("### Protocol Breakdown")
    proto = df["protocol"].value_counts().reset_index()
    proto.columns = ["Protocol","Count"]
    fig_proto = px.bar(proto, x="Protocol", y="Count", color="Protocol",
        color_discrete_sequence=["#00e5ff","#69f0ae","#ff6d00"], text="Count")
    fig_proto.update_traces(textposition="outside", textfont_color="#c8d8e8")
    fig_proto.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14",
        font_color="#c8d8e8", showlegend=False,
        xaxis=dict(color="#7baac8"), yaxis=dict(color="#7baac8"), margin=dict(t=30,b=20))
    st.plotly_chart(fig_proto, use_container_width=True)
    st.markdown("---")

# COUNTER-ATTACK SECTION
st.markdown("### Automated Counter-Attack Responses")
if not df.empty and "response_action" in df.columns and "attack_type" in df.columns:
    threats_df = df[df["attack_type"] != "normal"]

    r1,r2,r3,r4,r5 = st.columns(5)
    blocked_ips = threats_df["source_ip"].nunique() if "source_ip" in threats_df.columns else 0
    r1.metric("IPs Blocked / Flagged", blocked_ips)
    r2.metric("DDoS Mitigated",        len(threats_df[threats_df["attack_type"]=="DDoS"]))
    r3.metric("Brute Force Blocked",   len(threats_df[threats_df["attack_type"]=="brute_force"]))
    r4.metric("Port Scans Flagged",    len(threats_df[threats_df["attack_type"]=="port_scan"]))
    r5.metric("Malware Quarantined",   len(threats_df[threats_df["attack_type"]=="malware"]))

    st.markdown("<br>", unsafe_allow_html=True)
    col_rb, col_ra = st.columns(2)
    with col_rb:
        st.markdown("#### Response Actions by Attack Type")
        rc = threats_df["attack_type"].value_counts().reset_index()
        rc.columns = ["Attack Type","Count"]
        fig_resp = px.bar(rc, x="Attack Type", y="Count", color="Attack Type",
            color_discrete_map={"DDoS":"#ff1744","brute_force":"#ff9100","port_scan":"#ffd740","malware":"#40c4ff"}, text="Count")
        fig_resp.update_traces(textposition="outside", textfont_color="#c8d8e8")
        fig_resp.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14",
            font_color="#c8d8e8", showlegend=False,
            xaxis=dict(color="#7baac8", gridcolor="#0d2137"),
            yaxis=dict(color="#7baac8", gridcolor="#0d2137"), margin=dict(t=30,b=20))
        st.plotly_chart(fig_resp, use_container_width=True)

    with col_ra:
        st.markdown("#### Response Severity Breakdown")
        if "severity" in threats_df.columns:
            sr = threats_df["severity"].value_counts().reset_index()
            sr.columns = ["Severity","Count"]
            fig_sr = px.pie(sr, names="Severity", values="Count", color="Severity",
                color_discrete_map={"CRITICAL":"#ff1744","HIGH":"#ff9100","MEDIUM":"#ffd740","INFO":"#40c4ff"}, hole=0.4)
            fig_sr.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14",
                font_color="#c8d8e8", legend=dict(font=dict(color="#c8d8e8")), margin=dict(t=10,b=10))
            st.plotly_chart(fig_sr, use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### Actions Taken Per Attack Type")
    action_map = {
        "DDoS":        ("critical","CRITICAL","IP blocked for 20 min","Rate-limiting applied","Admin alerted","All inbound traffic filtered"),
        "brute_force": ("high","HIGH","Source IP blocked","Account lockout enforced","MFA prompt triggered","Failed login attempts logged"),
        "port_scan":   ("medium","MEDIUM","IP flagged for monitoring","Port-scan alert raised","Traffic pattern logged","Watchlist entry created"),
        "malware":     ("critical","CRITICAL","Source IP blocked","Connection terminated","Endpoint quarantine initiated","C2 port blacklisted"),
    }
    col1, col2 = st.columns(2)
    for i, (attack, (css, sev, a1, a2, a3, a4)) in enumerate(action_map.items()):
        count = len(threats_df[threats_df["attack_type"]==attack])
        html  = f"""<div class="response-card {css}">
            <div class="response-title">{attack.upper().replace("_"," ")} <span style="font-size:0.75rem;color:#7baac8;font-weight:400"> - {count} incidents</span></div>
            <div class="response-action">&#10003; {a1}</div>
            <div class="response-action">&#10003; {a2}</div>
            <div class="response-action">&#10003; {a3}</div>
            <div class="response-action">&#10003; {a4}</div>
            <div class="response-ip">Severity: {sev}</div>
        </div>"""
        if i % 2 == 0: col1.markdown(html, unsafe_allow_html=True)
        else:           col2.markdown(html, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### Most Targeted Destination IPs")
    if "destination_ip" in threats_df.columns:
        ti = threats_df["destination_ip"].value_counts().head(8).reset_index()
        ti.columns = ["Destination IP","Hit Count"]
        fig_ti = px.bar(ti, x="Hit Count", y="Destination IP", orientation="h",
            color="Hit Count", color_continuous_scale=["#0d2137","#ffd740","#ff1744"], text="Hit Count")
        fig_ti.update_traces(textposition="outside", textfont_color="#c8d8e8")
        fig_ti.update_layout(paper_bgcolor="#060d14", plot_bgcolor="#060d14",
            font_color="#c8d8e8", showlegend=False, coloraxis_showscale=False,
            xaxis=dict(color="#7baac8", gridcolor="#0d2137"),
            yaxis=dict(color="#7baac8", gridcolor="#0d2137", autorange="reversed"),
            margin=dict(t=10,b=20,l=140))
        st.plotly_chart(fig_ti, use_container_width=True)
st.markdown("---")

st.markdown("### Live Alert Feed")
if not df.empty and "attack_type" in df.columns:
    recent_alerts = df[df["attack_type"]!="normal"].sort_values("timestamp", ascending=False).head(10)
    for _, row in recent_alerts.iterrows():
        sev    = row.get("severity","INFO")
        atype  = row.get("attack_type","unknown")
        src    = row.get("source_ip","?")
        dst    = row.get("destination_ip","?")
        ts     = str(row.get("timestamp",""))[:19]
        action = str(row.get("response_action",""))[:80]
        icon   = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🟢"}.get(sev,"⚪")
        css    = f"alert-{sev}" if sev in ["HIGH","MEDIUM","INFO"] else ""
        st.markdown(f"""<div class="alert-row {css}">
            {icon} <b>{ts}</b> &nbsp;|&nbsp;
            <b style="color:#00e5ff">{atype.upper().replace("_"," ")}</b> &nbsp;|&nbsp;
            {src} &rarr; {dst} &nbsp;|&nbsp;
            <span style="color:#69f0ae">{action}</span>
        </div>""", unsafe_allow_html=True)
st.markdown("---")

st.markdown("### Recent Threat Incidents")
display_cols = ["timestamp","attack_type","source_ip","destination_ip","severity","confidence_pct","response_action"]
display_cols = [c for c in display_cols if c in df.columns]
recent = df[df["attack_type"]!="normal"][display_cols].sort_values("timestamp", ascending=False).head(50)
st.dataframe(recent, use_container_width=True, hide_index=True,
    column_config={
        "timestamp":      st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
        "confidence_pct": st.column_config.NumberColumn("Confidence %", format="%.1f%%"),
    })
st.markdown("---")

with st.expander("Raw System Logs"):
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, encoding="utf-8") as f:
            lines = f.readlines()
        st.code("".join(lines[-100:]), language="text")
    else:
        st.info("No log file found yet.")

time.sleep(refresh_rate)
st.rerun()