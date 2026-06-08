# CyberNexus: Multi-Agent Cybersecurity Threat Detection System

**Live Demo**: [cybernexus.streamlit.app](https://cybernexus.streamlit.app/)

A fully functional, end-to-end intelligent cybersecurity system where **five autonomous AI agents** collaborate to detect, classify, respond to, and report on network-based cyber threats.

---

## System Architecture

```
Network Traffic / Dataset
         ↓
  ┌──────────────────┐
  │ Monitoring Agent │  ← Collects & validates traffic records
  └──────────────────┘
         ↓
  ┌──────────────────────────┐
  │ Anomaly Detection Agent  │  ← Isolation Forest flags suspicious traffic
  └──────────────────────────┘
         ↓
  ┌────────────────────────────┐
  │ Threat Intelligence Agent  │  ← Random Forest classifies attack type
  └────────────────────────────┘
         ↓
  ┌─────────────────┐
  │ Response Agent  │  ← Executes automated firewall/alert actions
  └─────────────────┘
         ↓
  ┌──────────────────┐
  │ Reporting Agent  │  ← Generates logs, JSON reports, console summary
  └──────────────────┘
          ↓
  ┌─────────────────────┐
  │ Streamlit Dashboard │ ← Provides Real-Time AI Interception & Live UI
  └─────────────────────┘
```

---

## Folder Structure

```
multi_agent_cybersecurity_system/
├── agents/
│   ├── monitoring_agent.py           # Agent 1
│   ├── anomaly_detection_agent.py    # Agent 2
│   ├── threat_intelligence_agent.py  # Agent 3
│   ├── response_agent.py             # Agent 4
│   └── reporting_agent.py            # Agent 5
├── config/
│   └── config.py                     # Central configuration
├── dashboard/
│   └── dashboard.py                  # Streamlit dashboard
├── dataset/
│   ├── raw_data/                     # Raw or synthetic traffic CSV
│   └── processed_data/               # Normalised feature CSV
├── logs/
│   ├── system_logs.txt               # Human-readable event log
│   └── threat_report.json            # Machine-readable incident archive
├── models/
│   ├── train_model.py                # Train RandomForest classifier
│   ├── saved_model.pkl               # Saved classifier (auto-generated)
│   └── anomaly_model.pkl             # Saved Isolation Forest (auto-generated)
├── utils/
│   ├── data_preprocessing.py         # Dataset generation & preprocessing
│   └── helper_functions.py           # Logging, reporting helpers
├── main.py                           # Legacy CLI pipeline controller
├── requirements.txt                  # Deployment dependencies
└── README.md
```

---

## Agent Descriptions

### Agent 1 – Monitoring Agent
| | |
|---|---|
| **Input** | CSV path or synthetic generation flag |
| **Output** | `pd.DataFrame` with 7 network features |
| **Algorithm** | Rule-based validation + feature extraction |

Generates or loads a network traffic dataset containing: `source_ip`, `destination_ip`, `protocol_type`, `packet_size`, `connection_duration`, `login_attempts`, `port_number`.

---

### Agent 2 – Anomaly Detection Agent
| | |
|---|---|
| **Input** | Raw traffic DataFrame from Agent 1 |
| **Output** | Suspicious records with `anomaly_score` column |
| **Algorithm** | **Isolation Forest** (sklearn, 200 trees) |

Unsupervised anomaly detection. No labels required. Flags records whose feature distribution deviates significantly from the majority.

---

### Agent 3 – Threat Intelligence Agent
| | |
|---|---|
| **Input** | Suspicious DataFrame from Agent 2 |
| **Output** | DataFrame enriched with `attack_type` + `confidence` |
| **Algorithm** | **Random Forest Classifier** (sklearn, 300 trees) |

Supervised multi-class classification into: `normal`, `DDoS`, `brute_force`, `port_scan`, `malware`.

---

### Agent 4 – Response Agent
| | |
|---|---|
| **Input** | Classified DataFrame from Agent 3 |
| **Output** | DataFrame with `response_action` + `severity` |
| **Logic** | Rule-based decision engine |

Attack-to-response mapping:
| Attack | Response |
|--------|----------|
| DDoS | Block IP + rate-limit + admin alert |
| Brute Force | Block IP + account lockout + MFA prompt |
| Port Scan | Flag for monitoring + alert |
| Malware | Block IP + terminate connection + quarantine |

---

### Agent 5 – Reporting Agent
| | |
|---|---|
| **Input** | Responded DataFrame from Agent 4 |
| **Output** | `logs/system_logs.txt`, `logs/threat_report.json` |

Generates structured per-incident reports and prints a formatted summary table to the console.

---

## Machine Learning

### Anomaly Detection — Isolation Forest
Isolation Forest works by randomly partitioning the feature space. Anomalous points require fewer splits to isolate and receive lower anomaly scores.

- **Features**: protocol, packet size, duration, login attempts, port
- **Contamination**: 15% (configurable in `config/config.py`)

### Attack Classification — Random Forest
An ensemble of 300 decision trees trained on labelled synthetic traffic. Each tree votes on the attack class; the majority vote (+ probability) is returned.

- **Accuracy**: typically ≥ 95% on test set
- **Classes**: normal, DDoS, brute_force, port_scan, malware

---

## Installation

```bash
# 1. Clone / unzip the project
cd multi_agent_cybersecurity_system

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. (Optional) Train classifier explicitly
python models/train_model.py
```

---

## Running the System

### 1. Launch the Live Security Dashboard (Recommended)
Our newest update integrates the **entire 5-Agent Machine Learning pipeline natively into the web dashboard**. 

To run the full visual experience:
```bash
streamlit run dashboard/dashboard.py
```
*Once the dashboard opens in your browser, click **"Enable Interception"** in the sidebar. The server will begin capturing live windows of network traffic and actively processing them through the ML models in real-time, displaying the results instantly.*

### 2. Run Headless CLI Pipeline (Legacy)
If you want to bypass the web UI and run a massive 5000-record batch generation test in your terminal:
```bash
python main.py
```

### Force retrain the classifier
```bash
python main.py --retrain
```

---

## Dashboard Features

The dashboard operates as a professional Security Operations Center (SOC) interface featuring:

| Feature | Description |
|---------|-------------|
| **Top Command Bar** | Live system status, active agents, and calculated threat level. |
| **KPI Metric Cards** | High-level overview of detected threats, critical alerts, and protected systems. |
| **Agent Collaboration Pipeline** | Visual step-by-step pipeline showing real-time actions taken by all 5 agents. |
| **Attack Source Geo Map** | Interactive 3D globe visualizing where attacks are originating globally. |
| **Agent Status Table** | Authentic metrics showing exact processing time (ms) and records processed per agent. |
| **Threat Timeline** | Vertical feed tracking the exact timestamp, attack type, and response action. |
| **Spike Analysis Chart** | Real-time graph showing spikes in detected threats over the last 60 seconds. |
| **Attack Breakdown** | Interactive donut charts and protocol distributions. |

---

## Configuration

Edit `config/config.py` to tune:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `N_SAMPLES` | 5000 | Synthetic traffic records |
| `ANOMALY_CONTAMINATION` | 0.15 | Expected anomaly fraction |
| `BLOCK_DURATION_MINUTES` | 20 | IP block timeout |
| `RANDOM_STATE` | 42 | Reproducibility seed |

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `pandas` | Data manipulation |
| `numpy` | Numerical operations |
| `scikit-learn` | Isolation Forest + Random Forest |
| `streamlit` | Interactive dashboard |
| `plotly` | Interactive charts |
| `matplotlib` | Static plotting support |

---

## Extending the System

- **Real traffic**: Replace synthetic CSV with live tcpdump/tshark exports in the same column schema.
- **NSL-KDD**: Load NSL-KDD CSV and map its columns to the 7-feature schema in `MonitoringAgent`.
- **Autoencoder**: Swap `IsolationForest` in `AnomalyDetectionAgent` for a `keras` autoencoder.
- **Email alerts**: Add `smtplib` call in `ResponseAgent._decide_action()`.
- **Database**: Replace JSON report file with SQLite / PostgreSQL in `helper_functions.py`.
