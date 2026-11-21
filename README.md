# Local AI SOC Triage & Containment Agent

A lightweight, local SecOps prototype built with Python, SQLite, and Ollama (`qwen2.5:3b`). 

Instead of sending sensitive security logs to external cloud LLM APIs, this script runs entirely on-premise. It uses Python function-calling to force a local model to query historical login baselines and threat intelligence before deciding whether to block an IP.

## Architecture

```text
Incoming Alert (JSON)
        │
        ▼
Python Triage Loop (Ollama / Qwen 2.5 @ temp=0.0)
        ├──► query_threat_intel()  ──► SQLite (threat_intel)
        ├──► query_user_history()  ──► SQLite (auth_logs)
        └──► block_malicious_ip()  ──► SQLite (firewall_blocklist) [if risk >= 80]
```

## How It Works
1. **Local SIEM Store (`setup_siem.py`):** Initializes a SQLite database (`siem_telemetry.db`) with normalized authentication history and threat intelligence indicators to simulate a SIEM index without heavy container overhead.
2. **Deterministic Tool Use (`agent.py`):** Restricts the model from guessing. It must execute lookup functions to compare the incoming alert against the user's normal baseline and IP risk score.
3. **Guardrails & Containment:** Runs at `temperature=0.0` to prevent cross-log hallucinations. Includes a conditional firewall block action (`block_malicious_ip`) that only fires when an IP's risk score is 80 or higher, preventing accidental blocks on legitimate corporate IPs.

## Setup & Usage

```bash
# Pull the local model via Ollama
ollama pull qwen2.5:3b

# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install ollama

# Seed the local database and run the test scenarios
python setup_siem.py
python agent.py
```

## Test Scenarios Included
* **Scenario A (`SIEM-2026-8841`):** Successful login from a known malicious Tor exit node (`45.155.205.99`, risk score 95) following failed brute-force attempts -> **Confirmed True Positive & IP blocked.**
* **Scenario B (`SIEM-2026-8842`):** Admin login outside standard hours from a known clean corporate IP (`192.168.1.40`, risk score 0) -> **Confirmed False Positive & IP left unblocked.**
