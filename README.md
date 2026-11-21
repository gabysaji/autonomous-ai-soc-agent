# 🛡️ Autonomous Privacy-First AI SOC Triage & SOAR Agent

A local, air-gapped **Agentic AI Security Operations (SecOps) pipeline** engineered to automate Tier-1/Tier-2 alert triage, correlate SIEM telemetry, and execute automated SOAR containment with **zero external cloud data exposure** (GDPR / DSGVO compliant).

## 🏗️ System Architecture

```text
[ Incoming SIEM Alert (JSON) ]
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│       Autonomous Triage Engine (Python + Ollama)        │
│            Model: Qwen 2.5 (Temperature: 0.0)           │
└───────┬─────────────────────┬───────────────────┬───────┘
        │ (Tool 1)            │ (Tool 2)          │ (Tool 3 - Conditional)
        ▼                     ▼                   ▼
[ Threat Intel DB ]   [ Auth Logs DB ]    [ SOAR Firewall Block ]
 (IP Reputation)       (User Baseline)     (Only if Risk >= 80)
```

## 🚀 Key Engineering Features
* **100% On-Premise / Privacy-First Execution:** Runs locally via **Ollama** (`qwen2.5:3b`), eliminating the risk of leaking sensitive PII, internal IPs, or security telemetry to third-party LLM APIs.
* **Deterministic Tool-Use Guardrails:** Forces the LLM to query a normalized SQLite SIEM telemetry store (`auth_logs` and `threat_intel`) via Python function-calling before forming a verdict.
* **Hallucination Mitigation:** Configured with strict zero-temperature (`0.0`) inference and evidence-separation prompts to prevent cross-log field blending.
* **Safe SOAR Containment:** Includes an automated perimeter firewall blocklist action (`block_malicious_ip`) gated by strict risk-score thresholds (`>= 80`) to prevent self-inflicted Denial of Service (DoS) on legitimate corporate IPs.

## 🛠️ Tech Stack
* **AI Runtime & Model:** Ollama (`qwen2.5:3b`)
* **Backend & Orchestration:** Python 3, `ollama` SDK
* **SIEM & Threat Intel Storage:** SQLite3 (Abstracted Wazuh Indexer & CDB Threat Lists)

## ⚡ Quick Start
```bash
# 1. Pull the local model
ollama pull qwen2.5:3b

# 2. Set up environment
python3 -m venv venv && source venv/bin/activate
pip install ollama

# 3. Initialize local SIEM telemetry & run dual-scenario tests
python setup_siem.py
python agent.py
```
