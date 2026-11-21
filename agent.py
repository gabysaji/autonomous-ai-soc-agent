import json
import sqlite3
from datetime import datetime
import ollama

# --- 1. INVESTIGATION & CONTAINMENT TOOLS ---
def query_threat_intel(ip_address: str) -> str:
    """Queries the local threat intelligence table for an IP's reputation and risk score."""
    print(f"🔎 [TOOL 1] Querying Threat Intel DB for IP: {ip_address}...")
    conn = sqlite3.connect("siem_telemetry.db")
    cursor = conn.cursor()
    cursor.execute("SELECT reputation, risk_score, tags FROM threat_intel WHERE ip_address = ?", (ip_address,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return json.dumps({"ip_address": ip_address, "reputation": row, "risk_score": row, "tags": row})
    return json.dumps({"ip_address": ip_address, "reputation": "UNKNOWN", "risk_score": 0, "tags": "No record"})

def query_user_history(username: str) -> str:
    """Queries the local SIEM auth_logs table for a user's historical login behavior."""
    print(f"🔎 [TOOL 2] Querying Auth Logs DB for User: {username}...")
    conn = sqlite3.connect("siem_telemetry.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, src_ip, location, status FROM auth_logs WHERE username = ?", (username,))
    rows = cursor.fetchall()
    conn.close()
    
    logs = [{"timestamp": r, "src_ip": r, "location": r, "status": r} for r in rows]
    return json.dumps(logs)

def block_malicious_ip(ip_address: str, reason: str) -> str:
    """SOAR Containment Action: Blocks a confirmed malicious IP at the perimeter firewall."""
    print(f"🛑 [SOAR CONTAINMENT EXECUTED] Blocking IP {ip_address} on Firewall! Reason: {reason}")
    conn = sqlite3.connect("siem_telemetry.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS firewall_blocklist (blocked_at TEXT, ip_address TEXT, reason TEXT)")
    cursor.execute("INSERT INTO firewall_blocklist VALUES (?, ?, ?)", (datetime.now().isoformat(), ip_address, reason))
    conn.commit()
    conn.close()
    return json.dumps({"action": "IP_BLOCKED", "ip_address": ip_address, "status": "SUCCESS"})

# --- 2. AUTONOMOUS TRIAGE & RESPONSE ENGINE ---
def run_triage_agent(incoming_alert: dict):
    system_prompt = """
    You are an Autonomous Tier-3 SOC Triage & Response Agent.
    
    STRICT INVESTIGATION PROTOCOL:
    1. Always call query_threat_intel and query_user_history first.
    2. Carefully separate normal baseline logs (CLEAN IPs) from malicious logs (MALICIOUS IPs). Never mix up IP addresses between different log timestamps.
    3. ONLY call block_malicious_ip if the alert's src_ip is confirmed MALICIOUS (risk_score >= 80). If the IP is CLEAN, do NOT block it.
    4. Output a concise report with:
       - Verdict: (TRUE POSITIVE or FALSE POSITIVE)
       - Confidence Score: (0-100%)
       - MITRE ATT&CK ID: (or N/A if False Positive)
       - Evidence Breakdown: (Accurately list normal baseline vs. suspicious activity)
       - Automated Action Taken: (State whether IP was blocked or left untouched)
    """

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Investigate this SIEM alert:\n{json.dumps(incoming_alert, indent=2)}"}
    ]

    tools = [query_threat_intel, query_user_history, block_malicious_ip]
    available_functions = {
        "query_threat_intel": query_threat_intel,
        "query_user_history": query_user_history,
        "block_malicious_ip": block_malicious_ip
    }

    print(f"\n{'='*65}\n🚨 INCOMING ALERT: {incoming_alert['alert_id']} (Source IP: {incoming_alert['src_ip']})\n{'='*65}")
    
    # Loop up to 3 turns so the AI can query tools first, then trigger SOAR containment if needed
    for _ in range(3):
        response = ollama.chat(
            model="qwen2.5:3b",
            messages=messages,
            tools=tools,
            options={"temperature": 0.0} # Zero temperature eliminates hallucinations
        )
        messages.append(response["message"])

        if response["message"].get("tool_calls"):
            for tool_call in response["message"]["tool_calls"]:
                func_name = tool_call["function"]["name"]
                args = tool_call["function"]["arguments"]
                tool_result = available_functions[func_name](**args)
                messages.append({"role": "tool", "content": tool_result})
        else:
            print("\n🛡️  FINAL AGENT REPORT:\n")
            print(response["message"]["content"])
            break

# --- 3. TEST BOTH SCENARIOS (TRUE POSITIVE + FALSE POSITIVE) ---
if __name__ == "__main__":
    # Scenario A: Real Attack from Tor Exit Node
    malicious_alert = {
        "alert_id": "SIEM-2026-8841",
        "timestamp": "2026-11-20 02:59:01",
        "rule_description": "Successful SSH login following brute-force attempts",
        "username": "gaby.admin",
        "src_ip": "45.155.205.99",
        "target_host": "prod-eu-gateway-01"
    }

    # Scenario B: False Positive (Legitimate admin logging in from office IP)
    benign_alert = {
        "alert_id": "SIEM-2026-8842",
        "timestamp": "2026-11-20 09:05:12",
        "rule_description": "Privileged admin login outside standard maintenance window",
        "username": "gaby.admin",
        "src_ip": "192.168.1.40",
        "target_host": "prod-eu-gateway-01"
    }

    run_triage_agent(malicious_alert)
    run_triage_agent(benign_alert)

