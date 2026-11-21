import json
import sqlite3
from datetime import datetime
import ollama

DB_PATH = "siem_telemetry.db"

def query_threat_intel(ip_address: str) -> str:
    """Look up IP reputation and risk score from the local threat intel table."""
    print(f"[TOOL] Checking threat intel for {ip_address}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT reputation, risk_score, tags FROM threat_intel WHERE ip_address = ?",
        (ip_address,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return json.dumps({
            "ip_address": ip_address,
            "reputation": row[0],
            "risk_score": row[1],
            "tags": row[2]
        })
    return json.dumps({"ip_address": ip_address, "reputation": "UNKNOWN", "risk_score": 0})

def query_user_history(username: str) -> str:
    """Fetch recent authentication logs for a given username."""
    print(f"[TOOL] Fetching auth history for {username}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, src_ip, location, status FROM auth_logs WHERE username = ?",
        (username,)
    )
    rows = cursor.fetchall()
    conn.close()

    logs = [
        {"timestamp": r[0], "src_ip": r[1], "location": r[2], "status": r[3]}
        for r in rows
    ]
    return json.dumps(logs)

def block_malicious_ip(ip_address: str, reason: str) -> str:
    """Add a confirmed malicious IP to the local firewall blocklist table."""
    print(f"[ACTION] Blocking IP {ip_address} | Reason: {reason}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS firewall_blocklist (blocked_at TEXT, ip_address TEXT, reason TEXT)"
    )
    cursor.execute(
        "INSERT INTO firewall_blocklist VALUES (?, ?, ?)",
        (datetime.now().isoformat(), ip_address, reason)
    )
    conn.commit()
    conn.close()
    return json.dumps({"status": "BLOCKED", "ip_address": ip_address})

def run_triage(alert: dict):
    system_prompt = (
        "You are a SOC triage assistant. Investigate the incoming alert using your database tools. "
        "Always check both IP reputation and user login history first. "
        "Keep clean baseline logins separate from malicious IPs when citing logs. "
        "Only call block_malicious_ip if the alert's src_ip has a risk_score >= 80. "
        "Provide a short report covering: Verdict (TRUE POSITIVE or FALSE POSITIVE), "
        "Confidence, MITRE ATT&CK ID, Evidence, and Action Taken."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Investigate alert:\n{json.dumps(alert, indent=2)}"}
    ]

    tools = [query_threat_intel, query_user_history, block_malicious_ip]
    tool_map = {fn.__name__: fn for fn in tools}

    print(f"\n[ALERT] {alert['alert_id']} | src_ip={alert['src_ip']} | user={alert['username']}")

    for _ in range(3):
        response = ollama.chat(
            model="qwen2.5:3b",
            messages=messages,
            tools=tools,
            options={"temperature": 0.0}
        )
        messages.append(response["message"])

        if response["message"].get("tool_calls"):
            for call in response["message"]["tool_calls"]:
                name = call["function"]["name"]
                args = call["function"]["arguments"]
                result = tool_map[name](**args)
                messages.append({"role": "tool", "content": result})
        else:
            print("\n--- Triage Report ---")
            print(response["message"]["content"])
            break

if __name__ == "__main__":
    malicious_alert = {
        "alert_id": "SIEM-2026-8841",
        "timestamp": "2026-11-20 02:59:01",
        "rule_description": "Successful SSH login following brute-force attempts",
        "username": "gaby.admin",
        "src_ip": "45.155.205.99",
        "target_host": "prod-eu-gateway-01"
    }

    benign_alert = {
        "alert_id": "SIEM-2026-8842",
        "timestamp": "2026-11-20 09:05:12",
        "rule_description": "Admin login outside standard maintenance window",
        "username": "gaby.admin",
        "src_ip": "192.168.1.40",
        "target_host": "prod-eu-gateway-01"
    }

    run_triage(malicious_alert)
    run_triage(benign_alert)
