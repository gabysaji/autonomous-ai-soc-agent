import sqlite3

def create_mock_siem():
    # Connects to (or creates) a local database file in your folder
    conn = sqlite3.connect("siem_telemetry.db")
    cursor = conn.cursor()

    # Reset tables if running multiple times
    cursor.execute("DROP TABLE IF EXISTS auth_logs")
    cursor.execute("DROP TABLE IF EXISTS threat_intel")

    # 1. Create Authentication Logs Table (Simulates CloudTrail / Linux Auth Logs)
    cursor.execute("""
        CREATE TABLE auth_logs (
            timestamp TEXT,
            username TEXT,
            src_ip TEXT,
            location TEXT,
            status TEXT
        )
    """)

    # 2. Create Threat Intelligence Table (Simulates AbuseIPDB / MISP Feeds)
    cursor.execute("""
        CREATE TABLE threat_intel (
            ip_address TEXT,
            reputation TEXT,
            risk_score INTEGER,
            tags TEXT
        )
    """)

    # Insert historical normal behavior + recent suspicious attempts
    logs = [
        ("2026-11-18 09:05:00", "gaby.admin", "192.168.1.40", "Kochi, IN", "SUCCESS"),
        ("2026-11-19 09:12:00", "gaby.admin", "192.168.1.40", "Kochi, IN", "SUCCESS"),
        ("2026-11-20 02:58:10", "gaby.admin", "45.155.205.99", "Frankfurt, DE (VPN/Proxy)", "FAILED"),
        ("2026-11-20 02:58:45", "gaby.admin", "45.155.205.99", "Frankfurt, DE (VPN/Proxy)", "FAILED")
    ]
    cursor.executemany("INSERT INTO auth_logs VALUES (?, ?, ?, ?, ?)", logs)

    # Insert known threat intel indicators
    intel = [
        ("45.155.205.99", "MALICIOUS", 95, "Known Brute-Force Botnet, Tor Exit Node"),
        ("192.168.1.40", "CLEAN", 0, "Corporate Office Static IP")
    ]
    cursor.executemany("INSERT INTO threat_intel VALUES (?, ?, ?, ?)", intel)

    conn.commit()
    conn.close()
    print("✅ Local SIEM Database (siem_telemetry.db) successfully built and populated!")

if __name__ == "__main__":
    create_mock_siem()

