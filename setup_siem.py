import sqlite3

def create_mock_siem():
    conn = sqlite3.connect("siem_telemetry.db")
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS auth_logs")
    cursor.execute("DROP TABLE IF EXISTS threat_intel")

    cursor.execute("""
        CREATE TABLE auth_logs (
            timestamp TEXT,
            username TEXT,
            src_ip TEXT,
            location TEXT,
            status TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE threat_intel (
            ip_address TEXT,
            reputation TEXT,
            risk_score INTEGER,
            tags TEXT
        )
    """)

    logs = [
        ("2026-11-18 09:05:00", "gaby.admin", "192.168.1.40", "Kochi, IN", "SUCCESS"),
        ("2026-11-19 09:12:00", "gaby.admin", "192.168.1.40", "Kochi, IN", "SUCCESS"),
        ("2026-11-20 02:58:10", "gaby.admin", "45.155.205.99", "Frankfurt, DE", "FAILED"),
        ("2026-11-20 02:58:45", "gaby.admin", "45.155.205.99", "Frankfurt, DE", "FAILED")
    ]
    cursor.executemany("INSERT INTO auth_logs VALUES (?, ?, ?, ?, ?)", logs)

    intel = [
        ("45.155.205.99", "MALICIOUS", 95, "Brute-Force Botnet, Tor Exit Node"),
        ("192.168.1.40", "CLEAN", 0, "Corporate Office Static IP")
    ]
    cursor.executemany("INSERT INTO threat_intel VALUES (?, ?, ?, ?)", intel)

    conn.commit()
    conn.close()
    print("[OK] Local SIEM database initialized (siem_telemetry.db)")

if __name__ == "__main__":
    create_mock_siem()
