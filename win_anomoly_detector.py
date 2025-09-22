import subprocess
import sys

# -----------------------------
# Auto-install Missing Libraries
# -----------------------------
REQUIRED_PACKAGES = {
    "pywinrm": "pywinrm",
    "yaml": "pyyaml"
}

def ensure_dependencies():
    """Ensure all required packages are installed."""
    missing = []
    for module, pip_name in REQUIRED_PACKAGES.items():
        try:
            __import__(module)
        except ImportError:
            print(f"[!] Missing required package: {pip_name}")
            missing.append(pip_name)

    if missing:
        print(f"[+] Installing missing packages: {', '.join(missing)}\n")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        print("[✓] Packages installed. Continuing...\n")

ensure_dependencies()

# -----------------------------
# Core Imports (after verification)
# -----------------------------
import yaml
import winrm
import json
import sqlite3
from pathlib import Path

# -----------------------------
# Configuration
# -----------------------------
CONFIG_FILE = "config.yaml"
DB_FILE = "db.sqlite"
SCHEMA_FILE = "models/schema.sql"
MAX_EVENTS = 100

# Event ID Threat Scoring
EVENT_THREAT_SCORES = {
    1102: 1.0, 4624: 0.3, 4625: 0.6, 4657: 0.6, 4663: 0.4,
    4688: 0.8, 4700: 0.7, 4702: 0.6, 4719: 0.9, 4720: 1.0,
    4722: 0.9, 4724: 0.9, 4727: 0.9, 4732: 0.9, 4739: 1.0,
    4740: 0.6, 4825: 0.6, 4946: 0.8, 4948: 0.8
}

# -----------------------------
# Database Initialization
# -----------------------------
def init_db():
    """Initialize SQLite database with schema."""
    Path("models").mkdir(exist_ok=True)
    if not Path(SCHEMA_FILE).exists():
        print(f"[ERROR] Schema file not found: {SCHEMA_FILE}")
        sys.exit(1)

    conn = sqlite3.connect(DB_FILE)
    with open(SCHEMA_FILE, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    return conn

# -----------------------------
# Fetch Windows Event Logs via WinRM
# -----------------------------
def fetch_logs(ip, username, password):
    """Fetch Security Event Logs from a remote Windows host via WinRM."""
    session = winrm.Session(ip, auth=(username, password))
    ps = f"""
    Get-WinEvent -LogName Security -MaxEvents {MAX_EVENTS} | ForEach-Object {{
        [xml]$x = $_.ToXml()
        $x.Event
    }} | ConvertTo-Json -Depth 10
    """
    result = session.run_ps(ps)
    if result.status_code != 0:
        raise Exception(result.std_err.decode())

    logs = json.loads(result.std_out.decode())
    return logs if isinstance(logs, list) else [logs]

# -----------------------------
# Score to Risk Level Mapping
# -----------------------------
def get_risk_level(score):
    """Convert numerical score to risk level."""
    if score >= 0.8:
        return "High"
    elif score >= 0.5:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    return "No Risk"

# -----------------------------
# Analyze Logs and Store in DB
# -----------------------------
def analyze_logs(logs, host_name, conn):
    """Analyze logs and insert scored events into database."""
    cursor = conn.cursor()
    count = 0

    for entry in logs:
        try:
            event_id = int(entry["System"]["EventID"]["#text"])
            if event_id not in EVENT_THREAT_SCORES:
                continue

            # Extract user
            username = None
            for item in entry.get("EventData", {}).get("Data", []):
                if isinstance(item, dict) and item.get("@Name") in ["TargetUserName", "SubjectUserName"]:
                    username = item.get("#text", "").lower()
                    break

            if not username:
                continue

            score = EVENT_THREAT_SCORES[event_id]
            risk_level = get_risk_level(score)

            cursor.execute("""
                INSERT INTO events (host, username, event_id, risk_level, score)
                VALUES (?, ?, ?, ?, ?)
            """, (host_name, username, event_id, risk_level, score))
            count += 1

        except Exception:
            continue

    conn.commit()
    return count

# -----------------------------
# Main Execution
# -----------------------------
def main():
    print("🔍 Starting Network Anomaly Scan\n")

    if not Path(CONFIG_FILE).exists():
        print(f"[ERROR] Config file not found: {CONFIG_FILE}")
        sys.exit(1)

    with open(CONFIG_FILE, "r") as f:
        config = yaml.safe_load(f)

    db_conn = init_db()

    for host in config.get("hosts", []):
        name = host.get("name", "UnknownHost")
        ip = host.get("ip")
        user = host.get("username")
        password = host.get("password")

        print(f"[→] Connecting to {name} ({ip})...")
        try:
            logs = fetch_logs(ip, user, password)
            inserted = analyze_logs(logs, name, db_conn)
            print(f"[✓] {inserted} relevant events stored from {name}\n")
        except Exception as e:
            print(f"[!] Error processing {name}: {e}\n")

    db_conn.close()
    print("✅ All hosts processed. Results saved to 'db.sqlite'.")

# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    main()
