import sys
import os
import time
import re
import datetime
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'database'))

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI   = os.getenv("MONGO_URI", "mongodb://localhost:27017")
LOG_FILE    = "/var/log/auth.log"
THRESHOLD   = 5
WINDOW_SECS = 60

client = MongoClient(MONGO_URI)
db     = client["threat_intelligence"]

ip_attempts = {}


def block_ip(ip):
    subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    existing = db.indicators.find_one({"value": ip})
    if not existing:
        db.indicators.insert_one({
            "type": "ip", "value": ip,
            "source": "Behavioral Monitor",
            "severity": "CRITICAL", "risk_score": 100,
            "country": "Unknown",
            "tags": ["brute-force", "behavioral-anomaly"],
            "raw_score": 1.0,
            "ingested_at": datetime.datetime.utcnow().isoformat(),
            "processed": True, "blocked": True,
            "blocked_at": datetime.datetime.utcnow().isoformat()
        })
    else:
        db.indicators.update_one(
            {"value": ip},
            {"$set": {"blocked": True, "severity": "CRITICAL", "risk_score": 100}}
        )
    db.block_logs.insert_one({
        "ip": ip, "action": "block", "success": True,
        "message": "Behavioral Anomaly: Brute Force Detected",
        "severity": "CRITICAL", "source": "Behavioral Monitor",
        "risk_score": 100,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "logged_by": "log_watcher"
    })
    print(f"[LogWatcher] BLOCKED brute force IP: {ip}")


def watch():
    print(f"[LogWatcher] Monitoring {LOG_FILE} for brute force...")
    if not os.path.exists(LOG_FILE):
        print(f"[LogWatcher] {LOG_FILE} not found. Creating test log...")
        open(LOG_FILE, "a").close()

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            if "Failed password" in line:
                match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    ip  = match.group(1)
                    now = time.time()

                    if ip not in ip_attempts:
                        ip_attempts[ip] = []

                    ip_attempts[ip].append(now)
                    ip_attempts[ip] = [t for t in ip_attempts[ip] if now - t <= WINDOW_SECS]

                    print(f"[LogWatcher] Failed login from {ip} ({len(ip_attempts[ip])} attempts)")

                    if len(ip_attempts[ip]) >= THRESHOLD:
                        already = db.indicators.find_one({"value": ip, "blocked": True})
                        if not already:
                            block_ip(ip)
                        ip_attempts[ip] = []


if __name__ == "__main__":
    watch()
