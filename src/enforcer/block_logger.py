import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))

from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


def get_log_collection():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = MongoClient(mongo_uri)
    db = client["threat_intelligence"]
    return db["block_logs"]


def log_action(ip: str, action: str, success: bool,
               message: str, risk_score: int = 0,
               severity: str = "UNKNOWN", source: str = "Unknown"):
    collection = get_log_collection()
    log_entry = {
        "ip": ip,
        "action": action,
        "success": success,
        "message": message,
        "risk_score": risk_score,
        "severity": severity,
        "source": source,
        "timestamp": datetime.utcnow().isoformat(),
        "logged_by": "policy_daemon"
    }
    try:
        collection.insert_one(log_entry)
    except Exception as e:
        print(f"[Logger ERROR] Failed to log action: {e}")


def get_recent_logs(limit=20):
    collection = get_log_collection()
    logs = list(collection.find(
        {},
        {"_id": 0}
    ).sort("timestamp", -1).limit(limit))
    return logs


def get_blocked_count():
    collection = get_log_collection()
    return collection.count_documents({"action": "block", "success": True})


def print_recent_logs(limit=10):
    logs = get_recent_logs(limit)
    if not logs:
        print("[Logger] No logs found yet")
        return

    print(f"\n[Logger] Last {len(logs)} actions:")
    print(f"  {'IP':<20} {'Action':<10} {'Success':<8} {'Severity':<10} Timestamp")
    print("  " + "-" * 75)
    for log in logs:
        success_str = "YES" if log.get("success") else "NO"
        print(
            f"  {log.get('ip','?'):<20} "
            f"{log.get('action','?'):<10} "
            f"{success_str:<8} "
            f"{log.get('severity','?'):<10} "
            f"{log.get('timestamp','?')[:19]}"
        )


if __name__ == "__main__":
    log_action(
        ip="185.220.101.1",
        action="block",
        success=True,
        message="Blocked by policy daemon",
        risk_score=95,
        severity="CRITICAL",
        source="VirusTotal"
    )
    print("[Logger] Test log entry created")
    print_recent_logs()
