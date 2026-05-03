import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))

from datetime import datetime
from block_logger import get_recent_logs, get_blocked_count


def print_alert(ip: str, risk_score: int, severity: str,
                source: str, country: str = "Unknown"):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "!" * 60)
    print("  SECURITY ALERT — THREAT BLOCKED")
    print("!" * 60)
    print(f"  Time:      {timestamp} UTC")
    print(f"  IP:        {ip}")
    print(f"  Severity:  {severity}")
    print(f"  Score:     {risk_score}/100")
    print(f"  Source:    {source}")
    print(f"  Country:   {country}")
    print("!" * 60)


def check_and_alert(last_n: int = 5):
    logs = get_recent_logs(limit=last_n)

    if not logs:
        print("[Alert] No recent blocks found")
        return

    print(f"\n[Alert System] Checking last {last_n} blocks...")

    for log in logs:
        if log.get("action") == "block" and log.get("success"):
            print_alert(
                ip=log.get("ip", "Unknown"),
                risk_score=log.get("risk_score", 0),
                severity=log.get("severity", "Unknown"),
                source=log.get("source", "Unknown")
            )

    total = get_blocked_count()
    print(f"\n[Alert System] Total IPs blocked so far: {total}")


def show_summary():
    total = get_blocked_count()
    logs = get_recent_logs(limit=100)

    critical = sum(1 for l in logs if l.get("severity") == "CRITICAL")
    high = sum(1 for l in logs if l.get("severity") == "HIGH")
    rollbacks = sum(1 for l in logs if l.get("action") == "unblock")

    print("\n" + "=" * 50)
    print("  THREAT BLOCKING SUMMARY")
    print("=" * 50)
    print(f"  Total IPs blocked:    {total}")
    print(f"  CRITICAL blocks:      {critical}")
    print(f"  HIGH blocks:          {high}")
    print(f"  Rollbacks performed:  {rollbacks}")
    print("=" * 50)


if __name__ == "__main__":
    print("=" * 60)
    print("  ALERT SYSTEM — THREAT NOTIFICATION CENTER")
    print("=" * 60)

    check_and_alert(last_n=5)
    show_summary()
