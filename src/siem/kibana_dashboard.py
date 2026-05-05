import requests
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))
from mongo_handler import get_collection
from block_logger import get_recent_logs, get_blocked_count

KIBANA_HOST = "http://localhost:5601"


def check_kibana():
    try:
        response = requests.get(f"{KIBANA_HOST}/api/status", timeout=10)
        if response.status_code == 200:
            print("[Kibana] Connected successfully")
            return True
        else:
            print(f"[Kibana ERROR] Status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"[Kibana ERROR] Cannot connect: {e}")
        return False


def print_block_logs_summary():
    print("\n" + "=" * 60)
    print("  BLOCK LOGS SUMMARY FOR KIBANA DASHBOARD")
    print("=" * 60)

    logs = get_recent_logs(limit=50)
    total = get_blocked_count()

    print(f"\n  Total IPs blocked:    {total}")

    sources = {}
    countries = {}
    severities = {}

    collection = get_collection()
    blocked = list(collection.find(
        {"blocked": True},
        {"_id": 0, "value": 1, "risk_score": 1,
         "severity": 1, "source": 1, "country": 1}
    ))

    for b in blocked:
        src = b.get("source", "Unknown")
        country = b.get("country", "Unknown")
        severity = b.get("severity", "Unknown")

        sources[src] = sources.get(src, 0) + 1
        countries[country] = countries.get(country, 0) + 1
        severities[severity] = severities.get(severity, 0) + 1

    print("\n  Blocked IPs by source:")
    for src, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
        print(f"    {src:<20} {count}")

    print("\n  Blocked IPs by severity:")
    for sev, count in sorted(severities.items(), key=lambda x: x[1], reverse=True):
        print(f"    {sev:<20} {count}")

    print("\n  Top 10 countries with blocked IPs:")
    top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]
    for country, count in top_countries:
        print(f"    {country:<20} {count}")

    print("\n  Recent 10 block actions:")
    print(f"  {'IP':<22} {'Severity':<10} {'Source':<15} Timestamp")
    print("  " + "-" * 70)
    for log in logs[:10]:
        if log.get("action") == "block":
            print(
                f"  {log.get('ip','?'):<22} "
                f"{log.get('severity','?'):<10} "
                f"{log.get('source','?'):<15} "
                f"{log.get('timestamp','?')[:19]}"
            )

    print("\n" + "=" * 60)
    print("  Open Kibana at http://localhost:5601")
    print("  Dashboard: TIP Threat Overview")
    print("=" * 60)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'enforcer'))
    from block_logger import get_recent_logs, get_blocked_count

    check_kibana()
    print_block_logs_summary()
