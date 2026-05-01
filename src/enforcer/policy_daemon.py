import sys
import os
import time
import datetime

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))

from ip_blocker import block_ip, unblock_ip, check_root, list_blocked_ips
from block_logger import log_action, print_recent_logs, get_blocked_count
from mongo_handler import get_collection

SCAN_INTERVAL = 30
MIN_RISK_SCORE = 80
MAX_BLOCKS_PER_RUN = 10


def get_high_risk_ips():
    collection = get_collection()
    indicators = list(collection.find(
        {
            "type": "ip",
            "risk_score": {"$gte": MIN_RISK_SCORE},
            "severity": "CRITICAL",
            "blocked": {"$ne": True}
        },
        {"_id": 1, "value": 1, "risk_score": 1,
         "severity": 1, "source": 1, "country": 1}
    ).limit(MAX_BLOCKS_PER_RUN))
    return indicators


def mark_as_blocked(indicator_id, blocked: bool = True):
    collection = get_collection()
    collection.update_one(
        {"_id": indicator_id},
        {"$set": {
            "blocked": blocked,
            "blocked_at": datetime.datetime.utcnow().isoformat()
        }}
    )


def run_single_scan():
    indicators = get_high_risk_ips()

    if not indicators:
        print("[Daemon] No new high-risk IPs to block")
        return 0

    print(f"[Daemon] Found {len(indicators)} new CRITICAL IPs to block")
    blocked_count = 0

    for ind in indicators:
        ip = ind.get("value", "")
        risk_score = ind.get("risk_score", 0)
        severity = ind.get("severity", "UNKNOWN")
        source = ind.get("source", "Unknown")

        if not ip:
            continue

        result = block_ip(ip)

        log_action(
            ip=ip,
            action="block",
            success=result["success"],
            message=result["message"],
            risk_score=risk_score,
            severity=severity,
            source=source
        )

        if result["success"]:
            mark_as_blocked(ind["_id"], blocked=True)
            blocked_count += 1

    return blocked_count


def run_daemon():
    print("=" * 60)
    print("  DYNAMIC SECURITY POLICY ENFORCER — DAEMON")
    print("=" * 60)
    print(f"[Daemon] Monitoring MongoDB every {SCAN_INTERVAL} seconds")
    print(f"[Daemon] Blocking IPs with risk score >= {MIN_RISK_SCORE}")
    print(f"[Daemon] Press Ctrl+C to stop\n")

    scan_count = 0

    try:
        while True:
            scan_count += 1
            print(f"\n[Daemon] --- Scan #{scan_count} ---")
            blocked = run_single_scan()
            total_blocked = get_blocked_count()
            print(f"[Daemon] This scan: {blocked} new blocks")
            print(f"[Daemon] Total blocked so far: {total_blocked}")
            print(f"[Daemon] Waiting {SCAN_INTERVAL} seconds for next scan...")
            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print("\n\n[Daemon] Stopped by user")
        print_recent_logs(limit=10)
        print(f"[Daemon] Total IPs blocked: {get_blocked_count()}")


def run_once():
    print("=" * 60)
    print("  POLICY ENFORCER — SINGLE SCAN MODE")
    print("=" * 60)
    print("\n[Enforcer] Running single scan...")
    blocked = run_single_scan()
    print(f"\n[Enforcer] Blocked {blocked} IPs this scan")
    print("\n[Enforcer] Recent actions:")
    print_recent_logs(limit=10)
    print("\n[Enforcer] Current iptables rules:")
    list_blocked_ips()


if __name__ == "__main__":
    if not check_root():
        sys.exit(1)

    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        run_once()
    else:
        run_daemon()
