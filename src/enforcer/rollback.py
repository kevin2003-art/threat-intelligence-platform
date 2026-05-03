import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))

from ip_blocker import unblock_ip, list_blocked_ips, check_root
from block_logger import log_action, print_recent_logs
from mongo_handler import get_collection


def rollback_ip(ip: str, reason: str = "Manual rollback by SOC analyst"):
    print(f"\n[Rollback] Attempting to unblock {ip}...")
    print(f"[Rollback] Reason: {reason}")

    result = unblock_ip(ip)

    log_action(
        ip=ip,
        action="unblock",
        success=result["success"],
        message=reason,
        risk_score=0,
        severity="ROLLBACK",
        source="SOC Analyst"
    )

    collection = get_collection()
    collection.update_one(
        {"value": ip},
        {"$set": {
            "blocked": False,
            "rolled_back": True,
            "rollback_reason": reason
        }}
    )

    if result["success"]:
        print(f"[Rollback] SUCCESS — {ip} has been unblocked")
    else:
        print(f"[Rollback] FAILED — {result['message']}")

    return result


def rollback_multiple(ip_list: list, reason: str = "Bulk rollback by SOC analyst"):
    print(f"\n[Rollback] Rolling back {len(ip_list)} IPs...")
    success_count = 0
    fail_count = 0

    for ip in ip_list:
        result = rollback_ip(ip, reason)
        if result["success"]:
            success_count += 1
        else:
            fail_count += 1

    print(f"\n[Rollback] Done — Success: {success_count} | Failed: {fail_count}")


def show_blocked_ips():
    collection = get_collection()
    blocked = list(collection.find(
        {"blocked": True},
        {"_id": 0, "value": 1, "risk_score": 1, "severity": 1, "source": 1}
    ))

    if not blocked:
        print("[Rollback] No IPs currently marked as blocked in database")
        return

    print(f"\n[Rollback] IPs marked as blocked in MongoDB ({len(blocked)} total):")
    print(f"  {'IP':<25} {'Score':>5}  {'Severity':<10}  Source")
    print("  " + "-" * 60)
    for b in blocked:
        print(
            f"  {b.get('value','?'):<25} "
            f"{b.get('risk_score',0):>5}  "
            f"{b.get('severity','?'):<10}  "
            f"{b.get('source','?')}"
        )


if __name__ == "__main__":
    if not check_root():
        sys.exit(1)

    print("=" * 60)
    print("  ROLLBACK MECHANISM — SOC ANALYST TOOL")
    print("=" * 60)

    show_blocked_ips()

    if len(sys.argv) > 1:
        ip_to_rollback = sys.argv[1]
        reason = sys.argv[2] if len(sys.argv) > 2 else "Manual rollback"
        rollback_ip(ip_to_rollback, reason)
    else:
        print("\n[Rollback] Usage: sudo python3 rollback.py <IP> <reason>")
        print("[Rollback] Example: sudo python3 rollback.py 88.151.34.109 'False positive'")

    print("\n[Rollback] Recent log:")
    print_recent_logs(limit=5)
