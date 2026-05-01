
import subprocess
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from whitelist import is_whitelisted


def run_command(command: list) -> tuple:
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )
        success = result.returncode == 0
        output = result.stdout + result.stderr
        return success, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def check_root():
    
    if os.geteuid() != 0:
        print("[Blocker ERROR] This script must be run with sudo")
        print("Run: sudo python3 src/enforcer/ip_blocker.py")
        return False
    return True


def is_already_blocked(ip: str) -> bool:
    
    success, output = run_command([
        "iptables", "-C", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ])
    return success


def block_ip(ip: str) -> dict:
    
    result = {
        "ip": ip,
        "action": "block",
        "success": False,
        "message": ""
    }

    
    if is_whitelisted(ip):
        result["message"] = f"SKIPPED — {ip} is whitelisted"
        print(f"  [Blocker] {result['message']}")
        return result

    
    if is_already_blocked(ip):
        result["success"] = True
        result["message"] = f"ALREADY BLOCKED — {ip}"
        print(f"  [Blocker] {result['message']}")
        return result

    
    success, output = run_command([
        "iptables", "-A", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ])

    if success:
        result["success"] = True
        result["message"] = f"BLOCKED — {ip}"
        print(f"  [Blocker] ✓ {result['message']}")
    else:
        result["message"] = f"FAILED to block {ip}: {output}"
        print(f"  [Blocker] ✗ {result['message']}")

    return result


def unblock_ip(ip: str) -> dict:
    
    result = {
        "ip": ip,
        "action": "unblock",
        "success": False,
        "message": ""
    }

    
    if not is_already_blocked(ip):
        result["message"] = f"NOT BLOCKED — {ip} has no rule to remove"
        print(f"  [Blocker] {result['message']}")
        return result

    
    success, output = run_command([
        "iptables", "-D", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ])

    if success:
        result["success"] = True
        result["message"] = f"UNBLOCKED — {ip}"
        print(f"  [Blocker] ✓ {result['message']}")
    else:
        result["message"] = f"FAILED to unblock {ip}: {output}"
        print(f"  [Blocker] ✗ {result['message']}")

    return result


def block_multiple(ip_list: list) -> dict:
    
    print(f"[Blocker] Blocking {len(ip_list)} IPs...")
    blocked = 0
    skipped = 0
    failed = 0

    for ip in ip_list:
        result = block_ip(ip)
        if result["success"]:
            blocked += 1
        elif "SKIPPED" in result["message"] or "ALREADY" in result["message"]:
            skipped += 1
        else:
            failed += 1

    summary = {
        "total": len(ip_list),
        "blocked": blocked,
        "skipped": skipped,
        "failed": failed
    }
    print(f"[Blocker] Done — Blocked: {blocked} | Skipped: {skipped} | Failed: {failed}")
    return summary


def list_blocked_ips():
    
    success, output = run_command([
        "iptables", "-L", "INPUT", "-n", "--line-numbers"
    ])
    if success:
        print("[Blocker] Current iptables INPUT rules:")
        print(output)
    else:
        print(f"[Blocker ERROR] Could not list rules: {output}")


def flush_all_blocks():
    
    print("[Blocker] WARNING: Flushing all INPUT DROP rules...")
    success, output = run_command(["iptables", "-F", "INPUT"])
    if success:
        print("[Blocker] All INPUT rules cleared")
    else:
        print(f"[Blocker ERROR] Failed to flush: {output}")


if __name__ == "__main__":
    if not check_root():
        sys.exit(1)

    print("=" * 50)
    print("  IP BLOCKER — TEST RUN")
    print("=" * 50)

    # Test with a known malicious IP
    test_ip = "185.220.101.1"
    print(f"\nTesting block on {test_ip}...")
    block_ip(test_ip)

    print(f"\nListing current rules...")
    list_blocked_ips()

    print(f"\nTesting unblock on {test_ip}...")
    unblock_ip(test_ip)
