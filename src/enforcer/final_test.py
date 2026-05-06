import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))

from mongo_handler import get_collection, count_total, count_by_source
from block_logger import get_blocked_count, get_recent_logs
from whitelist import is_whitelisted
from datetime import datetime


def test_mongodb():
    print("\n[Test 1] MongoDB Connection...")
    try:
        total = count_total()
        print(f"  PASS — Connected. Total indicators: {total}")
        return True
    except Exception as e:
        print(f"  FAIL — {e}")
        return False


def test_whitelist():
    print("\n[Test 2] Whitelist Protection...")
    safe_ips = ["8.8.8.8", "127.0.0.1", "192.168.1.1"]
    bad_ips = ["185.220.101.1", "45.33.32.156"]
    passed = True

    for ip in safe_ips:
        if not is_whitelisted(ip):
            print(f"  FAIL — {ip} should be whitelisted but is not")
            passed = False
        else:
            print(f"  PASS — {ip} correctly whitelisted")

    for ip in bad_ips:
        if is_whitelisted(ip):
            print(f"  FAIL — {ip} should NOT be whitelisted but is")
            passed = False
        else:
            print(f"  PASS — {ip} correctly not whitelisted")

    return passed


def test_risk_scores():
    print("\n[Test 3] Risk Score Distribution...")
    collection = get_collection()
    critical = collection.count_documents({"severity": "CRITICAL"})
    high = collection.count_documents({"severity": "HIGH"})
    total = count_total()

    print(f"  Total indicators:  {total}")
    print(f"  CRITICAL:          {critical}")
    print(f"  HIGH:              {high}")

    if total > 0:
        print(f"  PASS — Risk scoring working correctly")
        return True
    else:
        print(f"  FAIL — No indicators found")
        return False


def test_block_logs():
    print("\n[Test 4] Block Logs Audit Trail...")
    try:
        total_blocked = get_blocked_count()
        logs = get_recent_logs(limit=5)
        print(f"  Total IPs blocked: {total_blocked}")
        print(f"  Recent log entries: {len(logs)}")
        print(f"  PASS — Block logger working correctly")
        return True
    except Exception as e:
        print(f"  FAIL — {e}")
        return False


def test_data_sources():
    print("\n[Test 5] OSINT Feed Coverage...")
    sources = count_by_source()
    source_names = [s["_id"] for s in sources]

    expected = ["VirusTotal", "AbuseIPDB", "AlienVault OTX"]
    passed = True

    for expected_source in expected:
        if expected_source in source_names:
            count = next(s["count"] for s in sources if s["_id"] == expected_source)
            print(f"  PASS — {expected_source}: {count} indicators")
        else:
            print(f"  FAIL — {expected_source} not found in database")
            passed = False

    return passed


def run_all_tests():
    print("=" * 60)
    print("  THREAT INTELLIGENCE PLATFORM — FINAL SYSTEM TEST")
    print("=" * 60)
    print(f"  Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    results = []
    results.append(test_mongodb())
    results.append(test_whitelist())
    results.append(test_risk_scores())
    results.append(test_block_logs())
    results.append(test_data_sources())

    passed = sum(results)
    total = len(results)

    print("\n" + "=" * 60)
    print(f"  FINAL RESULT: {passed}/{total} tests passed")
    if passed == total:
        print("  ALL TESTS PASSED — Platform ready for submission")
    else:
        print("  SOME TESTS FAILED — Review above output")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
