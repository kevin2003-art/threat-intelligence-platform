import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'enforcer'))

import requests
from pymongo import MongoClient
from datetime import datetime


def check_mongodb():
    print("\n[Health] Checking MongoDB...")
    try:
        client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=3000)
        client.server_info()
        db = client["threat_intelligence"]
        count = db["indicators"].count_documents({})
        print(f"  PASS — MongoDB running. Indicators: {count}")
        return True
    except Exception as e:
        print(f"  FAIL — MongoDB not running: {e}")
        print(f"  Fix:  sudo systemctl start mongod")
        return False


def check_elasticsearch():
    print("\n[Health] Checking Elasticsearch...")
    try:
        response = requests.get("http://localhost:9200", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"  PASS — Elasticsearch running. Version: {data['version']['number']}")
            return True
        else:
            print(f"  FAIL — Elasticsearch returned {response.status_code}")
            return False
    except Exception as e:
        print(f"  FAIL — Elasticsearch not running: {e}")
        print(f"  Fix:  sudo systemctl start elasticsearch")
        return False


def check_kibana():
    print("\n[Health] Checking Kibana...")
    try:
        response = requests.get("http://localhost:5601/api/status", timeout=5)
        if response.status_code == 200:
            print(f"  PASS — Kibana running at http://localhost:5601")
            return True
        else:
            print(f"  FAIL — Kibana returned {response.status_code}")
            return False
    except Exception as e:
        print(f"  FAIL — Kibana not running: {e}")
        print(f"  Fix:  sudo systemctl start kibana")
        return False


def check_threat_data():
    print("\n[Health] Checking threat data...")
    try:
        client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=3000)
        db = client["threat_intelligence"]
        indicators = db["indicators"].count_documents({})
        blocked = db["block_logs"].count_documents({"action": "block", "success": True})
        critical = db["indicators"].count_documents({"severity": "CRITICAL"})

        print(f"  Total indicators:  {indicators}")
        print(f"  CRITICAL threats:  {critical}")
        print(f"  IPs blocked:       {blocked}")

        if indicators > 0:
            print(f"  PASS — Threat data present")
            return True
        else:
            print(f"  FAIL — No threat data found")
            print(f"  Fix:  python3 src/aggregators/main_aggregator.py")
            return False
    except Exception as e:
        print(f"  FAIL — {e}")
        return False


def run_health_check():
    print("=" * 60)
    print("  THREAT INTELLIGENCE PLATFORM — HEALTH CHECK")
    print("=" * 60)
    print(f"  Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    results = []
    results.append(check_mongodb())
    results.append(check_elasticsearch())
    results.append(check_kibana())
    results.append(check_threat_data())

    passed = sum(results)
    total = len(results)

    print("\n" + "=" * 60)
    print(f"  HEALTH CHECK RESULT: {passed}/{total} services healthy")
    if passed == total:
        print("  ALL SERVICES HEALTHY — Platform fully operational")
    else:
        print("  SOME SERVICES DOWN — Check above for fix commands")
    print("=" * 60)


if __name__ == "__main__":
    run_health_check()
