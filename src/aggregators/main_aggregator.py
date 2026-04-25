"""
Main runner — combines all 3 OSINT feeds and stores everything to MongoDB.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))

from virustotal_feed import fetch_virustotal_indicators
from abuseipdb_feed import fetch_abuseipdb_indicators
from alienvault_feed import fetch_alienvault_indicators
from mongo_handler import insert_many_indicators, count_by_source, count_total

KNOWN_BAD_IPS = [
    "185.220.101.1",
    "185.220.101.2",
    "45.33.32.156",
    "192.42.116.16",
    "5.188.206.25",
    "194.165.16.76",
    "89.248.167.131",
    "171.25.193.78"
]


def run():
    print("=" * 60)
    print("  THREAT INTELLIGENCE PLATFORM — OSINT AGGREGATOR")
    print("=" * 60)

    all_indicators = []

    print("\n[1/3] Running VirusTotal feed...")
    vt_results = fetch_virustotal_indicators(KNOWN_BAD_IPS)
    all_indicators.extend(vt_results)

    print("\n[2/3] Running AbuseIPDB feed...")
    abuse_results = fetch_abuseipdb_indicators()
    all_indicators.extend(abuse_results)

    print("\n[3/3] Running AlienVault OTX feed...")
    otx_results = fetch_alienvault_indicators()
    all_indicators.extend(otx_results)

    print(f"\n[DB] Total collected: {len(all_indicators)} indicators")
    print("[DB] Saving to MongoDB...")
    result = insert_many_indicators(all_indicators)
    print(f"[DB] New entries:        {result['inserted']}")
    print(f"[DB] Duplicates skipped: {result['skipped_duplicates']}")

    print(f"\n[DB] Total in database: {count_total()}")
    print("[DB] Breakdown by source:")
    for entry in count_by_source():
        print(f"     {entry['_id']}: {entry['count']}")

    print("\nDone. Next run: python3 src/siem/risk_scorer.py")


if __name__ == "__main__":
    run()
