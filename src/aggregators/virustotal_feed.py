import requests
import os
from dotenv import load_dotenv
import time

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"


def get_ip_report(ip_address):
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json"
    }
    url = f"{BASE_URL}/ip_addresses/{ip_address}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 1

        if malicious_count == 0:
            print(f"  [VT] {ip_address} — clean")
            return None

        indicator = {
            "type": "ip",
            "value": ip_address,
            "source": "VirusTotal",
            "malicious_votes": malicious_count,
            "total_engines": total,
            "country": attributes.get("country", "Unknown"),
            "as_owner": attributes.get("as_owner", "Unknown"),
            "tags": attributes.get("tags", []),
            "raw_score": malicious_count / total if total > 0 else 0
        }
        print(f"  [VT] {ip_address} — MALICIOUS ({malicious_count}/{total} engines)")
        return indicator

    except requests.exceptions.HTTPError as e:
        if response.status_code == 429:
            print(f"  [VT] Rate limit hit, waiting 60 seconds...")
            time.sleep(60)
            return get_ip_report(ip_address)
        print(f"  [VT ERROR] HTTP error for {ip_address}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [VT ERROR] {ip_address}: {e}")
        return None


def fetch_virustotal_indicators(ip_list):
    print(f"[VirusTotal] Checking {len(ip_list)} IPs...")
    results = []
    for ip in ip_list:
        result = get_ip_report(ip)
        if result:
            results.append(result)
        time.sleep(15)  # Free tier: 4 requests per minute
    print(f"[VirusTotal] Done — found {len(results)} malicious indicators")
    return results


if __name__ == "__main__":
    test_ips = ["185.220.101.1", "45.33.32.156", "8.8.8.8"]
    indicators = fetch_virustotal_indicators(test_ips)
    for i in indicators:
        print(i)
