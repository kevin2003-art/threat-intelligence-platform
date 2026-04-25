import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2"


def fetch_abuseipdb_indicators(confidence_minimum=85, limit=200):
    """Fetch high-confidence abusive IPs from AbuseIPDB blacklist."""
    print(f"[AbuseIPDB] Fetching blacklist (confidence >= {confidence_minimum})...")

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "confidenceMinimum": confidence_minimum,
        "limit": limit
    }

    try:
        response = requests.get(
            f"{BASE_URL}/blacklist",
            headers=headers,
            params=params,
            timeout=15
        )
        response.raise_for_status()
        entries = response.json().get("data", [])

        indicators = []
        for entry in entries:
            abuse_score = entry.get("abuseConfidenceScore", 0)
            indicators.append({
                "type": "ip",
                "value": entry.get("ipAddress", ""),
                "source": "AbuseIPDB",
                "abuse_confidence": abuse_score,
                "country": entry.get("countryCode", "Unknown"),
                "total_reports": entry.get("totalReports", 0),
                "last_reported": entry.get("lastReportedAt", ""),
                "tags": ["blacklisted", "abuse-reported"],
                "raw_score": abuse_score / 100.0
            })

        print(f"[AbuseIPDB] Got {len(indicators)} indicators")
        return indicators

    except requests.exceptions.RequestException as e:
        print(f"[AbuseIPDB ERROR] {e}")
        return []


if __name__ == "__main__":
    results = fetch_abuseipdb_indicators()
    for r in results[:3]:
        print(r)
    print(f"Total: {len(results)}")
