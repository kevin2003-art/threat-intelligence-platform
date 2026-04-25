import requests
import os
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
BASE_URL = "https://otx.alienvault.com/api/v1"


def fetch_recent_pulses(limit=25):
    """Get recent threat intelligence pulses from AlienVault OTX."""
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Content-Type": "application/json"
    }
    url = f"{BASE_URL}/pulses/subscribed?limit={limit}"

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        return response.json().get("results", [])
    except requests.exceptions.RequestException as e:
        print(f"[OTX ERROR] {e}")
        return []


def fetch_alienvault_indicators():
    """Fetch pulses and extract all IP and domain indicators."""
    print("[AlienVault OTX] Fetching threat pulses...")
    pulses = fetch_recent_pulses(limit=25)
    print(f"[AlienVault OTX] Got {len(pulses)} pulses")

    indicators = []
    for pulse in pulses:
        pulse_name = pulse.get("name", "Unknown Pulse")
        pulse_tags = pulse.get("tags", [])

        for ind in pulse.get("indicators", []):
            ind_type = ind.get("type", "")

            if ind_type not in ["IPv4", "domain", "hostname", "URL"]:
                continue

            indicators.append({
                "type": "ip" if ind_type == "IPv4" else "domain",
                "value": ind.get("indicator", ""),
                "source": "AlienVault OTX",
                "pulse_name": pulse_name,
                "tags": pulse_tags,
                "description": ind.get("description", ""),
                "raw_score": 0.7
            })

    print(f"[AlienVault OTX] Extracted {len(indicators)} indicators")
    return indicators


if __name__ == "__main__":
    results = fetch_alienvault_indicators()
    for r in results[:3]:
        print(r)
    print(f"Total: {len(results)}")
