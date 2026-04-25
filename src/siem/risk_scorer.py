import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))

from mongo_handler import get_collection
from datetime import datetime, UTC


def calculate_risk_score(indicator: dict):
    """
    Calculate normalized risk score and severity for one indicator.
    Each source uses its own scoring logic then maps to 0-100.
    """
    source = indicator.get("source", "Unknown")

    if source == "VirusTotal":
        votes = indicator.get("malicious_votes", 0)
        total = indicator.get("total_engines", 1)
        ratio = votes / total if total > 0 else 0
        base = int(ratio * 70)
        if ratio > 0.5:
            bonus = 25
        elif ratio > 0.25:
            bonus = 15
        elif ratio > 0.1:
            bonus = 5
        else:
            bonus = 0
        score = min(100, base + bonus)

    elif source == "AbuseIPDB":
        score = indicator.get("abuse_confidence", 0)
        reports = indicator.get("total_reports", 0)
        if reports > 100:
            score = min(100, score + 10)
        elif reports > 20:
            score = min(100, score + 5)

    elif source == "AlienVault OTX":
        score = 65
        dangerous_tags = ["malware", "ransomware", "apt", "botnet", "c2",
                          "phishing", "trojan", "exploit", "backdoor"]
        for tag in indicator.get("tags", []):
            if any(d in str(tag).lower() for d in dangerous_tags):
                score = min(100, score + 15)
                break

    else:
        raw = indicator.get("raw_score", 0.0)
        score = int(raw * 60)

    # Assign severity label
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity


def normalize_all():
    """Score every indicator in the database."""
    collection = get_collection()
    indicators = list(collection.find({}))

    print(f"[Risk Scorer] Scoring {len(indicators)} indicators...")

    for ind in indicators:
        score, severity = calculate_risk_score(ind)
        collection.update_one(
            {"_id": ind["_id"]},
            {"$set": {
                "risk_score": score,
                "severity": severity,
                "scored_at": datetime.utcnow().isoformat()
            }}
        )

    print("[Risk Scorer] Done. Severity distribution:")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = collection.count_documents({"severity": level})
        bar = "#" * (count // 5 + 1) if count > 0 else ""
        print(f"  {level:10s}: {count:4d}  {bar}")


if __name__ == "__main__":
    normalize_all()
