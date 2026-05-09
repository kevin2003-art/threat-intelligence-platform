import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'database'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'enforcer'))

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import subprocess
import datetime

load_dotenv()

app = Flask(__name__)
CORS(app)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)
db = client["threat_intelligence"]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def get_stats():
    total = db.indicators.count_documents({})
    critical = db.indicators.count_documents({"severity": "CRITICAL"})
    high = db.indicators.count_documents({"severity": "HIGH"})
    medium = db.indicators.count_documents({"severity": "MEDIUM"})
    low = db.indicators.count_documents({"severity": "LOW"})
    blocked = db.block_logs.count_documents({"action": "block", "success": True})
    rollbacks = db.block_logs.count_documents({"action": "unblock", "success": True})
    sources = list(db.indicators.aggregate([
        {"$group": {"_id": "$source", "count": {"$sum": 1}}}
    ]))
    return jsonify({
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "blocked": blocked,
        "rollbacks": rollbacks,
        "sources": [{"name": s["_id"], "count": s["count"]} for s in sources]
    })


@app.route("/api/indicators")
def get_indicators():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 100))
    severity = request.args.get("severity", None)
    skip = (page - 1) * limit
    query = {}
    if severity:
        query["severity"] = severity
    indicators = list(db.indicators.find(
        query,
        {"_id": 0, "value": 1, "type": 1, "source": 1,
         "risk_score": 1, "severity": 1, "country": 1, "ingested_at": 1}
    ).sort("risk_score", -1).skip(skip).limit(limit))
    return jsonify(indicators)


@app.route("/api/blocked")
def get_blocked():
    blocked = list(db.indicators.find(
        {"blocked": True},
        {"_id": 0, "value": 1, "risk_score": 1,
         "severity": 1, "source": 1, "country": 1, "blocked_at": 1}
    ).sort("blocked_at", -1))
    return jsonify(blocked)


@app.route("/api/logs")
def get_logs():
    limit = int(request.args.get("limit", 50))
    logs = list(db.block_logs.find(
        {},
        {"_id": 0, "ip": 1, "action": 1, "success": 1,
         "severity": 1, "source": 1, "risk_score": 1,
         "message": 1, "timestamp": 1}
    ).sort("timestamp", -1).limit(limit))
    return jsonify(logs)


@app.route("/api/alerts")
def get_alerts():
    alerts = list(db.block_logs.find(
        {"action": "block", "success": True},
        {"_id": 0, "ip": 1, "severity": 1,
         "source": 1, "risk_score": 1, "timestamp": 1}
    ).sort("timestamp", -1).limit(10))
    return jsonify(alerts)


@app.route("/api/rollback", methods=["POST"])
def rollback():
    data = request.json
    ip = data.get("ip")
    reason = data.get("reason", "Manual rollback from SOC dashboard")
    if not ip:
        return jsonify({"success": False, "message": "IP is required"}), 400
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
        success = result.returncode == 0
        db.block_logs.insert_one({
            "ip": ip,
            "action": "unblock",
            "success": success,
            "message": reason,
            "severity": "ROLLBACK",
            "source": "SOC Dashboard",
            "risk_score": 0,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "logged_by": "dashboard"
        })
        db.indicators.update_one(
            {"value": ip},
            {"$set": {"blocked": False, "rolled_back": True}}
        )
        if success:
            return jsonify({"success": True, "message": f"{ip} successfully unblocked"})
        else:
            return jsonify({"success": False, "message": f"Failed: {result.stderr}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/feed_status")
def feed_status():
    sources = ["VirusTotal", "AbuseIPDB", "AlienVault OTX"]
    status = []
    for source in sources:
        count = db.indicators.count_documents({"source": source})
        status.append({
            "name": source,
            "count": count,
            "status": "ONLINE" if count > 0 else "NO DATA"
        })
    return jsonify(status)


@app.route("/api/countries")
def get_countries():
    countries = list(db.indicators.aggregate([
        {"$match": {"country": {"$exists": True, "$ne": "Unknown"}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]))
    return jsonify([{"country": c["_id"], "count": c["count"]} for c in countries])


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  TIP SOC DASHBOARD STARTING")
    print("  Open browser: http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
