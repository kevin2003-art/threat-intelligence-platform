import sys
import os
import subprocess
import datetime
import threading
import time
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'database'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'enforcer'))

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)
db = client["threat_intelligence"]


# ── HEALTH CHECK ──────────────────────────────────────────
def check_mongodb():
    try:
        client.server_info()
        return {"status": "ONLINE", "ok": True}
    except:
        return {"status": "OFFLINE", "ok": False}


def check_elasticsearch():
    try:
        import requests as req
        r = req.get("http://localhost:9200", timeout=3)
        if r.status_code == 200:
            return {"status": "ONLINE", "ok": True}
        return {"status": "DEGRADED", "ok": False}
    except:
        return {"status": "OFFLINE", "ok": False}


def check_iptables():
    try:
        r = subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n"],
                           capture_output=True, text=True, timeout=5)
        rules = r.stdout.count("DROP")
        return {"status": "ACTIVE", "rules": rules, "ok": True}
    except:
        return {"status": "UNKNOWN", "rules": 0, "ok": False}


# ── ROUTES ────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def get_stats():
    total    = db.indicators.count_documents({})
    critical = db.indicators.count_documents({"severity": "CRITICAL"})
    high     = db.indicators.count_documents({"severity": "HIGH"})
    medium   = db.indicators.count_documents({"severity": "MEDIUM"})
    low      = db.indicators.count_documents({"severity": "LOW"})
    blocked  = db.block_logs.count_documents({"action": "block",   "success": True})
    rollback = db.block_logs.count_documents({"action": "unblock", "success": True})
    sources  = list(db.indicators.aggregate([
        {"$group": {"_id": "$source", "count": {"$sum": 1}}}
    ]))
    return jsonify({
        "total": total, "critical": critical, "high": high,
        "medium": medium, "low": low,
        "blocked": blocked, "rollbacks": rollback,
        "sources": [{"name": s["_id"], "count": s["count"]} for s in sources]
    })


@app.route("/api/indicators")
def get_indicators():
    severity = request.args.get("severity")
    limit    = int(request.args.get("limit", 100))
    query    = {"severity": severity} if severity else {}
    data = list(db.indicators.find(
        query,
        {"_id": 0, "value": 1, "type": 1, "source": 1,
         "risk_score": 1, "severity": 1, "country": 1, "ingested_at": 1}
    ).sort("risk_score", -1).limit(limit))
    return jsonify(data)


@app.route("/api/blocked")
def get_blocked():
    data = list(db.indicators.find(
        {"blocked": True},
        {"_id": 0, "value": 1, "risk_score": 1,
         "severity": 1, "source": 1, "country": 1, "blocked_at": 1}
    ).sort("blocked_at", -1))
    return jsonify(data)


@app.route("/api/logs")
def get_logs():
    limit = int(request.args.get("limit", 50))
    data = list(db.block_logs.find(
        {},
        {"_id": 0, "ip": 1, "action": 1, "success": 1,
         "severity": 1, "source": 1, "risk_score": 1,
         "message": 1, "timestamp": 1}
    ).sort("timestamp", -1).limit(limit))
    return jsonify(data)


@app.route("/api/alerts")
def get_alerts():
    data = list(db.block_logs.find(
        {"action": "block", "success": True},
        {"_id": 0, "ip": 1, "severity": 1,
         "source": 1, "risk_score": 1, "timestamp": 1}
    ).sort("timestamp", -1).limit(10))
    return jsonify(data)


@app.route("/api/feed_status")
def feed_status():
    feeds = ["VirusTotal", "AbuseIPDB", "AlienVault OTX"]
    result = []
    for f in feeds:
        count = db.indicators.count_documents({"source": f})
        result.append({"name": f, "count": count,
                        "status": "ONLINE" if count > 0 else "NO DATA"})
    return jsonify(result)


@app.route("/api/countries")
def get_countries():
    data = list(db.indicators.aggregate([
        {"$match": {"country": {"$exists": True, "$nin": ["Unknown", None, ""]}}},
        {"$group": {"_id": "$country", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 15}
    ]))
    return jsonify([{"country": c["_id"], "count": c["count"]} for c in data])


@app.route("/api/health")
def health():
    return jsonify({
        "mongodb":       check_mongodb(),
        "elasticsearch": check_elasticsearch(),
        "iptables":      check_iptables(),
        "timestamp":     datetime.datetime.utcnow().isoformat()
    })


@app.route("/api/whois/<ip>")
def whois(ip):
    try:
        import requests as req
        r = req.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting",
                    timeout=8)
        data = r.json()
        return jsonify({
            "ip":       ip,
            "country":  data.get("country", "Unknown"),
            "region":   data.get("regionName", "Unknown"),
            "city":     data.get("city", "Unknown"),
            "isp":      data.get("isp", "Unknown"),
            "org":      data.get("org", "Unknown"),
            "as":       data.get("as", "Unknown"),
            "proxy":    data.get("proxy", False),
            "hosting":  data.get("hosting", False),
            "status":   data.get("status", "fail")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rollback", methods=["POST"])
def rollback():
    data   = request.json
    ip     = data.get("ip")
    reason = data.get("reason", "Manual rollback from SOC dashboard")
    mode   = data.get("mode", "permanent")

    if not ip:
        return jsonify({"success": False, "message": "IP required"}), 400

    try:
        result = subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
        success = result.returncode == 0

        db.block_logs.insert_one({
            "ip": ip, "action": "unblock", "success": success,
            "message": f"[{mode.upper()}] {reason}",
            "severity": "ROLLBACK", "source": "SOC Dashboard",
            "risk_score": 0,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "logged_by": "dashboard"
        })
        db.indicators.update_one(
            {"value": ip},
            {"$set": {"blocked": False, "rolled_back": True,
                       "rollback_reason": reason}}
        )

        if mode == "temp24h" and success:
            def reblock():
                time.sleep(86400)
                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True
                )
                db.block_logs.insert_one({
                    "ip": ip, "action": "block", "success": True,
                    "message": "Auto re-block after 24h temporary rollback",
                    "severity": "CRITICAL", "source": "SOC Auto",
                    "risk_score": 100,
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "logged_by": "auto_reblock"
                })
            threading.Thread(target=reblock, daemon=True).start()

        msg = f"{ip} unblocked" + (" (auto re-block in 24h)" if mode == "temp24h" else "")
        return jsonify({"success": success, "message": msg})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/manual-block", methods=["POST"])
def manual_block():
    data     = request.json
    ip       = data.get("ip", "").strip()
    severity = data.get("severity", "CRITICAL")
    reason   = data.get("reason", "Manual Admin Entry")

    if not ip:
        return jsonify({"success": False, "message": "IP required"}), 400

    score_map = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
    score = score_map.get(severity, 100)

    existing = db.indicators.find_one({"value": ip})
    if not existing:
        db.indicators.insert_one({
            "type": "ip", "value": ip, "source": "Manual Admin Entry",
            "severity": severity, "risk_score": score,
            "country": "Unknown", "tags": ["manual", "admin"],
            "raw_score": score / 100,
            "ingested_at": datetime.datetime.utcnow().isoformat(),
            "processed": True, "blocked": False
        })

    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True, timeout=10
    )
    success = result.returncode == 0

    db.indicators.update_one(
        {"value": ip},
        {"$set": {"blocked": True, "risk_score": score, "severity": severity,
                   "blocked_at": datetime.datetime.utcnow().isoformat()}}
    )
    db.block_logs.insert_one({
        "ip": ip, "action": "block", "success": success,
        "message": reason, "severity": severity,
        "source": "Manual Admin Entry", "risk_score": score,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "logged_by": "dashboard_manual"
    })

    return jsonify({
        "success": success,
        "message": f"{ip} blocked with {severity} severity" if success else f"Failed: {result.stderr}"
    })


@app.route("/api/abuse-report", methods=["POST"])
def abuse_report():
    data = request.json
    ip   = data.get("ip")
    return jsonify({
        "success": True,
        "message": f"Abuse report for {ip} logged. Submit to AbuseIPDB at https://www.abuseipdb.com/report",
        "abuseipdb_url": f"https://www.abuseipdb.com/report?ip={ip}"
    })


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  TIP ADVANCED SOC DASHBOARD")
    print("  Local:    http://localhost:5000")
    print("  Network:  http://0.0.0.0:5000")
    print("="*55 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
