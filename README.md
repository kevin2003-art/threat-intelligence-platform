k# Threat Intelligence Platform (TIP)

## Project Overview
Advanced Threat Intelligence Platform built for Finance and Banking security.
Aggregates OSINT from multiple sources, scores threats, and automatically
blocks malicious IPs using Linux iptables.

## Team
- Kevin — VirusTotal feed, AbuseIPDB feed, MongoDB handler, Elasticsearch, IP Blocker, Whitelist
- Shalwin — AlienVault OTX feed, Main aggregator, Risk scorer, Policy daemon, Block logger

## Technology Stack
- Python 3
- MongoDB
- Elasticsearch and Kibana
- Linux iptables
- Git and GitHub

## Week 1 — OSINT Ingestion
- Connected to 3 OSINT feeds
- Collected 661 threat indicators
- Stored in MongoDB with deduplication

## Week 2 — SIEM Integration
- Risk scored all indicators
- 484 CRITICAL, 169 HIGH, 8 LOW
- Indexed into Elasticsearch
- Kibana dashboard created

## Week 3 — Dynamic Policy Enforcement
- Auto-blocking CRITICAL IPs via iptables
- 40 IPs blocked automatically
- Block logger with full audit trail
- SOC analyst rollback mechanism
- Alert system for threat notifications

## How to Run

### Start services
```bash
sudo systemctl start mongod
sudo systemctl start elasticsearch
```

### Collect threat data
```bash
source venv/bin/activate
python3 src/aggregators/main_aggregator.py
```

### Score indicators
```bash
python3 src/siem/risk_scorer.py
```

### Index into Elasticsearch
```bash
python3 src/siem/elasticsearch_indexer.py
```

### Run policy enforcer
```bash
sudo /home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/policy_daemon.py --once
```

### Rollback a false positive
```bash
sudo /home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/rollback.py <IP> "reason"
```

### View alerts
```bash
/home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/alert_system.py
```

### Open Kibana dashboard
http://localhost:5601

## Compliance
- PCI-DSS compliant logging via immutable block_logs collection
- All actions timestamped and auditable
- Whitelist protection prevents blocking safe infrastructure
