# Threat Intelligence Platform (TIP)

## Infotact Technical Internship — Cybersecurity Project 1
### Finance and Banking — Advanced Threat Intelligence Platform

---

## Team
- Kevin — VirusTotal feed, AbuseIPDB feed, MongoDB handler,
  Elasticsearch indexer, IP blocker, Whitelist, Kibana dashboard
- Shalwin — AlienVault OTX feed, Main aggregator, Risk scorer,
  Policy daemon, Block logger, Alert system, Threat summary

---

## Project Overview
An advanced Threat Intelligence Platform that aggregates OSINT
from three public threat feeds, scores all indicators using a
custom risk engine, integrates with an ELK Stack SIEM, and
automatically enforces firewall rules using Linux iptables.

---

## Technology Stack
- Python 3
- MongoDB — NoSQL threat indicator storage
- Elasticsearch and Kibana — SIEM and visualization
- Linux iptables — Dynamic firewall enforcement
- Git and GitHub — Version control and collaboration

---

## Final Statistics
- Total indicators collected: 1419
- CRITICAL threats: 1234
- HIGH threats: 177
- IPs automatically blocked: 60
- Rollbacks performed: 2
- OSINT feeds: 3

---

## Project Structure
src/
aggregators/
virustotal_feed.py
abuseipdb_feed.py
alienvault_feed.py
main_aggregator.py
database/
mongo_handler.py
siem/
risk_scorer.py
elasticsearch_indexer.py
kibana_dashboard.py
enforcer/
whitelist.py
ip_blocker.py
block_logger.py
policy_daemon.py
rollback.py
alert_system.py
threat_summary.py
docs/
week2_summary.md
week3_report.md
week4_report.md
---

## How to Run

### 1. Start services
bash
sudo systemctl start mongod
sudo systemctl start elasticsearch


### 2. Activate environment
bash
source venv/bin/activate


### 3. Collect threat data
bash
python3 src/aggregators/main_aggregator.py


### 4. Score indicators
bash
python3 src/siem/risk_scorer.py


### 5. Index into Elasticsearch
bash
python3 src/siem/elasticsearch_indexer.py


### 6. Run policy enforcer
bash
sudo /home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/policy_daemon.py --once


### 7. View alerts
bash
cd src/enforcer
/home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 alert_system.py


### 8. Generate full report
bash
/home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 threat_summary.py


### 9. Rollback false positive
bash
sudo /home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 rollback.py <IP> "reason"


### 10. Open Kibana dashboard
http://localhost:5601
Dashboard: TIP Threat Overview
---

## Weekly Progress
- Week 1 — OSINT ingestion and MongoDB setup
- Week 2 — Risk scoring and Elasticsearch SIEM
- Week 3 — Dynamic policy enforcement and iptables
- Week 4 — Final dashboarding and documentation

---

## Compliance
- PCI-DSS compliant immutable audit logs
- SOC analyst rollback mechanism
- Whitelist protection for safe infrastructure
- Continuous 30 second monitoring intervals
