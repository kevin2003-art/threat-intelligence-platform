# System Architecture — Threat Intelligence Platform

## Overview
The platform follows a pipeline architecture with five layers:
Collection, Storage, Scoring, Enforcement and Visualization.

---

## Layer 1 — OSINT Collection
Three feeds run simultaneously collecting threat indicators:

- VirusTotal API
  Queries known malicious IPs against 91 antivirus engines.
  Returns malicious vote count and engine ratio.

- AbuseIPDB Blacklist
  Fetches IPs reported with confidence score above 85 percent.
  Returns abuse confidence score and total report count.

- AlienVault OTX
  Fetches community threat pulses containing IPs and domains.
  Returns pulse name, tags and indicator type.

---

## Layer 2 — Storage
MongoDB stores all indicators with deduplication.

Collection: indicators
- value: IP address or domain
- type: ip or domain
- source: VirusTotal, AbuseIPDB or AlienVault OTX
- raw_score: normalized 0 to 1 float
- risk_score: final score 0 to 100
- severity: CRITICAL, HIGH, MEDIUM or LOW
- blocked: boolean flag
- ingested_at: timestamp

Collection: block_logs
- ip: blocked IP address
- action: block or unblock
- success: boolean
- risk_score: score at time of blocking
- severity: threat level
- source: originating feed
- timestamp: when action occurred

---

## Layer 3 — Risk Scoring
Custom scoring engine assigns risk scores per source:

VirusTotal:
- Score based on ratio of malicious engine votes
- Bonus points for high ratio above 50 percent

AbuseIPDB:
- Uses their own confidence score directly
- Bonus points for high report volume

AlienVault OTX:
- Base score of 65 for all community indicators
- Bonus 15 points for dangerous tags like malware or ransomware

---

## Layer 4 — Policy Enforcement
Daemon continuously monitors MongoDB every 30 seconds.
Blocks all IPs with risk score above 80 using iptables.

iptables rule applied:
iptables -A INPUT -s IP_ADDRESS -j DROP

Whitelist checked before every block.
All actions logged to MongoDB block_logs collection.
SOC analyst rollback removes iptables rule and updates MongoDB.

---

## Layer 5 — Visualization
Elasticsearch indexes all scored indicators.
Kibana displays three dashboard panels:

- Pie chart: threats by severity
- Bar chart: indicators by feed source
- Data table: top threat indicators sorted by risk score

---

## Data Flow
OSINT Feeds
    |
    v
main_aggregator.py
    |
    v
MongoDB indicators collection
    |
    v
risk_scorer.py
    |
    v
elasticsearch_indexer.py
    |
    v
Kibana Dashboard
    |
    v
policy_daemon.py
    |
    v
iptables DROP rules
    |
    v
block_logger.py
    |
    v
MongoDB block_logs collection
