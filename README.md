# Threat Intelligence Platform

## Project Overview
Advanced Threat Intelligence Platform built for Finance & Banking security.
Aggregates OSINT from VirusTotal, AbuseIPDB and AlienVault OTX.

## Team
- Kevin — VirusTotal feed, AbuseIPDB feed, MongoDB handler, Elasticsearch
- Shalwin — AlienVault OTX feed, Main aggregator, Risk scorer

## Week 1 — OSINT Ingestion
- Connected to 3 OSINT feeds
- Stored 661 threat indicators in MongoDB

## Week 2 — SIEM Integration  
- Risk scored all indicators (484 CRITICAL, 169 HIGH)
- Indexed into Elasticsearch
- Kibana dashboard at http://localhost:5601

## How to Run
```bash
python3 src/aggregators/main_aggregator.py
python3 src/siem/risk_scorer.py
python3 src/siem/elasticsearch_indexer.py
```# threat-intelligence-platform
