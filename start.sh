#!/bin/bash
echo "Starting Threat Intelligence Platform..."
sudo systemctl start mongod elasticsearch kibana
cd ~/Desktop/threat-intelligence-platform
source venv/bin/activate
echo "Collecting fresh threat data..."
python3 src/aggregators/main_aggregator.py
echo "Scoring indicators..."
python3 src/siem/risk_scorer.py
echo "Indexing into Elasticsearch..."
python3 src/siem/elasticsearch_indexer.py
python3 src/siem/block_logs_indexer.py
echo "Running policy enforcer..."
sudo /home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/policy_daemon.py --once
echo "Launching SOC Dashboard..."
echo "Open http://localhost:5000 in Firefox"
python3 dashboard/app.py
