# Week 3 Report — Dynamic Policy Enforcement Engine

## Overview
Week 3 transitions the platform from passive threat collection
to active proactive defense using Linux iptables.

## Files Built This Week

### whitelist.py
Protects safe IPs from being blocked.
Checks localhost, private ranges and known safe DNS servers.

### ip_blocker.py
Core iptables engine.
Blocks and unblocks IPs at system level using subprocess.
Checks whitelist before every block action.

### block_logger.py
Immutable audit trail stored in MongoDB block_logs collection.
Logs every block and unblock with timestamp, severity and source.

### policy_daemon.py
Main enforcement daemon.
Monitors MongoDB every 30 seconds for new CRITICAL indicators.
Automatically applies iptables DROP rules for each one.

### rollback.py
SOC analyst tool for false positive management.
Removes iptables rule and updates MongoDB blocked status.
Logs every rollback action for compliance.

### alert_system.py
Threat notification center.
Shows recent block alerts with full threat details.
Displays summary of total blocks and severity breakdown.

## Results
- 40 CRITICAL IPs automatically blocked
- All actions logged in MongoDB
- Rollback mechanism tested and working
- Alert system firing for each blocked threat

## How Policy Enforcement Works
1. main_aggregator.py collects threats from 3 OSINT feeds
2. risk_scorer.py assigns scores 0-100 to each indicator
3. policy_daemon.py reads indicators with score >= 80
4. ip_blocker.py applies iptables DROP rule for each IP
5. block_logger.py records every action in MongoDB
6. alert_system.py notifies SOC analysts of new blocks
7. rollback.py allows analysts to reverse false positives

## Compliance
All block and unblock actions stored in MongoDB with:
- IP address
- Action type block or unblock
- Success status
- Risk score and severity
- Source feed
- Timestamp
- SOC analyst reason for rollback
