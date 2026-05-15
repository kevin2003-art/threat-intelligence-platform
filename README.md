# Threat Intelligence Platform (TIP)

**Infotact Technical Internship — Cybersecurity Project 1**
**Domain: Finance and Banking Security**

---

## What is this?

Banks and financial institutions get hit by thousands of malicious IP addresses every single day. Traditional setups wait for a human to notice and manually block them — by then the damage is done. This platform changes that. It pulls real threat data from three live sources, scores every threat automatically, and blocks the dangerous ones at the firewall level without anyone having to touch it. If something new tries to brute force the system, it catches that too.

Built on Kali Linux over four weeks by Kevin and Shalwin.

---

## Team

**Kevin**
VirusTotal feed, AbuseIPDB feed, MongoDB handler, Elasticsearch indexer, Block logs indexer, IP blocker engine, Whitelist system, Kibana dashboard script, Flask SOC web dashboard backend, System health API, Whois enrichment API, Manual block endpoint, Final test suite, Startup script, Behavioral log watcher

**Shalwin**
AlienVault OTX feed, Main aggregator, Risk scoring engine, Policy enforcement daemon, Block logger, Rollback mechanism, Alert system, Threat summary report, Health checker, Architecture documentation

---

## Tech Stack

- **Python 3** — All scripts, automation and Flask backend
- **MongoDB** — NoSQL storage for threat indicators and audit logs
- **Elasticsearch** — SIEM data indexing and fast search
- **Kibana** — Visual dashboards and threat analytics
- **Linux iptables** — System level firewall enforcement
- **Flask** — SOC web dashboard API and server
- **Git and GitHub** — Version control, branching and collaboration

---


## Project Structure
```

threat-intelligence-platform/
├── src/
│   ├── aggregators/
│   │   ├── virustotal_feed.py
│   │   ├── abuseipdb_feed.py
│   │   ├── alienvault_feed.py
│   │   └── main_aggregator.py
│   ├── database/
│   │   └── mongo_handler.py
│   ├── siem/
│   │   ├── risk_scorer.py
│   │   ├── elasticsearch_indexer.py
│   │   ├── block_logs_indexer.py
│   │   ├── kibana_dashboard.py
│   │   └── health_check.py
│   └── enforcer/
│       ├── whitelist.py
│       ├── ip_blocker.py
│       ├── block_logger.py
│       ├── policy_daemon.py
│       ├── rollback.py
│       ├── alert_system.py
│       ├── threat_summary.py
│       └── final_test.py
├── dashboard/
│   ├── app.py
│   ├── log_watcher.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── style.css
│       └── dashboard.js
├── docs/
│   ├── week2_summary.md
│   ├── week3_report.md
│   ├── week4_report.md
│   ├── architecture.md
│   └── final_submission.md
└── start.sh
```



---

## How it Works

### 1. Data Collection
Three OSINT feeds run together and pull live threat data:

- **VirusTotal** — Queries IPs against 92 antivirus engines and returns a malicious vote ratio
- **AbuseIPDB** — Pulls a blacklist of IPs reported by the community with abuse confidence scores
- **AlienVault OTX** — Fetches threat pulses from security researchers containing malicious IPs and domains

All results are cleaned, deduplicated and stored in MongoDB.

### 2. Risk Scoring
Every indicator gets a score from 0 to 100:

- VirusTotal — based on ratio of malicious engine votes
- AbuseIPDB — uses their confidence score directly
- AlienVault OTX — starts at 65, boosted by dangerous tags like malware, ransomware, botnet, APT

Scores map to severity levels: CRITICAL (80-100), HIGH (60-79), MEDIUM (40-59), LOW (0-39)

### 3. SIEM Integration
All scored indicators get indexed into Elasticsearch and visualized in Kibana across five dashboard panels.

### 4. Auto Enforcement
A Python daemon scans MongoDB every 30 seconds. Every CRITICAL indicator gets an iptables DROP rule applied automatically. The IP is then completely blocked at the network level.

### 5. Behavioral Detection
A log watcher monitors the Kali Linux system auth log. If any IP generates more than 5 failed SSH login attempts within 60 seconds it is flagged as CRITICAL, added to the database and blocked instantly — even if it has never appeared in any threat feed before.

### 6. SOC Dashboard
A professional web dashboard gives analysts full visibility and control in real time.

---

## SOC Dashboard Features

- Live stat cards — total indicators, CRITICAL, HIGH, blocked, rollbacks
- Severity donut chart 
- Feed source bar chart comparing all three feeds
- Global threat heat map with country-labeled rows and live intensity colors
- Live security alerts panel showing recent block events
- Full threat indicators table with severity filter buttons
- Active firewall blocks table with rollback button on each row
- Permanent and temporary 24 hour rollback with reason logging
- IP Whois enrichment — ISP, org, city, proxy and hosting detection
- Manual IP block panel for live demonstrations
- Compliance audit log with local timestamps for PCI-DSS
- System health monitor — MongoDB, Elasticsearch and iptables live status
- Kibana shortcut button for deep forensic analysis
- Dark and light mode toggle
- Auto refresh every 30 seconds

---

## API Endpoints

| Endpoint | Method | What it does |
|---|---|---|
| `/api/stats` | GET | Counts and severity breakdown |
| `/api/indicators` | GET | All threat indicators with filtering |
| `/api/blocked` | GET | Currently blocked IPs |
| `/api/logs` | GET | Full compliance audit log |
| `/api/alerts` | GET | Recent block alerts |
| `/api/feed_status` | GET | OSINT feed status |
| `/api/countries` | GET | Top threat origin countries |
| `/api/health` | GET | System health check |
| `/api/whois/<ip>` | GET | IP enrichment and Whois lookup |
| `/api/rollback` | POST | Unblock an IP with reason |
| `/api/manual-block` | POST | Manually block any IP instantly |
| `/api/abuse-report` | POST | Generate AbuseIPDB report link |

---

## Running the Platform

### One command startup
```bash
cd ~/Desktop/threat-intelligence-platform
./start.sh
```

This handles everything — starts MongoDB, Elasticsearch and Kibana, collects fresh threat data, scores all indicators, indexes into Elasticsearch, runs the policy enforcer to block CRITICAL IPs and launches the SOC dashboard.

### Access the dashboard
SOC Dashboard:  http://localhost:5000
Kibana SIEM:    http://localhost:5601


From another device on the same WiFi: http://192.168.1.39:5000


### Manual commands

Start services:
```bash
sudo systemctl start mongod elasticsearch kibana
source venv/bin/activate
```

Collect threats:
```bash
python3 src/aggregators/main_aggregator.py
```

Score indicators:
```bash
python3 src/siem/risk_scorer.py
```

Index into Elasticsearch:
```bash
python3 src/siem/elasticsearch_indexer.py
```

Auto block CRITICAL IPs:
```bash
sudo /home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/policy_daemon.py --once
```

Rollback a false positive:
```bash
sudo /home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/rollback.py <IP> "reason"
```

View alerts:
```bash
cd src/enforcer
/home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 alert_system.py
```

Generate threat report:
```bash
/home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/threat_summary.py
```

Run behavioral brute force detector:
```bash
sudo /home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 dashboard/log_watcher.py
```

Run system tests:
```bash
/home/kali/Desktop/threat-intelligence-platform/venv/bin/python3 src/enforcer/final_test.py
```

---

## Weekly Progress

**Week 1 — OSINT Ingestion**
Set up Kali Linux, connected all three threat feeds, built MongoDB storage with deduplication, collected first indicators.

**Week 2 — SIEM Integration**
Built risk scoring engine, integrated Elasticsearch, created Kibana dashboard with 5 panels, 1683 CRITICAL threats identified.

**Week 3 — Dynamic Policy Enforcement**
Built iptables auto-blocking daemon, whitelist protection, rollback mechanism, alert system, behavioral brute force detection. 92 IPs blocked automatically.

**Week 4 — SOC Dashboard and Final Reporting**
Built professional military-grade SOC web dashboard, IP Whois enrichment, manual blocking, system health monitor, final tests, complete documentation.

---

## Compliance

- PCI-DSS compliant immutable audit logs in MongoDB
- Every block and unblock action recorded with timestamp and reason
- SOC analyst rollback with mandatory reason logging
- Whitelist protection prevents blocking safe infrastructure
- Continuous 30 second monitoring intervals
- Behavioral detection catches unknown threats not in any feed

---

## GitHub

Repository: `https://github.com/kevin2003-art/threat-intelligence-platform`

All four weeks of commits visible with contributions from both Kevin and Shalwin. Feature branches and pull requests used throughout. No credentials or API keys ever committed.

