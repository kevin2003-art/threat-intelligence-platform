# Final Submission — Threat Intelligence Platform

## Infotact Technical Internship Program
### Project 1: Finance and Banking — Advanced Threat Intelligence Platform

---

## Team Members
- Kevin
- Shalwin

## Project Repository
https://github.com/kevin2003-art/threat-intelligence-platform

---

## Project Summary
We built a fully functional Threat Intelligence Platform that:
1. Collects threat data from 3 OSINT feeds automatically
2. Stores and deduplicates indicators in MongoDB
3. Scores all threats using a custom risk engine
4. Visualizes threats in an ELK Stack SIEM dashboard
5. Automatically blocks malicious IPs using Linux iptables
6. Logs all actions for PCI-DSS compliance
7. Provides SOC analyst rollback for false positives
8. Sends real time alerts for new threat blocks

---

## Final Statistics
- Total indicators collected: 1581
- CRITICAL threats: 1396
- HIGH threats: 177
- IPs automatically blocked: 70
- Rollbacks performed: 2
- OSINT feeds: 3
- Weeks of development: 4

---

## Week by Week Progress

### Week 1 — OSINT Ingestion
- Set up Kali Linux environment
- Connected VirusTotal API feed
- Connected AbuseIPDB blacklist feed
- Connected AlienVault OTX pulse feed
- Stored 1581 indicators in MongoDB with deduplication

### Week 2 — SIEM Integration
- Built risk scoring engine 0 to 100
- Integrated Elasticsearch for searchable threat data
- Created Kibana dashboard with 3 visualization panels
- 1396 CRITICAL and 177 HIGH threats identified

### Week 3 — Dynamic Policy Enforcement
- Built IP whitelist protection system
- Created iptables blocking engine
- Developed policy daemon with 30 second scan intervals
- Implemented SOC analyst rollback mechanism
- Built alert system for threat notifications
- 70 CRITICAL IPs automatically blocked

### Week 4 — Final Testing and Documentation
- Built Kibana dashboard summary script
- Created final threat summary report
- Built system health checker
- Completed full system test suite
- Finalized all documentation

---

## GitHub Commit History
All 4 weeks have daily commits from both Kevin and Shalwin.
Commits follow semantic versioning with feat, fix and docs prefixes.
All features developed on separate branches with pull requests.

---

## Compliance
- PCI-DSS compliant immutable audit logs
- All network actions timestamped and logged
- Whitelist protection prevents blocking safe infrastructure
- SOC analyst rollback mechanism implemented
- Continuous 30 second monitoring intervals

---

## How to Run the Platform
See README.md for complete run instructions.
