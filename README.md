# Threat Intelligence Aggregator

## Description
Educational cybersecurity project demonstrating how Security Operations Centers (SOCs) process threat intelligence feeds, correlate Indicators of Compromise (IOCs), assign severity levels, and generate actionable blocklists using Python in a Linux environment.

This project focuses on defensive (Blue Team) security practices without using AI or machine learning.

---

## Features
- Multi-feed threat intelligence ingestion  
- IOC Parsing (IP, Domain, URL, Hash, Email)  
- Data normalization & deduplication  
- Cross-feed correlation engine  
- Severity scoring (Low / Medium / High)  
- Automated blocklist generation  
- Separate blocklists for Firewall, DNS, Proxy, and EDR  

---

## System Workflow
Threat Feeds  
→ IOC Parser  
→ Normalization Engine  
→ Correlation Engine  
→ Severity Scoring  
→ Blocklist Generator  

---

## Severity Logic
- 1 Feed  → Low  
- 2–3 Feeds → Medium  
- 4+ Feeds → High  

Only Medium and High severity indicators are exported to blocklists.

---

## Tools Used
- Python 3  
- Linux (Kali / Ubuntu)  
- Python built-in libraries:
  - re
  - datetime
  - collections
  - os

---

## Project Structure
ThreatIntel-Aggregator/
├── parser.py
├── normalizer.py
├── correlator.py
├── blocklist.py
├── feeds/
└── output/

---

## How to Run

```bash
python3 parser.py
