# IOC Enrichment & Threat Intelligence Tool

A Python-based SOC automation project for enriching Indicators of Compromise (IOCs) using threat intelligence sources.

## Features

* Identifies IOC types:

  * IPv4 addresses
  * Domains
  * MD5 hashes
  * SHA-1 hashes
  * SHA-256 hashes
* Enriches IOCs using VirusTotal
* Enriches IP addresses using AbuseIPDB
* Extracts threat intelligence data
* Performs rule-based risk assessment
* Generates SOC-style investigation recommendations
* Handles API and network errors

## Threat Intelligence Sources

### VirusTotal

Used for:

* Reputation
* Malicious detections
* Suspicious detections
* Harmless detections
* Undetected results

### AbuseIPDB

Used for IP addresses:

* Abuse confidence score
* Total reports
* Country
* ISP

## Project Workflow

```text
IOC Input
   ↓
IOC Identification
   ↓
Threat Intelligence Enrichment
   ↓
Risk Assessment
   ↓
SOC Recommendation
```

## Technologies

* Python
* Requests
* python-dotenv
* VirusTotal API
* AbuseIPDB API

## Setup

1. Clone or download the project.

2. Create and activate a Python virtual environment.

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root and add your API keys:

```text
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

5. Run the project:

```bash
python main.py
```

## Security

API keys are stored in a `.env` file and should never be committed to GitHub.

The `.env` file is excluded through `.gitignore`.
