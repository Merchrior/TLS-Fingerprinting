# AI-Driven TLS Fingerprinting: Autonomous Characterization and Verification Framework

A privacy-preserving TLS/SSL traffic analysis platform that identifies applications from encrypted network flows **without decrypting payloads**.

The system focuses on **TLS ClientHello metadata** extraction, **JA3 fingerprint generation**, real-time monitoring, whitelist-based fast matching, and candidate-based analysis for unknown fingerprints.

---

## Project Objective

Modern networks increasingly rely on encrypted traffic, which creates a **visibility gap** for network monitoring and application identification.

This project addresses that problem by:

- capturing TLS traffic
- extracting only **ClientHello metadata**
- generating **JA3 fingerprints**
- identifying known applications using a **local SQLite whitelist**
- tracking unknown signatures as **candidates**
- providing an operational dashboard for monitoring captures, PCAP processing, fingerprints, and system activity

No payload decryption is performed, which helps preserve privacy.

---

## Core Features

- **Privacy-preserving TLS analysis**
- **JA3 fingerprint extraction**
- **Whitelist-first decision engine**
- **Candidate tracking for unknown fingerprints**
- **Live PCAP monitoring**
- **PCAP Explorer**
- **System Console / operational logs**
- **Settings-based interface selection**
- **Dockerized dashboard/backend**
- **Host-side TShark capture agent (Windows-friendly hybrid architecture)**

---

## High-Level Architecture

### Host Side
- `TShark` performs live packet capture
- ring-buffer `.pcapng` files are written into `data/captures`
- `host_capture_agent.py` manages capture lifecycle and interface synchronization

### Docker App Side
- backend watches `data/captures`
- extractor parses TLS ClientHello metadata
- JA3 hash and JA3 string are generated
- predictor checks whitelist / candidates
- results are stored in SQLite
- Streamlit dashboard visualizes operational and analytical data

---

## Why Hybrid Instead of Full Docker Capture?

On Windows, fully containerized live packet sniffing is not always reliable because host network interface access behaves differently under Docker Desktop.

For that reason, this project uses a **hybrid deployment model**:

- **Docker** for the application platform
- **host machine** for live packet capture

This gives a more stable and practical setup for development and demonstration.

---

## Technology Stack

- **Python**
- **TShark**
- **SQLite**
- **Streamlit**
- **Plotly**
- **Docker / Docker Compose**

---

## Project Structure

```text
app/
├── main.py
├── models/
│   └── predictor.py
├── processing/
│   └── extractor.py
├── ui/
│   ├── dashboard.py
│   └── style.css
└── utils/
    └── db_handler.py

data/
├── captures/
├── processed/
└── runtime/

host_capture_agent.py
Dockerfile
docker-compose.yml
requirements.txt
README.md
```

## Functional Modules
### 1. Capture Layer
●Host-side TShark

● ring-buffer capture

● configurable interface, filter, duration, and file count
### 2. Extraction Layer
● reads .pcap/.pcapng files

● extracts TLS ClientHello metadata

● generates:

● ja3_string

● ja3_hash

### 3. Decision Layer
● Fast Path: check JA3 in whitelist

● Unknown Path: classify as candidate / unknown using heuristic logic

● candidate records are stored for future enrichment

### 4. Storage Layer

●SQLite stores:

● TLS events

● whitelist entries

● candidate entries

● PCAP processing states

● app logs

configuration values

### 5. Dashboard Layer

● The dashboard includes:

● Overview

● Live Monitor

● PCAP Explorer

● Fingerprint Intelligence

● Whitelist

● Candidates

● System Console

● Settings

● Requirements

● On Host Machine

● Python 3.11+ recommended

● Wireshark / TShark installed

● Docker Desktop installed
