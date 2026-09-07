# 🛡️ AlphaShield AI — Multi-Engine Threat Detection & Telemetry Platform

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)
![PyQt5](https://img.shields.io/badge/GUI-PyQt5-41CD52)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)

AlphaShield AI is an enterprise-grade threat intelligence and security operations console designed to analyze, detect, and neutralize digital security threats in real-time. Powered by specialized Machine Learning models, Transformer networks, and Gemini 2.0 reasoning, AlphaShield AI provides coverage across web URLs, raw DOM payloads, email content, and structural PDF assets.

---

## ✨ Key Features & Architecture

* **🌐 Dynamic URL & DOM Inspector**: Combines structural entropy analysis, feature scoring, and active DOM inspection to spot phishing and credential theft vectors.
* **✉️ DistilBERT Neural Intent Engine**: Employs fine-tuned Transformer NLP models to analyze email text and detect spear-phishing intents with confidence metrics.
* **📄 Structural PDF ML Payload Scanner**: Utilizes a trained Random Forest model to inspect binary structures, streams, and embedded script hazards within PDF files.
* **🤖 Gemini 2.0 Deep Semantic Engine**: Multimodal fallback and deep analysis layer for complex payload reasoning and attack vector classification.
* **💻 Desktop SOC Security Console**: Built-in PyQt5 desktop application providing real-time telemetry graphs, scan counters, and interactive tool suites.
* **🧩 Chrome Security Extension**: Browser sidecar that continuously communicates with the local FastAPI engine to scan visited URLs on the fly.

---

## 🛠️ Project Structure

```text
AlphaShield-AI/
├── Backend/
│   ├── main.py                # FastAPI REST API Engine
│   ├── ai_suite.py            # ML & DistilBERT Transformer Pipeline
│   ├── gemini_engine.py       # Gemini 2.0 Integration & Fallback Logic
│   ├── database.py            # SQLite Telemetry & Audit Logs Manager
│   ├── alphashield_software.py# PyQt5 Desktop SOC Application
│   └── requirements.txt       # Python Dependencies
├── dashboard_3.py             # Streamlit Telemetry Web Console
├── Dockerfile                 # Backend Container Setup
├── docker-compose.yml         # Container Orchestration
└── manifest.json              # Chrome Extension Manifest
