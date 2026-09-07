<<<<<<< HEAD
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
=======
# 🛡️ AlphaShield AI - Enterprise SOC Threat Detection Suite

A comprehensive AI-powered cybersecurity threat detection and analysis platform combining multiple threat detection engines (RandomForest ML, DistilBERT NLP, Gemini AI) for enterprise-grade security operations.

## 🎯 Features

### Multi-Engine Threat Detection
- **Gemini 3.6 Flash AI Engine** - Deep semantic threat analysis with brand impersonation detection
- **RandomForest ML Engine** - PDF structural analysis for malicious payload detection
- **DistilBERT NLP Engine** - Email intent analysis for phishing/social engineering detection
- **Entropy Analysis** - Malicious string and obfuscation detection

### Security Capabilities
- URL/Domain threat analysis (phishing, typosquatting, credential harvesting)
- PDF document malware detection
- Email spam/phishing classification
- Brand protection and impersonation detection
- Threat severity scoring (0-100%)
- Attack vector classification

### Multi-Interface Access
- **PyQt6 Desktop GUI** - Rich cyberpunk-themed SOC interface
- **Streamlit Web Dashboard** - Real-time threat telemetry and analytics
- **FastAPI REST API** - Programmatic threat scanning integration
- **Chrome Extension** - Real-time URL scanning from browser

## 📋 System Architecture

```
AlphaShield-AI/
├── Backend/
│   ├── main.py                 # FastAPI server
│   ├── alphashield_software.py # PyQt6 desktop GUI
│   ├── database.py             # SQLite database layer
│   ├── ai_suite.py             # ML/NLP threat engines
│   ├── gemini_engine.py        # Gemini AI integration
│   ├── extractor.py            # Text extraction utilities
│   └── requirements.txt        # Python dependencies
├── Extension/                  # Chrome extension (manifest v3)
│   ├── manifest.json
│   ├── content.js
│   ├── background.js
│   ├── Popup.html
│   └── Popup.js
├── dashboard.py                # Streamlit analytics dashboard
├── Dockerfile                  # Docker containerization
├── docker-compose.yml          # Multi-container orchestration
└── .env.example               # Environment configuration template
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Google Gemini API key (free tier available)
- pip or conda package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/AlphaShield-AI.git
   cd AlphaShield-AI
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # macOS/Linux
   ```

3. **Install dependencies**
   ```bash
   pip install -r Backend/requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env and add your Gemini API key
   # Get API key from: https://aistudio.google.com/apikey
   ```

### Running the Application

**Desktop GUI (PyQt6)**
```bash
python Backend/alphashield_software.py
```

**Web Dashboard (Streamlit)**
```bash
streamlit run dashboard.py
```

**REST API (FastAPI)**
```bash
python Backend/main.py
# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

**Docker Deployment**
```bash
docker-compose up --build
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file (copy from `.env.example`):

```env
# Required
GEMINI_API_KEY=your_api_key_here

# Optional
DATABASE_URL=sqlite:///alphashield.db
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO
```

### API Configuration

Get your free Gemini API key:
1. Visit https://aistudio.google.com/apikey
2. Click "Create API Key"
3. Select your Google Cloud project
4. Copy the API key to `.env` file

## 📊 API Endpoints

### FastAPI REST API

```bash
POST /api/scan/url
  Input: { url: string, html_content: string }
  Output: { risk_score: float, is_threat: bool, analysis: object }

POST /api/scan/pdf
  Input: { file: binary, filename: string }
  Output: { risk_score: float, is_threat: bool, analysis: object }

POST /api/scan/email
  Input: { email_text: string }
  Output: { risk_score: float, is_threat: bool, analysis: object }

POST /api/scan/gemini
  Input: { content: string, target_name: string }
  Output: { gemini_active: bool, risk_score: float, attack_vector: string }

GET /api/logs
  Output: Array of scan results with timestamps
```

### Response Format

```json
{
  "gemini_active": true,
  "risk_score": 95.0,
  "is_threat": true,
  "attack_vector": "Credential Harvesting / Phishing",
  "ai_reasoning": "The target domain uses potential financial brand impersonation...",
  "timestamp": "2026-09-07T10:30:00Z"
}
```

## 🎨 User Interfaces

### Desktop GUI Features
- **Cyberpunk-themed UI** with real-time threat gauge animation
- **Live Threat Intelligence Dashboard** with telemetry graphs
- **Radar Animation Widget** for scanning visualization
- **Color-coded Risk Indicators** (Green: Safe, Orange: Moderate, Red: Critical)
- **Multi-tab interface** for URL, PDF, Email, and Logs scanning

### Web Dashboard Features
- **Real-time telemetry** visualization with Plotly
- **Threat statistics** and risk metrics
- **PDF file upload** and analysis
- **Email text input** for spam/phishing detection
- **Gemini semantic** analysis panel
- **Audit log** export to CSV

## 🛡️ Security Best Practices

### Before Deployment
- ✓ Never commit `.env` file (use `.env.example`)
- ✓ Rotate API keys regularly
- ✓ Use HTTPS for production APIs
- ✓ Implement rate limiting
- ✓ Add authentication/authorization

### API Security
- Implement JWT or OAuth 2.0 authentication
- Use API keys with appropriate scopes
- Enable CORS restrictions
- Monitor for suspicious patterns
- Log all scan requests

## 📦 Dependencies

**Core Libraries:**
- `google-genai` - Gemini AI API
- `fastapi` - REST API framework
- `streamlit` - Web dashboard
- `PyQt6` - Desktop GUI
- `pydantic` - Data validation
- `transformers` - DistilBERT NLP model
- `scikit-learn` - RandomForest ML model
- `pandas`, `numpy` - Data processing
- `plotly` - Interactive visualizations
- `python-dotenv` - Environment configuration

See `Backend/requirements.txt` for complete list with versions.

## 🧪 Testing

```bash
# Test Gemini API connection
python -c "from Backend.gemini_engine import deep_scan_with_gemini; print(deep_scan_with_gemini('URL', '<html>test</html>', 'test.com'))"

# Test URL scanning
python -m Backend.main

# Test database
python -c "from Backend.database import get_db_connection; print(get_db_connection())"
```

## 🐛 Troubleshooting

### Gemini API Error: "Model not found"
- Update to latest `google-genai` package
- Verify API key is valid at https://aistudio.google.com/apikey
- Check `.env` file has correct key format

### PyQt6 Import Error
- Ensure PyQt6 is installed: `pip install PyQt6`
- On Linux, may need: `sudo apt-get install python3-pyqt6`

### Database Lock Error
- Ensure no other instances are running
- Delete `alphashield.db` to start fresh
- Check file permissions

### API Port Already in Use
- Change port in code or use: `python Backend/main.py --port 8001`

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

## ⚠️ Disclaimer

This tool is for authorized security testing and enterprise threat analysis only. Unauthorized access to computer systems is illegal. Users are responsible for compliance with all applicable laws and regulations.

## 📧 Support

For issues, questions, or suggestions:
- GitHub Issues: [Create an issue](https://github.com/yourusername/AlphaShield-AI/issues)
- Email: support@alphashield.dev

## 🙏 Acknowledgments

- Google Gemini API for AI threat analysis
- Hugging Face for transformer models
- Open source community for all libraries

---

**Made with ❤️ for Enterprise Cybersecurity**

*Last Updated: September 2026*
>>>>>>> b2802b2 (feat: initial release of AlphaShield AI platform)
