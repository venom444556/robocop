# RoboCop

**Reasoning-Orchestrated Bot for Cyber Operations Protection**

AI-powered malware analysis platform with multi-agent reasoning, threat intelligence enrichment, and SOC analyst workflows.

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![React 18](https://img.shields.io/badge/react-18-61dafb.svg)](https://reactjs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## What Is RoboCop?

RoboCop is a static malware analysis platform that combines **6 Claude AI agents**, **8 threat intelligence sources**, and **automated n8n workflows** to analyze suspicious files and URLs, extract indicators of compromise, and generate professional investigation reports.

Submit a file or URL. RoboCop's agents analyze the content, enrich IOCs against threat intel feeds, map behaviors to MITRE ATT&CK, generate investigation plans, and produce a detailed report -- all automatically.

### Key Features

**AI-Powered Analysis**
- 6 specialized Claude AI agents working in concert: Enrichment, Investigation, Reasoning, Report Writer, Threat Hunter, and a shared Base agent
- MITRE ATT&CK technique mapping validated against the official framework (prevents LLM hallucination)
- Threat severity assessment with confidence scoring
- DFIR investigation plans with prioritized containment/eradication steps

**Threat Intelligence Enrichment**
- VirusTotal (file/URL reputation and detection counts)
- Shodan (IP intelligence and port data)
- URLhaus (malware URL database)
- Google Safe Browsing (phishing/malware site detection)
- CheckPhish (URL categorization)
- IPQualityScore (URL risk scoring)
- NVD (CVE vulnerability lookups)
- URL unshortening (redirect chain analysis)

**SOC Analyst Dashboard**
- Real-time submission metrics and completion rates
- 7-day submission trend charts
- MITRE ATT&CK heatmap by tactic
- Severity distribution overview
- Recent submissions with one-click access

**Static Analysis Engines**
- Script analysis for PowerShell, JavaScript, VBScript, Batch, and Python
- Automatic script decoding (Base64, URL encoding, hex, ROT13, PowerShell obfuscation)
- IOC extraction (IPs, domains, URLs, hashes, emails, registry keys, file paths, mutexes)
- Sandbox report parsing (Any.Run, Joe Sandbox, generic JSON)

**IOC Search & Correlation**
- Cross-submission IOC search with type filtering
- IOC correlation to identify related campaigns
- Side-by-side submission comparison
- Paginated results (25 per page)

**YARA Rule Management**
- Create, edit, delete, and toggle YARA rules
- Categories: Malware, Ransomware, Exploit, APT, Custom
- Search and filter rules
- Scan submissions against rules

**Professional Reports**
- JSON, HTML, and PDF output formats
- TLP marking support (WHITE, GREEN, AMBER, RED)
- Executive summary, technical analysis, threat hunt findings
- IOC tables, MITRE mappings, CVE intelligence
- Investigation plans with prioritized response actions
- [View a sample report](docs/sample-report-mockup.html)

**Workflow Orchestration**
- 5 n8n workflows: Ingestion, Analysis, Enrichment, Reasoning, Reporting
- Webhook-driven pipeline automation
- n8n Community Edition (free, Sustainable Use License)

**Frontend Resilience**
- Error boundaries with error IDs for SOC correlation
- Toast notifications (error, success, warning, info)
- Skeleton loaders for smooth loading states
- Accessible severity badges (icon + text + color)
- Debounced search with pagination
- Real-time WebSocket updates with 30s heartbeat
- Dark mode support

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Anthropic API key ([get one here](https://console.anthropic.com/))

### One-Click Deploy (Recommended)

```bash
git clone https://github.com/venom444556/robocop.git
cd robocop
cp .env.example .env
# Edit .env -- set ANTHROPIC_API_KEY and a secure API_KEY (32+ chars)
docker compose --profile allinone up -d allinone
```

Access at **http://localhost:3000**

This runs PostgreSQL, FastAPI, n8n, and Nginx in a single container via supervisord.

### Multi-Service Deploy

```bash
docker compose up -d
```

Access points:
- **Dashboard**: http://localhost:3000
- **API**: http://localhost:8000/docs
- **n8n Workflows**: http://localhost:5678

---

## Architecture

```
                          +---------------------------+
                          |     React SPA (Vite)      |
                          |  Dashboard / Search / YARA |
                          +-------------+-------------+
                                        |
                          +-------------v-------------+
                          |     Nginx Reverse Proxy    |
                          +--+------+------+------+---+
                             |      |      |      |
                    /api/    | /ws/  | /webhook/  | /n8n/
                             |      |      |      |
                    +--------v--+   |   +--v------v---+
                    |  FastAPI   |   |   |    n8n CE   |
                    |  Backend   <---+   |  5 Workflows|
                    +-----+------+       +------+------+
                          |                     |
            +-------------+-------------+       |
            |             |             |       |
      +-----v----+ +-----v----+ +-----v----+  |
      |Enrichment| |Reasoning | |  Report   |  |
      |  Agent   | |  Agent   | |  Writer   |  |
      +----------+ +----------+ +----------+  |
      +-----v----+ +-----v----+ +-----v----+  |
      |  Threat  | |Investig- | |   Base    |  |
      |  Hunter  | |  ation   | |  Agent    |  |
      +----------+ +----------+ +----------+  |
            |             |             |       |
      +-----v-------------v-------------v------v---+
      |              PostgreSQL 16                   |
      +---+---+---+---+---+---+---+---+---+--------+
          |   |   |   |   |   |   |   |
         VT Shodan URLh GSB  CP  IPQS NVD  Unshorten
      (8 Threat Intelligence Integrations)
```

---

## API Overview

| Endpoint Group | Description |
|----------------|-------------|
| `POST /api/submissions/file\|url\|sandbox-report` | Submit samples for analysis |
| `GET /api/analysis/{id}/results\|status\|mitre-validation` | Retrieve analysis results |
| `GET /api/dashboard/stats` | Dashboard metrics, trends, MITRE heatmap |
| `GET /api/search/iocs?q=...&type=...` | IOC search and correlation |
| `GET\|POST\|PUT\|DELETE /api/yara-rules/` | YARA rule management |
| `POST /api/reports/{id}/generate` | Generate JSON/HTML/PDF reports |
| `GET /api/management/health` | Health check and uptime |
| `WS /ws` | Real-time status updates |

Full API documentation: [docs/API.md](docs/API.md)

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and set:

| Variable | Required | Description |
|----------|----------|-------------|
| `API_KEY` | Yes | Platform auth key (32+ chars in production) |
| `ANTHROPIC_API_KEY` | Yes | Claude AI API key |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal file/URL reputation |
| `SHODAN_API_KEY` | No | IP intelligence |
| `URLHAUS_AUTH_KEY` | No | Malware URL database |
| `GOOGLE_SAFEBROWSING_API_KEY` | No | Phishing detection |
| `CHECKPHISH_API_KEY` | No | URL categorization |
| `IPQUALITYSCORE_API_KEY` | No | URL risk scoring |
| `NVD_API_KEY` | No | CVE lookups |

Full configuration guide: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI, SQLAlchemy, asyncpg, Anthropic Claude SDK, WeasyPrint |
| **Frontend** | React 18, Vite, TanStack React Query, Tailwind CSS, Lucide Icons |
| **Orchestration** | n8n Community Edition 1.76.1 |
| **Database** | PostgreSQL 16 |
| **Testing** | Pytest + pytest-asyncio (backend), Vitest + Testing Library (frontend) |
| **Deployment** | Docker, supervisord, Nginx |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | 5-minute setup guide |
| [Installation](docs/INSTALLATION.md) | Full installation instructions |
| [Configuration](docs/CONFIGURATION.md) | Environment variables and API keys |
| [User Guide](docs/USER_GUIDE.md) | How to use the platform |
| [API Reference](docs/API.md) | Complete REST and WebSocket API docs |
| [Architecture](docs/ARCHITECTURE.md) | System design and component overview |
| [Deployment](docs/DEPLOYMENT.md) | Production deployment guide |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Sample Report](docs/sample-report-mockup.html) | Example analysis report output |

---

## Development

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r ../requirements.txt
pip install -r ../requirements-dev.txt
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev       # Development server
npm run build     # Production build
npx vitest run    # Run tests
```

### Running Tests

```bash
# Backend tests
cd backend && pytest

# Frontend tests (16 tests: client, ErrorBoundary, ToastProvider)
cd frontend && npx vitest run
```

---

## Security

RoboCop handles potentially malicious files. Follow these practices:

- Run in isolated environments (Docker containers, VMs)
- Never execute uploaded samples on production systems
- Use strong, unique API keys (enforced: 32+ chars in production mode)
- Enable HTTPS in production via reverse proxy
- API authentication via `X-API-Key` header with timing-safe comparison
- Rate limiting (120 req/min with burst allowance)
- Request logging with unique request IDs
- CORS restricted to configured origins
- SSRF protection on URL analysis

---

## License

MIT License
