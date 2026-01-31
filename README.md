# Malware Analysis Platform

A static malware analysis platform using Claude AI for reasoning, intelligence enrichment, and report generation, orchestrated by n8n workflows.

## Features

- **File Analysis**: Upload scripts (PowerShell, JavaScript, VBScript, Batch, Python) for static analysis
- **URL Analysis**: Analyze URLs with automatic expansion, categorization, and script fetching
- **Sandbox Report Parsing**: Import reports from Any.Run, Joe Sandbox, or generic JSON
- **Script Decoding**: Automatic detection and decoding of obfuscated scripts
- **IOC Extraction**: Extract IPs, domains, URLs, hashes, emails, and more
- **Intelligence Enrichment**: VirusTotal, Shodan, URLhaus, Google Safe Browsing integration
- **Claude AI Reasoning**: MITRE ATT&CK mapping and threat assessment
- **Professional Reports**: Generate JSON, HTML, and PDF reports

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Anthropic API key (required for Claude AI features)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd malware-analysis-platform
```

2. Copy and configure environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys
```

3. Start the services:
```bash
docker-compose up -d
```

4. Access the platform:
- **Dashboard**: http://localhost:3000
- **API**: http://localhost:8000
- **n8n Workflows**: http://localhost:5678

## Development Setup

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r ../requirements.txt
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## API Endpoints

### Submissions

- `POST /api/submissions/file` - Upload a file for analysis
- `POST /api/submissions/url` - Submit a URL for analysis
- `POST /api/submissions/sandbox-report` - Upload a sandbox report
- `GET /api/submissions/` - List all submissions
- `GET /api/submissions/{id}` - Get submission details

### Analysis

- `GET /api/analysis/{id}/results` - Get analysis results
- `GET /api/analysis/{id}/status` - Get analysis status
- `POST /api/analysis/{id}/trigger` - Trigger analysis manually

### Reports

- `POST /api/reports/{id}/generate` - Generate a report
- `GET /api/reports/{id}/{format}` - Get report (json, html, pdf)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Web Dashboard (React)                          │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
┌─────────────────────────────────────────────────────────────────────────┐
│                              n8n Workflow Engine                         │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
┌──────────────┬──────────────┬──────────────┬───────────────────────────┐
│   Ingestion  │   Analysis   │  Enrichment  │      Claude Agents        │
│    Service   │   Engines    │   Service    │                           │
└──────────────┴──────────────┴──────────────┴───────────────────────────┘
                                      │
┌─────────────────────────────────────────────────────────────────────────┐
│                            Storage Layer                                 │
│              SQLite (metadata) │ S3 (artifacts - optional)              │
└─────────────────────────────────────────────────────────────────────────┘
```

## Configuration

All configuration is done via environment variables. See `.env.example` for available options.

### Required

- `API_KEY` - Platform authentication key
- `ANTHROPIC_API_KEY` - For Claude AI features

### Optional Enrichment APIs

- `VIRUSTOTAL_API_KEY` - VirusTotal lookups
- `SHODAN_API_KEY` - IP intelligence
- `URLHAUS_AUTH_KEY` - Malware URL database
- `GOOGLE_SAFEBROWSING_API_KEY` - Phishing detection
- `CHECKPHISH_API_KEY` - URL categorization
- `IPQUALITYSCORE_API_KEY` - URL risk scoring

## Documentation

Comprehensive documentation is available in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/INSTALLATION.md) | Setup and installation instructions |
| [Configuration Guide](docs/CONFIGURATION.md) | Environment variables and API keys |
| [User Guide](docs/USER_GUIDE.md) | How to use the platform |
| [API Reference](docs/API.md) | Complete API documentation |
| [Architecture](docs/ARCHITECTURE.md) | Technical architecture overview |
| [Deployment Guide](docs/DEPLOYMENT.md) | Production deployment |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |

## Security

This platform handles potentially malicious files. Please ensure:

- Run in isolated environments (Docker, VMs)
- Never execute uploaded samples on production systems
- Use strong, unique API keys
- Enable HTTPS in production
- Regularly update dependencies

Report security issues responsibly.

## License

MIT License
