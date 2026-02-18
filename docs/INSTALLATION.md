# Installation Guide

This guide covers how to install and set up RoboCop (Reasoning-Orchestration Bot for Cyber Operations Protection) for development and production use.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Docker All-in-One (Recommended)](#docker-all-in-one-recommended)
- [Quick Start with Docker Compose](#quick-start-with-docker-compose)
- [Manual Installation](#manual-installation)
- [Verifying Installation](#verifying-installation)

---

## Prerequisites

### Required Software

| Software | Minimum Version | Purpose |
|----------|-----------------|---------|
| Docker | 20.10+ | Container runtime |
| Docker Compose | 2.0+ | Multi-container orchestration |
| Git | 2.30+ | Source code management |

### For Manual Installation (without Docker)

| Software | Minimum Version | Purpose |
|----------|-----------------|---------|
| Python | 3.11+ | Backend runtime |
| Node.js | 18+ | Frontend build |
| npm | 9+ | Package management |

### Required API Keys

| Service | Required | Purpose | Get Key |
|---------|----------|---------|---------|
| Anthropic Claude | **Yes** | AI analysis and reasoning | [console.anthropic.com](https://console.anthropic.com/) |

### Optional API Keys (for enrichment)

RoboCop integrates 13 threat intel sources — all free tier. **Each service requires its own free account** to get a personal API key (~2 min signup each). Sources marked * work with no signup at all.

| Service | Purpose | Get Key |
|---------|---------|---------|
| VirusTotal | Hash/URL/domain reputation | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| Shodan | IP intelligence | [account.shodan.io](https://account.shodan.io/) |
| Google Safe Browsing | Phishing detection | [console.cloud.google.com](https://console.cloud.google.com/) |
| IPQualityScore | IP/URL risk scoring | [ipqualityscore.com](https://www.ipqualityscore.com/) |
| CheckPhish | URL categorization | [checkphish.ai](https://checkphish.ai/) |
| URLhaus* | Malware URL database | [urlhaus-api.abuse.ch](https://urlhaus-api.abuse.ch/) |
| NVD* | CVE vulnerability data | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| GreyNoise | IP noise/threat classification | [viz.greynoise.io](https://viz.greynoise.io/signup) |
| AbuseIPDB | IP abuse reputation | [abuseipdb.com](https://www.abuseipdb.com/register) |
| urlscan.io | URL visual analysis | [urlscan.io](https://urlscan.io/user/signup) |
| AlienVault OTX | Community threat intelligence | [otx.alienvault.com](https://otx.alienvault.com/) |
| MalwareBazaar* | Malware sample lookups | [auth.abuse.ch](https://auth.abuse.ch/) |
| URL Unshortening* | Redirect chain expansion | No signup needed |

---

## Docker All-in-One (Recommended)

The fastest way to get RoboCop running — a single container with all services.

### Step 1: Clone and Configure

```bash
git clone https://github.com/venom444556/robocop.git
cd robocop
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY and a secure API_KEY (32+ chars)
```

### Step 2: Start

```bash
docker compose --profile allinone up -d allinone
```

### Step 3: Access

Open **http://localhost:3000** — you're done!

This runs PostgreSQL 16, FastAPI, n8n Community Edition, and Nginx in a single container via supervisord.

---

## Quick Start with Docker Compose

### Step 1: Clone the Repository

```bash
git clone https://github.com/venom444556/robocop.git
cd robocop
```

### Step 2: Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration
# At minimum, set these values:
#   - API_KEY (generate a secure random string)
#   - ANTHROPIC_API_KEY (your Claude API key)
```

**Generate a secure API key:**

```bash
# On Linux/macOS
openssl rand -hex 32

# On Windows PowerShell
[System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

### Step 3: Start Services

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### Step 4: Access the Platform

| Service | URL | Credentials |
|---------|-----|-------------|
| Web Dashboard | http://localhost:3000 | N/A |
| API | http://localhost:8000 | API key in header |
| API Docs | http://localhost:8000/docs | N/A |
| n8n Workflows | http://localhost:5678 | Set in .env |

---

## Manual Installation

### Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r ../requirements.txt

# Create uploads directory
mkdir -p uploads

# Run database migrations (creates SQLite DB)
python -c "import asyncio; from database import init_db; asyncio.run(init_db())"

# Start the backend server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

### n8n Setup (Optional)

```bash
# Install n8n globally
npm install -g n8n

# Start n8n
n8n start

# Or use Docker
docker run -d \
  --name n8n \
  -p 5678:5678 \
  -v n8n_data:/home/node/.n8n \
  n8nio/n8n
```

---

## Verifying Installation

### Check Backend Health

```bash
# Health check endpoint
curl http://localhost:8000/api/management/health

# Expected response:
# {"status": "healthy"}
```

### Check API Documentation

Open http://localhost:8000/docs in your browser to see the interactive Swagger UI.

### Test File Submission

```bash
# Submit a test file
curl -X POST "http://localhost:8000/api/submissions/file" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@test_script.ps1"

# Expected response:
# {"id": 1, "type": "file", "status": "pending", ...}
```

### Run Frontend Tests

```bash
cd frontend && npx vitest run
```

### Check Frontend

Open http://localhost:3000 in your browser. You should see the dashboard.

---

## Directory Structure After Installation

```
robocop/
├── backend/
│   ├── venv/              # Python virtual environment
│   ├── uploads/           # Uploaded files (created automatically)
│   ├── malware_analysis.db  # SQLite database
│   └── ...
├── frontend/
│   ├── node_modules/      # Node.js dependencies
│   └── ...
├── n8n_data/              # n8n workflow data (if using Docker)
├── .env                   # Your configuration
└── docker-compose.yml
```

---

## Next Steps

1. **Configure the platform**: See [CONFIGURATION.md](CONFIGURATION.md)
2. **Learn how to use it**: See [USER_GUIDE.md](USER_GUIDE.md)
3. **Explore the API**: See [API.md](API.md)
4. **Deploy to production**: See [DEPLOYMENT.md](DEPLOYMENT.md)
