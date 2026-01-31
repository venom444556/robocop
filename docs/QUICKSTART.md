# Quick Start Guide

Get the Malware Analysis Platform running in 5 minutes.

## Prerequisites

- Docker and Docker Compose installed
- An Anthropic API key ([get one here](https://console.anthropic.com/))

## Step 1: Clone and Configure

```bash
# Clone the repository
git clone <repository-url>
cd malware-analysis-platform

# Copy environment file
cp .env.example .env

# Edit .env and add your API key
# Required: ANTHROPIC_API_KEY=sk-ant-api03-...
# Required: API_KEY=<generate-a-random-string>
```

**Generate a secure API key:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Step 2: Start the Platform

```bash
docker-compose up -d
```

Wait about 30 seconds for all services to initialize.

## Step 3: Access the Platform

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API Docs | http://localhost:8000/docs |
| n8n Workflows | http://localhost:5678 |

## Step 4: Submit Your First Sample

### Via Dashboard

1. Open http://localhost:3000
2. Click "Submit"
3. Upload a suspicious file or paste a URL
4. Watch the analysis progress

### Via API

```bash
# Submit a file
curl -X POST http://localhost:8000/api/submissions/file \
  -F "file=@suspicious_script.ps1"

# Submit a URL
curl -X POST http://localhost:8000/api/submissions/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com"}'
```

## Step 5: View Results

```bash
# Check status
curl http://localhost:8000/api/analysis/1/status

# Get full results
curl http://localhost:8000/api/analysis/1/results
```

## What Happens During Analysis

```
1. File uploaded → validated and stored
2. Static analysis → behaviors detected, IOCs extracted
3. Enrichment → VirusTotal, Shodan lookups (if configured)
4. AI Reasoning → Claude analyzes and maps to MITRE ATT&CK
5. Report generated → JSON, HTML, or PDF
```

## Next Steps

- **Add enrichment APIs**: [Configuration Guide](CONFIGURATION.md#api-keys-setup)
- **Learn the features**: [User Guide](USER_GUIDE.md)
- **Automate with API**: [API Reference](API.md)
- **Deploy to production**: [Deployment Guide](DEPLOYMENT.md)

## Troubleshooting

**Platform not starting?**
```bash
docker-compose logs
```

**Analysis stuck?**
Check n8n workflows are active at http://localhost:5678

**More help:** [Troubleshooting Guide](TROUBLESHOOTING.md)
