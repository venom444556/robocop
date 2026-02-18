# Configuration Guide

This guide covers all configuration options for RoboCop (Reasoning-Orchestrated Bot for Cyber Operations Protection).

## Table of Contents

- [Environment Variables](#environment-variables)
- [API Keys Setup](#api-keys-setup)
- [Database Configuration](#database-configuration)
- [Storage Configuration](#storage-configuration)
- [Security Configuration](#security-configuration)
- [n8n Workflow Configuration](#n8n-workflow-configuration)

---

## Environment Variables

All configuration is done via environment variables. Create a `.env` file in the project root or set them in your environment.

### Core Settings

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `API_KEY` | `change-this-in-production` | **Yes** | Platform authentication key |
| `DEBUG` | `false` | No | Enable debug mode (never in production) |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:5173` | No | Allowed CORS origins (comma-separated) |

### Claude AI Settings

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `ANTHROPIC_API_KEY` | - | **Yes** | Your Anthropic API key |
| `CLAUDE_MODEL` | `claude-haiku-4-5-20241022` | No | Claude model to use |

**Recommended Models:**

| Model | Use Case | Cost |
|-------|----------|------|
| `claude-haiku-4-5-20241022` | Cost-effective, fast analysis | ~$0.25/$1.25 per MTok |
| `claude-sonnet-4-20250514` | Balanced performance | ~$3/$15 per MTok |
| `claude-opus-4-5-20251101` | Highest quality analysis | ~$15/$75 per MTok |

### Intelligence Enrichment APIs

| Variable | Default | Description |
|----------|---------|-------------|
| `VIRUSTOTAL_API_KEY` | - | VirusTotal API key (free: 4 req/min) |
| `VIRUSTOTAL_RATE_LIMIT` | `4` | Requests per minute |
| `SHODAN_API_KEY` | - | Shodan API key |
| `GOOGLE_SAFEBROWSING_API_KEY` | - | Google Safe Browsing API key |
| `IPQUALITYSCORE_API_KEY` | - | IPQualityScore API key |
| `CHECKPHISH_API_KEY` | - | CheckPhish API key |
| `URLHAUS_AUTH_KEY` | - | URLhaus authentication key |
| `NVD_API_KEY` | - | NVD/CVE vulnerability lookups (without key: 5 req/30s, with: 50 req/30s) |

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./malware_analysis.db` | Database connection string |

### Storage Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `UPLOAD_DIR` | `./uploads` | Directory for uploaded files |
| `MAX_FILE_SIZE` | `52428800` (50MB) | Maximum file upload size in bytes |
| `AWS_ACCESS_KEY_ID` | - | AWS access key (for S3 storage) |
| `AWS_SECRET_ACCESS_KEY` | - | AWS secret key |
| `AWS_REGION` | `us-east-1` | AWS region |
| `S3_BUCKET_NAME` | `robocop-artifacts` | S3 bucket name |

### n8n Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `N8N_WEBHOOK_BASE_URL` | `http://localhost:5678/webhook` | n8n webhook base URL |
| `N8N_USER` | `admin` | n8n basic auth username |
| `N8N_PASSWORD` | - | n8n basic auth password |
| `N8N_ENCRYPTION_KEY` | - | n8n encryption key |

### Report Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `REPORT_RETENTION_DAYS` | `30` | Days to retain reports |
| `DEFAULT_TLP_MARKING` | `TLP:AMBER` | Default TLP marking for reports (options: WHITE, GREEN, AMBER, RED) |

### MITRE ATT&CK Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_ATTACK_JSON_URL` | `https://raw.githubusercontent.com/.../enterprise-attack.json` | MITRE ATT&CK data source |
| `MITRE_ATTACK_CACHE_DIR` | `./data/mitre_cache` | Cache directory for ATT&CK data |

---

## API Keys Setup

### Anthropic Claude API (Required)

1. Go to [console.anthropic.com](https://console.anthropic.com/)
2. Create an account or sign in
3. Navigate to API Keys
4. Create a new API key
5. Add to `.env`:
   ```
   ANTHROPIC_API_KEY=sk-ant-api03-...
   ```

### VirusTotal (Recommended)

1. Go to [virustotal.com](https://www.virustotal.com/)
2. Create a free account
3. Go to your profile → API Key
4. Copy your API key
5. Add to `.env`:
   ```
   VIRUSTOTAL_API_KEY=your-api-key
   ```

**Rate Limits (Free Tier):**
- 4 requests per minute
- 500 requests per day
- 15,500 requests per month

### Shodan (Recommended)

1. Go to [account.shodan.io](https://account.shodan.io/)
2. Create a free account
3. Your API key is shown on the dashboard
4. Add to `.env`:
   ```
   SHODAN_API_KEY=your-api-key
   ```

### Google Safe Browsing

1. Go to [console.cloud.google.com](https://console.cloud.google.com/)
2. Create a project
3. Enable the Safe Browsing API
4. Create credentials → API Key
5. Add to `.env`:
   ```
   GOOGLE_SAFEBROWSING_API_KEY=your-api-key
   ```

**Rate Limits (Free):** 10,000 requests per day

### IPQualityScore

1. Go to [ipqualityscore.com](https://www.ipqualityscore.com/)
2. Create a free account
3. Get your API key from the dashboard
4. Add to `.env`:
   ```
   IPQUALITYSCORE_API_KEY=your-api-key
   ```

**Rate Limits (Free):** 5,000 lookups per month

---

## Database Configuration

### SQLite (Default - Development)

SQLite is the default database, suitable for development and small deployments.

```env
DATABASE_URL=sqlite+aiosqlite:///./malware_analysis.db
```

### PostgreSQL (Production)

For production deployments, use PostgreSQL:

```env
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/malware_analysis
```

**Docker Compose with PostgreSQL:**

```yaml
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_USER: malware
      POSTGRES_PASSWORD: secure_password
      POSTGRES_DB: malware_analysis
    volumes:
      - postgres_data:/var/lib/postgresql/data

  backend:
    environment:
      DATABASE_URL: postgresql+asyncpg://malware:secure_password@db:5432/malware_analysis
```

---

## Storage Configuration

### Local Storage (Default)

Files are stored in the `uploads` directory:

```env
UPLOAD_DIR=./uploads
MAX_FILE_SIZE=52428800
```

### AWS S3 Storage (Production)

For production, use S3 for artifact storage:

```env
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
S3_BUCKET_NAME=robocop-artifacts
```

**S3 Bucket Policy (recommended):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::robocop-artifacts",
        "arn:aws:s3:::robocop-artifacts/*"
      ]
    }
  ]
}
```

**S3 Lifecycle Policy (30-day retention):**

```json
{
  "Rules": [
    {
      "ID": "DeleteOldArtifacts",
      "Status": "Enabled",
      "Filter": {},
      "Expiration": {
        "Days": 30
      }
    }
  ]
}
```

---

## Security Configuration

### API Key Security

**Generate a secure API key:**

```bash
# Python
python -c "import secrets; print(secrets.token_urlsafe(32))"

# OpenSSL
openssl rand -hex 32
```

**Never use default keys in production!**

> **Note:** In production (`DEBUG=false`), the platform requires API keys of at least 32 characters and refuses to start with insecure default values.

### CORS Configuration

For production, specify exact origins:

```env
CORS_ORIGINS=https://your-domain.com,https://app.your-domain.com
```

### HTTPS (Production)

Always use HTTPS in production. Configure your reverse proxy (nginx, Traefik) to handle TLS.

---

## n8n Workflow Configuration

### Importing Workflows

1. Access n8n at http://localhost:5678
2. Log in with your credentials
3. Go to Settings → Import from File
4. Import workflows from `n8n/workflows/`:
   - `ingestion.json`
   - `analysis.json`
   - `enrichment.json`
   - `reasoning.json`
   - `reporting.json`

### Webhook Configuration

Each workflow uses webhooks. After importing:

1. Open each workflow
2. Click on the webhook node
3. Copy the webhook URL
4. The platform automatically uses these webhooks

### Connecting to Backend

In n8n, create credentials for the backend API:

1. Go to Settings → Credentials
2. Add "Header Auth" credential:
   - Name: `RoboCop API`
   - Header Name: `X-API-Key`
   - Header Value: Your `API_KEY` from `.env`

---

## Example Complete Configuration

```env
# ===========================================
# Core Configuration
# ===========================================
API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
DEBUG=false
CORS_ORIGINS=https://robocop.example.com

# ===========================================
# Claude AI
# ===========================================
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
CLAUDE_MODEL=claude-haiku-4-5-20241022

# ===========================================
# Intelligence APIs
# ===========================================
VIRUSTOTAL_API_KEY=xxxxx
SHODAN_API_KEY=xxxxx
GOOGLE_SAFEBROWSING_API_KEY=xxxxx

# ===========================================
# Database
# ===========================================
DATABASE_URL=postgresql+asyncpg://malware:password@db:5432/malware_analysis

# ===========================================
# Storage
# ===========================================
UPLOAD_DIR=/data/uploads
MAX_FILE_SIZE=52428800
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
S3_BUCKET_NAME=robocop-prod

# ===========================================
# n8n
# ===========================================
N8N_WEBHOOK_BASE_URL=http://n8n:5678/webhook
N8N_USER=admin
N8N_PASSWORD=secure_password_here
N8N_ENCRYPTION_KEY=random_32_char_string_here
```

---

## Next Steps

- [User Guide](USER_GUIDE.md) - Learn how to use the platform
- [API Reference](API.md) - Detailed API documentation
- [Deployment Guide](DEPLOYMENT.md) - Production deployment
