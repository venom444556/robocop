# Architecture Guide

Technical architecture documentation for RoboCop (Reasoning-Orchestration Bot for Cyber Operations Protection).

## Table of Contents

- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Analysis Pipeline](#analysis-pipeline)
- [Database Schema](#database-schema)
- [Security Architecture](#security-architecture)
- [Integration Points](#integration-points)
- [Docker All-in-One Architecture](#docker-all-in-one-architecture)
- [Scalability Considerations](#scalability-considerations)

---

## System Overview

RoboCop is a modular, microservices-inspired application designed for static malware analysis with AI-powered reasoning.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Web Dashboard                                   │
│                         (React + TailwindCSS)                               │
│                    Submissions | Reports | Search                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            API Gateway (FastAPI)                             │
│                     Authentication | Rate Limiting | Routing                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
┌──────────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐
│   Analysis Engine    │  │  Enrichment Svc  │  │    Claude AI Agents      │
│                      │  │                  │  │                          │
│ • Script Analyzer    │  │ • VirusTotal     │  │ • Base Agent (shared)    │
│ • Script Decoder     │  │ • Shodan         │  │ • Enrichment Agent       │
│ • IOC Extractor      │  │ • URLhaus        │  │ • Investigation Agent    │
│ • URL Analyzer       │  │ • Safe Browsing  │  │ • Reasoning Agent        │
│ • Sandbox Parser     │  │ • IPQualityScore │  │ • Report Writer Agent    │
│                      │  │ • CheckPhish     │  │ • Threat Hunt Agent      │
│                      │  │ • NVD            │  │                          │
└──────────────────────┘  └──────────────────┘  └──────────────────────────┘
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              n8n Workflow Engine                             │
│            Ingestion → Analysis → Enrichment → Reasoning → Reporting         │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Storage Layer                                   │
│               PostgreSQL 16 (metadata) │ S3/Local (artifacts)              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### Backend (Python FastAPI)

```
backend/
├── main.py                    # Application entry point
├── config.py                  # Configuration management
├── database.py                # SQLAlchemy models and DB setup
│
├── api/                       # REST API endpoints
│   ├── submissions.py         # File/URL/sandbox submission
│   ├── analysis.py            # Analysis triggers and results
│   ├── reports.py             # Report generation
│   ├── webhooks.py            # n8n integration webhooks
│   ├── dashboard.py           # SOC dashboard stats & metrics
│   ├── search.py              # Full-text search across submissions/IOCs
│   ├── yara_rules.py          # YARA rule CRUD and scanning
│   └── management.py          # System management & health checks
│
├── analyzers/                 # Static analysis engines
│   ├── script_analyzer.py     # Behavior detection, MITRE mapping
│   ├── script_decoder.py      # Encoding/obfuscation decoder
│   ├── ioc_extractor.py       # IOC pattern extraction
│   ├── url_analyzer.py        # URL expansion and analysis
│   └── sandbox_parser.py      # Sandbox report parsing
│
├── enrichment/                # External intelligence
│   ├── virustotal.py          # VirusTotal API client
│   ├── shodan.py              # Shodan API client
│   ├── urlhaus.py             # URLhaus lookups
│   ├── google_safebrowsing.py # Safe Browsing API
│   ├── ipqualityscore.py      # URL risk scoring
│   ├── checkphish.py          # Phishing detection
│   ├── nvd.py                 # NVD CVE vulnerability lookups
│   └── unshorten.py           # URL expansion
│
├── agents/                    # Claude AI agents
│   ├── base.py               # Shared base agent (prompts, API calls)
│   ├── enrichment.py         # Intelligence correlation
│   ├── investigation.py      # DFIR investigation planning
│   ├── reasoning.py          # MITRE ATT&CK mapping & severity
│   ├── report_writer.py      # Narrative generation
│   └── threat_hunter.py      # Threat hunt findings
│
└── utils/                     # Utility modules
    ├── file_handler.py        # File operations, S3
    └── report_generator.py    # JSON/HTML/PDF generation
```

### Frontend (React)

```
frontend/
├── src/
│   ├── pages/                 # Page components
│   │   ├── Dashboard.tsx      # Main dashboard
│   │   ├── DashboardPage.jsx  # SOC analyst dashboard
│   │   ├── Submit.tsx         # Submission forms
│   │   ├── Submissions.tsx    # Submission list
│   │   ├── SubmissionDetail.tsx  # Analysis results
│   │   ├── Reports.tsx        # Report viewer
│   │   ├── SearchPage.jsx     # Full-text search interface
│   │   └── YaraRulesPage.jsx  # YARA rule management
│   │
│   ├── components/            # Reusable components
│   │   ├── Layout.tsx         # App layout
│   │   ├── ErrorBoundary.jsx  # React error boundary wrapper
│   │   ├── ToastProvider.jsx  # Toast notification context
│   │   ├── SeverityBadge.jsx  # Color-coded severity indicator
│   │   ├── Skeleton/          # Skeleton loaders for loading states
│   │   ├── FileUpload.tsx     # File upload widget
│   │   ├── IOCTable.tsx       # IOC display table
│   │   └── MitreMatrix.tsx    # ATT&CK visualization
│   │
│   ├── api/                   # API client
│   │   └── client.ts          # Axios/fetch wrapper
│   │
│   └── App.tsx                # Root component
```

### n8n Workflows

```
n8n/workflows/
├── ingestion.json             # Receive and validate submissions
├── analysis.json              # Orchestrate static analysis
├── enrichment.json            # IOC enrichment pipeline
├── reasoning.json             # Claude AI analysis
└── reporting.json             # Report generation
```

---

## Data Flow

### Submission Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │────▶│   API    │────▶│ Database │────▶│ n8n Hook │
│          │     │          │     │          │     │          │
│ Upload   │     │ Validate │     │ Store    │     │ Trigger  │
│ File/URL │     │ & Save   │     │ Metadata │     │ Workflow │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
```

### Analysis Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           n8n Workflow                                   │
└─────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    Decode    │────▶│   Analyze    │────▶│   Extract    │
│    Scripts   │     │   Behavior   │     │    IOCs      │
└──────────────┘     └──────────────┘     └──────────────┘
         │                   │                    │
         └───────────────────┼────────────────────┘
                             ▼
                    ┌──────────────┐
                    │    Enrich    │
                    │     IOCs     │
                    └──────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  VirusTotal  │     │    Shodan    │     │   URLhaus    │
└──────────────┘     └──────────────┘     └──────────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             ▼
                    ┌──────────────┐
                    │  Claude AI   │
                    │  Reasoning   │
                    └──────────────┘
                             │
                             ▼
                    ┌──────────────┐
                    │   Generate   │
                    │    Report    │
                    └──────────────┘
```

---

## Analysis Pipeline

### Stage 1: Ingestion

```python
# submissions.py
@router.post("/file")
async def submit_file(file: UploadFile):
    # 1. Validate file type
    # 2. Sanitize filename
    # 3. Calculate hash
    # 4. Save to disk
    # 5. Create DB record
    # 6. Trigger n8n workflow
```

### Stage 2: Static Analysis

| Analyzer | Input | Output |
|----------|-------|--------|
| Script Decoder | Raw script | Decoded content, encoding chain |
| Script Analyzer | Script content | Behaviors, risk level, MITRE techniques |
| IOC Extractor | Any text | IPs, domains, URLs, hashes, emails |
| URL Analyzer | URL | Redirect chain, content type, fetched script |
| Sandbox Parser | JSON report | Normalized behaviors, IOCs |

### Stage 3: Enrichment

```
For each IOC:
  ├── IP → Shodan, VirusTotal
  ├── Domain → VirusTotal, Shodan DNS
  ├── URL → VirusTotal, Safe Browsing, URLhaus
  ├── Hash → VirusTotal
  └── All → Store enrichment data
```

### Stage 4: AI Reasoning

```python
# reasoning.py
class ReasoningAgent:
    async def analyze_script(self, content, analysis_results):
        # 1. Build prompt with script + analysis
        # 2. Call Claude API
        # 3. Parse MITRE mappings
        # 4. Extract severity assessment
        # 5. Generate recommendations
```

### Stage 5: Report Generation

```python
# report_generator.py
class ReportGenerator:
    def generate(self, format, submission, analysis, iocs, enrichment, narrative):
        if format == "json":
            return self._generate_json(...)
        elif format == "html":
            return self._generate_html(...)  # Jinja2 template
        elif format == "pdf":
            return self._generate_pdf(...)   # WeasyPrint
```

---

## Database Schema

### Entity Relationship Diagram

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│   Submissions   │       │AnalysisResults  │       │      IOCs       │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id (PK)         │──┐    │ id (PK)         │       │ id (PK)         │
│ type            │  │    │ submission_id(FK)│◀──────│ submission_id(FK│
│ filename        │  │    │ analyzer        │       │ type            │
│ original_url    │  └───▶│ results_json    │       │ value           │
│ file_hash_sha256│       │ created_at      │       │ context         │
│ status          │       └─────────────────┘       │ created_at      │
│ error_message   │                                 └────────┬────────┘
│ created_at      │                                          │
│ completed_at    │                                          │
└─────────────────┘                                          │
         │                                                   ▼
         │                                          ┌─────────────────┐
         │                                          │   Enrichment    │
         │                                          ├─────────────────┤
         ▼                                          │ id (PK)         │
┌─────────────────┐                                 │ ioc_id (FK)     │
│     Reports     │                                 │ source          │
├─────────────────┤                                 │ data_json       │
│ id (PK)         │                                 │ queried_at      │
│ submission_id(FK)│                                └─────────────────┘
│ format          │
│ content         │
│ s3_key          │
│ created_at      │
└─────────────────┘
```

### Table Definitions

Primary database: **PostgreSQL 16** (SQLite supported for local development only).

```sql
-- Submissions (PostgreSQL 16)
CREATE TABLE submissions (
    id SERIAL PRIMARY KEY,
    type VARCHAR(20) NOT NULL,  -- 'file', 'url', 'sandbox_report'
    filename VARCHAR(255),
    original_url TEXT,
    file_hash_sha256 VARCHAR(64),
    status VARCHAR(20) DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Analysis Results
CREATE TABLE analysis_results (
    id SERIAL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions(id),
    analyzer VARCHAR(50) NOT NULL,
    results_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- IOCs
CREATE TABLE iocs (
    id SERIAL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions(id),
    type VARCHAR(20) NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enrichment
CREATE TABLE enrichment (
    id SERIAL PRIMARY KEY,
    ioc_id INTEGER NOT NULL REFERENCES iocs(id),
    source VARCHAR(50) NOT NULL,
    data_json JSONB NOT NULL,
    queried_at TIMESTAMPTZ DEFAULT NOW()
);

-- Reports
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions(id),
    format VARCHAR(10) NOT NULL,
    content TEXT NOT NULL,
    s3_key VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## Security Architecture

### Authentication & Authorization

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Client    │─────▶│  API Key    │─────▶│  Endpoint   │
│             │      │  Verify     │      │             │
└─────────────┘      └─────────────┘      └─────────────┘
                            │
                            ▼
                     ┌─────────────┐
                     │   Timing-   │
                     │    Safe     │
                     │  Compare    │
                     └─────────────┘
```

### Input Validation

| Layer | Validation |
|-------|------------|
| File Upload | Extension whitelist, size limit, filename sanitization |
| URL Submission | URL parsing, SSRF protection, internal IP blocking |
| Webhook Data | Schema validation, IOC type validation |
| Report Gen | HTML auto-escaping (XSS prevention) |

### SSRF Protection

```python
BLOCKED_IP_RANGES = [
    '10.0.0.0/8',      # Private
    '172.16.0.0/12',   # Private
    '192.168.0.0/16',  # Private
    '127.0.0.0/8',     # Loopback
    '169.254.0.0/16',  # Link-local
]

def is_safe_url(url):
    # Block internal IPs
    # Block non-HTTP schemes
    # Validate on redirects
```

### Data Protection

```
┌─────────────────────────────────────────────────────────────┐
│                    Data Classification                       │
├───────────────────┬─────────────────────────────────────────┤
│ Submitted Files   │ Potentially malicious - isolated storage │
│ API Keys          │ Environment variables only               │
│ Analysis Results  │ Database with access controls            │
│ Reports           │ User-accessible, XSS-sanitized           │
└───────────────────┴─────────────────────────────────────────┘
```

---

## Integration Points

### n8n Webhook Integration

```
Backend ──POST /api/webhooks/analysis-trigger──▶ n8n
n8n ──POST /api/webhooks/analysis-complete──▶ Backend
n8n ──POST /api/webhooks/enrichment-complete──▶ Backend
n8n ──POST /api/webhooks/status-update──▶ Backend
n8n ──GET /api/webhooks/submission/{id}/data──▶ Backend
```

### External API Integration

```
┌─────────────────────────────────────────────────────────────┐
│                    Rate Limiting Strategy                    │
├─────────────────────┬───────────────────────────────────────┤
│ VirusTotal          │ 4 req/min - Queue with delays         │
│ Shodan              │ No strict limit - Standard throttling  │
│ Claude API          │ Token-based - Monitor usage            │
│ URLhaus             │ Fair use - Standard throttling         │
│ Safe Browsing       │ 10K/day - Request batching             │
│ CheckPhish          │ Rate-limited - Async polling           │
│ NVD                 │ 5 req/30s - Request queuing            │
└─────────────────────┴───────────────────────────────────────┘
```

### Output Formats

```
Platform ──▶ JSON Report ──▶ SIEM Integration
         ──▶ STIX 2.1   ──▶ Threat Intel Platform
         ──▶ MISP Event ──▶ MISP Instance
         ──▶ CSV IOCs   ──▶ Firewall/EDR
         ──▶ HTML/PDF   ──▶ Human Review
```

### WebSocket Real-Time Updates

The platform supports real-time updates via WebSocket connections. The backend uses FastAPI's built-in WebSocket support to push live analysis progress, enrichment results, and status changes to connected clients.

```
┌─────────────┐     WebSocket (ws://)     ┌──────────────┐
│   Browser    │◀────────────────────────▶│   FastAPI     │
│   Client     │     30s heartbeat ping    │   Backend     │
└─────────────┘                            └──────────────┘
```

- **Heartbeat interval**: 30 seconds (client sends ping, server responds with pong)
- **Events pushed**: `analysis_started`, `enrichment_complete`, `report_ready`, `status_changed`
- **Reconnection**: Clients auto-reconnect with exponential backoff on disconnect

---

## Docker All-in-One Architecture

For simplified deployment, the platform provides a single Docker image (`robocop-allinone`) that bundles all services using **supervisord** to manage 4 processes:

```
┌──────────────────────────────────────────────────────────────┐
│                   robocop-allinone container                  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │                   supervisord (PID 1)                 │    │
│  └───────┬──────────┬──────────┬──────────┬─────────────┘    │
│          │          │          │          │                   │
│          ▼          ▼          ▼          ▼                   │
│  ┌───────────┐ ┌─────────┐ ┌─────────┐ ┌──────────────┐    │
│  │  FastAPI   │ │ React   │ │ Postgres│ │     n8n      │    │
│  │  Backend   │ │ (nginx) │ │   16    │ │  Workflows   │    │
│  │  :8000     │ │  :80    │ │ :5432   │ │   :5678      │    │
│  └───────────┘ └─────────┘ └─────────┘ └──────────────┘    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

- **Process 1**: FastAPI backend (uvicorn) on port 8000
- **Process 2**: React frontend served by nginx on port 80
- **Process 3**: PostgreSQL 16 database on port 5432
- **Process 4**: n8n workflow engine on port 5678
- **Health checks**: supervisord monitors all 4 processes and restarts on failure

---

## Scalability Considerations

### Horizontal Scaling

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    └────────┬────────┘
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │  Backend 1  │   │  Backend 2  │   │  Backend 3  │
    └─────────────┘   └─────────────┘   └─────────────┘
           │                 │                 │
           └─────────────────┼─────────────────┘
                             ▼
                    ┌─────────────────┐
                    │   PostgreSQL    │
                    │   (shared DB)   │
                    └─────────────────┘
```

### Queue-Based Processing

```
For high-volume deployments:

Submission ──▶ Redis Queue ──▶ Worker Pool ──▶ Results
                    │
                    └──▶ Celery / RQ workers
```

---

## Next Steps

- [Deployment Guide](DEPLOYMENT.md) - Production setup
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues
- [API Reference](API.md) - Detailed API docs
