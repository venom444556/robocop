# Architecture Guide

Technical architecture documentation for the Malware Analysis Platform.

## Table of Contents

- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Analysis Pipeline](#analysis-pipeline)
- [Database Schema](#database-schema)
- [Security Architecture](#security-architecture)
- [Integration Points](#integration-points)

---

## System Overview

The Malware Analysis Platform is a modular, microservices-inspired application designed for static malware analysis with AI-powered reasoning.

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
│ • Script Analyzer    │  │ • VirusTotal     │  │ • Reasoning Agent        │
│ • Script Decoder     │  │ • Shodan         │  │ • Enrichment Agent       │
│ • IOC Extractor      │  │ • URLhaus        │  │ • Report Writer Agent    │
│ • URL Analyzer       │  │ • Safe Browsing  │  │                          │
│ • Sandbox Parser     │  │ • IPQualityScore │  │                          │
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
│               SQLite/PostgreSQL (metadata) │ S3/Local (artifacts)           │
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
│   └── webhooks.py            # n8n integration webhooks
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
│   └── unshorten.py           # URL expansion
│
├── agents/                    # Claude AI agents
│   ├── reasoning.py           # MITRE ATT&CK mapping
│   ├── enrichment.py          # Intelligence correlation
│   └── report_writer.py       # Narrative generation
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
│   │   ├── Submit.tsx         # Submission forms
│   │   ├── Submissions.tsx    # Submission list
│   │   ├── SubmissionDetail.tsx  # Analysis results
│   │   └── Reports.tsx        # Report viewer
│   │
│   ├── components/            # Reusable components
│   │   ├── Layout.tsx         # App layout
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

```sql
-- Submissions
CREATE TABLE submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type VARCHAR(20) NOT NULL,  -- 'file', 'url', 'sandbox_report'
    filename VARCHAR(255),
    original_url TEXT,
    file_hash_sha256 VARCHAR(64),
    status VARCHAR(20) DEFAULT 'pending',
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);

-- Analysis Results
CREATE TABLE analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    analyzer VARCHAR(50) NOT NULL,
    results_json JSON NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

-- IOCs
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    type VARCHAR(20) NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);

-- Enrichment
CREATE TABLE enrichment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    source VARCHAR(50) NOT NULL,
    data_json JSON NOT NULL,
    queried_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id)
);

-- Reports
CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    format VARCHAR(10) NOT NULL,
    content TEXT NOT NULL,
    s3_key VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
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
