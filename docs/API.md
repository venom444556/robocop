# API Reference

Complete API documentation for RoboCop (Reasoning-Orchestrated Bot for Cyber Operations Protection).

## Table of Contents

- [Authentication](#authentication)
- [Base URL](#base-url)
- [Submissions API](#submissions-api)
- [Analysis API](#analysis-api)
- [Reports API](#reports-api)
- [Webhooks API](#webhooks-api)
- [Dashboard API](#dashboard-api)
- [Search & Correlation API](#search--correlation-api)
- [YARA Rules API](#yara-rules-api)
- [Management API](#management-api)
- [WebSocket API](#websocket-api)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)

---

## Authentication

The API uses API key authentication via the `X-API-Key` header.

```bash
curl -H "X-API-Key: your-api-key" https://api.example.com/api/...
```

**Note:** The submissions endpoints (`/api/submissions/*`) do not require authentication for file uploads, but webhook endpoints require the API key.

---

## Base URL

| Environment | Base URL |
|-------------|----------|
| Development | `http://localhost:8000` |
| Production | `https://your-domain.com` |

---

## Submissions API

### Submit File

Upload a file for malware analysis.

```
POST /api/submissions/file
```

**Content-Type:** `multipart/form-data`

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | File | Yes | The file to analyze |

**Example:**

```bash
curl -X POST "http://localhost:8000/api/submissions/file" \
  -F "file=@malicious_script.ps1"
```

**Response:** `200 OK`

```json
{
  "id": 1,
  "type": "file",
  "filename": "malicious_script.ps1",
  "original_url": null,
  "status": "pending",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Errors:**

| Code | Description |
|------|-------------|
| 400 | Invalid file type or empty file |
| 413 | File too large (max 50MB) |

---

### Submit URL

Submit a URL for analysis.

```
POST /api/submissions/url
```

**Content-Type:** `application/json`

**Request Body:**

```json
{
  "url": "https://suspicious-site.com/payload"
}
```

**Example:**

```bash
curl -X POST "http://localhost:8000/api/submissions/url" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://bit.ly/suspicious"}'
```

**Response:** `200 OK`

```json
{
  "id": 2,
  "type": "url",
  "filename": null,
  "original_url": "https://bit.ly/suspicious",
  "status": "pending",
  "created_at": "2024-01-15T10:35:00Z"
}
```

---

### Submit Sandbox Report

Upload a sandbox analysis report.

```
POST /api/submissions/sandbox-report
```

**Content-Type:** `application/json`

**Request Body:**

```json
{
  "report_source": "anyrun",
  "report_data": {
    "analysis": { ... },
    "processes": [ ... ],
    "network": [ ... ]
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `report_source` | string | Yes | `anyrun`, `joesandbox`, or `generic` |
| `report_data` | object | Yes | The sandbox report JSON |

**Example:**

```bash
curl -X POST "http://localhost:8000/api/submissions/sandbox-report" \
  -H "Content-Type: application/json" \
  -d '{
    "report_source": "anyrun",
    "report_data": {"tasks": [...]}
  }'
```

**Response:** `200 OK`

```json
{
  "id": 3,
  "type": "sandbox_report",
  "filename": "sandbox_report_anyrun_a1b2c3d4.json",
  "original_url": null,
  "status": "pending",
  "created_at": "2024-01-15T10:40:00Z"
}
```

---

### List Submissions

Get all submissions with optional filtering.

```
GET /api/submissions/
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status |
| `type` | string | - | Filter by type |
| `limit` | integer | 50 | Max results |
| `offset` | integer | 0 | Pagination offset |

**Example:**

```bash
# Get all pending submissions
curl "http://localhost:8000/api/submissions/?status=pending&limit=10"

# Get all file submissions
curl "http://localhost:8000/api/submissions/?type=file"
```

**Response:** `200 OK`

```json
[
  {
    "id": 1,
    "type": "file",
    "filename": "script.ps1",
    "original_url": null,
    "status": "complete",
    "created_at": "2024-01-15T10:30:00Z"
  },
  {
    "id": 2,
    "type": "url",
    "filename": null,
    "original_url": "https://example.com",
    "status": "analyzing",
    "created_at": "2024-01-15T10:35:00Z"
  }
]
```

---

### Get Submission

Get a specific submission by ID.

```
GET /api/submissions/{submission_id}
```

**Example:**

```bash
curl "http://localhost:8000/api/submissions/1"
```

**Response:** `200 OK`

```json
{
  "id": 1,
  "type": "file",
  "filename": "script.ps1",
  "original_url": null,
  "status": "complete",
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

## Analysis API

### Trigger Analysis

Manually trigger analysis for a submission.

```
POST /api/analysis/{submission_id}/trigger
```

**Example:**

```bash
curl -X POST "http://localhost:8000/api/analysis/1/trigger"
```

**Response:** `200 OK`

```json
{
  "message": "Analysis triggered",
  "submission_id": 1
}
```

**Errors:**

| Code | Description |
|------|-------------|
| 400 | Cannot trigger (already running or complete) |
| 404 | Submission not found |

---

### Get Analysis Results

Get complete analysis results for a submission.

```
GET /api/analysis/{submission_id}/results
```

**Example:**

```bash
curl "http://localhost:8000/api/analysis/1/results"
```

**Response:** `200 OK`

```json
{
  "submission_id": 1,
  "status": "complete",
  "analysis_results": [
    {
      "id": 1,
      "submission_id": 1,
      "analyzer": "script_decoder",
      "results_json": {
        "decoded": true,
        "encoding_type": "base64_powershell",
        "decoded_content": "..."
      },
      "created_at": "2024-01-15T10:31:00Z"
    },
    {
      "id": 2,
      "submission_id": 1,
      "analyzer": "script_analyzer",
      "results_json": {
        "behaviors": [...],
        "risk_level": "high",
        "mitre_techniques": [...]
      },
      "created_at": "2024-01-15T10:32:00Z"
    }
  ],
  "iocs": [
    {
      "id": 1,
      "type": "ip",
      "value": "192.168.1.100",
      "context": "C2 server connection"
    },
    {
      "id": 2,
      "type": "domain",
      "value": "malware.com",
      "context": "Download URL"
    }
  ]
}
```

---

### Get Analysis Status

Get the current status of an analysis.

```
GET /api/analysis/{submission_id}/status
```

**Example:**

```bash
curl "http://localhost:8000/api/analysis/1/status"
```

**Response:** `200 OK`

```json
{
  "submission_id": 1,
  "status": "enriching",
  "error_message": null,
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": null
}
```

---

### Validate MITRE Mappings

```
GET /api/analysis/{submission_id}/mitre-validation
```

Returns validated MITRE ATT&CK technique mappings with confidence levels.

---

## Reports API

### Generate Report

Generate a report for a submission.

```
POST /api/reports/{submission_id}/generate
```

**Content-Type:** `application/json`

**Request Body:**

```json
{
  "format": "html"
}
```

| Field | Type | Required | Options |
|-------|------|----------|---------|
| `format` | string | Yes | `json`, `html`, `pdf` |

**Example:**

```bash
curl -X POST "http://localhost:8000/api/reports/1/generate" \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'
```

**Response:** `200 OK`

```json
{
  "message": "Report generated",
  "submission_id": 1,
  "format": "html",
  "report_id": 1
}
```

---

### Get Report

Retrieve a generated report.

```
GET /api/reports/{submission_id}/{format}
```

| Path Parameter | Options |
|----------------|---------|
| `format` | `json`, `html`, `pdf` |

**Example:**

```bash
# Get JSON report
curl "http://localhost:8000/api/reports/1/json"

# Get HTML report
curl "http://localhost:8000/api/reports/1/html"

# Get PDF report (base64 encoded)
curl "http://localhost:8000/api/reports/1/pdf"
```

**Response (JSON):** `200 OK`

```json
{
  "report_metadata": {
    "submission_id": 1,
    "generated_at": "2024-01-15T11:00:00Z",
    "format": "json",
    "version": "1.0"
  },
  "submission": {
    "id": 1,
    "type": "file",
    "filename": "script.ps1",
    "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb924..."
  },
  "analysis_results": [...],
  "iocs": [...],
  "enrichment": {...},
  "narrative": "## Executive Summary\n..."
}
```

---

### Export IOCs

Export IOCs in various formats.

```
GET /api/reports/{submission_id}/iocs
```

**Query Parameters:**

| Parameter | Type | Default | Options |
|-----------|------|---------|---------|
| `format` | string | `csv` | `csv`, `stix`, `misp` |

**Example:**

```bash
# CSV export
curl "http://localhost:8000/api/reports/1/iocs?format=csv"

# STIX 2.1 bundle
curl "http://localhost:8000/api/reports/1/iocs?format=stix"

# MISP event
curl "http://localhost:8000/api/reports/1/iocs?format=misp"
```

**Response (CSV):**

```csv
Type,Value,Context,Defanged
ip,192.168.1.100,C2 server,192.168.1[.]100
domain,malware.com,Download URL,malware[.]com
```

---

## Webhooks API

These endpoints are used by n8n workflows. They require the `X-API-Key` header.

### Analysis Complete

Called when an analysis step completes.

```
POST /api/webhooks/analysis-complete
```

**Headers:**

```
X-API-Key: your-api-key
Content-Type: application/json
```

**Request Body:**

```json
{
  "submission_id": 1,
  "analyzer": "script_analyzer",
  "results": {
    "behaviors": [...],
    "risk_level": "high"
  },
  "iocs": [
    {"type": "ip", "value": "192.168.1.100", "context": "C2"}
  ]
}
```

**Response:** `200 OK`

```json
{
  "status": "success",
  "message": "Analysis results stored"
}
```

---

### Enrichment Complete

Called when IOC enrichment completes.

```
POST /api/webhooks/enrichment-complete
```

**Headers:**

```
X-API-Key: your-api-key
Content-Type: application/json
```

**Request Body:**

```json
{
  "submission_id": 1,
  "ioc_id": 1,
  "source": "virustotal",
  "data": {
    "found": true,
    "total_detections": 45,
    "total_engines": 70
  }
}
```

---

### Status Update

Update submission status.

```
POST /api/webhooks/status-update
```

**Headers:**

```
X-API-Key: your-api-key
Content-Type: application/json
```

**Request Body:**

```json
{
  "submission_id": 1,
  "status": "complete",
  "error_message": null
}
```

| Status Values |
|---------------|
| `pending` |
| `analyzing` |
| `enriching` |
| `reasoning` |
| `complete` |
| `failed` |

---

### Get Submission Data

Get all data for a submission (used by n8n).

```
GET /api/webhooks/submission/{submission_id}/data
```

**Headers:**

```
X-API-Key: your-api-key
```

**Response:** `200 OK`

```json
{
  "submission": {
    "id": 1,
    "type": "file",
    "filename": "script.ps1",
    "file_hash_sha256": "...",
    "status": "complete",
    "created_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:45:00Z"
  },
  "analysis_results": [...],
  "iocs": [
    {
      "id": 1,
      "type": "ip",
      "value": "192.168.1.100",
      "context": "C2",
      "enrichment": [
        {"source": "virustotal", "data": {...}},
        {"source": "shodan", "data": {...}}
      ]
    }
  ]
}
```

---

## Dashboard API

### Get Dashboard Stats

Get SOC analyst dashboard metrics.

```
GET /api/dashboard/stats
```

**Response:** `200 OK`

```json
{
  "total_submissions": 142,
  "completion_rate": 94.2,
  "submissions_today": 12,
  "avg_analysis_time_seconds": 45,
  "severity_distribution": {"critical": 8, "high": 23, "medium": 45, "low": 66},
  "trend_7d": [{"date": "2024-12-13", "count": 18}, ...],
  "mitre_heatmap": {"Execution": 34, "Defense Evasion": 28, ...},
  "recent_submissions": [...]
}
```

---

## Search & Correlation API

### Search IOCs

Search IOCs across all submissions.

```
GET /api/search/iocs?q={query}&type={ioc_type}&page={page}
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `q` | string | - | Search query (IOC value) |
| `type` | string | - | Filter by IOC type (ip, domain, url, hash, email) |
| `page` | integer | 1 | Page number (25 results per page) |

### Correlate IOCs

Find related submissions sharing common IOCs.

```
GET /api/search/correlate/{submission_id}
```

### Compare Submissions

Side-by-side comparison of two submissions.

```
GET /api/search/compare/{id1}/{id2}
```

---

## YARA Rules API

### List YARA Rules

```
GET /api/yara-rules/
```

### Create YARA Rule

```
POST /api/yara-rules/
```

### Update YARA Rule

```
PUT /api/yara-rules/{rule_id}
```

### Delete YARA Rule

```
DELETE /api/yara-rules/{rule_id}
```

### Scan Submission Against Rules

```
POST /api/yara-rules/scan/{submission_id}
```

---

## Management API

### Health Check

```
GET /api/management/health
```

**Response:**
```json
{
  "status": "healthy",
  "uptime_seconds": 86400,
  "version": "1.0.0"
}
```

---

## WebSocket API

### Real-Time Updates

```
WS /ws
```

Connect for real-time submission status updates. The server sends a heartbeat every 30 seconds.

**Message Format:**
```json
{
  "type": "status_update",
  "submission_id": 1,
  "status": "analyzing",
  "timestamp": "2024-12-19T14:32:07Z"
}
```

---

## Error Handling

All errors return JSON with a `detail` field:

```json
{
  "detail": "Error message here"
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid or missing API key |
| 404 | Not Found - Resource doesn't exist |
| 413 | Payload Too Large - File exceeds limit |
| 422 | Unprocessable Entity - Validation error |
| 500 | Internal Server Error |

### Validation Errors

```json
{
  "detail": [
    {
      "loc": ["body", "url"],
      "msg": "invalid or missing URL",
      "type": "value_error"
    }
  ]
}
```

---

## Rate Limiting

The API implements rate limiting to prevent abuse:

| Endpoint | Limit |
|----------|-------|
| File upload | 10/minute |
| URL submission | 20/minute |
| Analysis trigger | 10/minute |
| Report generation | 5/minute |

When rate limited, you'll receive:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

---

## SDK Examples

### Python

```python
import httpx

class RoboCopClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"X-API-Key": api_key}

    async def submit_file(self, file_path: str):
        async with httpx.AsyncClient() as client:
            with open(file_path, "rb") as f:
                response = await client.post(
                    f"{self.base_url}/api/submissions/file",
                    files={"file": f}
                )
            return response.json()

    async def submit_url(self, url: str):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/submissions/url",
                json={"url": url}
            )
            return response.json()

    async def get_results(self, submission_id: int):
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/api/analysis/{submission_id}/results",
                headers=self.headers
            )
            return response.json()

# Usage
client = RoboCopClient("http://localhost:8000", "your-api-key")
result = await client.submit_file("suspicious.ps1")
print(f"Submission ID: {result['id']}")
```

### JavaScript/TypeScript

```typescript
class RoboCopClient {
  constructor(
    private baseUrl: string,
    private apiKey: string
  ) {}

  async submitFile(file: File): Promise<Submission> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${this.baseUrl}/api/submissions/file`, {
      method: 'POST',
      body: formData
    });
    return response.json();
  }

  async submitUrl(url: string): Promise<Submission> {
    const response = await fetch(`${this.baseUrl}/api/submissions/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    return response.json();
  }

  async getResults(submissionId: number): Promise<AnalysisResults> {
    const response = await fetch(
      `${this.baseUrl}/api/analysis/${submissionId}/results`,
      { headers: { 'X-API-Key': this.apiKey } }
    );
    return response.json();
  }
}
```

---

## OpenAPI Specification

The full OpenAPI (Swagger) specification is available at:

```
GET /openapi.json
```

Interactive API documentation:

```
GET /docs      # Swagger UI
GET /redoc     # ReDoc
```
