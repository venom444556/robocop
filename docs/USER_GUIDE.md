# User Guide

This guide covers how to use the RoboCop for analyzing suspicious files, URLs, and sandbox reports.

## Table of Contents

- [Overview](#overview)
- [SOC Analyst Dashboard](#soc-analyst-dashboard)
- [Submitting Samples](#submitting-samples)
- [Understanding Analysis Results](#understanding-analysis-results)
- [Working with Reports](#working-with-reports)
- [IOC Management](#ioc-management)
- [IOC Search & Correlation](#ioc-search--correlation)
- [YARA Rule Management](#yara-rule-management)
- [Real-Time Updates](#real-time-updates)
- [Best Practices](#best-practices)

---

## Overview

The RoboCop provides three main submission types:

| Type | Use Case | What Gets Analyzed |
|------|----------|-------------------|
| **File** | Suspicious scripts, executables, documents | Static code analysis, IOC extraction, behavior patterns |
| **URL** | Phishing links, malware distribution URLs | URL expansion, categorization, hosted content analysis |
| **Sandbox Report** | Existing analysis from Any.Run, Joe Sandbox | Behavior extraction, IOC correlation, MITRE mapping |

### Analysis Pipeline

```
Submit → Static Analysis → IOC Extraction → Enrichment → 6 Claude AI Agents → Report
```

---

## SOC Analyst Dashboard

The Dashboard (http://localhost:3000/dashboard) provides real-time operational metrics:

- **Submission Metrics**: Total submissions, completion rate, today's count
- **7-Day Trend Chart**: Submission volume over the past week
- **MITRE ATT&CK Heatmap**: Technique frequency by tactic across all analyses
- **Severity Distribution**: Breakdown of critical/high/medium/low findings
- **Recent Submissions**: Quick access to latest analyses with status indicators

---

## Submitting Samples

### Submitting a File

**Via Web Dashboard:**

1. Navigate to the Submit page
2. Click "Upload File" or drag and drop
3. Wait for upload confirmation
4. You'll be redirected to the analysis status page

**Via API:**

```bash
curl -X POST "http://localhost:8000/api/submissions/file" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@suspicious_script.ps1"
```

**Supported File Types:**

| Category | Extensions |
|----------|------------|
| Scripts | `.ps1`, `.psm1`, `.js`, `.vbs`, `.vbe`, `.bat`, `.cmd`, `.py`, `.sh`, `.hta` |
| Executables | `.exe`, `.dll`, `.scr`, `.sys`, `.msi` |
| Documents | `.doc`, `.docx`, `.docm`, `.xls`, `.xlsx`, `.xlsm`, `.pdf`, `.rtf` |
| Archives | `.zip`, `.rar`, `.7z`, `.tar`, `.gz` |
| Other | `.lnk`, `.iso`, `.img`, `.json`, `.xml`, `.html` |

**File Size Limit:** 50MB (configurable)

---

### Submitting a URL

**Via Web Dashboard:**

1. Navigate to the Submit page
2. Select "URL" tab
3. Paste the URL
4. Click "Analyze"

**Via API:**

```bash
curl -X POST "http://localhost:8000/api/submissions/url" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com/download.php"}'
```

**What Happens:**

1. **URL Expansion** - Shortened URLs (bit.ly, t.co, etc.) are expanded
2. **Redirect Chain** - All redirects are recorded
3. **Categorization** - URL is categorized (phishing, malware, business, etc.)
4. **Content Analysis** - If URL serves a script, it's downloaded and analyzed
5. **Enrichment** - VirusTotal, Google Safe Browsing, URLhaus lookups

**Example URL Analysis Output:**

```json
{
  "original_url": "https://bit.ly/3abc123",
  "effective_url": "https://malicious-site.com/payload.ps1",
  "redirect_chain": [
    {"url": "https://bit.ly/3abc123", "status_code": 301},
    {"url": "https://malicious-site.com/payload.ps1", "status_code": 200, "final": true}
  ],
  "is_shortened": true,
  "is_script": true,
  "script_type": "powershell"
}
```

---

### Submitting a Sandbox Report

**Via Web Dashboard:**

1. Navigate to the Submit page
2. Select "Sandbox Report" tab
3. Choose the source (Any.Run, Joe Sandbox, or Generic)
4. Paste the JSON report or upload the file
5. Click "Analyze"

**Via API:**

```bash
curl -X POST "http://localhost:8000/api/submissions/sandbox-report" \
  -H "Content-Type: application/json" \
  -d '{
    "report_source": "anyrun",
    "report_data": { ... }
  }'
```

**Supported Formats:**

| Source | Format | How to Export |
|--------|--------|---------------|
| Any.Run | JSON | Task → Export → JSON |
| Joe Sandbox | JSON | Analysis → Download → JSON Report |
| Generic | JSON | Any structured JSON with process/network data |

---

## Understanding Analysis Results

### Analysis Status

| Status | Description |
|--------|-------------|
| `pending` | Queued for analysis |
| `analyzing` | Static analysis in progress |
| `enriching` | IOC enrichment in progress |
| `reasoning` | Claude AI analysis in progress |
| `complete` | Analysis finished |
| `failed` | Analysis failed (check error message) |

### Script Analysis Results

For script files, you'll see:

**Decoded Content:**
```json
{
  "decoded": true,
  "encoding_type": "base64_powershell",
  "original_content": "powershell -enc SGVsbG8gV29ybGQ=",
  "decoded_content": "Hello World",
  "decode_chain": ["base64"]
}
```

**Behavior Detection:**
```json
{
  "behaviors": [
    {
      "category": "execution",
      "description": "Uses Invoke-Expression for dynamic code execution",
      "severity": "high",
      "mitre_technique": "T1059.001"
    }
  ],
  "risk_level": "high",
  "risk_score": 85
}
```

**MITRE ATT&CK Mapping:**
```json
{
  "mitre_techniques": [
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "tactic": "Execution",
      "confidence": "high"
    },
    {
      "id": "T1027",
      "name": "Obfuscated Files or Information",
      "tactic": "Defense Evasion",
      "confidence": "high"
    }
  ]
}
```

### IOC Types

| Type | Description | Example |
|------|-------------|---------|
| `ip` | IP addresses | `192.168.1.1` |
| `domain` | Domain names | `malware.com` |
| `url` | Full URLs | `http://malware.com/payload` |
| `hash_md5` | MD5 hashes | `d41d8cd98f00b204e9800998ecf8427e` |
| `hash_sha1` | SHA1 hashes | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `hash_sha256` | SHA256 hashes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `email` | Email addresses | `attacker@malware.com` |
| `filename` | File names | `payload.exe` |
| `registry_key` | Registry keys | `HKLM\Software\Malware` |
| `mutex` | Mutex names | `Global\MalwareMutex` |

### Enrichment Data

Each IOC is enriched with external intelligence:

**VirusTotal:**
```json
{
  "found": true,
  "total_detections": 45,
  "total_engines": 70,
  "detection_stats": {
    "malicious": 45,
    "suspicious": 5,
    "undetected": 20
  },
  "popular_threat_names": "Trojan.GenericKD"
}
```

**Shodan (for IPs):**
```json
{
  "found": true,
  "country": "Russia",
  "org": "Bulletproof Hosting Inc",
  "ports": [22, 80, 443, 4444],
  "services": [
    {"port": 4444, "service": "Metasploit"}
  ]
}
```

---

## Working with Reports

### Report Formats

| Format | Use Case | Content |
|--------|----------|---------|
| **JSON** | Integration, archival | Complete structured data |
| **HTML** | Human review, sharing | Formatted visual report |
| **PDF** | Documentation, legal | Printable professional report |

### Generating Reports

**Via Web Dashboard:**

1. Go to the submission details page
2. Click "Generate Report"
3. Select format (JSON, HTML, PDF)
4. Download or view the report

**Via API:**

```bash
# Generate report
curl -X POST "http://localhost:8000/api/reports/1/generate" \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'

# Get report
curl "http://localhost:8000/api/reports/1/html"
```

### Report Sections

1. **Executive Summary** - High-level overview for management
2. **Technical Analysis** - Detailed Claude AI reasoning
3. **MITRE ATT&CK Mapping** - Techniques with IDs
4. **Indicators of Compromise** - Complete IOC table
5. **Enrichment Results** - Intelligence from external sources
6. **Recommendations** - Actionable mitigation steps

### Exporting IOCs

Export IOCs in standard formats for integration with security tools:

**CSV Export:**
```bash
curl "http://localhost:8000/api/reports/1/iocs?format=csv"
```

**STIX 2.1 Export:**
```bash
curl "http://localhost:8000/api/reports/1/iocs?format=stix"
```

**MISP Export:**
```bash
curl "http://localhost:8000/api/reports/1/iocs?format=misp"
```

---

## IOC Management

### Viewing IOCs

**Via Web Dashboard:**

1. Go to submission details
2. Scroll to "Indicators of Compromise" section
3. Click on any IOC to see enrichment details

**Via API:**

```bash
curl "http://localhost:8000/api/analysis/1/results"
```

### IOC Defanging

For safe sharing, IOCs are automatically defanged in exports:

| Original | Defanged |
|----------|----------|
| `malware.com` | `malware[.]com` |
| `http://evil.com` | `hxxp://evil[.]com` |
| `attacker@evil.com` | `attacker[@]evil[.]com` |

---

## IOC Search & Correlation

The Search page (http://localhost:3000/search) enables cross-submission IOC analysis:

### Searching IOCs
1. Navigate to the Search page
2. Enter an IOC value (IP, domain, URL, hash, or email)
3. Optionally filter by IOC type
4. Results show all matching IOCs across submissions (25 per page)

### Correlating Submissions
Click "Correlate" on any submission to find other submissions sharing the same IOCs. This helps identify related campaigns or recurring threat actors.

### Comparing Submissions
Select two submissions for a side-by-side comparison of IOCs, behaviors, and MITRE techniques.

---

## YARA Rule Management

The YARA Rules page (http://localhost:3000/yara-rules) lets you create and manage detection rules:

### Creating Rules
1. Click "Create Rule"
2. Enter rule name, category (Malware, Ransomware, Exploit, APT, Custom), and YARA source
3. Rules can be enabled/disabled with a toggle

### Scanning
Scan any submission against your YARA rules to check for matches.

---

## Real-Time Updates

RoboCop uses WebSocket connections to provide live status updates. When you submit a sample, the UI automatically updates as the analysis progresses through each stage (analyzing → enriching → reasoning → complete). A 30-second heartbeat keeps the connection alive.

---

## Best Practices

### Sample Handling

1. **Never execute samples** on production systems
2. **Use isolated VMs** or dedicated analysis machines
3. **Disable network** when manually inspecting samples
4. **Hash everything** before and after analysis

### Analysis Workflow

```
1. Submit sample
2. Wait for automatic analysis
3. Review Claude AI reasoning
4. Check enrichment data
5. Export IOCs for blocking
6. Generate report for documentation
```

### Interpreting Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| **Critical** | 80-100 | Immediate blocking, incident response |
| **High** | 60-79 | Priority investigation, likely blocking |
| **Medium** | 40-59 | Investigation required, monitor |
| **Low** | 20-39 | Low priority, contextual review |
| **Minimal** | 0-19 | Likely benign, document only |

### Integration with Security Tools

**SIEM Integration:**
- Export IOCs in STIX format
- Ingest into your SIEM for correlation

**Firewall/EDR Blocking:**
- Export high-confidence IOCs
- Push to blocking lists

**Threat Intelligence Platform:**
- Export in MISP format
- Share with your TIP

---

## Keyboard Shortcuts (Dashboard)

| Shortcut | Action |
|----------|--------|
| `Ctrl+U` | New file upload |
| `Ctrl+K` | Search submissions |
| `Ctrl+R` | Refresh current view |
| `Esc` | Close modal/dialog |

---

## Next Steps

- [API Reference](API.md) - Automate with the API
- [Architecture](ARCHITECTURE.md) - Understand the system
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues
