# Troubleshooting Guide

Common issues and solutions for RoboCop.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Docker All-in-One Issues](#docker-all-in-one-issues)
- [Runtime Errors](#runtime-errors)
- [Analysis Issues](#analysis-issues)
- [API Issues](#api-issues)
- [Performance Issues](#performance-issues)
- [n8n Workflow Issues](#n8n-workflow-issues)
- [WebSocket Issues](#websocket-issues)
- [Frontend Issues](#frontend-issues)
- [Debug Mode](#debug-mode)
- [Getting Help](#getting-help)

---

## Installation Issues

### Docker won't start

**Symptom:** `docker-compose up` fails or containers exit immediately.

**Solutions:**

1. **Check Docker is running:**
   ```bash
   docker info
   ```

2. **Check port conflicts:**
   ```bash
   # Windows
   netstat -ano | findstr :8000
   netstat -ano | findstr :3000

   # Linux/macOS
   lsof -i :8000
   lsof -i :3000
   ```

3. **Check logs:**
   ```bash
   docker-compose logs backend
   docker-compose logs db
   ```

4. **Reset Docker state:**
   ```bash
   docker-compose down -v
   docker system prune -f
   docker-compose up --build
   ```

---

### Database connection failed

**Symptom:** `sqlalchemy.exc.OperationalError: could not connect to server`

**Solutions:**

1. **Check database is running:**
   ```bash
   docker-compose ps db
   ```

2. **Wait for database initialization:**
   ```bash
   # The database takes a few seconds to initialize
   docker-compose logs db | grep "ready to accept connections"
   ```

3. **Check DATABASE_URL format:**
   ```
   # SQLite
   DATABASE_URL=sqlite+aiosqlite:///./malware_analysis.db

   # PostgreSQL
   DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/malware_analysis
   ```

4. **Check password special characters:**
   ```bash
   # URL-encode special characters in password
   # @ becomes %40
   # # becomes %23
   ```

---

### Python dependencies fail to install

**Symptom:** `pip install` errors for specific packages.

**Solutions:**

1. **WeasyPrint issues (PDF generation):**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0

   # macOS
   brew install pango

   # Windows - use Docker instead
   ```

2. **aiosqlite/asyncpg issues:**
   ```bash
   pip install --upgrade pip
   pip install aiosqlite asyncpg
   ```

3. **Use virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

---

## Docker All-in-One Issues

### Container exits immediately

**Symptom:** `docker compose --profile allinone up allinone` exits or restarts in a loop.

**Solutions:**

1. **Check logs:**
   ```bash
   docker compose --profile allinone logs allinone
   ```

2. **Check supervisord logs inside the container:**
   ```bash
   docker compose --profile allinone exec allinone cat /var/log/supervisor/backend-error.log
   docker compose --profile allinone exec allinone cat /var/log/supervisor/postgresql-error.log
   ```

3. **PostgreSQL data directory permissions:**
   ```bash
   # Reset if corrupted
   docker compose --profile allinone down -v
   docker compose --profile allinone up -d allinone
   ```

### n8n workflows not imported

**Symptom:** Workflows don't appear in n8n after first start.

**Solutions:**

1. **Check import log:**
   ```bash
   docker compose --profile allinone exec allinone cat /var/log/supervisor/workflow-import.log
   ```

2. **Manually trigger import:**
   ```bash
   docker compose --profile allinone exec allinone bash -c "for wf in /opt/n8n/workflows/*.json; do su - n8n -c \"N8N_USER_FOLDER=/home/n8n/.n8n n8n import:workflow --input=\$wf\"; done"
   ```

---

## Runtime Errors

### "API key required" / 401 Unauthorized

**Symptom:** Webhook endpoints return 401 errors.

**Solutions:**

1. **Check API key is set:**
   ```bash
   # In .env file
   API_KEY=your-secure-key-here
   ```

2. **Check header format:**
   ```bash
   curl -H "X-API-Key: your-key" http://localhost:8000/api/webhooks/...
   ```

3. **Ensure no whitespace:**
   ```bash
   # Wrong
   API_KEY= your-key

   # Correct
   API_KEY=your-key
   ```

---

### "File type not allowed" when uploading

**Symptom:** 400 error when uploading files.

**Solutions:**

1. **Check file extension:**
   Allowed extensions:
   ```
   .ps1, .js, .vbs, .bat, .py, .sh, .exe, .dll,
   .doc, .docx, .pdf, .zip, .rar, .json, .xml, .html
   ```

2. **Check filename:**
   - No special characters
   - No path components (../)
   - Under 200 characters

3. **Check file size:**
   Default limit is 50MB. Check `MAX_FILE_SIZE` in config.

---

### "SSRF protection: Blocked" when analyzing URL

**Symptom:** URL analysis fails with SSRF protection message.

**Cause:** The platform blocks requests to internal/private IP addresses for security.

**Solutions:**

1. **This is expected for internal URLs** - Private IPs (10.x, 192.168.x, 127.x) are blocked.

2. **For legitimate internal testing:**
   ```python
   # In url_analyzer.py, temporarily allow (NOT for production):
   url_result = await url_analyzer.analyze(url, allow_internal=True)
   ```

---

### "Anthropic API key not configured"

**Symptom:** Claude AI analysis returns errors.

**Solutions:**

1. **Set the API key:**
   ```bash
   ANTHROPIC_API_KEY=sk-ant-api03-...
   ```

2. **Verify key is valid:**
   ```bash
   curl https://api.anthropic.com/v1/messages \
     -H "x-api-key: $ANTHROPIC_API_KEY" \
     -H "anthropic-version: 2023-06-01" \
     -H "content-type: application/json" \
     -d '{"model":"claude-haiku-4-5-20241022","max_tokens":10,"messages":[{"role":"user","content":"Hi"}]}'
   ```

3. **Check billing:** Ensure your Anthropic account has credits.

---

## Analysis Issues

### Analysis stuck in "pending" status

**Symptom:** Submission stays in pending state.

**Solutions:**

1. **Check n8n is running:**
   ```bash
   docker-compose ps n8n
   curl http://localhost:5678/healthz
   ```

2. **Check n8n workflows are active:**
   - Open http://localhost:5678
   - Verify workflows are enabled (toggle is on)

3. **Trigger analysis manually:**
   ```bash
   curl -X POST http://localhost:8000/api/analysis/1/trigger
   ```

4. **Check backend logs:**
   ```bash
   docker-compose logs -f backend | grep -i error
   ```

---

### No IOCs extracted

**Symptom:** Analysis completes but IOC list is empty.

**Solutions:**

1. **Check file content is text-based:**
   Binary files may not have extractable text IOCs.

2. **Verify file encoding:**
   ```bash
   file suspicious_file.ps1
   # Should show: ASCII text or UTF-8 text
   ```

3. **Check for obfuscation:**
   The platform decodes common encodings, but heavily obfuscated content may not parse.

4. **Manual check:**
   ```python
   from analyzers.ioc_extractor import IOCExtractor
   extractor = IOCExtractor()
   iocs = extractor.extract("your content here")
   print(iocs)
   ```

---

### Enrichment data missing

**Symptom:** IOCs have no enrichment data.

**Solutions:**

1. **Check API keys are set:**
   ```bash
   VIRUSTOTAL_API_KEY=...
   SHODAN_API_KEY=...
   ```

2. **Check rate limits:**
   VirusTotal free tier: 4 requests/minute

   ```bash
   # Check VT rate limit status
   docker-compose logs backend | grep -i "rate limit"
   ```

3. **IOC may not be in database:**
   New/unknown IOCs won't have VT data.

4. **Test API connectivity:**
   ```bash
   curl "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8" \
     -H "x-apikey: YOUR_VT_KEY"
   ```

---

### Claude AI analysis is empty or low quality

**Symptom:** Reasoning results are brief or unhelpful.

**Solutions:**

1. **Check model setting:**
   ```bash
   # For better results, use a more capable model
   CLAUDE_MODEL=claude-sonnet-4-20250514
   ```

2. **Check script content:**
   Very short scripts may not provide enough context.

3. **Check for API errors:**
   ```bash
   docker-compose logs backend | grep -i anthropic
   ```

---

## API Issues

### CORS errors in browser

**Symptom:** Browser console shows CORS policy errors.

**Solutions:**

1. **Check CORS_ORIGINS setting:**
   ```bash
   CORS_ORIGINS=http://localhost:3000,http://localhost:5173
   ```

2. **Include your frontend URL:**
   ```bash
   CORS_ORIGINS=http://localhost:3000,https://your-domain.com
   ```

3. **Restart backend after changes:**
   ```bash
   docker-compose restart backend
   ```

---

### 422 Validation Error

**Symptom:** API returns 422 with validation details.

**Solutions:**

1. **Check request body format:**
   ```bash
   # Correct
   curl -X POST -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}' \
     http://localhost:8000/api/submissions/url

   # Wrong (missing Content-Type)
   curl -X POST -d '{"url": "https://example.com"}' \
     http://localhost:8000/api/submissions/url
   ```

2. **Check required fields:**
   Read the error response - it indicates which field failed.

3. **Check data types:**
   ```json
   {
     "submission_id": 1,    // integer, not "1"
     "status": "complete"   // string
   }
   ```

---

## Performance Issues

### Slow analysis times

**Symptom:** Analysis takes longer than expected.

**Solutions:**

1. **Check system resources:**
   ```bash
   docker stats
   ```

2. **Increase container resources:**
   ```yaml
   # docker-compose.yml
   services:
     backend:
       deploy:
         resources:
           limits:
             cpus: '2'
             memory: 4G
   ```

3. **Check enrichment API response times:**
   External API calls add latency.

4. **Use faster Claude model:**
   ```bash
   CLAUDE_MODEL=claude-haiku-4-5-20241022
   ```

---

### High memory usage

**Symptom:** Container uses excessive memory.

**Solutions:**

1. **Check for large files:**
   ```bash
   du -sh uploads/*
   ```

2. **Clean old uploads:**
   ```bash
   find uploads/ -mtime +7 -delete
   ```

3. **Reduce log retention:**
   ```yaml
   logging:
     options:
       max-size: "50m"
       max-file: "3"
   ```

---

## n8n Workflow Issues

### Workflows not triggering

**Symptom:** Submissions don't start analysis.

**Solutions:**

1. **Check webhook URL:**
   ```bash
   # In backend .env
   N8N_WEBHOOK_BASE_URL=http://n8n:5678/webhook

   # Or for local development
   N8N_WEBHOOK_BASE_URL=http://localhost:5678/webhook
   ```

2. **Verify workflows are active:**
   Open n8n UI → Each workflow should have toggle ON

3. **Check webhook paths match:**
   The backend expects `/analysis-trigger` webhook path.

4. **Test webhook manually:**
   ```bash
   curl -X POST http://localhost:5678/webhook/analysis-trigger \
     -H "Content-Type: application/json" \
     -d '{"submission_id": 1}'
   ```

---

### n8n can't reach backend

**Symptom:** n8n workflow fails with connection errors.

**Solutions:**

1. **Use Docker network hostname:**
   ```
   # In n8n HTTP Request nodes, use:
   http://backend:8000/api/...

   # NOT localhost:8000
   ```

2. **Check network:**
   ```bash
   docker network ls
   docker network inspect robocop_default
   ```

---

## WebSocket Issues

### Real-time updates not working

**Symptom:** Submission status doesn't update in real-time on the dashboard.

**Solutions:**

1. **Check WebSocket connection in browser:**
   Open browser DevTools → Network → WS tab. Look for a connection to `/ws/`.

2. **Check Nginx WebSocket proxy:**
   Ensure your Nginx config includes WebSocket upgrade headers:
   ```nginx
   location /ws/ {
       proxy_pass http://127.0.0.1:8000/ws/;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
       proxy_read_timeout 86400s;
   }
   ```

3. **Heartbeat timeout:**
   The server sends a heartbeat every 30 seconds. If you see disconnections, check for proxies or firewalls that close idle connections.

---

## Frontend Issues

### Error boundary triggered

**Symptom:** A section of the page shows "Something went wrong" with an error ID.

**Solutions:**

1. **Note the error ID** — it can be correlated with backend logs for debugging.
2. **Click "Try Again"** to reset that component.
3. **Check browser console** for the full error stack trace.

### Toast notifications not appearing

**Symptom:** No success/error notifications after actions.

**Solutions:**

1. **Check ToastProvider** is wrapping the app in main.jsx.
2. **Check browser console** for React errors.

---

## Debug Mode

### Enable debug logging

```bash
# In .env
DEBUG=true
```

### View detailed logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend

# Filter for errors
docker-compose logs backend 2>&1 | grep -i error
```

### Python debugging

```python
# Add to any file for breakpoint
import pdb; pdb.set_trace()

# Or use logging
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.debug("Debug message here")
```

### Test individual components

```python
# Test IOC extractor
python -c "
from analyzers.ioc_extractor import IOCExtractor
e = IOCExtractor()
print(e.extract('Contact admin@evil.com or visit http://malware.com'))
"

# Test script decoder
python -c "
from analyzers.script_decoder import ScriptDecoder
d = ScriptDecoder()
print(d.decode('powershell -enc SGVsbG8gV29ybGQ=', 'test.ps1'))
"
```

---

## Getting Help

### Collect diagnostic information

```bash
# System info
docker version
docker-compose version
python --version

# Container status
docker-compose ps

# Recent logs
docker-compose logs --tail=100 > logs.txt

# Configuration (sanitized)
cat .env | grep -v KEY | grep -v PASSWORD > config.txt
```

### Check GitHub Issues

Search existing issues at: `https://github.com/venom444556/robocop/issues`

### Report a bug

Include:
1. Steps to reproduce
2. Expected behavior
3. Actual behavior
4. Logs (sanitized of secrets)
5. Environment details

---

## Quick Reference

| Issue | First Thing to Check |
|-------|---------------------|
| 401 Unauthorized | API_KEY in .env |
| 500 Internal Error | `docker-compose logs backend` |
| Analysis stuck | n8n workflow status |
| No enrichment | External API keys |
| CORS error | CORS_ORIGINS setting |
| Slow performance | `docker stats` |
| DB connection | DATABASE_URL format |
| WebSocket disconnects | Nginx proxy config |
| All-in-one not starting | supervisord logs |
