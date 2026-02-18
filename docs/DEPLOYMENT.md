# Deployment Guide

Production deployment guide for RoboCop (Reasoning-Orchestrated Bot for Cyber Operations Protection).

## Table of Contents

- [Deployment Options](#deployment-options)
- [Docker All-in-One Deployment](#docker-all-in-one-deployment-recommended)
- [Docker Compose Deployment](#docker-compose-deployment)
- [AWS Deployment](#aws-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Security Hardening](#security-hardening)
- [Monitoring & Logging](#monitoring--logging)
- [Backup & Recovery](#backup--recovery)
- [Maintenance](#maintenance)

---

## Deployment Options

| Option | Best For | Complexity |
|--------|----------|------------|
| Docker All-in-One | Quick start, small teams | Very Low |
| Docker Compose | Small teams, single server | Low |
| AWS EC2 + RDS | Medium scale, managed services | Medium |
| Kubernetes | Enterprise, high availability | High |

---

## Docker All-in-One Deployment (Recommended)

The simplest deployment — everything in one container.

```bash
git clone https://github.com/venom444556/robocop.git
cd robocop
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY and API_KEY
docker compose --profile allinone up -d allinone
```

Access at http://localhost:3000. This runs PostgreSQL 16, FastAPI, n8n, and Nginx via supervisord.

---

## Docker Compose Deployment

### Production docker-compose.yml

```yaml
version: '3.8'

services:
  # PostgreSQL Database
  db:
    image: postgres:15-alpine
    restart: always
    environment:
      POSTGRES_USER: ${DB_USER:-malware}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: ${DB_NAME:-malware_analysis}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-malware}"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Backend API
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    restart: always
    environment:
      - DATABASE_URL=postgresql+asyncpg://${DB_USER:-malware}:${DB_PASSWORD}@db:5432/${DB_NAME:-malware_analysis}
      - API_KEY=${API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - SHODAN_API_KEY=${SHODAN_API_KEY}
      - CORS_ORIGINS=${CORS_ORIGINS:-https://your-domain.com}
      - N8N_WEBHOOK_BASE_URL=http://n8n:5678/webhook
    volumes:
      - uploads:/app/uploads
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Frontend (Nginx)
  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    restart: always
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - backend

  # n8n Workflow Engine
  n8n:
    image: n8nio/n8n:latest
    restart: always
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=${N8N_USER:-admin}
      - N8N_BASIC_AUTH_PASSWORD=${N8N_PASSWORD}
      - N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}
      - WEBHOOK_URL=https://your-domain.com/n8n/
      - N8N_HOST=your-domain.com
      - N8N_PROTOCOL=https
    volumes:
      - n8n_data:/home/node/.n8n
    depends_on:
      - backend

volumes:
  postgres_data:
  uploads:
  n8n_data:
```

### Production Nginx Configuration

```nginx
# nginx/nginx.conf
upstream backend {
    server backend:8000;
}

upstream n8n {
    server n8n:5678;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Frontend
    location / {
        root /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api/ {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # File upload settings
        client_max_body_size 50M;
        proxy_read_timeout 300s;
    }

    # WebSocket
    location /ws/ {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
    }

    # n8n
    location /n8n/ {
        proxy_pass http://n8n/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Deployment Steps

```bash
# 1. Clone repository
git clone https://github.com/venom444556/robocop.git
cd robocop

# 2. Create production environment file
cp .env.example .env.production

# 3. Generate secure secrets
echo "DB_PASSWORD=$(openssl rand -hex 32)" >> .env.production
echo "API_KEY=$(openssl rand -hex 32)" >> .env.production
echo "N8N_PASSWORD=$(openssl rand -hex 16)" >> .env.production
echo "N8N_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env.production

# 4. Add your API keys
nano .env.production

# 5. Set up SSL certificates (Let's Encrypt)
sudo certbot certonly --standalone -d your-domain.com
mkdir -p nginx/ssl
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/

# 6. Deploy
docker-compose -f docker-compose.prod.yml --env-file .env.production up -d

# 7. Import n8n workflows
# Access https://your-domain.com/n8n and import workflows
```

---

## AWS Deployment

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AWS Cloud                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         VPC (10.0.0.0/16)                            │    │
│  │  ┌─────────────────────┐      ┌─────────────────────┐               │    │
│  │  │   Public Subnet     │      │   Private Subnet    │               │    │
│  │  │   10.0.1.0/24       │      │   10.0.2.0/24       │               │    │
│  │  │                     │      │                     │               │    │
│  │  │  ┌───────────────┐  │      │  ┌───────────────┐  │               │    │
│  │  │  │      ALB      │──┼──────┼─▶│   EC2 (App)   │  │               │    │
│  │  │  └───────────────┘  │      │  └───────────────┘  │               │    │
│  │  │                     │      │          │          │               │    │
│  │  │  ┌───────────────┐  │      │          ▼          │               │    │
│  │  │  │   NAT GW      │◀─┼──────┼──────────┘          │               │    │
│  │  │  └───────────────┘  │      │                     │               │    │
│  │  └─────────────────────┘      │  ┌───────────────┐  │               │    │
│  │                               │  │   RDS Postgres │  │               │    │
│  │                               │  └───────────────┘  │               │    │
│  │                               └─────────────────────┘               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐      │
│  │       S3        │      │   CloudWatch    │      │  Secrets Mgr    │      │
│  │   (artifacts)   │      │   (logs)        │      │   (API keys)    │      │
│  └─────────────────┘      └─────────────────┘      └─────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Terraform Configuration

```hcl
# main.tf
provider "aws" {
  region = "us-east-1"
}

# VPC
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0"

  name = "robocop-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true
}

# RDS PostgreSQL
resource "aws_db_instance" "malware_db" {
  identifier           = "robocop-db"
  engine               = "postgres"
  engine_version       = "15"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  storage_encrypted    = true

  db_name  = "malware_analysis"
  username = "malware"
  password = var.db_password

  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name

  backup_retention_period = 7
  skip_final_snapshot     = false
  final_snapshot_identifier = "malware-db-final"
}

# S3 Bucket
resource "aws_s3_bucket" "artifacts" {
  bucket = "robocop-artifacts-${random_id.bucket.hex}"
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"

    expiration {
      days = 30
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# EC2 Instance
resource "aws_instance" "app" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.large"
  subnet_id     = module.vpc.private_subnets[0]

  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  user_data = base64encode(templatefile("user_data.sh", {
    db_host     = aws_db_instance.malware_db.endpoint
    s3_bucket   = aws_s3_bucket.artifacts.id
  }))

  root_block_device {
    volume_size = 100
    encrypted   = true
  }

  tags = {
    Name = "robocop-app"
  }
}

# ALB
resource "aws_lb" "main" {
  name               = "robocop-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
```

### EC2 User Data Script

```bash
#!/bin/bash
# user_data.sh

# Install Docker
yum update -y
yum install -y docker
systemctl start docker
systemctl enable docker

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Clone application
git clone https://github.com/venom444556/robocop.git /opt/robocop
cd /opt/robocop

# Configure environment
cat > .env <<EOF
DATABASE_URL=postgresql+asyncpg://${db_user}:${db_password}@${db_host}:5432/malware_analysis
AWS_ACCESS_KEY_ID=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role | jq -r .AccessKeyId)
S3_BUCKET_NAME=${s3_bucket}
# Add other environment variables from Secrets Manager
EOF

# Start services
docker-compose -f docker-compose.prod.yml up -d
```

---

## Kubernetes Deployment

### Helm Chart Structure

```
helm/robocop/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── pvc.yaml
│   └── hpa.yaml
```

### Deployment Manifest

```yaml
# templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-backend
spec:
  replicas: {{ .Values.backend.replicas }}
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: backend
        image: {{ .Values.backend.image }}
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: {{ .Release.Name }}-secrets
              key: database-url
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: {{ .Release.Name }}-secrets
              key: api-key
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: uploads
          mountPath: /app/uploads
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: {{ .Release.Name }}-uploads
```

### Values File

```yaml
# values.yaml
backend:
  replicas: 3
  image: your-registry/robocop-backend:latest
  resources:
    requests:
      memory: "512Mi"
      cpu: "250m"
    limits:
      memory: "2Gi"
      cpu: "1000m"

frontend:
  replicas: 2
  image: your-registry/robocop-frontend:latest

n8n:
  replicas: 1
  image: n8nio/n8n:latest

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: robocop.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: robocop-tls
      hosts:
        - robocop.example.com

postgresql:
  enabled: true
  auth:
    database: malware_analysis
```

---

## Security Hardening

### Checklist

- [ ] **HTTPS Only** - Redirect all HTTP to HTTPS
- [ ] **Strong API Keys** - Minimum 32 characters, random
- [ ] **Database Encryption** - Enable at-rest encryption
- [ ] **Secret Management** - Use AWS Secrets Manager or Vault
- [ ] **Network Isolation** - Private subnets for DB and app
- [ ] **WAF** - Enable AWS WAF or Cloudflare
- [ ] **File Scanning** - Scan uploads for known malware
- [ ] **Rate Limiting** - Implement per-IP rate limits
- [ ] **Audit Logging** - Log all API access

### Security Headers

```nginx
# Add to nginx.conf
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

---

## Monitoring & Logging

### Prometheus Metrics

```python
# Add to main.py
from prometheus_client import Counter, Histogram, generate_latest
from fastapi import Response

submissions_total = Counter('submissions_total', 'Total submissions', ['type'])
analysis_duration = Histogram('analysis_duration_seconds', 'Analysis duration')

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### CloudWatch Dashboard

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["RoboCop", "SubmissionsPerMinute"],
          ["RoboCop", "AnalysisErrors"],
          ["RoboCop", "APILatency"]
        ],
        "title": "Platform Metrics"
      }
    }
  ]
}
```

### Log Aggregation

```yaml
# docker-compose logging
services:
  backend:
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"
```

---

## Backup & Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh

# PostgreSQL backup
pg_dump -h $DB_HOST -U $DB_USER -d malware_analysis | gzip > backup_$(date +%Y%m%d).sql.gz

# Upload to S3
aws s3 cp backup_$(date +%Y%m%d).sql.gz s3://backups/db/

# Retain 30 days
find /backups -mtime +30 -delete
```

### Recovery Procedure

```bash
# 1. Stop services
docker-compose down

# 2. Download latest backup
aws s3 cp s3://backups/db/backup_latest.sql.gz .

# 3. Restore database
gunzip -c backup_latest.sql.gz | psql -h $DB_HOST -U $DB_USER -d malware_analysis

# 4. Restart services
docker-compose up -d
```

---

## Maintenance

### Regular Tasks

| Task | Frequency | Command |
|------|-----------|---------|
| Update containers | Weekly | `docker-compose pull && docker-compose up -d` |
| Rotate logs | Daily | Automatic with logrotate |
| Backup database | Daily | Cron job |
| Clean old uploads | Weekly | `find /uploads -mtime +30 -delete` |
| Renew SSL certs | Auto | Certbot auto-renewal |

### Health Check Script

```bash
#!/bin/bash
# health_check.sh

# Check backend
if ! curl -sf http://localhost:8000/health > /dev/null; then
    echo "Backend unhealthy"
    docker-compose restart backend
fi

# Check database
if ! docker-compose exec db pg_isready > /dev/null; then
    echo "Database unhealthy"
    # Alert team
fi

# Check disk space
USAGE=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
if [ $USAGE -gt 80 ]; then
    echo "Disk usage above 80%"
    # Clean up old files
fi
```

---

## Rollback Procedure

```bash
# 1. Stop current deployment
docker-compose down

# 2. Checkout previous version
git checkout v1.2.3

# 3. Deploy previous version
docker-compose up -d

# 4. Verify
curl -sf http://localhost:8000/health
```

---

## Next Steps

- [Troubleshooting](TROUBLESHOOTING.md) - Common issues
- [Architecture](ARCHITECTURE.md) - System design
- [API Reference](API.md) - API documentation
