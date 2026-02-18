#!/bin/bash
set -e

# ── RoboCop — All-in-One Container Entrypoint ─────────────
# Initializes PostgreSQL, imports n8n workflows, and starts supervisord.

PGDATA="/var/lib/postgresql/16/main"
PGBIN="/usr/lib/postgresql/16/bin"
PGUSER="malware"
PGDB="malware_analysis"
PGPASS="${POSTGRES_PASSWORD:-malware_dev_only}"

echo "=== RoboCop — Starting ==="

# ── 1. Initialize PostgreSQL if needed ───────────────────────────────────────
if [ ! -f "$PGDATA/PG_VERSION" ]; then
    echo "[init] Initializing PostgreSQL data directory..."
    mkdir -p "$PGDATA"
    chown -R postgres:postgres "$PGDATA"
    su - postgres -c "$PGBIN/initdb -D $PGDATA --encoding=UTF8 --locale=C.UTF-8"

    # Allow local connections with password auth
    echo "host all all 127.0.0.1/32 md5" >> "$PGDATA/pg_hba.conf"
    echo "local all all trust" >> "$PGDATA/pg_hba.conf"

    # Configure to listen on localhost only
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '127.0.0.1'/" "$PGDATA/postgresql.conf"

    echo "[init] Starting PostgreSQL temporarily to create database..."
    su - postgres -c "$PGBIN/pg_ctl -D $PGDATA -l /tmp/pg_init.log start -w"

    # Create user and database
    su - postgres -c "$PGBIN/psql -c \"CREATE USER $PGUSER WITH PASSWORD '$PGPASS';\""
    su - postgres -c "$PGBIN/psql -c \"CREATE DATABASE $PGDB OWNER $PGUSER;\""
    su - postgres -c "$PGBIN/psql -c \"GRANT ALL PRIVILEGES ON DATABASE $PGDB TO $PGUSER;\""

    echo "[init] Stopping temporary PostgreSQL..."
    su - postgres -c "$PGBIN/pg_ctl -D $PGDATA stop -w"
    echo "[init] PostgreSQL initialized."
else
    echo "[init] PostgreSQL data directory already exists, skipping init."
fi

# Ensure PostgreSQL runtime directory exists
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql

# ── 2. Set environment defaults ──────────────────────────────────────────────
export DATABASE_URL="${DATABASE_URL:-postgresql+asyncpg://$PGUSER:$PGPASS@127.0.0.1:5432/$PGDB}"
export UPLOAD_DIR="${UPLOAD_DIR:-/app/uploads}"
export N8N_WEBHOOK_BASE_URL="${N8N_WEBHOOK_BASE_URL:-http://127.0.0.1:5678/webhook}"
export CORS_ORIGINS="${CORS_ORIGINS:-http://localhost:3000}"
export DEBUG="${DEBUG:-false}"

# Pass env vars to n8n via supervisord environment
export N8N_BASIC_AUTH_ACTIVE="${N8N_BASIC_AUTH_ACTIVE:-true}"
export N8N_BASIC_AUTH_USER="${N8N_USER:-admin}"
export N8N_BASIC_AUTH_PASSWORD="${N8N_PASSWORD:-change-this}"
export N8N_ENCRYPTION_KEY="${N8N_ENCRYPTION_KEY:-change-this-key}"

# ── 3. Create data directories ───────────────────────────────────────────────
mkdir -p /app/data /app/uploads /app/data/mitre_cache /app/data/threat_archive
mkdir -p /home/n8n/.n8n
chown -R n8n:n8n /home/n8n

# ── 4. Import n8n workflows (first run only) ────────────────────────────────
N8N_IMPORTED_MARKER="/home/n8n/.n8n/.workflows_imported"
if [ ! -f "$N8N_IMPORTED_MARKER" ] && [ -d "/opt/n8n/workflows" ]; then
    echo "[init] Will import n8n workflows after n8n starts (first run)."
    # We schedule workflow import as a background task since n8n needs to be running.
    # The import will happen after supervisord starts n8n.
    cat > /tmp/import-workflows.sh << 'IMPORT_EOF'
#!/bin/bash
echo "[import] Waiting for n8n to become ready..."
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:5678/healthz > /dev/null 2>&1; then
        echo "[import] n8n is ready. Importing workflows..."
        for wf in /opt/n8n/workflows/*.json; do
            echo "[import] Importing $(basename $wf)..."
            su - n8n -c "N8N_USER_FOLDER=/home/n8n/.n8n n8n import:workflow --input=$wf" || true
        done
        touch /home/n8n/.n8n/.workflows_imported
        echo "[import] Workflow import complete."
        exit 0
    fi
    sleep 2
done
echo "[import] WARNING: n8n did not become ready in 60s, skipping workflow import."
IMPORT_EOF
    chmod +x /tmp/import-workflows.sh
    # Run in background — supervisord will start n8n, then this script imports
    nohup /tmp/import-workflows.sh > /var/log/supervisor/workflow-import.log 2>&1 &
fi

# ── 5. Start supervisord ────────────────────────────────────────────────────
echo "[init] Starting all services via supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
