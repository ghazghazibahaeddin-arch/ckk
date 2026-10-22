# CCK Release, Deployment, and Rollback Operations

This document outlines the standard operational procedures for deploying, upgrading, backing up, and rolling back CCK in production environments.

---

## 1. Preparing a Production Release

1. Verify all unit, integration, and scenario tests pass:
   ```bash
   pytest -v
   cck test ./scenarios
   ```
2. Build the production Docker container:
   ```bash
   docker build -t cck-control-plane:v0.1.0 .
   ```
3. Tag and push to private container registry:
   ```bash
   docker tag cck-control-plane:v0.1.0 registry.internal.corp/cck:v0.1.0
   docker push registry.internal.corp/cck:v0.1.0
   ```

---

## 2. Backup & Disaster Recovery Procedures

CCK stores state in SQLite or PostgreSQL.

### Backing Up SQLite
```bash
# Safely snapshot SQLite with WAL mode enabled
sqlite3 /app/data/cck.db ".backup /app/backups/cck_backup_$(date +%Y%m%d_%H%M%S).db"
```

### Backing Up PostgreSQL
```bash
pg_dump -Fc -h $PGHOST -U $PGUSER -d $PGDATABASE -f /app/backups/cck_pg_$(date +%Y%m%d_%H%M%S).dump
```

---

## 3. Safe Rollback Procedure

If a deployed policy version or software upgrade causes operational issues:

1. **Policy Rollback**:
   Revert to previous policy version without restarting services:
   ```bash
   cck policy set-active v1.0.0
   ```
2. **Container Rollback**:
   Update `docker-compose.yml` to the previous known good image tag:
   ```bash
   docker-compose pull cck-engine
   docker-compose up -d --no-deps cck-engine
   ```
3. **Database Restore**:
   If database schema or data needs restoration:
   ```bash
   cp /app/backups/cck_backup_TIMESTAMP.db /app/data/cck.db
   ```
