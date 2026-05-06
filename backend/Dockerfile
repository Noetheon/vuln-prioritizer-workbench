FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY README.md LICENSE ./
COPY backend/pyproject.toml backend/requirements.txt backend/MANIFEST.in backend/README.md backend/alembic.ini ./backend/
COPY backend/app ./backend/app
COPY backend/src ./backend/src

RUN python -m pip install --upgrade pip \
    && python -m pip install ./backend \
    && adduser --disabled-password --gecos "" --uid 10001 workbench \
    && mkdir -p \
        /app/data \
        /app/uploads \
        /app/reports \
        /app/provider-snapshots \
        /app/workbench-import-uploads \
        /app/workbench-reports \
        /app/workbench-provider-cache \
        /app/.cache/vuln-prioritizer \
    && chown -R workbench:workbench /app

USER workbench
WORKDIR /app/backend

ENV SQLALCHEMY_DATABASE_URI=sqlite:////app/data/workbench.db \
    IMPORT_UPLOAD_DIR=/app/workbench-import-uploads \
    REPORT_DIR=/app/workbench-reports \
    PROVIDER_SNAPSHOT_DIR=/app/provider-snapshots \
    PROVIDER_CACHE_DIR=/app/workbench-provider-cache \
    ATTACK_ARTIFACT_DIR=/app/examples/attack \
    DEMO_PROVIDER_SNAPSHOT_ENABLED=false \
    RATE_LIMIT_ENABLED=true \
    API_RATE_LIMIT_PER_MINUTE=600 \
    LOGIN_RATE_LIMIT_PER_MINUTE=60 \
    TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE=60 \
    AUDIT_RETENTION_DAYS=365 \
    SESSION_RETENTION_DAYS=30 \
    REVOKED_API_TOKEN_RETENTION_DAYS=365 \
    MAX_UPLOAD_MB=25

EXPOSE 8000

CMD ["sh", "-c", "python -m app.core.migration_bootstrap && alembic -c /app/backend/alembic.ini upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
