FROM python:3.15.0rc2-slim-trixie@sha256:14684656c0069b49e897c63d52bbbe7df8a4bf189911a597403fd3b4ffeaae06 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY README.md LICENSE ./
COPY backend/pyproject.toml backend/requirements.runtime.lock.txt backend/MANIFEST.in backend/README.md backend/alembic.ini ./backend/
COPY backend/app ./backend/app

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --require-hashes -r backend/requirements.runtime.lock.txt \
    && python -m pip install --no-deps ./backend \
    && python -m pip uninstall -y pip setuptools wheel \
    && adduser --disabled-password --gecos "" --uid 10001 workbench \
    && mkdir -p \
        /app/data \
        /app/uploads \
        /app/reports \
        /app/provider-snapshots \
        /app/workbench-import-uploads \
        /app/workbench-reports \
        /app/workbench-provider-cache \
        /app/.cache/vuln-prioritizer-workbench \
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
    AUDIT_RETENTION_DAYS=365 \
    MAX_UPLOAD_MB=25

# Single-container runtime for self-hosting: `vpw serve` runs the API, the
# browser app, migrations, and the worker in one process with data in /data.
FROM base AS serve

USER root
RUN mkdir -p /data && chown workbench:workbench /data
USER workbench
WORKDIR /data

ENV VPW_DATA_DIR=/data

EXPOSE 8765
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/v1/utils/health-check/', timeout=4)"]

ENTRYPOINT ["vpw"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8765", "--allow-network", "--no-browser"]

# Deprecated Compose topology (API process); stays the default build target.
FROM base AS runtime

EXPOSE 8000

CMD ["sh", "-c", ": \"${SECRET_KEY:?Set SECRET_KEY before starting the backend container.}\"; alembic -c /app/backend/alembic.ini upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
