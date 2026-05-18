FROM python:3.12-slim@sha256:ec948fa5f90f4f8907e89f4800cfd2d2e91e391a4bce4a6afa77ba265bc3a2fe AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY README.md LICENSE ./
COPY backend/pyproject.toml backend/requirements.runtime.lock.txt backend/MANIFEST.in backend/README.md backend/alembic.ini ./backend/
COPY backend/app ./backend/app
COPY backend/src ./backend/src

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --only-upgrade \
        libc-bin \
        libc6 \
        libcap2 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --require-hashes -r backend/requirements.runtime.lock.txt \
    && python -m pip install --no-deps ./backend \
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
    AUDIT_RETENTION_DAYS=365 \
    MAX_UPLOAD_MB=25

EXPOSE 8000

CMD ["sh", "-c", ": \"${SECRET_KEY:?Set SECRET_KEY before starting the backend container.}\"; alembic -c /app/backend/alembic.ini upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
