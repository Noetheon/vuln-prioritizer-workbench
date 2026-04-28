FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY README.md LICENSE ./
COPY backend/pyproject.toml backend/requirements.txt backend/MANIFEST.in backend/README.md ./backend/
COPY backend/src ./backend/src

RUN python -m pip install --upgrade pip \
    && python -m pip install ./backend \
    && adduser --disabled-password --gecos "" --uid 10001 workbench \
    && mkdir -p /app/data /app/uploads /app/reports /app/provider-snapshots /app/.cache/vuln-prioritizer \
    && chown -R workbench:workbench /app

USER workbench

ENV VULN_PRIORITIZER_DB_URL=sqlite:////app/data/workbench.db \
    VULN_PRIORITIZER_UPLOAD_DIR=/app/uploads \
    VULN_PRIORITIZER_REPORT_DIR=/app/reports \
    VULN_PRIORITIZER_PROVIDER_SNAPSHOT_DIR=/app/provider-snapshots \
    VULN_PRIORITIZER_CACHE_DIR=/app/.cache/vuln-prioritizer \
    VULN_PRIORITIZER_MAX_UPLOAD_MB=25

EXPOSE 8000

CMD ["vuln-prioritizer", "web", "serve", "--host", "0.0.0.0", "--port", "8000"]
