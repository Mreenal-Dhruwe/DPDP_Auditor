# DPDP Compliance Auditor: one container serves the React UI and the FastAPI backend.
#
#   docker build -t dpdp-auditor .
#   docker run --rm -p 8000:8000 dpdp-auditor        # then open http://localhost:8000
#
# Settings come from environment variables (see .env.example), e.g. -e MAX_UPLOAD_MB=100.
# Hosts such as Render set PORT; the server listens on it (default 8000).

# --- Stage 1: build the frontend (react-router 8 needs Node 22.22+) ----------------------
FROM node:22-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build


# --- Stage 2: the Python runtime -------------------------------------------------------
FROM python:3.13-slim

# System packages:
#   libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0  WeasyPrint (PDF export)
#   fonts-dejavu-core   the slim image has no fonts; WeasyPrint needs one to draw text
#   git                 cloning repositories for Git-URL scans (the scanner never runs them)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core git \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    UPLOAD_DIR=/data/uploads \
    REPORT_DIR=/data/reports

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Code is owned by root and read-only for the app user; only /data is writable.
COPY scanner/ scanner/
COPY backend/ backend/
COPY rules/ rules/
# The two demo targets and their answer keys, so the CLI and evaluator work in the container:
#   docker run --rm dpdp-auditor python -m scanner.evaluate
COPY target_app/ target_app/
COPY target_app_js/ target_app_js/
COPY ground_truth.yml ground_truth_js.yml ./
COPY --from=frontend /build/frontend/dist frontend/dist

RUN useradd --create-home --uid 10001 auditor \
 && mkdir -p /data/uploads /data/reports \
 && chown -R auditor:auditor /data
USER auditor

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8000\")}/api/health', timeout=4)"
CMD ["sh", "-c", "exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
