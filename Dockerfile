# ──────────────────────────────────────────────────────────────────────
# Ai:oS Unified — Production Docker Image
# ──────────────────────────────────────────────────────────────────────
# Multi-stage build for a minimal, secure production image.
#
#   docker build -t aios-unified .
#   docker run --env-file .env -p 8080:8080 aios-unified
# ──────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ─────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps for compilation (numpy, scipy, torch wheels, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="team@aios.is"
LABEL org.opencontainers.image.title="aios-unified"
LABEL org.opencontainers.image.description="Ai:oS Unified Runtime — agentic AI operating system"
LABEL org.opencontainers.image.source="https://github.com/Workofarttattoo/aios-unified"

# Unprivileged user
RUN groupadd -r aios && useradd -r -g aios -m -s /bin/bash aios

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code (respects .dockerignore)
COPY . .

# Ensure the aios package is importable
ENV PYTHONPATH="/app:${PYTHONPATH}"
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=info
ENV PORT=8080

# Drop privileges
RUN chown -R aios:aios /app
USER aios

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "from aios.config import DISPLAY_NAME; print(DISPLAY_NAME)" || exit 1

# Default: start the FastAPI server via uvicorn
CMD ["python", "-m", "uvicorn", "runtime_unified:app", "--host", "0.0.0.0", "--port", "8080"]
